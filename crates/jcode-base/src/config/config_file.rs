use super::*;
use crate::storage::jcode_dir;
use std::path::PathBuf;
use std::sync::Mutex;

/// Serializes all `Config::save()` writers in this process so concurrent
/// `load -> mutate -> save` helpers cannot clobber each other (RC-01). This is
/// intra-process; the atomic temp-file + `rename` in `save()` additionally makes
/// writes crash-safe and reduces (though cannot fully eliminate) cross-process
/// interleavings.
static CONFIG_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Last config that parsed successfully in this process (REL-02).
///
/// When a later reload hits a malformed file, we return this instead of
/// `Config::default()` so a single TOML typo cannot silently wipe live user
/// settings (including security opt-outs). `None` until the first good load.
static LAST_GOOD_CONFIG: Mutex<Option<Config>> = Mutex::new(None);

/// Cross-process advisory lock over config writes (RC-01).
///
/// Held for the whole read-modify-write in [`Config::mutate_if`] so two
/// separate jcode processes serialize their `load -> mutate -> save` cycles and
/// cannot lose one another's updates. On Unix this is a `flock(LOCK_EX)` on a
/// dedicated `config.toml.lock` file; on other platforms it is a no-op and only
/// the in-process mutex applies (documented limitation). Acquisition is
/// best-effort: a lock failure logs and proceeds rather than blocking config
/// writes, since the atomic rename still prevents a torn file.
struct ConfigFileLock {
    /// Held open for the lock's lifetime on Unix and Windows; `None` when the
    /// lock file could not be opened or on platforms with no advisory-lock
    /// path (then only the in-process mutex applies). Unused otherwise.
    #[cfg_attr(not(any(unix, windows)), allow(dead_code))]
    file: Option<std::fs::File>,
}

impl ConfigFileLock {
    /// Open (creating if needed) and harden the `config.toml.lock` file.
    fn open_lock_file() -> Option<std::fs::File> {
        let lock_path = Config::path()?.with_extension("toml.lock");
        if let Some(parent) = lock_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .ok()?;
        // Harden the lock file (it lives beside the secret-bearing config);
        // ignore failures.
        let _ = jcode_core::fs::set_permissions_owner_only(&lock_path);
        Some(f)
    }

    fn acquire() -> Self {
        let file = Self::open_lock_file();

        #[cfg(unix)]
        if let Some(ref f) = file {
            use std::os::unix::io::AsRawFd;
            // Blocking exclusive advisory lock. flock retries EINTR itself.
            let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                crate::logging::warn(
                    "config: could not acquire inter-process write lock; proceeding \
                     with in-process lock only",
                );
            }
        }

        #[cfg(windows)]
        if let Some(ref f) = file {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx};
            use windows_sys::Win32::System::IO::OVERLAPPED;
            // Blocking exclusive lock over the whole (0..u32::MAX,u32::MAX)
            // range — the byte range is nominal since the file is empty; the
            // lock is what serializes writers across processes.
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            let ok = unsafe {
                LockFileEx(
                    f.as_raw_handle() as _,
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            };
            if ok == 0 {
                crate::logging::warn(
                    "config: could not acquire inter-process write lock; proceeding \
                     with in-process lock only",
                );
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            // No advisory-lock API wired for this platform; the in-process mutex
            // still serializes threads. Kept explicit rather than silent.
            let _ = &file;
        }

        ConfigFileLock { file }
    }
}

impl Drop for ConfigFileLock {
    fn drop(&mut self) {
        let Some(ref f) = self.file else { return };

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // Release the advisory lock; closing the fd would also drop it, but
            // be explicit so the unlock is visible and prompt.
            unsafe {
                libc::flock(f.as_raw_fd(), libc::LOCK_UN);
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
            use windows_sys::Win32::System::IO::OVERLAPPED;
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            unsafe {
                UnlockFileEx(
                    f.as_raw_handle() as _,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                );
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = f;
        }
    }
}

impl Config {
    /// Get the config file path
    pub fn path() -> Option<PathBuf> {
        jcode_dir().ok().map(|d| d.join("config.toml"))
    }

    /// Load config from file, with environment variable overrides
    pub fn load() -> Self {
        let mut config = Self::load_from_file().unwrap_or_default();
        config.apply_env_overrides();
        config
    }

    /// Load config from file, with environment variable overrides.
    ///
    /// Unlike [`Self::load`], this returns TOML/read errors to callers that need
    /// to distinguish a malformed config from an absent config.
    pub fn load_strict() -> anyhow::Result<Self> {
        let mut config = Self::load_from_file_strict()?.unwrap_or_default();
        config.apply_env_overrides();
        Ok(config)
    }

    /// Load config from file only (no env overrides).
    ///
    /// REL-02: on a parse/read error we must NOT silently fall through to
    /// `Config::default()`, which would drop every user setting — including
    /// security opt-outs like telemetry/discovery — the moment a single TOML
    /// typo lands. Instead we (1) back up the corrupt file once so it is
    /// recoverable and the user can repair it, and (2) return the last config
    /// that loaded successfully in this process, so a bad edit does not reset
    /// live settings. Interactive callers that need to surface the error use
    /// [`Self::load_strict`] (see `config_edit_notice`).
    fn load_from_file() -> Option<Self> {
        match Self::load_from_file_strict() {
            Ok(config) => {
                if let Some(ref cfg) = config {
                    Self::remember_last_good(cfg);
                }
                config
            }
            Err(e) => {
                crate::logging::error(&format!(
                    "Failed to parse config file (keeping last-good settings; not resetting to                      defaults): {}",
                    e
                ));
                Self::back_up_corrupt_config(&e);
                Self::last_good()
            }
        }
    }

    /// Snapshot the most recently parsed-good config for REL-02 fallback, both
    /// in-process and on disk.
    ///
    /// The in-process copy protects a running session; the on-disk copy
    /// (`config.toml.last-good`) preserves the last known-good settings across
    /// application restarts, so a fresh process that finds `config.toml`
    /// corrupt recovers real settings instead of silently reverting to
    /// `Config::default()`. The disk copy is a byte-for-byte snapshot of the
    /// valid file (comments/formatting preserved) written 0o600 atomically.
    fn remember_last_good(cfg: &Self) {
        if let Ok(mut guard) = LAST_GOOD_CONFIG.lock() {
            *guard = Some(cfg.clone());
        }
        // Persist a raw snapshot of the just-validated file. Copy the on-disk
        // bytes rather than re-serializing so comments and layout survive.
        let Some(path) = Self::path() else { return };
        let Ok(raw) = std::fs::read(&path) else {
            return;
        };
        let snapshot = Self::last_good_path();
        // Skip the write when the snapshot already matches, to avoid churn.
        if std::fs::read(&snapshot).ok().as_deref() == Some(raw.as_slice()) {
            return;
        }
        if let Err(e) = Self::write_atomic_hardened(&snapshot, &raw) {
            crate::logging::warn(&format!(
                "Failed to persist last-good config snapshot to {}: {}",
                snapshot.display(),
                e
            ));
        }
    }

    /// Path to the on-disk last-good config snapshot (REL-02).
    fn last_good_path() -> std::path::PathBuf {
        // Fall back to a relative name only if the primary path is unavailable;
        // callers guard on that separately.
        Self::path()
            .map(|p| p.with_extension("toml.last-good"))
            .unwrap_or_else(|| std::path::PathBuf::from("config.toml.last-good"))
    }

    /// Test-only: clear the in-process last-good snapshot to simulate a fresh
    /// process, so tests can exercise the on-disk restore path (REL-02).
    #[cfg(test)]
    pub(crate) fn clear_in_process_last_good_for_tests() {
        if let Ok(mut guard) = LAST_GOOD_CONFIG.lock() {
            *guard = None;
        }
    }

    /// The last config that parsed successfully — the in-process snapshot if
    /// present, otherwise the on-disk `config.toml.last-good` from a prior run.
    ///
    /// The on-disk fallback is what makes REL-02 survive restarts: on a fresh
    /// process with a malformed `config.toml`, this returns the persisted
    /// known-good settings instead of `None` (which would become defaults).
    fn last_good() -> Option<Self> {
        if let Some(cfg) = LAST_GOOD_CONFIG.lock().ok().and_then(|g| g.clone()) {
            return Some(cfg);
        }
        // Restore from the on-disk snapshot written by a previous good load.
        let snapshot = Self::last_good_path();
        let content = std::fs::read_to_string(&snapshot).ok()?;
        match toml::from_str::<Self>(&content) {
            Ok(mut cfg) => {
                cfg.display.apply_legacy_compat();
                cfg.repair_frozen_sponsors_optout(&content);
                crate::logging::warn(&format!(
                    "config.toml was unreadable; recovered last-good settings from {}.",
                    snapshot.display()
                ));
                Some(cfg)
            }
            // A corrupt snapshot is useless; let the caller fall through to defaults.
            Err(_) => None,
        }
    }

    /// Copy a corrupt config file aside so the user can inspect/repair it and so
    /// the bad content is never silently overwritten by the next `save()`.
    ///
    /// Idempotent per corrupt version: the backup is only (re)written when its
    /// contents differ from the current corrupt file, so a repeated reload loop
    /// does not churn the disk.
    fn back_up_corrupt_config(error: &anyhow::Error) {
        let Some(path) = Self::path() else { return };
        let Ok(corrupt) = std::fs::read(&path) else {
            return;
        };
        let backup = path.with_extension("toml.corrupt");
        if std::fs::read(&backup).ok().as_deref() == Some(corrupt.as_slice()) {
            return; // already backed up this exact corrupt content
        }
        // Use the same secure temp-file-then-rename path as save() so the backup
        // is created 0o600 BEFORE the (possibly key-bearing) corrupt bytes are
        // written — never a window at the default umask (SEC-04 hardening gap).
        match Self::write_atomic_hardened(&backup, &corrupt) {
            Ok(()) => crate::logging::warn(&format!(
                "Backed up unparseable config to {} so it can be repaired ({}).",
                backup.display(),
                error
            )),
            Err(e) => crate::logging::error(&format!(
                "Failed to back up unparseable config to {}: {}",
                backup.display(),
                e
            )),
        }
    }

    /// Load config from file only (no env overrides), preserving parse/read errors.
    fn load_from_file_strict() -> anyhow::Result<Option<Self>> {
        let Some(path) = Self::path() else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", path.display(), e))?;
        let mut config = toml::from_str::<Self>(&content).map_err(|e| {
            anyhow::anyhow!("Failed to parse config file {}: {}", path.display(), e)
        })?;
        config.display.apply_legacy_compat();
        config.repair_frozen_sponsors_optout(&content);
        Ok(Some(config))
    }

    /// Undo a machine-frozen partner-discovery opt-out.
    ///
    /// Discovery shipped opt-in (`enabled = false`), and because [`Self::save`]
    /// serializes the whole struct, any config write during that window baked
    /// the old default into the user's file. Those users keep discovery
    /// permanently disabled even after the default flipped to opt-out, and
    /// telemetry shows this is the single largest discovery blocker.
    ///
    /// A machine-written section is exactly `enabled` plus `endpoint` with a
    /// known default endpoint. A hand-written opt-out (`enabled = false` alone,
    /// or paired with a custom endpoint) is always respected. Repair happens in
    /// memory only; the section then disappears on the next save because it
    /// serializes back to the default.
    pub(crate) fn repair_frozen_sponsors_optout(&mut self, raw: &str) {
        if self.sponsors.enabled {
            return;
        }
        let Ok(doc) = raw.parse::<toml::Value>() else {
            return;
        };
        let Some(table) = doc.get("sponsors").and_then(toml::Value::as_table) else {
            return;
        };
        let machine_written = table.len() == 2
            && table.get("enabled").and_then(toml::Value::as_bool) == Some(false)
            && table
                .get("endpoint")
                .and_then(toml::Value::as_str)
                .is_some_and(super::is_default_discovery_endpoint);
        if !machine_written {
            return;
        }
        self.sponsors = SponsorsConfig::default();
        crate::logging::info(
            "config: restored integration discovery default (legacy opt-in value was frozen by an \
             earlier config save)",
        );
    }

    /// Save config to file.
    ///
    /// The write is **atomic** and **hardened**: content goes to a temp file in
    /// the same directory, is fsynced, then `rename()`d over the target so a
    /// crash mid-write can never leave a truncated `config.toml`; the file is
    /// `0o600` inside a `0o700` directory (SEC-04) because it may hold provider
    /// `api_key`s. A process-wide lock serializes the physical write.
    ///
    /// NOTE (RC-01): `save()` alone does not make a `load -> mutate -> save`
    /// sequence race-free — two callers can each load the old state and then
    /// serialize only at write time, losing one update. Mutation paths must go
    /// through [`Self::mutate`], which holds the lock across the whole cycle.
    pub fn save(&self) -> anyhow::Result<()> {
        let _guard = CONFIG_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Serialize direct physical writes with mutate_if() writers in other
        // processes too. A caller that needs an atomic read-modify-write must
        // still use mutate()/mutate_if() so the read also occurs under the lock.
        let _file_lock = ConfigFileLock::acquire();
        self.save_locked()
    }

    /// Physical atomic+hardened write. Caller must hold [`CONFIG_WRITE_LOCK`].
    fn save_locked(&self) -> anyhow::Result<()> {
        let path = Self::path().ok_or_else(|| anyhow::anyhow!("No config path"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        Self::write_atomic_hardened(&path, content.as_bytes())?;
        Self::invalidate_cache();
        Ok(())
    }

    /// Atomically read-modify-write the config (RC-01).
    ///
    /// Holds the process-wide write lock across the entire `load -> apply ->
    /// save` cycle so concurrent mutations of disjoint fields cannot clobber
    /// each other. `f` receives the freshly loaded config and mutates it in
    /// place; the result is persisted atomically before the lock is released.
    pub fn mutate(f: impl FnOnce(&mut Self)) -> anyhow::Result<()> {
        Self::mutate_if(|cfg| {
            f(cfg);
            true
        })
    }

    /// Like [`Self::mutate`], but only persists when the closure returns `true`.
    ///
    /// Lets callers keep an "only write when something actually changed"
    /// optimization while still performing the whole read-modify-decide-write
    /// cycle under the write lock (RC-01). Returns `Ok(())` whether or not a
    /// write occurred.
    pub fn mutate_if(f: impl FnOnce(&mut Self) -> bool) -> anyhow::Result<()> {
        // Intra-process: serialize threads cheaply.
        let _guard = CONFIG_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Inter-process (RC-01): hold an advisory file lock across the whole
        // read-modify-write so two separate jcode processes cannot each load,
        // edit disjoint fields, and clobber one another. Best-effort: if the
        // lock cannot be taken we proceed (never worse than before, and the
        // atomic rename still prevents a torn file).
        let _flock = ConfigFileLock::acquire();
        // Load fresh from disk INSIDE both locks so we never mutate a stale copy.
        let mut cfg = Self::load();
        if f(&mut cfg) {
            cfg.save_locked()?;
        }
        Ok(())
    }

    /// Atomically write `bytes` to `path` with owner-only permissions.
    ///
    /// Temp-file-plus-rename gives crash safety (RC-01); the `0o600`/`0o700`
    /// hardening gives secret-file protection for in-file API keys (SEC-04).
    fn write_atomic_hardened(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
        use std::io::Write;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?;

        // Temp file in the SAME directory so `rename` stays on one filesystem
        // (cross-device rename is not atomic and would fall back to copy).
        let mut tmp = tempfile::Builder::new()
            .prefix(".config.toml.")
            .suffix(".tmp")
            .tempfile_in(parent)?;

        // Harden the temp file BEFORE it holds secrets, so there is never a
        // window where the key-bearing bytes sit at default (readable) perms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }

        tmp.write_all(bytes)?;
        tmp.flush()?;
        // Durability: flush the file's contents to disk before the rename so a
        // crash cannot expose an empty/torn config (REL-02 defense in depth).
        tmp.as_file().sync_all()?;

        // Atomic replace.
        tmp.persist(path)
            .map_err(|e| anyhow::anyhow!("failed to persist config file: {}", e.error))?;

        // Best-effort hardening of the final file + parent dir (covers Windows
        // ACLs and tightens a pre-existing permissive directory).
        crate::storage::harden_secret_file_permissions(path);
        Ok(())
    }

    /// Mark the process-cached config as stale and notify dependent caches.
    pub fn invalidate_cache() {
        super::invalidate_config_cache();
    }

    /// Update the copilot premium mode in the config file.
    /// Reloads, patches, and saves so it doesn't clobber other fields.
    pub fn set_copilot_premium(mode: Option<&str>) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.provider.copilot_premium = mode.map(|s| s.to_string()))?;
        crate::logging::info(&format!(
            "Saved copilot_premium to config: {}",
            mode.unwrap_or("(none)")
        ));
        Ok(())
    }

    /// Update just the default model and provider in the config file.
    /// This reloads, patches, and saves so it doesn't clobber other fields.
    pub fn set_default_model(model: Option<&str>, provider: Option<&str>) -> anyhow::Result<()> {
        Self::mutate(|cfg| {
            cfg.provider.default_model = model.map(|s| s.to_string());
            cfg.provider.default_provider = provider.map(|s| s.to_string());
        })?;
        crate::logging::info(&format!(
            "Saved default model: {}, provider: {}",
            model.unwrap_or("(none)"),
            provider.unwrap_or("(auto)")
        ));
        Ok(())
    }

    /// Update just the default provider in the config file.
    pub fn set_default_provider(provider: Option<&str>) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.provider.default_provider = provider.map(|s| s.to_string()))
    }

    /// Update just the default model in the config file.
    pub fn set_default_model_only(model: Option<&str>) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.provider.default_model = model.map(|s| s.to_string()))
    }

    /// Update the persisted OpenAI reasoning effort preference.
    pub fn set_openai_reasoning_effort(value: Option<&str>) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.provider.openai_reasoning_effort = value.map(|s| s.to_string()))?;
        crate::logging::info(&format!(
            "Saved openai_reasoning_effort to config: {}",
            value.unwrap_or("(none)")
        ));
        Ok(())
    }

    /// Update the persisted Anthropic reasoning effort preference.
    pub fn set_anthropic_reasoning_effort(value: Option<&str>) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.provider.anthropic_reasoning_effort = value.map(|s| s.to_string()))?;
        crate::logging::info(&format!(
            "Saved anthropic_reasoning_effort to config: {}",
            value.unwrap_or("(none)")
        ));
        Ok(())
    }

    /// Update the persisted OpenAI transport preference.
    pub fn set_openai_transport(value: Option<&str>) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.provider.openai_transport = value.map(|s| s.to_string()))?;
        crate::logging::info(&format!(
            "Saved openai_transport to config: {}",
            value.unwrap_or("(none)")
        ));
        Ok(())
    }

    /// Update the persisted OpenAI service tier preference.
    pub fn set_openai_service_tier(value: Option<&str>) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.provider.openai_service_tier = value.map(|s| s.to_string()))?;
        crate::logging::info(&format!(
            "Saved openai_service_tier to config: {}",
            value.unwrap_or("(none)")
        ));
        Ok(())
    }

    /// Update the persisted default alignment preference.
    pub fn set_display_centered(centered: bool) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.display.centered = centered)?;
        crate::logging::info(&format!("Saved display.centered to config: {}", centered));
        Ok(())
    }

    /// Update the persisted reasoning display mode preference.
    pub fn set_reasoning_display(mode: ReasoningDisplayMode) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.display.set_reasoning_display(mode))?;
        crate::logging::info(&format!(
            "Saved display.reasoning_display to config: {}",
            mode.label()
        ));
        Ok(())
    }

    /// Update the persisted compact-notifications preference.
    pub fn set_compact_notifications(compact: bool) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.display.compact_notifications = compact)?;
        crate::logging::info(&format!(
            "Saved display.compact_notifications to config: {}",
            compact
        ));
        Ok(())
    }

    /// Update the persisted pinned-todos preference.
    pub fn set_pin_todos(pin: bool) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.display.pin_todos = pin)?;
        crate::logging::info(&format!("Saved display.pin_todos to config: {}", pin));
        Ok(())
    }

    /// Update the persisted show-agentgrep-output preference.
    pub fn set_show_agentgrep_output(show: bool) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.display.show_agentgrep_output = show)?;
        crate::logging::info(&format!(
            "Saved display.show_agentgrep_output to config: {}",
            show
        ));
        Ok(())
    }

    /// Update the persisted tool-call-details preference.
    pub fn set_tool_call_details(show: bool) -> anyhow::Result<()> {
        Self::mutate(|cfg| cfg.display.tool_call_details = show)?;
        crate::logging::info(&format!(
            "Saved display.tool_call_details to config: {}",
            show
        ));
        Ok(())
    }

    /// Persist the baked global launch-hotkey mapping.
    ///
    /// Auto-import calls this once with the per-repo chord -> directory layout it
    /// inferred. `imported` is set so the bake never runs twice and later manual
    /// edits are not clobbered.
    pub fn set_launch_hotkeys(
        entries: Vec<jcode_config_types::LaunchHotkeyEntry>,
        enabled: bool,
    ) -> anyhow::Result<()> {
        let entry_count = entries.len();
        Self::mutate(|cfg| {
            cfg.launch_hotkeys.entries = entries;
            cfg.launch_hotkeys.enabled = Some(enabled);
            cfg.launch_hotkeys.imported = true;
        })?;
        crate::logging::info(&format!(
            "Saved {entry_count} launch hotkey(s) to config (enabled={enabled})"
        ));
        Ok(())
    }

    /// One-time bake of per-repo launch hotkeys from session history.
    ///
    /// Scans `~/.jcode/sessions` for the directories the user works in most,
    /// ranks them (recency-weighted, git-root folded, home excluded), and writes
    /// a static chord -> directory mapping into config: top repo on `Cmd+;`, home
    /// on `Cmd+'`, and the next repos on `Cmd+[` / `Cmd+]` / `Cmd+\`.
    ///
    /// Idempotent and side-effect-light:
    /// - Runs only on platforms with global launch hotkeys (macOS, Linux,
    ///   Windows).
    /// - No-ops once `launch_hotkeys.imported` is set, so it bakes exactly once
    ///   and never overwrites later manual edits.
    /// - No-ops when there are not at least two rankable repos, so we do not
    ///   commit a degenerate "everything is home" layout on a fresh machine; the
    ///   built-in 3 hotkeys keep working until there is real history.
    ///
    /// Returns `true` when it wrote a baked mapping (so the caller can trigger a
    /// hotkey reinstall), `false` otherwise. Best-effort: errors are logged and
    /// swallowed.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    pub fn bake_launch_hotkeys_once() -> bool {
        use jcode_import_core::repo_ranking;

        let cfg = Self::load();
        if cfg.launch_hotkeys.imported {
            return false;
        }
        let Ok(jcode_dir) = jcode_dir() else {
            return false;
        };
        let sessions_dir = jcode_dir.join("sessions");
        let Some(home) = dirs::home_dir() else {
            return false;
        };

        // Cheap gate: count session files without reading them. Skip the full
        // scan until there is at least a little history, so brand-new installs do
        // not pay the read cost (and we do not bake a degenerate layout).
        let session_count = std::fs::read_dir(&sessions_dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_name().to_str().is_some_and(|n| n.ends_with(".json")))
                    .count()
            })
            .unwrap_or(0);
        const MIN_SESSIONS_TO_BAKE: usize = 3;
        const GIVE_UP_SESSION_COUNT: usize = 50;
        if session_count < MIN_SESSIONS_TO_BAKE {
            return false;
        }

        let plan = repo_ranking::plan_launch_hotkeys_from_sessions(
            &sessions_dir,
            &home,
            chrono::Utc::now(),
        );

        // `plan` always contains the home slot; a length of 1 means no rankable
        // repos were found.
        if plan.len() < 2 {
            // If the user has lots of history but still no rankable repos, stop
            // re-scanning on every launch: mark imported with no custom entries
            // (the built-in 3 hotkeys keep working).
            if session_count >= GIVE_UP_SESSION_COUNT
                && let Err(err) = Self::set_launch_hotkeys(Vec::new(), true)
            {
                crate::logging::warn(&format!("launch hotkey bake give-up persist failed: {err}"));
            }
            crate::logging::info(
                "launch hotkey bake: not enough repo history yet; keeping defaults",
            );
            return false;
        }

        let entries: Vec<jcode_config_types::LaunchHotkeyEntry> = plan
            .into_iter()
            .map(|p| jcode_config_types::LaunchHotkeyEntry {
                chord: p.chord,
                // Home keeps the dynamic sentinel so it tracks `$HOME`; repos are
                // baked to absolute paths.
                dir: if p.label == "home" {
                    "$HOME".to_string()
                } else {
                    p.dir
                },
                label: p.label,
                self_dev: false,
            })
            .collect();

        match Self::set_launch_hotkeys(entries, true) {
            Ok(()) => {
                crate::logging::info("launch hotkey bake: wrote per-repo mapping to config");
                true
            }
            Err(err) => {
                crate::logging::warn(&format!("launch hotkey bake failed to persist: {err}"));
                false
            }
        }
    }

    /// No-op bake on platforms without global launch hotkeys.
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    pub fn bake_launch_hotkeys_once() -> bool {
        false
    }

    /// One-time migration: flip a persisted legacy `swarm_spawn_mode =
    /// "visible"` to the current `"inline"` default.
    ///
    /// Historically `visible` was the default, and any full-config
    /// `Config::save()` (model switches, display toggles, ...) baked that
    /// then-default into the user's config.toml. When the default changed to
    /// `inline`, those users stayed pinned to `visible` forever. This rewrites
    /// exactly that one line (preserving the rest of the file byte-for-byte)
    /// and drops a marker so it runs at most once. A user who explicitly sets
    /// `visible` after the migration is never flipped again.
    ///
    /// Returns `true` when it rewrote the config. Best-effort: errors are
    /// logged and swallowed.
    pub fn migrate_legacy_swarm_spawn_mode_once() -> bool {
        let Ok(dir) = jcode_dir() else {
            return false;
        };
        let marker = dir.join("migrations").join("swarm-spawn-mode-inline");
        if marker.exists() {
            return false;
        }
        let write_marker = || {
            if let Some(parent) = marker.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(
                &marker,
                "swarm_spawn_mode default migration: visible -> inline\n",
            );
        };

        let path = dir.join("config.toml");
        let Ok(content) = std::fs::read_to_string(&path) else {
            // No config file (fresh install): nothing to migrate.
            write_marker();
            return false;
        };

        let mut changed = false;
        let migrated: Vec<String> = content
            .lines()
            .map(|line| {
                if changed {
                    return line.to_string();
                }
                let trimmed = line.trim_start();
                let Some(rest) = trimmed.strip_prefix("swarm_spawn_mode") else {
                    return line.to_string();
                };
                let Some(value) = rest.trim_start().strip_prefix('=') else {
                    return line.to_string();
                };
                let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
                if matches!(value, "visible" | "headed") {
                    changed = true;
                    let indent = &line[..line.len() - trimmed.len()];
                    format!("{indent}swarm_spawn_mode = \"inline\"")
                } else {
                    line.to_string()
                }
            })
            .collect();

        if !changed {
            write_marker();
            return false;
        }

        let mut new_content = migrated.join("\n");
        if content.ends_with('\n') {
            new_content.push('\n');
        }
        match std::fs::write(&path, new_content) {
            Ok(()) => {
                Self::invalidate_cache();
                write_marker();
                crate::logging::info(
                    "Migrated legacy swarm_spawn_mode \"visible\" to \"inline\" in config.toml",
                );
                true
            }
            Err(err) => {
                crate::logging::warn(&format!(
                    "swarm_spawn_mode migration failed to write config: {err}"
                ));
                false
            }
        }
    }

    /// One-time migration: flip a persisted `idle_animation = true` to `false`.
    ///
    /// The idle animation is being turned off for everyone. Users who toggled
    /// it on earlier (or had the old `true` default baked in by a full
    /// `Config::save()`) get flipped off once. This rewrites exactly that one
    /// line (preserving the rest of the file byte-for-byte) and drops a marker
    /// so it runs at most once. A user who explicitly re-enables it after the
    /// migration is never flipped again.
    ///
    /// Returns `true` when it rewrote the config. Best-effort: errors are
    /// logged and swallowed.
    pub fn migrate_idle_animation_off_once() -> bool {
        let Ok(dir) = jcode_dir() else {
            return false;
        };
        let marker = dir.join("migrations").join("idle-animation-off");
        if marker.exists() {
            return false;
        }
        let write_marker = || {
            if let Some(parent) = marker.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&marker, "idle_animation forced migration: true -> false\n");
        };

        let path = dir.join("config.toml");
        let Ok(content) = std::fs::read_to_string(&path) else {
            // No config file (fresh install): nothing to migrate.
            write_marker();
            return false;
        };

        let mut changed = false;
        let migrated: Vec<String> = content
            .lines()
            .map(|line| {
                if changed {
                    return line.to_string();
                }
                let trimmed = line.trim_start();
                let Some(rest) = trimmed.strip_prefix("idle_animation") else {
                    return line.to_string();
                };
                let Some(value) = rest.trim_start().strip_prefix('=') else {
                    return line.to_string();
                };
                let value = value.split('#').next().unwrap_or("");
                if value.trim() == "true" {
                    changed = true;
                    let indent = &line[..line.len() - trimmed.len()];
                    format!("{indent}idle_animation = false")
                } else {
                    line.to_string()
                }
            })
            .collect();

        if !changed {
            write_marker();
            return false;
        }

        let mut new_content = migrated.join("\n");
        if content.ends_with('\n') {
            new_content.push('\n');
        }
        match std::fs::write(&path, new_content) {
            Ok(()) => {
                Self::invalidate_cache();
                write_marker();
                crate::logging::info(
                    "Migrated idle_animation \"true\" to \"false\" in config.toml",
                );
                true
            }
            Err(err) => {
                crate::logging::warn(&format!(
                    "idle_animation migration failed to write config: {err}"
                ));
                false
            }
        }
    }

    fn normalize_external_auth_source_id(source_id: &str) -> String {
        source_id.trim().to_ascii_lowercase()
    }

    pub(crate) fn trusted_external_auth_path_entry(
        source_id: &str,
        path: &std::path::Path,
    ) -> anyhow::Result<String> {
        let source_id = Self::normalize_external_auth_source_id(source_id);
        if source_id.is_empty() {
            anyhow::bail!("External auth source id cannot be empty");
        }
        let canonical = crate::storage::validate_external_auth_file(path)?;
        Ok(format!(
            "{}|{}",
            source_id,
            canonical.to_string_lossy().to_ascii_lowercase()
        ))
    }

    pub fn external_auth_source_allowed(source_id: &str) -> bool {
        let source_id = Self::normalize_external_auth_source_id(source_id);
        if source_id.is_empty() {
            return false;
        }

        let cfg = Self::load();
        cfg.auth
            .trusted_external_sources
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(&source_id))
    }

    pub fn external_auth_source_allowed_for_path(source_id: &str, path: &std::path::Path) -> bool {
        let Ok(entry) = Self::trusted_external_auth_path_entry(source_id, path) else {
            return false;
        };

        let cfg = Self::load();
        cfg.auth
            .trusted_external_source_paths
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(&entry))
    }

    /// Startup-sensitive variant that uses the process-cached config snapshot.
    ///
    /// This avoids reloading config.toml repeatedly during cold-start probes.
    pub fn external_auth_source_allowed_for_path_cached(
        source_id: &str,
        path: &std::path::Path,
    ) -> bool {
        let Ok(entry) = Self::trusted_external_auth_path_entry(source_id, path) else {
            return false;
        };

        if config()
            .auth
            .trusted_external_source_paths
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(&entry))
        {
            return true;
        }

        // The global config snapshot can be initialized before an auth flow saves
        // a new path-bound trust decision, or before tests switch JCODE_HOME. Fall
        // back to a fresh load on cache misses so fast auth probes remain correct
        // without penalizing the common already-trusted path.
        Self::load()
            .auth
            .trusted_external_source_paths
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(&entry))
    }

    pub fn allow_external_auth_source(source_id: &str) -> anyhow::Result<()> {
        let source_id = Self::normalize_external_auth_source_id(source_id);
        if source_id.is_empty() {
            anyhow::bail!("External auth source id cannot be empty");
        }

        Self::mutate_if(|cfg| {
            if cfg
                .auth
                .trusted_external_sources
                .iter()
                .any(|value| value.trim().eq_ignore_ascii_case(&source_id))
            {
                return false;
            }
            cfg.auth.trusted_external_sources.push(source_id.clone());
            cfg.auth.trusted_external_sources.sort();
            cfg.auth.trusted_external_sources.dedup();
            true
        })?;

        crate::logging::info(&format!(
            "Saved trusted external auth source to config: {}",
            source_id
        ));
        Ok(())
    }

    pub fn allow_external_auth_source_for_path(
        source_id: &str,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let entry = Self::trusted_external_auth_path_entry(source_id, path)?;
        Self::mutate_if(|cfg| {
            if cfg
                .auth
                .trusted_external_source_paths
                .iter()
                .any(|value| value.trim().eq_ignore_ascii_case(&entry))
            {
                return false;
            }
            cfg.auth.trusted_external_source_paths.push(entry.clone());
            cfg.auth.trusted_external_source_paths.sort();
            cfg.auth.trusted_external_source_paths.dedup();
            true
        })?;
        crate::logging::info(&format!(
            "Saved trusted external auth source path: {}",
            entry
        ));
        Ok(())
    }

    pub fn revoke_external_auth_source_for_path(
        source_id: &str,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let entry = Self::trusted_external_auth_path_entry(source_id, path)?;
        Self::mutate_if(|cfg| {
            let before = cfg.auth.trusted_external_source_paths.len();
            cfg.auth
                .trusted_external_source_paths
                .retain(|value| !value.trim().eq_ignore_ascii_case(&entry));
            let changed = cfg.auth.trusted_external_source_paths.len() != before;
            if changed {
                crate::logging::info(&format!(
                    "Removed trusted external auth source path: {}",
                    entry
                ));
            }
            changed
        })
    }

    /// Remove a source-level (non-path) trust decision, e.g. for credentials
    /// that have no stable on-disk path (macOS Keychain items).
    pub fn revoke_external_auth_source(source_id: &str) -> anyhow::Result<()> {
        let source_id = Self::normalize_external_auth_source_id(source_id);
        if source_id.is_empty() {
            return Ok(());
        }
        Self::mutate_if(|cfg| {
            let before = cfg.auth.trusted_external_sources.len();
            cfg.auth
                .trusted_external_sources
                .retain(|value| !value.trim().eq_ignore_ascii_case(&source_id));
            let changed = cfg.auth.trusted_external_sources.len() != before;
            if changed {
                crate::logging::info(&format!(
                    "Removed trusted external auth source: {}",
                    source_id
                ));
            }
            changed
        })
    }
}

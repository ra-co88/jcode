//! RC-01 + SEC-04 tests: config saves must be atomic and owner-only.
//!
//! RC-01 (lost-update race): every `set_*` helper does `load -> mutate -> save`,
//! and `save()` must serialize writers + write atomically so two concurrent
//! mutations of disjoint fields cannot clobber each other or leave a torn file.
//!
//! SEC-04 (plaintext key exposure): `config.toml` can hold provider `api_key`s,
//! so the written file must be `0o600` (owner-only) rather than default perms.

use super::Config;

/// A freshly saved config file must be owner-only (SEC-04).
#[cfg(unix)]
#[test]
fn saved_config_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = crate::storage::lock_test_env();
    let prev_home = std::env::var_os("JCODE_HOME");
    let dir = tempfile::TempDir::new().expect("tempdir");
    crate::env::set_var("JCODE_HOME", dir.path());
    Config::invalidate_cache();

    // config.toml can carry provider secrets (named-provider `api_key`, bing
    // key, ...), so the written file must be owner-only regardless of contents.
    Config::default().save().expect("save config");

    let path = Config::path().expect("config path");
    let mode = std::fs::metadata(&path)
        .expect("stat config")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "config.toml with an api_key must be owner-only"
    );

    // The parent directory should also be owner-only.
    let dir_mode = std::fs::metadata(path.parent().unwrap())
        .expect("stat dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "config dir must be owner-only");

    match prev_home {
        Some(prev) => crate::env::set_var("JCODE_HOME", prev),
        None => crate::env::remove_var("JCODE_HOME"),
    }
    Config::invalidate_cache();
}

/// Concurrent `set_*` helpers touching disjoint fields must not lose updates
/// (RC-01). Before the fix, `load -> mutate -> save` racing on two fields would
/// drop one write; the write lock + atomic rename must preserve both.
#[test]
fn concurrent_disjoint_writes_do_not_lose_updates() {
    let _guard = crate::storage::lock_test_env();
    let prev_home = std::env::var_os("JCODE_HOME");
    let dir = tempfile::TempDir::new().expect("tempdir");
    crate::env::set_var("JCODE_HOME", dir.path());
    Config::invalidate_cache();

    // Seed a file so both writers start from the same on-disk state.
    Config::default().save().expect("seed save");

    // Hammer two disjoint fields from many threads. Each call is a full
    // load->mutate->save cycle, exactly the racy pattern RC-01 describes.
    let threads: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                if i % 2 == 0 {
                    Config::set_default_model_only(Some("model-x")).expect("set model");
                } else {
                    Config::set_display_centered(true).expect("set centered");
                }
            })
        })
        .collect();
    for t in threads {
        t.join().expect("thread join");
    }

    // The file must remain parseable (no torn write) and reflect BOTH last
    // writes, not just whichever raced last.
    Config::invalidate_cache();
    let loaded = Config::load_strict().expect("config must stay parseable after concurrent saves");
    assert_eq!(
        loaded.provider.default_model.as_deref(),
        Some("model-x"),
        "the model write must survive the race"
    );
    assert!(
        loaded.display.centered,
        "the centered write must survive the race"
    );

    match prev_home {
        Some(prev) => crate::env::set_var("JCODE_HOME", prev),
        None => crate::env::remove_var("JCODE_HOME"),
    }
    Config::invalidate_cache();
}

/// REL-02: a malformed config file must NOT silently reset live settings to
/// defaults; the last good config is preserved and the bad file is backed up.
#[test]
fn malformed_config_preserves_last_good_and_backs_up() {
    let _guard = crate::storage::lock_test_env();
    let prev_home = std::env::var_os("JCODE_HOME");
    let dir = tempfile::TempDir::new().expect("tempdir");
    crate::env::set_var("JCODE_HOME", dir.path());
    Config::invalidate_cache();

    // Establish a known-good on-disk + last-good state with a non-default value.
    Config::set_display_centered(true).expect("seed good config");
    let good = Config::load();
    assert!(
        good.display.centered,
        "precondition: good config has centered=true"
    );

    // Corrupt the file with invalid TOML.
    let path = Config::path().expect("config path");
    std::fs::write(
        &path,
        "this = is = not valid toml
[[[",
    )
    .expect("write corrupt");

    // Loading now must fall back to the last-good config, NOT Config::default().
    let recovered = Config::load();
    assert!(
        recovered.display.centered,
        "malformed config must preserve last-good settings, not reset to defaults"
    );

    // The corrupt file must be backed up for repair.
    let backup = path.with_extension("toml.corrupt");
    assert!(
        backup.exists(),
        "corrupt config should be backed up to {backup:?}"
    );
    let backed = std::fs::read_to_string(&backup).expect("read backup");
    assert!(
        backed.contains("not valid toml"),
        "backup must hold the corrupt bytes"
    );

    match prev_home {
        Some(prev) => crate::env::set_var("JCODE_HOME", prev),
        None => crate::env::remove_var("JCODE_HOME"),
    }
    Config::invalidate_cache();
}

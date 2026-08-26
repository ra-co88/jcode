# Apodex Audit Remediation — Status & Honest Scope

This records what each audit fix on `fix/apodex-audit-findings` actually does,
with precise scope. It exists because an earlier summary over-claimed a few
points; a follow-up review (correctly) flagged them. Each item below states the
mechanism, what it does cover, and what it deliberately does **not**.

## P0

### SEC-01 — PKCE verifier no longer used as OAuth `state` (Claude) — DELIVERED
Generates an independent CSRF `state`; the PKCE `code_verifier` never enters
the authorization URL. Verified by tests asserting `state != verifier` and that
the verifier is absent from the URL. No scope caveats.

### SEC-02 — AppleScript/JXA routed through the #604 destructive gate — DELIVERED as **heuristic defense-in-depth**, not a sandbox
`run_applescript`/`run_jxa` scripts are scanned for embedded shell payloads
(`do shell script`, JXA `doShellScript`) which are routed through the exact
shipped #604 policy, dynamic/computed shell arguments are held for
justification, and a small set of native permanent-destruction verbs
(`NSFileManager removeItem*`, `NSTask`) are flagged.

**Scope (honest):** this is a static heuristic. It does **not** catch every
interpreter obfuscation, alternate ObjC API, or dynamic dispatch, and it is not
an OS sandbox (see SEC-05). A native-verb match with any non-empty
`justification` proceeds — that is a reflection/confirmation gate, not
prevention. Comprehensive enforcement requires OS-level sandboxing (SEC-05).

## P1

### SEC-03 — SSRF guard on webfetch — DELIVERED, with connection pinning
Resolves the host and rejects if **any** resolved IP is
loopback/private/link-local (incl. `169.254.169.254`)/unspecified/multicast/
CGNAT/IPv6-ULA/IPv4-mapped. webfetch disables auto-redirects and re-guards
**every** redirect hop, and **pins** the connection to the validated IP
(reqwest `.resolve()`), so the address checked is the address connected to —
closing the resolve-then-connect DNS-rebinding TOCTOU gap for the pinned client.

**Scope (honest):** pinning closes the common TOCTOU case. It does **not** cover
requests that bypass the pinned client (proxies, other code paths), and there is
no allowlist escape hatch for legitimately-internal hosts yet. The `websearch`
SearXNG endpoint is intentionally **not** guarded — it is operator-configured
(config/env), commonly self-hosted on localhost/LAN, so the operator config is
the trust boundary, not a model-influenced input.

### RC-01 — Atomic, race-free config writes — DELIVERED for intra- **and** inter-process
`save()` writes via temp-file + fsync + atomic rename (crash-safe). All ~19
mutation helpers go through `mutate()`/`mutate_if()`, which hold both a
process-local `Mutex` **and** a cross-process advisory file lock
(`flock(LOCK_EX)` on `config.toml.lock`, Unix) across the whole
load-modify-save, so two separate jcode processes cannot lose one another's
updates.

**Scope (honest):** the cross-process lock is implemented on **Unix**. On
non-Unix platforms only the in-process mutex applies (documented in code); a
cross-process race remains possible there until a Windows `LockFileEx` path is
added.

### REL-01 — Bounded network reconnect — DELIVERED
`wait_until_probably_online()` is bounded (default 300s ceiling), returns
`Online`/`GaveUp`, and all four `turn.rs` call sites surface a clear message and
stop on give-up instead of hanging forever. No scope caveats.

## P2

### SEC-04 — Config file hardened to `0o600` — DELIVERED
`config.toml`, its temp file (hardened **before** secret bytes are written), the
corrupt backup, and the last-good snapshot are all owner-only, inside a `0o700`
dir.

### REL-02 — Malformed config no longer silently resets — DELIVERED across restarts
On a parse error: the corrupt file is backed up (`config.toml.corrupt`,
`0o600`), and the config falls back to the last known-good — the in-process
snapshot if present, otherwise an on-disk `config.toml.last-good` (`0o600`,
written atomically on every good load). This survives process restarts.

**Scope (honest):** the disk snapshot is only as fresh as the last successful
load in any prior run; if a user has never loaded a valid config on this
machine, there is nothing to recover and defaults still apply.

## P3 / Informational

### A11Y-01 — DELIVERED as documentation + `NO_COLOR`
`docs/ACCESSIBILITY.md` gives an honest screen-reader account. The proposed
`--json-events` structured stream is a documented tracked enhancement, not
implemented.

### VC-01 — DELIVERED (narrow residual)
The meta-audit confirmed contrast is already computed/asserted and the CLI
honors `NO_COLOR`. The residual — the TUI renderer ignoring `NO_COLOR` — is
fixed (`strip_colors_for_no_color` in the render loop). Contrast remains OKLab
lightness-delta (not WCAG 2.x ratio) and is not a hard build gate; documented.

### SEC-07 — DELIVERED as documentation + roadmap
`SECURITY.md` documents the install/update trust model (checksums prove
integrity, not authenticity; `curl|bash` is trust-on-first-use; binaries
unsigned) and a hardening roadmap. Signature verification itself is **not**
implemented — it requires a maintainer decision on signing-key custody.

## Not addressed here
- **SEC-06** (iOS keychain fail-closed): Swift; not buildable on this Rust
  toolchain — needs Xcode.
- **SEC-05** (OS-level command sandbox): large architectural effort; SEC-02 is
  the interim heuristic mitigation.

## Verification note
Built and tested with `cargo <cmd> --ignore-rust-version` because the installed
Homebrew rustc is 1.94.0 while pinned AWS SDK crates declare MSRV 1.94.1 (a
cosmetic bump). A reviewer on stock 1.94.0 without that flag will see a
toolchain error, not a code failure.

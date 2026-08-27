# Security

This document covers jcode's software supply-chain trust model for
installation and updates (audit finding SEC-07), and where to report issues.

## Reporting a vulnerability

Please report security issues privately to the maintainer rather than opening a
public issue. Include repro steps and the affected version/commit.

## Install & update trust model (SEC-07)

### What is verified today

- **Checksum integrity.** The install script and the in-app updater download a
  `SHA256SUMS` file and verify the downloaded binary's SHA-256 against it
  (`scripts/install.sh`, `crates/jcode-update-core::verify_asset_checksum_text`).
  The installer tries multiple checksum sources (the release metadata host and
  the GitHub release assets) before trusting one.
- **Transport.** All downloads are over HTTPS/TLS.

This reliably prevents **accidental corruption** (partial downloads, mirror
rot, CDN glitches).

### What is NOT verified — and the residual risk

- **No independent cryptographic signature.** The `SHA256SUMS` file and the
  binary share the same trust root (the release host / repository). An attacker
  who compromises that origin can serve a malicious binary *and* a matching
  `SHA256SUMS`, and checksum verification will pass. Checksums prove integrity,
  not authenticity.
- **`curl | bash` install is trust-on-first-use.** `curl -fsSL
  https://jcode.sh/install | bash` (and the PowerShell equivalent) pipes remote
  code into a shell with the user's privileges. This is industry-standard for
  CLI tools but means a compromise of the install host serves code directly.
- **Prebuilt binaries are not code-signed/notarized** at time of writing, so the
  OS cannot independently attest their origin.

### Recommendations for cautious users

- Prefer building from source (`cargo build --release`) if you want to avoid the
  `curl | bash` trust-on-first-use step.
- Or download the release archive and the `SHA256SUMS` from the GitHub release
  page, inspect the installer script before running it, and verify the checksum
  by hand.
- Pin to a specific released version rather than always taking latest.

### Hardening roadmap (tracked, not yet implemented)

These are the concrete steps to close the authenticity gap. They are recorded
here so the trust model is honest and the work is visible; they intentionally
require a maintainer decision on signing-key custody and are out of scope for
the change that added this document.

1. **Detached signatures over `SHA256SUMS`.** Sign the sums file with a
   long-lived key (minisign/signify or cosign/Sigstore) whose public key is
   published out-of-band (README, website, and a pinned repo file). Verify the
   signature in `jcode-update-core` and `scripts/install.sh` before trusting any
   checksum. `jcode-update-core` already isolates checksum parsing/verification,
   so a signature-verification step slots in ahead of it behind an opt-in
   configured public key (no behavior change until a key ships).
2. **Multi-channel checksum/signature publication.** Publish the sums (and their
   signature) on at least two independent roots (e.g. GitHub releases + a signed
   git tag) so a single-origin compromise is insufficient.
3. **Platform code signing / notarization.** Sign+notarize macOS binaries and
   sign Windows binaries so the OS attests origin; verify update payloads
   against those signatures where the platform supports it.
4. **Pin the installer artifact hash inside the install script** so the script
   and the artifact it fetches are bound together.

Until (1)-(3) land, treat installation and updates as trust-on-first-use rooted
in the release host's integrity.

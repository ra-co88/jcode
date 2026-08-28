# Verify-then-commit

> **Status:** Shipped server-side (opt-in). Client answer-UX coverage below.
> **Origin:** Apodex improvement report, top-5 pick #1 — "inline diff preview +
> accept/reject before mutations", rooted in the same instinct as the #604
> destructive-command gate.

When `[tools] verify_file_edits = true`, file mutations held by the gate ask the
user before the write lands:

- **Trivial changes are never gated** — up to `AUTO_ACCEPT_MAX_CHANGED_LINES`
  changed lines (3 today) apply silently, so typo fixes stay zero-friction.
- Everything larger sends a prompt containing the path, action (create / modify /
  delete), and a diff excerpt through jcode's existing interactive stdin channel
  (`ServerEvent::StdinRequest`) and waits up to 5 minutes for one line:
  - `y` / `yes` / `ok` / `approve` — apply this change.
  - `n` / `no` / empty / anything unrecognized — reject; the model is told the
    user declined and not to retry unchanged.
  - `all` / `always` — bulk-accept every later edit in this session.
- No interactive user attached (headless runs), a dropped client, or a timeout
  blocks the mutation with an actionable message ("Nothing was written"). The
  gate fails closed: an ambiguous answer never becomes a silent write.
- Deletions (`apply_patch` delete hunks, unified-diff deletes) are gated like
  any other mutation.

## Enabled surfaces

| Tool | Gated operations |
|------|------------------|
| `edit` | single replacement |
| `multiedit` | whole-file result after applying its edit list |
| `write` | overwrites and new-file creation (before parent dirs are made) |
| `apply_patch` | AddFile, DeleteFile, Update, Move destination |
| `patch` | unified-diff create, modify, delete |

## Known gaps / follow-ups

1. **Client answer UX**: the daemon forwards the prompt to connected clients,
   and both TUI backend (`send_stdin_response`) and server
   (`handle_stdin_response`) can route replies, but remote-mode status output
   currently only shows "Interactive terminal detected" rather than capturing
   the answer. Until that capture mode ships, enabling this flag on such a
   surface means prompts time out and edits block — keep it off there.
2. Timeout is fixed at 5 minutes; a config knob can follow if sessions need
   unattended-but-gated modes.
3. Path-scoped trust rules ("always allow under `.jcode/skills/`") are not yet
   implemented; bulk-accept is session-wide only.

## Tests

`crates/jcode-app-core/src/tool/edit_approval_tests.rs` covers classification,
prompt construction/reply parsing, channel round-trips (approve / reject / bulk
/ dropped responder), and fail-closed behavior without a channel.

Run with:

```
cargo test -p jcode-app-core --lib edit_approval
```

**Local-machine note (2026-08-27):** the full in-workspace run needs ~1.5 GB of
scratch for the test-profile link and this machine peaked at ~200 MB free, so
verification used a standalone harness at `/tmp/vtc_scratch` that `#[path]`-
includes the real `edit_approval.rs` (and, through it, the real tests file)
against field-identical stubs of `jcode_tool_core` and `config`: all 13 tests
pass on the shipped source. `cargo check -p jcode-app-core --lib` passed on the
wiring before the disk filled; re-run the command above when space allows.

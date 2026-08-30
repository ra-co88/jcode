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

1. **Client answer UX — SHIPPED (remote TUI).** `ServerEvent::StdinRequest`
   now arms a pending-answer state in the remote TUI: the prompt is shown in
   the transcript, **Enter** sends the composer line as the reply
   (`Request::StdinResponse`), **Esc** declines with an empty reply (which the
   edit gate treats as a rejection), and other keys keep editing the draft
   without consuming the request. Interactive bash stdin benefits too —
   prompts no longer just show a "will timeout" notice.
   Not yet covered: local (non-remote) sessions route tools without a stdin
   channel, so the gate there still fails closed (documented above); masked
   (`is_password`) replies currently render unmasked in the composer.
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

**Local-machine note (2026-08-30):** the full in-workspace run completed after
disk was freed: `cargo test -p jcode-app-core --lib edit_approval` — **13/13
pass**. The TUI answer-UX is covered by 4 tests in
`crates/jcode-tui/src/tui/app/tests/stdin_answer_remote.rs` (capture, Enter
routing, Esc decline, draft-preserving keys), run with
`cargo test -p jcode-tui --lib stdin_` plus the `esc_declines other_keys`
filters — **4/4 pass**. An earlier scratch-harness verification on this machine
(`#[path]`-including the real module against stubs) is now redundant.

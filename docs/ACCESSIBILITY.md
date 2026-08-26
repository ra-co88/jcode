# Accessibility

jcode's primary interface is a character-cell terminal UI (TUI) built on
Ratatui. This document is an honest account of what that means for assistive
technology today, what already works, and what does not yet — so users relying
on screen readers or low-vision configurations can make an informed choice.

## The short version

- A text terminal is intrinsically more screen-reader-friendly than a
  canvas/WebGL/chat-native UI: everything jcode draws is real text in the
  terminal buffer, which terminal-attached screen readers can read.
- jcode is fully keyboard-driven; nothing requires a mouse.
- The known gap: jcode has **no dedicated screen-reader announcement channel**.
  Streaming model tokens, evolving tool-call panels, and background-task status
  are written to the cell buffer, so a screen reader only sees them if it
  re-reads the region. There is no ARIA-live-region equivalent for a TUI.

## What works today

- **Keyboard-only operation.** All actions are reachable via key bindings; see
  `docs/KEYMAP_CONFLICTS.md` for the current bindings and how to rebind.
- **Colors can be disabled.** jcode honors the `NO_COLOR` convention and its
  own `JCODE_NO_COLOR`. When either is set (and for non-TTY output), colorized
  CLI output is suppressed. See `src/cli/dispatch.rs` and
  `src/cli/provider_doctor.rs`.
- **Status is not encoded by color alone.** The activity spinner uses distinct
  Braille-pattern glyphs (`⠋⠙⠹⠸…`), and jcode automatically drops to a slower,
  lower-motion "liveness" indicator in reduced-capability environments (SSH,
  WSL, minimal terminals). Status therefore remains distinguishable without
  color perception.
- **Theme contrast is measured.** `jcode-tui-style` includes a color-harmony
  engine that scores role text/background contrast against a target and warns
  on low-contrast palettes (`crates/jcode-tui-style/src/harmony.rs`). Custom
  palettes that score poorly are flagged rather than shipped blindly.

## Known limitations

- **No announcement stream.** Off-screen buffer changes (a tool result that
  scrolled up, a background task finishing) are not announced. A screen-reader
  user must navigate to the region to hear updates. There is no
  `--json-events`/structured-event feed yet that assistive tooling could
  consume for spoken announcements (this is the tracked enhancement below).
- **Contrast is OKLab lightness-delta, not WCAG 2.x ratio**, and the shipped
  theme audit is not a hard build gate. Terminal emulators also remap colors,
  so the same RGB can render at different luminance; measured guarantees hold
  for the computed palette, not for every emulator's rendering.
- **Fast spinner cadence.** In full-capability terminals the activity spinner
  animates smoothly. There is not yet a `prefers-reduced-motion`-style opt-out
  for the fast path specifically (the reduced-motion *tiers* above are driven by
  terminal capability, not an explicit user preference flag).

## Recommendations for screen-reader users

- Set `NO_COLOR=1` (or `JCODE_NO_COLOR=1`) if your reader mis-handles ANSI color.
- Use a terminal + screen reader combination known to read cell content well
  (e.g. Orca with a supported terminal on Linux).
- For scripting or bridging, prefer the harness API / SDK
  (`crates/jcode-harness-api`, `crates/jcode-sdk`) which expose structured data
  rather than scraping the TUI.

## Tracked enhancement: structured event stream

The most impactful future improvement is an opt-in machine-readable event
stream (proposed `--json-events`: JSONL on stdout or a local socket) emitting
turn start/end, tool call start/complete, and status transitions. External
assistive tooling could consume it to produce spoken announcements, and it
doubles as a scripting/automation surface. This is intentionally out of scope
for the documentation pass that added this file; it is recorded here so the
limitation is visible and the design is captured.

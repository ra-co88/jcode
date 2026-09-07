//! The destructive-command gate for the `bash` tool (issue #604).
//!
//! Kept in its own file so the policy seam is easy to find and review: this is
//! the only thing standing between a model's `rm -rf` and the user's data.

/// Apply the deterministic destructive-command gate, returning refusal text
/// when the command must not run as-issued.
///
/// Stage 1 is a pure blast-radius assessment; stage 2 turns a `Confirm` verdict
/// into a reflection prompt that a blind retry cannot satisfy. Catastrophic
/// targets (`/`, `$HOME`, credential stores, device nodes) are denied outright.
/// See issue #604.
pub(crate) fn destructive_command_refusal(
    command: &str,
    justification: Option<&str>,
    working_dir: Option<std::path::PathBuf>,
) -> Option<String> {
    destructive_command_refusal_labeled(command, justification, working_dir, "bash")
}

/// Same policy as [`destructive_command_refusal`], but with a caller label so
/// log lines identify which tool surface issued the command (e.g. `bash`,
/// `macos_computer_use`). Reused by the computer-use scripting gate (SEC-02) so
/// AppleScript/JXA go through the exact same shipped, tested #604 policy.
pub(crate) fn destructive_command_refusal_labeled(
    command: &str,
    justification: Option<&str>,
    working_dir: Option<std::path::PathBuf>,
    caller: &str,
) -> Option<String> {
    let risk_ctx = jcode_command_risk::RiskContext::from_env(working_dir);
    let assessment = jcode_command_risk::assess(command, &risk_ctx);
    if assessment.level.runs_immediately() {
        return None;
    }

    let justification = jcode_command_risk::Justification {
        text: justification.map(str::to_string),
    };
    match jcode_command_risk::gate(&assessment, &justification) {
        jcode_command_risk::GateOutcome::Allow => None,
        jcode_command_risk::GateOutcome::Deny { reason } => {
            crate::logging::warn(&format!("[{caller}] denied destructive command: {command}"));
            Some(reason)
        }
        jcode_command_risk::GateOutcome::Reflect { prompt } => {
            crate::logging::info(&format!(
                "[{caller}] destructive command held for justification: {command}"
            ));
            Some(prompt)
        }
    }
}

/// The `bash` tool's JSON schema, including the `justification` field the
/// destructive-command gate consumes.
///
/// Lives beside the gate so the schema and the policy that reads it stay in
/// sync, and so bash.rs stays inside the code-size budget.
pub(crate) fn bash_parameters_schema() -> serde_json::Value {
    let cmd_desc = if cfg!(windows) {
        "The Windows command to execute via cmd.exe. Use cmd.exe syntax and quoting, not Bash syntax."
    } else {
        "The bash command to execute. Put large temp files under `$JCODE_SCRATCH_DIR`, not `/tmp`."
    };
    serde_json::json!({
        "type": "object",
        "required": ["command"],
        "properties": {
            "intent": crate::tool::intent_schema_property(),
            "command": {
                "type": "string",
                "description": cmd_desc
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in MILLISECONDS (not seconds), e.g. 600000 = 10min; kills with exit 124. Omit for no timeout."
            },
            "run_in_background": {
                "type": "boolean",
                "description": "Run in background. Emit `JCODE_PROGRESS {json}` lines for progress reporting."
            },
            "notify": {
                "type": "boolean",
                "description": "Notify on completion."
            },
            "wake": {
                "type": "boolean",
                "description": "Wake on completion."
            },
            "stall_wake_seconds": {
                "type": "integer",
                "description": "With run_in_background: wake the agent after this many seconds of no output/progress (min 30, resets on activity). Use for long jobs that may hang silently."
            },
            "justification": {
                "type": "string",
                "description": "Only when re-issuing a command the destructive gate refused; explain which user request it serves."
            }
        }
    })
}

// ============================================================================
// SEC-02: destructive-command gate for macOS computer-use scripting.
//
// `macos_computer_use`'s `run_applescript` / `run_jxa` actions execute
// model-supplied source via `/usr/bin/osascript`. AppleScript can shell out
// with `do shell script "..."` and JXA with `Application(...).doShellScript(...)`
// / `$.NSTask` / `ObjC` bridges, so an ungated script is a #604-class data
// destruction path that neighbours the `bash` tool while bypassing its gate.
//
// This is defense-in-depth, honestly scoped (cf. SEC-05): a static parser
// cannot catch every obfuscation an interpreter allows. It reuses the shipped,
// tested #604 policy for the common, high-signal cases: embedded `do shell
// script` / `doShellScript` payloads are routed through the exact same gate as
// bash, and a small set of native permanent-destruction verbs are treated as
// requiring justification.
// ============================================================================

/// Return refusal text when an AppleScript/JXA `script` must not run as issued.
///
/// `None` means "no destructive signal detected, proceed"; `Some(reason)` is a
/// refusal/reflection prompt to surface to the model, mirroring the bash gate.
#[cfg(target_os = "macos")]
pub(crate) fn applescript_destructive_refusal(
    script: &str,
    justification: Option<&str>,
    working_dir: Option<std::path::PathBuf>,
) -> Option<String> {
    // 1) Handle embedded shell payloads.
    for payload in extract_embedded_shell_commands(script) {
        match payload {
            // A readable literal: route through the exact shipped #604 gate.
            ShellPayload::Literal(cmd) => {
                if let Some(refusal) = destructive_command_refusal_labeled(
                    &cmd,
                    justification,
                    working_dir.clone(),
                    "macos_computer_use",
                ) {
                    return Some(refusal);
                }
            }
            // A computed/opaque argument we cannot inspect statically. We cannot
            // prove it is safe, so hold it for justification (reflection-level),
            // mirroring how the #604 gate treats an unknown-target command.
            ShellPayload::Dynamic => {
                if justification
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_none()
                {
                    crate::logging::warn(
                        "[macos_computer_use] held script: `do shell script` with a \
                         non-literal (computed) argument",
                    );
                    return Some(
                        "This script passes a computed value to `do shell script`, so its \
                         effect cannot be verified before it runs. Because the scripting \
                         actions bypass the terminal's destructive-command gate (#604), it \
                         is held.\n\nRe-issue with a `justification` explaining which user \
                         request it serves, or inline the exact shell command as a string \
                         literal so it can be checked."
                            .to_string(),
                    );
                }
                crate::logging::info(
                    "[macos_computer_use] allowed dynamic `do shell script` with justification",
                );
            }
        }
    }

    // 2) Flag native permanent-destruction verbs the shell gate cannot see.
    if let Some(verb) = detect_native_destruction_verb(script) {
        if justification
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_none()
        {
            crate::logging::warn(&format!(
                "[macos_computer_use] held potentially destructive script (matched `{verb}`)"
            ));
            return Some(format!(
                "This AppleScript/JXA uses `{verb}`, which can permanently delete or                  overwrite user data outside any recycle bin. The `macos_computer_use`                  scripting actions bypass the terminal, so this is held for the same                  reason the bash destructive-command gate (#604) holds `rm -rf`.\n\n                 If this is genuinely required by the user's request, re-issue the action                  with a `justification` explaining which request it serves and why a                  non-destructive approach will not work. Prefer moving items to the Trash                  (Finder `delete`) over `NSFileManager removeItem` / `rm`."
            ));
        }
        crate::logging::info(&format!(
            "[macos_computer_use] allowed script matching `{verb}` with justification"
        ));
    }

    None
}

/// A shell payload discovered inside an AppleScript/JXA source.
#[cfg(target_os = "macos")]
enum ShellPayload {
    /// A shell command we could read as a string literal — check it directly.
    Literal(String),
    /// A `do shell script` whose argument is a computed value we cannot read
    /// statically (variable, concatenation, function call). Cannot be proven
    /// safe, so it is held for justification rather than passed to the gate.
    Dynamic,
}

/// Extract shell payloads embedded in an AppleScript/JXA source via the
/// documented shell-escape verbs (`do shell script`, JXA `doShellScript`).
/// When a verb's argument is a static string literal we return it verbatim for
/// the #604 gate; when it is a computed value we return [`ShellPayload::Dynamic`]
/// so the caller can hold it rather than silently allow it.
#[cfg(target_os = "macos")]
fn extract_embedded_shell_commands(script: &str) -> Vec<ShellPayload> {
    let lower = script.to_ascii_lowercase();
    // Verbs that hand a string to a shell. Keep this list tight and documented.
    const VERBS: [&str; 3] = ["do shell script", "doshellscript", "shellscript"];

    let mut out = Vec::new();
    for verb in VERBS {
        let mut from = 0usize;
        while let Some(rel) = lower[from..].find(verb) {
            let idx = from + rel + verb.len();
            from = idx;
            // Only accept a literal that begins at the verb's argument position
            // (allowing whitespace / an opening paren for the JXA form). A literal
            // that appears only *after* other tokens means the argument itself is
            // computed, so we escalate as Dynamic.
            match literal_at_argument_start(&script[idx..]) {
                Some(cmd) => out.push(ShellPayload::Literal(cmd)),
                None => out.push(ShellPayload::Dynamic),
            }
        }
    }
    out
}

/// Read a quoted string literal that begins at the argument position following a
/// shell verb — i.e. after only insignificant tokens (whitespace, `(`, `:`).
/// Returns `None` if the argument is not an immediate literal (e.g. a variable),
/// which the caller treats as a non-inspectable dynamic argument.
#[cfg(target_os = "macos")]
fn literal_at_argument_start(s: &str) -> Option<String> {
    let mut chars = s.char_indices();
    for (i, c) in chars.by_ref() {
        match c {
            // Insignificant leading tokens between the verb and its argument.
            ' ' | '\t' | '\n' | '\r' | '(' | ':' => continue,
            '"' | '\'' => return first_string_literal_after(&s[i..]),
            // Any other token first means the argument is not an immediate
            // literal (variable name, expression, etc.).
            _ => return None,
        }
    }
    None
}

/// Read the first double- or single-quoted string literal in `s`, unescaping
/// the common `\"` / `\'` sequences. Returns `None` if no literal is found.
#[cfg(target_os = "macos")]
fn first_string_literal_after(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '"' || c == '\'' {
            let quote = c;
            let mut out = String::new();
            let mut j = i + 1;
            while j < bytes.len() {
                let cj = bytes[j] as char;
                if cj == '\\' && j + 1 < bytes.len() {
                    out.push(bytes[j + 1] as char);
                    j += 2;
                    continue;
                }
                if cj == quote {
                    return Some(out);
                }
                out.push(cj);
                j += 1;
            }
            return Some(out); // unterminated literal: return what we have
        }
        i += 1;
    }
    None
}

/// Detect native (non-shell) permanent-destruction verbs. Returns the matched
/// token for use in the refusal message. Deliberately narrow: Finder `delete`
/// moves to Trash and is intentionally NOT matched.
#[cfg(target_os = "macos")]
fn detect_native_destruction_verb(script: &str) -> Option<&'static str> {
    let lower = script.to_ascii_lowercase();
    const VERBS: [&str; 5] = [
        "removeitematpath", // NSFileManager removeItemAtPath:
        "removeitematurl",  // NSFileManager removeItemAtURL:
        "nstask",           // arbitrary process launch (shell-equivalent)
        "trashitematurl",   // ok to Trash, but pair with recursive removal below
        "removeitem",       // generic NSFileManager removeItem
    ];
    for v in VERBS {
        // `trashitematurl` alone is non-destructive (recycle bin); only flag it
        // when combined with an explicit unlink verb elsewhere in the script.
        if v == "trashitematurl" {
            continue;
        }
        if lower.contains(v) {
            return Some(match v {
                "removeitematpath" => "NSFileManager removeItemAtPath",
                "removeitematurl" => "NSFileManager removeItemAtURL",
                "removeitem" => "NSFileManager removeItem",
                "nstask" => "NSTask",
                _ => "destructive file API",
            });
        }
    }
    None
}

#[cfg(all(test, target_os = "macos"))]
mod sec02_scripting_gate_tests {
    //! SEC-02: `macos_computer_use` scripting (`run_applescript`/`run_jxa`) must
    //! route embedded shell payloads through the shipped #604 gate and flag
    //! native permanent-destruction verbs. These tests are pure logic (no
    //! osascript), so they run wherever the gate itself compiles (macOS).
    use super::*;

    #[test]
    fn allows_benign_shell_script() {
        assert!(
            applescript_destructive_refusal("do shell script \"echo hi\"", None, None).is_none(),
            "a harmless echo must not be gated"
        );
    }

    #[test]
    fn allows_non_destructive_applescript() {
        // Pure GUI automation with no shell/removal verbs proceeds.
        let script = "tell application \"Finder\" to activate";
        assert!(applescript_destructive_refusal(script, None, None).is_none());
    }

    #[test]
    fn blocks_catastrophic_embedded_shell_even_with_justification() {
        // `rm -rf $HOME` is catastrophic in the #604 policy: no justification
        // can unlock it, and it must be caught when embedded in AppleScript.
        let script = "do shell script \"rm -rf $HOME\"";
        assert!(applescript_destructive_refusal(script, None, None).is_some());
        assert!(
            applescript_destructive_refusal(script, Some("user asked"), None).is_some(),
            "catastrophic targets stay blocked regardless of justification"
        );
    }

    #[test]
    fn flags_native_removeitem_without_justification() {
        // JXA file deletion via NSFileManager bypasses the shell gate; the
        // native-verb detector must hold it for justification.
        let script =
            "$.NSFileManager.defaultManager.removeItemAtPathError('/Users/x/.ssh/id_ed25519')";
        let refusal = applescript_destructive_refusal(script, None, None)
            .expect("removeItemAtPath must be gated");
        assert!(refusal.contains("removeItemAtPath"));
    }

    #[test]
    fn native_verb_passes_with_justification() {
        // Unlike catastrophic shell targets, a native-verb match is a
        // reflection-level hold: an explicit justification lets it proceed.
        let script = "$.NSFileManager.defaultManager.removeItemAtPathError('/tmp/scratch')";
        assert!(applescript_destructive_refusal(script, None, None).is_some());
        assert!(
            applescript_destructive_refusal(script, Some("clean up my temp scratch dir"), None)
                .is_none(),
            "a justified native removal should proceed"
        );
    }

    #[test]
    fn detects_do_shell_script_case_insensitively() {
        // AppleScript is case-insensitive; the verb scan must be too.
        let script = "DO SHELL SCRIPT \"rm -rf $HOME\"";
        assert!(applescript_destructive_refusal(script, None, None).is_some());
    }

    #[test]
    fn dynamic_shell_argument_is_escalated_not_ignored() {
        // When `do shell script` receives a computed value we cannot read
        // statically, we must still escalate (unknown target), never silently
        // allow it.
        let script = "set cmd to \"rm -rf \" & targetDir\ndo shell script cmd";
        assert!(
            applescript_destructive_refusal(script, None, None).is_some(),
            "a non-literal shell argument must be escalated, not ignored"
        );
    }

    #[test]
    fn first_string_literal_handles_escaped_quotes() {
        // Sanity-check the literal extractor used by the shell-payload scan.
        assert_eq!(
            first_string_literal_after(" \"echo \\\"hi\\\"\""),
            Some("echo \"hi\"".to_string())
        );
    }
}

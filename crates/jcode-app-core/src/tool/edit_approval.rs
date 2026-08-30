//! Verify-then-commit: explicit user confirmation before non-trivial file
//! mutations (improvement-report pick #1).
//!
//! The audit-era diff previews show what an edit did *after* it happened;
//! this gate asks *before* the write lands. The shape deliberately mirrors
//! the shipped #604 destructive-command gate: a small deterministic policy
//! seam that refuses or holds a mutation and returns text the model can act
//! on, instead of a side-channel UI contract.
//!
//! Flow when enabled (`[tools] verify_file_edits = true`):
//! 1. Trivial changes (≤ [`AUTO_ACCEPT_MAX_CHANGED_LINES`] changed lines) are
//!    applied without asking — friction stays near zero.
//! 2. Anything larger sends a prompt with a diff excerpt through the tool
//!    stdin channel (`ServerEvent::StdinRequest`) and waits for one line:
//!    `y` approves, `n` rejects, `all` bulk-approves the rest of the session.
//! 3. No channel (headless runs), timeout, or an unrecognized reply blocks
//!    the mutation with an actionable message. The model is told not to
//!    retry unchanged so rejection always means the edit does not land.
//!
//! Defaults to off until the answer UX on the client side lands for every
//! surface; see docs/VERIFY_THEN_COMMIT.md.

use jcode_tool_core::{StdinInputRequest, ToolContext};
use similar::TextDiff;
use std::sync::{LazyLock, RwLock};

/// Changed lines (insertions + deletions) at or below this are applied
/// without asking. Small enough to keep honest refactors interactive,
/// large enough that a typo fix never prompts.
pub(crate) const AUTO_ACCEPT_MAX_CHANGED_LINES: usize = 3;

/// How long to wait for the user's reply before blocking the mutation.
const ASK_TIMEOUT_SECS: u64 = 300;

/// How many diff lines ride along in the prompt before truncation.
const PROMPT_DIFF_MAX_LINES: usize = 40;

/// What a pre-write check tells the calling tool to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MutationDecision {
    /// Apply the mutation as usual.
    Proceed,
    /// Skip the mutation and return this text as the tool result.
    Blocked(String),
}

impl MutationDecision {
    /// True when the write may proceed.
    pub(crate) fn is_proceed(&self) -> bool {
        matches!(self, MutationDecision::Proceed)
    }
}

/// Sessions where the user answered "all", covering every later edit this
/// session without asking again (the report's bulk-accept rule).
static BULK_ACCEPTED_SESSIONS: LazyLock<RwLock<std::collections::HashSet<String>>> =
    LazyLock::new(|| RwLock::new(std::collections::HashSet::new()));

fn session_bulk_accepted(session_id: &str) -> bool {
    BULK_ACCEPTED_SESSIONS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(session_id)
}

fn mark_session_bulk_accepted(session_id: &str) {
    BULK_ACCEPTED_SESSIONS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(session_id.to_string());
}

/// Count changed lines between old and new content (insertions + deletions).
///
/// A deletion counts its removed lines and an insertion its added ones; a
/// modified line therefore costs two, matching how a human reads a diff.
pub(crate) fn changed_line_count(old: Option<&str>, new_content: &str) -> usize {
    let old = old.unwrap_or("");
    TextDiff::from_lines(old, new_content)
        .iter_all_changes()
        .filter(|change| change.tag() != similar::ChangeTag::Equal)
        .count()
}

/// Classify a pending mutation against the auto-accept rules alone.
///
/// Pure and config-free so tests and future callers (batch tools, MCP proxy
/// surfaces) can reuse the policy without touching channels. `enabled` is
/// the resolved `[tools] verify_file_edits` value.
pub(crate) fn classify(
    enabled: bool,
    bulk_accepted: bool,
    changed_lines: usize,
) -> MutationDecision {
    if !enabled || bulk_accepted || changed_lines <= AUTO_ACCEPT_MAX_CHANGED_LINES {
        return MutationDecision::Proceed;
    }
    // Everything else needs the user; whether we can actually ask depends on
    // having an interactive channel, decided by the async wrapper below.
    MutationDecision::Blocked(String::new())
}

/// Build the prompt shown to the user for a held mutation.
pub(crate) fn build_approval_prompt(
    display_path: &str,
    existed: bool,
    old: Option<&str>,
    new_content: &str,
) -> String {
    let mut prompt = String::new();
    let action = if existed { "Modify" } else { "Create" };
    prompt.push_str(&format!("VERIFY EDIT: {action} {display_path}\n"));
    let diff = TextDiff::from_lines(old.unwrap_or(""), new_content);
    let mut diff_lines = diff.iter_all_changes().map(|change| {
        use similar::ChangeTag::*;
        match change.tag() {
            Delete => format!("- {}", change.value()),
            Insert => format!("+ {}", change.value()),
            Equal => format!("  {}", change.value()),
        }
    });
    for line in (&mut diff_lines).take(PROMPT_DIFF_MAX_LINES) {
        prompt.push_str(line.trim_end_matches('\n'));
        prompt.push('\n');
    }
    if diff_lines.next().is_some() {
        prompt.push_str("… (diff truncated)\n");
    }
    prompt.push_str(
        "Reply 'y' to apply, 'n' to reject, 'all' to approve remaining edits \
         for this session.",
    );
    prompt
}

/// Interpret the user's one-line reply.
enum Reply {
    ApproveOnce,
    ApproveAll,
    Reject(String),
}

fn classify_reply(raw: &str) -> Reply {
    match raw.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "ok" | "approve" | "a" | "apply" => Reply::ApproveOnce,
        "all" | "always" => Reply::ApproveAll,
        "" | "n" | "no" | "deny" | "reject" | "esc" | "cancel" | "stop" => {
            Reply::Reject("The user REJECTED this edit.".to_string())
        }
        other => Reply::Reject(format!(
            "Unrecognized confirmation reply '{other}', treated as rejection. \
             Ask the user to reply 'y' or 'n'."
        )),
    }
}

/// Pre-write gate for a single file mutation. Call after the new content is
/// fully computed but before anything touches disk.
///
/// Blocked results are meant to become the whole tool output so the model
/// understands the user declined rather than seeing an error trace.
pub(crate) async fn ensure_mutation_approved(
    ctx: &ToolContext,
    display_path: &str,
    existed: bool,
    old_content: Option<&str>,
    new_content: &str,
) -> MutationDecision {
    let enabled = crate::config::config().tools.verify_file_edits;
    ensure_mutation_approved_with(
        enabled,
        std::time::Duration::from_secs(ASK_TIMEOUT_SECS),
        ctx,
        display_path,
        existed,
        old_content,
        new_content,
    )
    .await
}

/// Same policy with an explicit flag so tests never depend on the developer
/// machine's real `~/.jcode/config.toml`. `ask_timeout` is likewise injected:
/// production passes [`ASK_TIMEOUT_SECS`], tests shrink it so the
/// timeout-fails-closed path takes milliseconds.
pub(crate) async fn ensure_mutation_approved_with(
    enabled: bool,
    ask_timeout: std::time::Duration,
    ctx: &ToolContext,
    display_path: &str,
    existed: bool,
    old_content: Option<&str>,
    new_content: &str,
) -> MutationDecision {
    let decision = classify(
        enabled,
        session_bulk_accepted(&ctx.session_id),
        changed_line_count(old_content, new_content),
    );
    // Config off or auto-accepted (classify returns Proceed for both).
    if decision.is_proceed() {
        return MutationDecision::Proceed;
    }

    let Some(stdin_tx) = ctx.stdin_request_tx.clone() else {
        return MutationDecision::Blocked(format!(
            "Edit verification is enabled ([tools] verify_file_edits), but this \
             session has no interactive user attached, so {display_path} could \
             not be confirmed. Nothing was written."
        ));
    };

    let prompt = build_approval_prompt(display_path, existed, old_content, new_content);
    let request_id = format!("edit-approval-{}", ctx.tool_call_id);
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    if stdin_tx
        .send(StdinInputRequest {
            request_id,
            prompt,
            is_password: false,
            response_tx,
        })
        .is_err()
    {
        return MutationDecision::Blocked(format!(
            "No user surface available to confirm {display_path}. Nothing was written."
        ));
    }

    let reply = tokio::time::timeout(ask_timeout, response_rx).await;
    match reply {
        Ok(Ok(answer)) => match classify_reply(&answer) {
            Reply::ApproveOnce => MutationDecision::Proceed,
            Reply::ApproveAll => {
                mark_session_bulk_accepted(&ctx.session_id);
                MutationDecision::Proceed
            }
            Reply::Reject(reason) => MutationDecision::Blocked(format!(
                "{reason} No changes were made to {display_path}. Do not retry the same edit."
            )),
        },
        _ => MutationDecision::Blocked(format!(
            "No approval arrived for {display_path} within {} seconds, \
             so the edit was dropped. Nothing was written.",
            ask_timeout.as_secs()
        )),
    }
}

/// Convenience for write-sites that need a refusal string instead of an enum.
/// Returns `Some(refusal_text)` when the mutation must not proceed.
pub(crate) async fn refusal_text_for(
    ctx: &ToolContext,
    display_path: &str,
    existed: bool,
    old_content: Option<&str>,
    new_content: &str,
) -> Option<String> {
    match ensure_mutation_approved(ctx, display_path, existed, old_content, new_content).await {
        MutationDecision::Proceed => None,
        MutationDecision::Blocked(text) => Some(text),
    }
}

/// Forget bulk-accept state (tests only today; keeps maps from leaking
/// across restarts should future code call it at session teardown).
#[cfg(test)]
pub(crate) fn clear_bulk_accepted_for_tests() {
    BULK_ACCEPTED_SESSIONS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

#[cfg(test)]
#[path = "edit_approval_tests.rs"]
mod tests;

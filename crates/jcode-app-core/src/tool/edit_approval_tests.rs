//! Tests for the verify-then-commit pre-write gate.
//!
//! Policy tests are pure; channel tests drive a real mpsc/oneshot pair the
//! same way `bash_tests` exercises stdin forwarding.

use super::*;
use jcode_tool_core::ToolExecutionMode;
use std::time::Duration;
use tokio::sync::mpsc;

/// Shrink the ask window so timeout paths run in milliseconds. Production
/// passes `Duration::from_secs(ASK_TIMEOUT_SECS)` instead.
const TEST_TIMEOUT: Duration = Duration::from_millis(200);

/// The bulk-accept map is process-global, and cargo runs tests in parallel.
/// Channel tests that read or mutate it take this guard so one test's
/// `clear_bulk_accepted_for_tests()` cannot race another's assertions.
static BULK_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn bulk_guard() -> std::sync::MutexGuard<'static, ()> {
    BULK_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn test_ctx(
    session_id: &str,
) -> (
    ToolContext,
    Option<mpsc::UnboundedReceiver<StdinInputRequest>>,
) {
    let (tx, rx) = mpsc::unbounded_channel::<StdinInputRequest>();
    (
        ToolContext {
            session_id: session_id.to_string(),
            message_id: String::new(),
            tool_call_id: "call-1".to_string(),
            working_dir: None,
            stdin_request_tx: Some(tx),
            graceful_shutdown_signal: None,
            execution_mode: ToolExecutionMode::AgentTurn,
        },
        Some(rx),
    )
}

const OLD: &str = "line one\nline two\nline three";
const BIG_NEW: &str = "line one\nCHANGED two\nCHANGED three";

#[test]
fn changed_line_count_counts_both_sides_of_a_modification() {
    // One line replaced = one deletion + one insertion.
    assert_eq!(changed_line_count(Some(OLD), BIG_NEW), 4);
}

#[test]
fn changed_line_counts_new_file_as_all_insertions() {
    assert_eq!(changed_line_count(None, OLD), 3);
    assert_eq!(changed_line_count(Some(""), OLD), 3);
}

#[test]
fn identical_content_is_zero_changed_lines() {
    assert_eq!(changed_line_count(Some(OLD), OLD), 0);
}

#[test]
fn classification_auto_accepts_trivial_changes_when_enabled() {
    assert!(classify(true, false, AUTO_ACCEPT_MAX_CHANGED_LINES).is_proceed());
    assert!(!classify(true, false, AUTO_ACCEPT_MAX_CHANGED_LINES + 1).is_proceed());
}

#[test]
fn classification_disabled_or_bulk_accepted_never_asks() {
    assert!(classify(false, false, 5_000).is_proceed());
    assert!(classify(true, true, 5_000).is_proceed());
}

#[test]
fn prompt_shows_path_action_and_diff() {
    let prompt = build_approval_prompt("src/lib.rs", true, Some(OLD), BIG_NEW);
    assert!(prompt.contains("VERIFY EDIT: Modify src/lib.rs"));
    assert!(prompt.contains("- line two"));
    assert!(prompt.contains("+ CHANGED two"));
    assert!(prompt.contains("'y'"));
    let create = build_approval_prompt("docs/new.md", false, None, "# title");
    assert!(create.contains("VERIFY EDIT: Create docs/new.md"));
    assert!(create.contains("+ # title"));
}

#[test]
fn prompt_truncates_large_diffs() {
    let big: String = std::iter::repeat_n("row\n", PROMPT_DIFF_MAX_LINES + 20).collect();
    let prompt = build_approval_prompt("x", false, None, &big);
    assert!(
        prompt.contains("(diff truncated)"),
        "long diff must truncate"
    );
    let small_prompt = build_approval_prompt("x", false, None, "a\n");
    assert!(!small_prompt.contains("(diff truncated)"));
}

#[tokio::test]
async fn disabled_gate_proceeds_without_any_channel() {
    let (mut ctx, _rx) = test_ctx("disabled");
    ctx.stdin_request_tx = None;
    assert!(
        ensure_mutation_approved_with(false, TEST_TIMEOUT, &ctx, "f.rs", true, Some(OLD), BIG_NEW)
            .await
            .is_proceed()
    );
}

#[tokio::test]
async fn enabled_without_channel_blocks_instead_of_silent_write() {
    let (mut ctx, _rx) = test_ctx("no-channel");
    ctx.stdin_request_tx = None;
    match ensure_mutation_approved_with(true, TEST_TIMEOUT, &ctx, "f.rs", true, Some(OLD), BIG_NEW)
        .await
    {
        MutationDecision::Blocked(text) => {
            assert!(text.contains("verify_file_edits"));
            assert!(text.contains("Nothing was written"));
        }
        MutationDecision::Proceed => panic!("enabled gate with no user surface must block"),
    }
}

#[tokio::test]
async fn approve_reply_lets_the_write_proceed() {
    let _guard = bulk_guard();
    let (ctx, rx) = test_ctx("approve");
    let feeder = tokio::spawn(async move {
        let req = rx.unwrap().recv().await.expect("request arrives");
        assert!(req.prompt.contains("VERIFY EDIT"));
        req.response_tx.send("y".to_string()).unwrap();
    });
    let decision =
        ensure_mutation_approved_with(true, TEST_TIMEOUT, &ctx, "f.rs", true, Some(OLD), BIG_NEW)
            .await;
    assert!(decision.is_proceed(), "{decision:?}");
    feeder.await.unwrap();
    clear_bulk_accepted_for_tests();
}

#[tokio::test]
async fn reject_reply_blocks_and_names_the_file() {
    let _guard = bulk_guard();
    let (ctx, rx) = test_ctx("reject");
    let feeder = tokio::spawn(async move {
        let req = rx.unwrap().recv().await.expect("request arrives");
        req.response_tx.send("n".to_string()).unwrap();
    });
    match ensure_mutation_approved_with(true, TEST_TIMEOUT, &ctx, "f.rs", true, Some(OLD), BIG_NEW)
        .await
    {
        MutationDecision::Blocked(text) => {
            assert!(text.contains("REJECTED"));
            assert!(text.contains("f.rs"));
            assert!(text.contains("Do not retry"), "model must be told to stop");
        }
        MutationDecision::Proceed => panic!("rejection must block the write"),
    }
    feeder.await.unwrap();
    clear_bulk_accepted_for_tests();
}

#[tokio::test]
async fn dropped_responder_blocks_rather_than_writes() {
    let _guard = bulk_guard();
    // The client vanished between ask and answer: the request is delivered,
    // but its responder is dropped without a reply.
    let (ctx, rx) = test_ctx("dropped");
    let feeder = tokio::spawn(async move {
        let req = rx.unwrap().recv().await.expect("request arrives");
        drop(req); // drops response_tx without answering
    });
    match ensure_mutation_approved_with(true, TEST_TIMEOUT, &ctx, "f.rs", true, Some(OLD), BIG_NEW)
        .await
    {
        MutationDecision::Blocked(text) => assert!(text.contains("No approval arrived")),
        MutationDecision::Proceed => panic!("dropped responder must not approve"),
    }
    feeder.await.unwrap();
    clear_bulk_accepted_for_tests();
}

#[tokio::test]
async fn bulk_accept_answer_covers_later_edits_in_the_session() {
    let _guard = bulk_guard();
    let (first_ctx, first_rx) = test_ctx("bulk-session");
    let feeder = tokio::spawn(async move {
        let req = first_rx.unwrap().recv().await.expect("first request");
        req.response_tx.send("all".to_string()).unwrap();
    });
    assert!(
        ensure_mutation_approved_with(
            true,
            TEST_TIMEOUT,
            &first_ctx,
            "a.rs",
            true,
            Some(OLD),
            BIG_NEW
        )
        .await
        .is_proceed()
    );
    feeder.await.unwrap();

    // Same session: subsequent big edits skip the prompt entirely.
    let (second_ctx, second_rx) = test_ctx("bulk-session");
    let decision = ensure_mutation_approved_with(
        true,
        TEST_TIMEOUT,
        &second_ctx,
        "b.rs",
        true,
        Some(OLD),
        BIG_NEW,
    )
    .await;
    assert!(
        decision.is_proceed(),
        "bulk accept must persist per session"
    );
    // No request was sent for the second edit.
    assert!(
        second_rx.unwrap().try_recv().is_err(),
        "bulk-accepted edits must not prompt again"
    );

    // A different session is still gated.
    let (third_ctx, _third_rx) = test_ctx("other-session");
    assert!(
        !ensure_mutation_approved_with(
            true,
            TEST_TIMEOUT,
            &third_ctx,
            "c.rs",
            true,
            Some(OLD),
            BIG_NEW
        )
        .await
        .is_proceed()
    );
    clear_bulk_accepted_for_tests();
}

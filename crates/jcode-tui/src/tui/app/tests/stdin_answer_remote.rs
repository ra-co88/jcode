// Verify-then-commit / interactive stdin answer UX in remote mode.
//
// Covers the server-event capture (`StdinRequest` → pending answer state +
// visible prompt) and the composer routing (Enter sends the reply through
// `Request::StdinResponse`, Esc declines with an empty line, other keys keep
// editing the draft without consuming the pending state).
//
// NOTE: this file is spliced into the tests module via include!; KeyCode and
// KeyModifiers are already imported by a sibling test file.

fn stdin_request_event(request_id: &str, prompt: &str) -> crate::protocol::ServerEvent {
    crate::protocol::ServerEvent::StdinRequest {
        request_id: request_id.to_string(),
        prompt: prompt.to_string(),
        is_password: false,
        tool_call_id: "call_stdin".to_string(),
    }
}

#[test]
fn stdin_request_event_captures_prompt_and_arms_reply() {
    let mut app = create_test_app();
    app.is_remote = true;
    // dummy() builds a real socketpair, which needs a reactor in scope.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut remote = crate::tui::backend::RemoteConnection::dummy();

    // House style: display-message branches return false (repaint flows
    // through the display-message dirty path, not this return value).
    let redraw = app.handle_server_event(
        stdin_request_event(
            "stdin-1",
            "VERIFY EDIT: Modify src/lib.rs\nReply 'y' to apply, 'n' to reject.",
        ),
        &mut remote,
    );
    assert!(!redraw);
    let pending = app
        .pending_stdin_answer
        .as_ref()
        .expect("stdin request must arm the reply state");
    assert_eq!(pending.request_id, "stdin-1");
    assert!(pending.prompt.contains("VERIFY EDIT"));
    // The prompt must be visible in the transcript so the user can read the
    // diff before answering.
    let last = app.display_messages().last().unwrap().content.clone();
    assert!(last.contains("VERIFY EDIT"), "{last}");
}

#[test]
fn enter_routes_reply_to_stdin_response_and_clears_pending() {
    use tokio::io::AsyncBufReadExt;

    let mut app = create_test_app();
    app.is_remote = true;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut line = String::new();
    rt.block_on(async {
        let mut remote = crate::tui::backend::RemoteConnection::dummy();
        let peer = remote
            .take_dummy_peer()
            .expect("dummy remote should retain peer stream");
        let (reader, _writer) = peer.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        app.handle_server_event(stdin_request_event("stdin-1", ""), &mut remote);
        app.input = "y".to_string();
        app.cursor_pos = 1;

        app.handle_remote_key(KeyCode::Enter, KeyModifiers::empty(), &mut remote)
            .await
            .expect("Enter should route the reply");
        reader
            .read_line(&mut line)
            .await
            .expect("reply should be readable by peer");

        assert!(
            app.pending_stdin_answer.is_none(),
            "Enter must consume the pending request"
        );
        assert!(app.input.is_empty(), "input buffer is consumed as the reply");
    });

    match serde_json::from_str::<crate::protocol::Request>(&line)
        .expect("reply should deserialize")
    {
        crate::protocol::Request::StdinResponse {
            request_id, input, ..
        } => {
            assert_eq!(request_id, "stdin-1");
            assert_eq!(input, "y");
        }
        other => panic!("expected StdinResponse, got {other:?}"),
    }
}

#[test]
fn esc_declines_with_empty_reply_and_keeps_draft() {
    use tokio::io::AsyncBufReadExt;

    let mut app = create_test_app();
    app.is_remote = true;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut line = String::new();
    rt.block_on(async {
        let mut remote = crate::tui::backend::RemoteConnection::dummy();
        let peer = remote
            .take_dummy_peer()
            .expect("dummy remote should retain peer stream");
        let (reader, _writer) = peer.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        app.handle_server_event(
            stdin_request_event("stdin-2", "VERIFY EDIT: Modify x.rs"),
            &mut remote,
        );
        // A draft typed while waiting must survive the decline.
        app.input = "actually, let me rephrase".to_string();

        app.handle_remote_key(KeyCode::Esc, KeyModifiers::empty(), &mut remote)
            .await
            .expect("Esc should decline");
        reader
            .read_line(&mut line)
            .await
            .expect("decline should be readable by peer");

        assert!(app.pending_stdin_answer.is_none());
        assert_eq!(
            app.input, "actually, let me rephrase",
            "Esc declines but must not erase the draft"
        );
    });

    match serde_json::from_str::<crate::protocol::Request>(&line)
        .expect("decline should deserialize")
    {
        crate::protocol::Request::StdinResponse {
            request_id, input, ..
        } => {
            assert_eq!(request_id, "stdin-2");
            assert_eq!(input, "", "Esc declines with an empty reply");
        }
        other => panic!("expected StdinResponse, got {other:?}"),
    }
}

#[test]
fn other_keys_keep_editing_without_consuming_the_pending_request() {
    let mut app = create_test_app();
    app.is_remote = true;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let mut remote = crate::tui::backend::RemoteConnection::dummy();

    app.handle_server_event(stdin_request_event("stdin-3", ""), &mut remote);
    rt.block_on(
        app.handle_remote_key(KeyCode::Char('n'), KeyModifiers::empty(), &mut remote),
    )
    .expect("typing should still work while a reply is pending");

    assert!(
        app.pending_stdin_answer.is_some(),
        "non-Enter/Esc keys must not consume the pending request"
    );
    assert_eq!(app.input, "n", "typed characters keep building the reply");
}
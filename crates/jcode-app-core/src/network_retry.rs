use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::process::Command;
use tokio::time::sleep;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::time::timeout;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkWaitPlan {
    pub reason: String,
    pub listener_summary: String,
}

pub fn classify_network_interruption(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut parts = Vec::new();
    let mut current = Some(error);
    while let Some(err) = current {
        let text = err.to_string().to_ascii_lowercase();
        parts.push(text);
        current = err.source();
    }
    classify_text(&parts.join(" | "))
}

pub fn classify_message(message: &str) -> Option<String> {
    classify_text(&message.to_ascii_lowercase())
}

fn classify_text(text: &str) -> Option<String> {
    let network_markers = [
        "connection reset",
        "connection aborted",
        "connection refused",
        "broken pipe",
        "network is unreachable",
        "network unreachable",
        "host is down",
        "no route to host",
        "not connected",
        // TLS-level drops. rustls reports an abrupt close as "peer closed
        // connection without sending TLS close_notify" (its docs URL spells
        // it "unexpected-eof", which the plain "unexpected eof" marker below
        // does not match).
        "close_notify",
        "peer closed connection",
        "tls handshake eof",
        // reqwest/hyper wrap connect-phase failures as "client error
        // (Connect)" and connection-level faults as "connection error: ...".
        "client error (connect)",
        "connection error",
        "dns error",
        "failed to lookup address",
        "temporary failure in name resolution",
        "name or service not known",
        "could not resolve host",
        "couldn't resolve host",
        "host is unreachable",
        "operation timed out",
        "timed out",
        "timeout",
        "error trying to connect",
        "connection closed before message completed",
        "unexpected eof",
        "end of file before message completed",
    ];
    if network_markers.iter().any(|marker| text.contains(marker)) {
        return Some("the network connection appears to have dropped".to_string());
    }
    None
}

pub fn wait_plan() -> NetworkWaitPlan {
    #[cfg(target_os = "linux")]
    {
        NetworkWaitPlan {
            reason: "stream interrupted by a likely network disconnect".to_string(),
            listener_summary:
                "listening for Linux netlink changes via `ip monitor`; also verifying with reconnect probes"
                    .to_string(),
        }
    }
    #[cfg(target_os = "macos")]
    {
        return NetworkWaitPlan {
            reason: "stream interrupted by a likely network disconnect".to_string(),
            listener_summary:
                "listening for macOS route/interface changes via `route -n monitor`; also verifying with reconnect probes"
                    .to_string(),
        };
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        NetworkWaitPlan {
            reason: "stream interrupted by a likely network disconnect".to_string(),
            listener_summary: "waiting with lightweight reconnect probes".to_string(),
        }
    }
}

/// Default ceiling for a single reconnect wait. Long enough to ride out a VPN
/// flap or a sleeping laptop, short enough that a permanently offline state
/// (broken VPN profile, captive portal that never satisfies the probe) cannot
/// wedge a caller forever (REL-01).
pub const DEFAULT_RECONNECT_CEILING: Duration = Duration::from_secs(300);

/// Outcome of a bounded reconnect wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconnectOutcome {
    /// Connectivity was observed; the caller should retry its request.
    Online,
    /// The ceiling elapsed while still offline; the caller must surface this
    /// and stop rather than block forever.
    GaveUp { waited: Duration },
}

impl ReconnectOutcome {
    pub fn is_online(self) -> bool {
        matches!(self, ReconnectOutcome::Online)
    }
}

/// Wait until connectivity is probably restored, bounded by [`DEFAULT_RECONNECT_CEILING`].
///
/// REL-01: previously this looped forever with exponential backoff and no
/// ceiling, so a permanent offline state wedged the caller with no escape. It
/// now returns [`ReconnectOutcome::GaveUp`] once the ceiling elapses so callers
/// can fail with a visible diagnostic instead of hanging.
pub async fn wait_until_probably_online() -> ReconnectOutcome {
    wait_until_probably_online_bounded(DEFAULT_RECONNECT_CEILING).await
}

/// Bounded reconnect wait with an explicit total-time ceiling.
///
/// Polls with exponential backoff (capped at 30s per interval) until either
/// connectivity is observed ([`ReconnectOutcome::Online`]) or `max_total`
/// elapses ([`ReconnectOutcome::GaveUp`]). A zero or negative budget still makes
/// at least one connectivity probe so a transient blip is caught cheaply.
pub async fn wait_until_probably_online_bounded(max_total: Duration) -> ReconnectOutcome {
    let start = std::time::Instant::now();
    let mut delay = Duration::from_secs(1);
    loop {
        if probe_connectivity().await {
            return ReconnectOutcome::Online;
        }
        let elapsed = start.elapsed();
        if elapsed >= max_total {
            return ReconnectOutcome::GaveUp { waited: elapsed };
        }
        // Never sleep past the remaining budget, so we return close to the
        // ceiling rather than overshooting by a full backoff interval.
        let remaining = max_total - elapsed;
        wait_for_platform_change_or_delay(delay.min(remaining)).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

pub async fn is_probably_online() -> bool {
    probe_connectivity().await
}

async fn probe_connectivity() -> bool {
    let client = jcode_provider_core::shared_http_client();
    let request = client
        .head("https://www.gstatic.com/generate_204")
        .timeout(Duration::from_secs(5));
    matches!(request.send().await, Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 204)
}

async fn wait_for_platform_change_or_delay(delay: Duration) {
    #[cfg(target_os = "linux")]
    {
        if command_exists("ip").await {
            let fut = wait_for_command_output("ip", &["monitor", "link", "address", "route"]);
            let _ = timeout(delay, fut).await;
            return;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if command_exists("route").await {
            let fut = wait_for_command_output("route", &["-n", "monitor"]);
            let _ = timeout(delay, fut).await;
            return;
        }
    }
    sleep(delay).await;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn command_exists(command: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "command -v {} >/dev/null 2>&1",
            shell_escape(command)
        ))
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn shell_escape(value: &str) -> String {
    value.replace('\'', "'\\''")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn wait_for_command_output(command: &str, args: &[&str]) {
    let mut command_builder = Command::new(command);
    command_builder
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = match command_builder.spawn() {
        Ok(child) => child,
        Err(_) => return,
    };
    if let Some(mut stdout) = child.stdout.take() {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1];
        let _ = stdout.read(&mut buf).await;
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REL-01: a bounded wait must return within roughly its ceiling and never
    /// hang, whatever the network state. With a tiny budget it resolves fast;
    /// if offline it reports `GaveUp` rather than looping forever.
    #[tokio::test]
    async fn bounded_wait_respects_its_ceiling() {
        let ceiling = Duration::from_millis(200);
        let start = std::time::Instant::now();
        let outcome = wait_until_probably_online_bounded(ceiling).await;
        let elapsed = start.elapsed();

        // Must not overshoot the ceiling by more than one probe timeout (5s)
        // plus scheduling slack — the key property is that it terminates.
        assert!(
            elapsed < ceiling + Duration::from_secs(8),
            "bounded wait ran {elapsed:?}, far past its {ceiling:?} ceiling"
        );
        // Whatever the CI network state, the outcome must be one of the two
        // terminal states (i.e. the function returned at all).
        match outcome {
            ReconnectOutcome::Online => assert!(outcome.is_online()),
            ReconnectOutcome::GaveUp { waited } => {
                assert!(!outcome.is_online());
                assert!(
                    waited >= ceiling,
                    "GaveUp waited {waited:?} < ceiling {ceiling:?}"
                );
            }
        }
    }

    #[test]
    fn classifies_common_network_errors() {
        assert!(classify_message("connection reset by peer").is_some());
        assert!(classify_message("temporary failure in name resolution").is_some());
        assert!(classify_message("network is unreachable").is_some());
        assert!(classify_message("401 unauthorized").is_none());
    }

    /// Real error strings harvested from ~/.jcode/logs. Every wifi-outage
    /// shape observed in the wild must classify as a network interruption so
    /// the wait-for-network path engages instead of failing the turn.
    #[test]
    fn classifies_real_world_outage_errors() {
        let real_errors = [
            // DNS failure: wifi down when a new request starts, or link up
            // before DHCP delivers DNS servers.
            "Failed to send request to Anthropic API: error sending request for url \
             (https://api.anthropic.com/v1/messages): client error (Connect): dns error: \
             failed to lookup address information: Name or service not known",
            "error sending request for url (https://models.dev/api.json): client error \
             (Connect): dns error: failed to lookup address information: Temporary failure \
             in name resolution",
            // Stale pooled HTTP/2 connection dying after an outage.
            "Failed to send request to Anthropic API: error sending request for url \
             (https://api.anthropic.com/v1/messages): client error (SendRequest): \
             http2 error: keep-alive timed out: operation timed out",
            // rustls abrupt-close shape (docs URL spells "unexpected-eof" so
            // the plain "unexpected eof" marker never matched it).
            "error sending request for url (https://generativelanguage.googleapis.com/v1beta/models): \
             client error (SendRequest): connection error: peer closed connection without \
             sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof",
            // Connect-phase timeout.
            "error sending request for url (https://html.duckduckgo.com/html/): \
             client error (Connect): operation timed out",
            // Connection-level timeout on an established connection.
            "error sending request for url (https://dblp.org/search/author/api): \
             client error (SendRequest): connection error: timed out",
            // TLS handshake dying mid-outage.
            "error sending request for url (https://generativelanguage.googleapis.com/v1beta/models): \
             client error (Connect): tls handshake eof",
            // Body cut off mid-stream.
            "error decoding response body: request or response body error: operation timed out",
        ];
        for error in real_errors {
            assert!(
                classify_message(error).is_some(),
                "should classify as network interruption: {error}"
            );
        }
    }

    /// Deterministic failures must NOT trigger the wait-for-network path,
    /// otherwise a bad API key or exhausted quota would hang forever waiting
    /// for connectivity that is already fine.
    #[test]
    fn does_not_classify_deterministic_failures() {
        let deterministic = [
            "401 unauthorized",
            "403 forbidden: permission_denied",
            "invalid x-api-key",
            "404 not_found_error: model: claude-fable-5",
            "insufficient_quota: your credit balance is too low",
            "400 bad request: context length exceeded",
            "content_policy_violation",
        ];
        for error in deterministic {
            assert!(
                classify_message(error).is_none(),
                "should NOT classify as network interruption: {error}"
            );
        }
    }
}

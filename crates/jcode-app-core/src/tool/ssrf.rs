//! SEC-03: SSRF guard for agent-driven HTTP tools (`webfetch`, `websearch`).
//!
//! An AI agent that can be steered to fetch arbitrary URLs is a Server-Side
//! Request Forgery vector: it can be pointed at the host's own loopback
//! services, the LAN, or cloud instance-metadata endpoints
//! (`169.254.169.254`) to read credentials. This module resolves a URL's host
//! and refuses any destination that resolves to a non-public IP.
//!
//! DNS-rebinding hardening: we re-check every resolved address and reject if
//! ANY is private (defeats the "one public + one private A record" trick), and
//! the caller pins the connection to the validated address via
//! [`guard_public_url_pinned`] + reqwest `resolve()`, so the IP we checked is
//! the IP actually connected to — closing the resolve-then-connect TOCTOU gap
//! for the common case. Residual limits (cf. SEC-05): a hostile custom DNS that
//! returns different sets per lookup is bounded by pinning, but proxies and
//! any code path that bypasses the pinned client are not covered. There is no
//! allowlist escape hatch yet for legitimately-internal hosts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Boolean form of [`guard_public_url_pinned`] for tests: `Ok(())` when the
/// URL targets only public addresses, `Err` naming the blocked class.
#[cfg(test)]
pub(crate) async fn guard_public_url(raw_url: &str) -> anyhow::Result<()> {
    guard_public_url_pinned(raw_url).await.map(|_| ())
}

/// What a passing SSRF check resolved to, so the caller can *pin* the
/// connection to the exact validated address (closing the TOCTOU/DNS-rebinding
/// gap: reqwest reuses this address instead of re-resolving at connect time).
pub(crate) struct GuardedTarget {
    /// The hostname to pin (only set when DNS was used, not for literal IPs).
    pub host: Option<String>,
    /// A validated socket address to pin the host to. `None` for a literal-IP
    /// URL, which needs no pinning because there is no name to re-resolve.
    pub pinned: Option<std::net::SocketAddr>,
}

/// Validate that `raw_url` targets a public host, resolving DNS and checking
/// every returned address. Returns a [`GuardedTarget`] the caller pins the
/// connection to, so the IP we checked is the IP actually connected to.
pub(crate) async fn guard_public_url_pinned(raw_url: &str) -> anyhow::Result<GuardedTarget> {
    let url = url::Url::parse(raw_url)
        .map_err(|e| anyhow::anyhow!("Could not parse URL for safety check: {e}"))?;

    match url.scheme() {
        "http" | "https" => {}
        other => anyhow::bail!("URL scheme `{other}` is not allowed; use http or https."),
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host to validate."))?;

    // A bracketed/literal IP host is checked directly (no DNS, no pinning
    // needed — there is no name that could be re-resolved to something else).
    if let Ok(ip) = host.parse::<IpAddr>() {
        reject_if_blocked(host, ip)?;
        return Ok(GuardedTarget {
            host: None,
            pinned: None,
        });
    }

    // Guard against obviously-internal names even if resolution is skipped by a
    // proxy later (defense in depth; the resolve below is the real check).
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
        anyhow::bail!(
            "Refusing to fetch `{host}`: internal/loopback hostnames are blocked to prevent \
             server-side request forgery (SSRF)."
        );
    }

    // Resolve. `lookup_host` needs a port; the scheme default is fine since we
    // only care about the IP.
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("Could not resolve `{host}` for safety check: {e}"))?
        .collect();

    if resolved.is_empty() {
        anyhow::bail!("`{host}` did not resolve to any address.");
    }
    // Reject if ANY resolved address is non-public (defeats "one public + one
    // private A record" rebinding).
    for addr in &resolved {
        reject_if_blocked(host, addr.ip())?;
    }
    // Pin the connection to the first validated address so the IP we checked is
    // the IP actually connected to, closing the resolve-then-connect TOCTOU gap.
    Ok(GuardedTarget {
        host: Some(host.to_string()),
        pinned: resolved.into_iter().next(),
    })
}

/// Reject a single resolved address if it is not a public, routable unicast IP.
fn reject_if_blocked(host: &str, ip: IpAddr) -> anyhow::Result<()> {
    if let Some(reason) = blocked_reason(ip) {
        anyhow::bail!(
            "Refusing to fetch `{host}` ({ip}): {reason}. This is blocked to prevent \
             server-side request forgery (SSRF) against internal services and cloud \
             metadata. If you truly need an internal host, fetch it outside the agent."
        );
    }
    Ok(())
}

/// Why an IP is not a safe public destination, or `None` if it is fine.
fn blocked_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => blocked_reason_v4(v4),
        IpAddr::V6(v6) => blocked_reason_v6(v6),
    }
}

fn blocked_reason_v4(ip: Ipv4Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("loopback address");
    }
    if ip.is_private() {
        return Some("private network address");
    }
    if ip.is_link_local() {
        // Covers 169.254.0.0/16, including the 169.254.169.254 metadata IP.
        return Some("link-local address (includes cloud metadata 169.254.169.254)");
    }
    if ip.is_unspecified() {
        return Some("unspecified address 0.0.0.0");
    }
    if ip.is_broadcast() {
        return Some("broadcast address");
    }
    if ip.is_multicast() {
        return Some("multicast address");
    }
    // Carrier-grade NAT 100.64.0.0/10 (is_shared is unstable in std; check by hand).
    let o = ip.octets();
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return Some("carrier-grade NAT address");
    }
    // 192.0.0.0/24 IETF protocol assignments, 198.18.0.0/15 benchmarking.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Some("IETF-reserved address");
    }
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return Some("benchmarking-reserved address");
    }
    None
}

fn blocked_reason_v6(ip: Ipv6Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("IPv6 loopback address");
    }
    if ip.is_unspecified() {
        return Some("IPv6 unspecified address ::");
    }
    if ip.is_multicast() {
        return Some("IPv6 multicast address");
    }
    let seg = ip.segments();
    // Unique local addresses fc00::/7.
    if (seg[0] & 0xfe00) == 0xfc00 {
        return Some("IPv6 unique-local address");
    }
    // Link-local fe80::/10.
    if (seg[0] & 0xffc0) == 0xfe80 {
        return Some("IPv6 link-local address");
    }
    // IPv4-mapped ::ffff:0:0/96 — unwrap and apply the v4 rules so a mapped
    // 127.0.0.1 / 169.254.x cannot slip through.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return blocked_reason_v4(v4);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(ip: &str) -> bool {
        blocked_reason(ip.parse().unwrap()).is_some()
    }

    #[test]
    fn blocks_loopback_private_and_metadata() {
        assert!(blocked("127.0.0.1"));
        assert!(blocked("10.0.0.5"));
        assert!(blocked("192.168.1.1"));
        assert!(blocked("172.16.0.1"));
        assert!(blocked("169.254.169.254"), "cloud metadata must be blocked");
        assert!(blocked("0.0.0.0"));
        assert!(blocked("100.64.0.1"), "CGNAT must be blocked");
        assert!(blocked("::1"));
        assert!(blocked("fd00::1"), "IPv6 ULA must be blocked");
        assert!(blocked("fe80::1"), "IPv6 link-local must be blocked");
        assert!(
            blocked("::ffff:127.0.0.1"),
            "mapped loopback must be blocked"
        );
        assert!(
            blocked("::ffff:169.254.169.254"),
            "mapped metadata must be blocked"
        );
    }

    #[test]
    fn allows_public_addresses() {
        assert!(!blocked("8.8.8.8"));
        assert!(!blocked("1.1.1.1"));
        assert!(!blocked("93.184.216.34")); // example.com
        assert!(!blocked("2606:4700:4700::1111")); // cloudflare v6
    }

    #[tokio::test]
    async fn guard_rejects_literal_internal_urls() {
        assert!(guard_public_url("http://127.0.0.1/").await.is_err());
        assert!(
            guard_public_url("http://169.254.169.254/latest/meta-data/")
                .await
                .is_err()
        );
        assert!(guard_public_url("http://[::1]:6379/").await.is_err());
        assert!(
            guard_public_url("http://localhost:8080/admin")
                .await
                .is_err()
        );
        assert!(
            guard_public_url("ftp://example.com/").await.is_err(),
            "non-http scheme rejected"
        );
    }

    #[tokio::test]
    async fn pinned_guard_rejects_internal_and_needs_no_pin_for_literal_public_ip() {
        // Internal targets are rejected by the pinned variant too.
        assert!(
            guard_public_url_pinned("http://169.254.169.254/")
                .await
                .is_err()
        );
        assert!(guard_public_url_pinned("http://10.0.0.1/").await.is_err());

        // A literal public IP passes and needs no pinning (there is no name to
        // re-resolve), so `host`/`pinned` are None.
        let t = guard_public_url_pinned("http://1.1.1.1/")
            .await
            .expect("public literal IP should pass");
        assert!(t.host.is_none(), "literal-IP URL needs no host pin");
        assert!(t.pinned.is_none(), "literal-IP URL needs no pinned address");
    }
}

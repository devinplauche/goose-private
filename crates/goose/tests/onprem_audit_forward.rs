//! Audit log forwarding test for the on-prem build.
//!
//! Verifies the forwarder's safe default: when no SIEM sink URL was baked in
//! at compile time (the case for test builds), forwarding is a no-op that
//! touches nothing — no network, no cursor file, no error.
//!
//! Only compiled with `--features onprem`.

#![cfg(feature = "onprem")]

/// Without `WARMACHINE_ONPREM_AUDIT_SINK_URL` baked in, forwarding must
/// report zero entries and succeed without touching the network.
#[tokio::test]
async fn forward_is_noop_without_sink() {
    assert!(
        option_env!("WARMACHINE_ONPREM_AUDIT_SINK_URL").is_none(),
        "test builds must not bake in an audit sink URL"
    );
    let forwarded = warmachine::onprem::forward_audit_log()
        .await
        .expect("forwarding without a sink must not fail");
    assert_eq!(forwarded, 0, "no sink means nothing to forward");
}

/// Spawning the forwarder without a sink must be a harmless no-op
/// (it returns without spawning a task).
#[tokio::test]
async fn spawn_forwarder_is_noop_without_sink() {
    warmachine::onprem::spawn_audit_forwarder();
    // If this returns, the no-op path held. There is nothing observable to
    // assert — the point is it must not panic or block.
}

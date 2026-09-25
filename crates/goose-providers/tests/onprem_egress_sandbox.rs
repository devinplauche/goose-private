//! Sandbox egress test for the on-prem build variant.
//!
//! This test verifies the network sandbox that keeps CUI/ITAR data inside the
//! controlled environment: the on-prem binary must refuse to construct an HTTP
//! client for any host outside its compile-time allowlist, so no provider code
//! path can exfiltrate data even if misconfigured.
//!
//! Only compiled with `--features onprem` and a `WARMACHINE_ONPREM_BASE_URL`
//! set at compile time (the on-prem CI job sets both).

#![cfg(feature = "onprem")]

use goose_providers::api_client::{ApiClient, AuthMethod};
use goose_providers::onprem::{allowed_origins, check_url_allowed, primary_base_url};

/// The allowlist must contain exactly the baked-in primary origin (plus any
/// extra hosts from WARMACHINE_ONPREM_EXTRA_HOSTS).
#[test]
fn allowlist_contains_primary_origin() {
    let origins = allowed_origins();
    assert!(!origins.is_empty(), "on-prem allowlist must not be empty");
    let primary = primary_base_url();
    assert!(
        check_url_allowed(primary).is_ok(),
        "primary base URL must be allowlisted: {primary}"
    );
}

/// Known public LLM endpoints must be refused — this is the exfiltration
/// vector the sandbox exists to close.
#[test]
fn public_cloud_endpoints_are_refused() {
    for url in [
        "https://api.openai.com/v1/chat/completions",
        "https://api.anthropic.com/v1/messages",
        "https://generativelanguage.googleapis.com/v1beta/models",
        "https://api.cohere.ai/v1/chat",
        "https://openrouter.ai/api/v1/chat/completions",
    ] {
        assert!(
            check_url_allowed(url).is_err(),
            "public endpoint must be refused: {url}"
        );
    }
}

/// Plaintext HTTP to non-loopback hosts must be refused: CUI/ITAR data must
/// be encrypted in transit.
#[test]
fn plaintext_http_to_non_loopback_is_refused() {
    assert!(check_url_allowed("http://llm.internal.example/v1").is_err());
    assert!(check_url_allowed("http://10.0.0.5:8080/v1").is_err());
}

/// URL tricks must not bypass the allowlist: wrong scheme, wrong port,
/// lookalike hosts, and userinfo smuggling.
#[test]
fn allowlist_bypass_attempts_are_refused() {
    let primary = primary_base_url();
    // Extract the host from the primary URL for lookalike tests.
    let host = url::Url::parse(primary)
        .expect("primary base URL must parse")
        .host_str()
        .expect("primary base URL must have a host")
        .to_string();

    for url in [
        // Wrong port on the allowlisted host.
        format!("https://{host}:444/v1"),
        // Lookalike host.
        format!("https://{host}.evil.example/v1"),
        // Subdomain of the allowlisted host (not the same origin).
        format!("https://sub.{host}/v1"),
        // Userinfo smuggling: the real host is evil.example.
        format!("https://{host}@evil.example/v1"),
        // Non-HTTP schemes.
        format!("ftp://{host}/v1"),
        format!("file:///etc/passwd"),
    ] {
        assert!(
            check_url_allowed(&url).is_err(),
            "bypass attempt must be refused: {url}"
        );
    }
}

/// The enforcement point: `ApiClient` construction must fail for disallowed
/// hosts so no provider can ever issue a request outside the sandbox.
#[test]
fn api_client_refuses_disallowed_host() {
    let result = ApiClient::new_with_tls(
        "https://api.openai.com".to_string(),
        AuthMethod::NoAuth,
        None,
    );
    assert!(
        result.is_err(),
        "ApiClient must refuse to construct for a non-allowlisted host"
    );
}

/// The enforcement point must still permit the allowlisted primary endpoint.
#[test]
fn api_client_permits_primary_host() {
    let result = ApiClient::new_with_tls(primary_base_url().to_string(), AuthMethod::NoAuth, None);
    assert!(
        result.is_ok(),
        "ApiClient must construct for the allowlisted primary endpoint"
    );
}

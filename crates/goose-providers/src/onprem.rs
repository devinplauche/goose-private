//! On-prem build lockdown: network egress allowlist.
//!
//! This module is only compiled into the `onprem` build variant of WarMachine,
//! a dedicated build for DoD use where developer laptops may only talk to an
//! internal LLM server. The allowlist is baked in at compile time and cannot
//! be changed at runtime, so the lockdown cannot be disabled without rebuilding.
//!
//! Build configuration (required when the `onprem` feature is enabled):
//! - `WARMACHINE_ONPREM_BASE_URL`: the on-prem OpenAI-compatible endpoint,
//!   e.g. `https://llm.internal.example/v1`. The build fails if this is unset.
//! - `WARMACHINE_ONPREM_EXTRA_HOSTS` (optional): comma-separated list of
//!   additional allowlisted origins, e.g. an internal observability collector.

use anyhow::{Context, Result};

/// The on-prem LLM endpoint this build is locked to.
///
/// Baked in at compile time via `WARMACHINE_ONPREM_BASE_URL`; the build fails
/// if it is not set, so an on-prem binary can never ship without an endpoint.
pub fn primary_base_url() -> &'static str {
    env!("WARMACHINE_ONPREM_BASE_URL")
}

/// Additional allowlisted origins, baked in at compile time.
fn extra_origins() -> Vec<String> {
    option_env!("WARMACHINE_ONPREM_EXTRA_HOSTS")
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| origin_of(s).ok())
        .collect()
}

/// Normalize a URL to `scheme://host[:port]`, filling in default ports.
fn origin_of(raw: &str) -> Result<String> {
    let url = url::Url::parse(raw).with_context(|| format!("invalid on-prem URL: {raw}"))?;
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        anyhow::bail!("on-prem URLs must use http or https: {raw}");
    }
    let host = url
        .host_str()
        .with_context(|| format!("on-prem URL has no host: {raw}"))?;
    let port = url
        .port_or_known_default()
        .with_context(|| format!("cannot determine port for on-prem URL: {raw}"))?;
    Ok(format!("{scheme}://{host}:{port}"))
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

/// Every origin this build is permitted to contact.
pub fn allowed_origins() -> Vec<String> {
    let mut origins = vec![
        origin_of(primary_base_url()).expect("WARMACHINE_ONPREM_BASE_URL must be a valid URL")
    ];
    origins.extend(extra_origins());
    origins
}

/// Refuse any URL whose origin is not on the compile-time allowlist.
///
/// Policy:
/// - The URL's origin (scheme + host + port) must be allowlisted.
/// - Plain `http` is only permitted for loopback hosts; all other traffic
///   must be `https` so CUI/ITAR data is encrypted in transit.
pub fn check_url_allowed(raw_url: &str) -> Result<()> {
    let url = url::Url::parse(raw_url).with_context(|| format!("invalid URL: {raw_url}"))?;
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();

    if url.scheme() == "http" && !is_loopback_host(&host) {
        anyhow::bail!(
            "on-prem builds require https for non-loopback hosts (CUI/ITAR must be encrypted in transit): {raw_url}"
        );
    }

    let origin = origin_of(raw_url)?;
    if allowed_origins().iter().any(|o| o == &origin) {
        Ok(())
    } else {
        anyhow::bail!(
            "URL origin {origin} is not on the on-prem allowlist for this build; \
             refusing to connect (CUI/ITAR must not leave the controlled environment)"
        )
    }
}

#[cfg(test)]
mod tests {
    // Note: these tests only run with `--features onprem` and a
    // WARMACHINE_ONPREM_BASE_URL set at compile time.
    use super::*;

    #[test]
    fn primary_origin_is_allowlisted() {
        let primary = primary_base_url();
        assert!(check_url_allowed(primary).is_ok());
        // Same origin, different path: still allowed.
        let with_path = format!("{}/v1/chat/completions", primary.trim_end_matches('/'));
        assert!(check_url_allowed(&with_path).is_ok());
    }

    #[test]
    fn public_cloud_is_refused() {
        assert!(check_url_allowed("https://api.openai.com/v1/chat/completions").is_err());
        assert!(check_url_allowed("https://api.anthropic.com/v1/messages").is_err());
    }

    #[test]
    fn plaintext_to_non_loopback_is_refused() {
        assert!(check_url_allowed("http://llm.internal.example/v1").is_err());
    }
}

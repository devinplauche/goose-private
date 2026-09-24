//! Storage seal for session message payloads.
//!
//! Single funnel for writing/reading `messages.content_json`. Under the
//! `onprem` build this is AES-256-GCM envelope encryption (see
//! [`crate::onprem`]) so CUI never rests in plaintext; in every other build
//! it is a pass-through and storage behavior is byte-identical to before.

use anyhow::Result;
use serde::de::DeserializeOwned;

/// Seal serialized content for storage.
#[cfg(feature = "onprem")]
pub(crate) fn seal(plaintext_json: &str) -> Result<String> {
    crate::onprem::seal_payload(plaintext_json)
}

/// Seal serialized content for storage (pass-through outside on-prem builds).
#[cfg(not(feature = "onprem"))]
pub(crate) fn seal(plaintext_json: &str) -> Result<String> {
    Ok(plaintext_json.to_string())
}

/// Open stored content, decrypting sealed envelopes and parsing legacy
/// plaintext rows as-is.
#[cfg(feature = "onprem")]
pub(crate) fn open<T: DeserializeOwned>(stored: &str) -> Result<T> {
    crate::onprem::open_payload(stored)
}

/// Open stored content (plain parse outside on-prem builds).
#[cfg(not(feature = "onprem"))]
pub(crate) fn open<T: DeserializeOwned>(stored: &str) -> Result<T> {
    Ok(serde_json::from_str(stored)?)
}

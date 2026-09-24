//! On-prem build: audit logging for CUI/ITAR compliance.
//!
//! Only compiled with the `onprem` feature. Provides:
//! - Re-exports of the compile-time network allowlist
//!   ([`goose_providers::onprem`]).
//! - An append-only, hash-chained audit log of every model request. Each entry
//!   records what was sent to the on-prem LLM (as a SHA-256 over the request
//!   payload, verifiable against the session database) chained to the previous
//!   entry's hash, so tampering with or deleting entries is detectable. This
//!   is the tamper-evident trail behind NIST 800-171 3.3.1 audit logging: the
//!   session database holds the content, this log proves the sequence.

pub use goose_providers::onprem::{allowed_origins, check_url_allowed, primary_base_url};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const AUDIT_LOG_NAME: &str = "audit.log";
const GENESIS_HASH: &str = "GENESIS";

fn audit_log_path() -> Result<PathBuf> {
    Ok(crate::config::paths::Paths::config_dir().join(AUDIT_LOG_NAME))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn last_entry_hash(path: &Path) -> String {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return GENESIS_HASH.to_string(),
    };
    let reader = BufReader::new(file);
    let mut last_hash = GENESIS_HASH.to_string();
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(h) = entry.get("entry_hash").and_then(|h| h.as_str()) {
                last_hash = h.to_string();
            }
        }
    }
    last_hash
}

/// Append one audit entry for a model request.
///
/// `request_json` is the serialized request payload; the log stores its
/// SHA-256 (not the content itself — content lives in the session database).
/// Best-effort: callers must not fail a request because the audit write failed.
pub fn audit_model_request(
    session_id: &str,
    model: &str,
    endpoint: &str,
    request_json: &str,
) -> Result<()> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create audit log dir {}", parent.display()))?;
    }

    let prev_hash = last_entry_hash(&path);
    let request_sha256 = sha256_hex(request_json);
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let entry_hash = sha256_hex(&format!(
        "{prev_hash}|{ts}|{session_id}|{model}|{endpoint}|{request_sha256}"
    ));

    let entry = serde_json::json!({
        "ts": ts,
        "session_id": session_id,
        "model": model,
        "endpoint": endpoint,
        "request_chars": request_json.chars().count(),
        "request_sha256": request_sha256,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    });

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot open audit log {}", path.display()))?;
    writeln!(file, "{}", entry)
        .with_context(|| format!("cannot write audit log {}", path.display()))?;
    Ok(())
}

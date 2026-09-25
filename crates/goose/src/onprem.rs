//! On-prem build: CUI/ITAR controls compiled into the binary.
//!
//! Only compiled with the `onprem` feature. Provides:
//! - Re-exports of the compile-time network allowlist
//!   ([`goose_providers::onprem`]).
//! - Payload sealing: session message content is encrypted at rest with
//!   AES-256-GCM (envelope encryption; the data-encryption key lives in the
//!   OS keychain, never on disk). Plaintext from databases created before
//!   sealing was introduced still reads, and is re-sealed on its next write.
//! - An append-only, hash-chained audit log of every model request plus
//!   session-lifecycle and extension-change events. Each entry records what
//!   was sent to the on-prem LLM (as a SHA-256 over the request payload,
//!   verifiable against the session database) chained to the previous
//!   entry's hash, so tampering with or deleting entries is detectable. This
//!   is the tamper-evident trail behind NIST 800-171 3.3.1 audit logging:
//!   the session database holds the content, this log proves the sequence.
//!   `verify_audit_log` re-checks the whole chain; point a log shipper at the
//!   JSONL file to forward entries to a SIEM.

pub use goose_providers::onprem::{allowed_origins, check_url_allowed, primary_base_url};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

// The `onprem` feature implies `system-keyring` and `dep:aes-gcm` in
// Cargo.toml; this is a backstop so a future edit that drops the implication
// fails loudly instead of silently weakening the build.
#[cfg(not(feature = "system-keyring"))]
compile_error!(
    "the `onprem` build requires the `system-keyring` feature: \
     the session-encryption key is held in the OS keychain, never on disk"
);

// ---------------------------------------------------------------------------
// Payload sealing (encryption at rest)
// ---------------------------------------------------------------------------

const DEK_KEYRING_SERVICE: &str = "warmachine";
const DEK_KEYRING_ACCOUNT: &str = "session-dek";
const SEAL_ALG: &str = "aes-256-gcm";
const SEAL_VERSION: u64 = 1;

/// Load this install's data-encryption key from the OS keychain, generating
/// and storing it on first use.
///
/// The DEK never touches disk: it lives in the platform keychain (Keychain /
/// Credential Manager / Secret Service) and only resides in process memory.
/// Keychain failure is fatal — failing closed is the point; a build that
/// cannot reach its key must not silently write plaintext instead.
#[cfg(feature = "system-keyring")]
fn session_dek() -> Result<[u8; 32]> {
    use base64::Engine as _;

    let entry = keyring::Entry::new(DEK_KEYRING_SERVICE, DEK_KEYRING_ACCOUNT)
        .map_err(|e| anyhow::anyhow!("OS keychain unavailable for session encryption key: {e}"))?;

    let decode = |encoded: &str| -> Result<[u8; 32]> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .context("stored session encryption key is not valid base64")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored session encryption key has wrong length"))
    };

    match entry.get_password() {
        Ok(encoded) => decode(&encoded),
        Err(keyring::Error::NoEntry) => {
            // First run on this machine: generate, store, then re-read, so a
            // concurrent first-run writer winning the race still leaves every
            // process using the same stored key.
            let mut dek = [0u8; 32];
            rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut dek)
                .map_err(|e| anyhow::anyhow!("OS RNG failure generating session key: {e}"))?;
            entry
                .set_password(&base64::engine::general_purpose::STANDARD.encode(dek))
                .map_err(|e| anyhow::anyhow!("cannot store session encryption key: {e}"))?;
            let stored = entry
                .get_password()
                .map_err(|e| anyhow::anyhow!("cannot re-read session encryption key: {e}"))?;
            decode(&stored)
        }
        Err(e) => Err(anyhow::anyhow!(
            "OS keychain unavailable for session encryption key: {e}"
        )),
    }
}

/// Seal a serialized session payload for storage.
///
/// Returns a self-describing JSON envelope
/// `{"enc":"aes-256-gcm","v":1,"nonce":..,"ct":..}` (base64 fields), with a
/// fresh 96-bit nonce per message. AES-256-GCM gives confidentiality plus
/// integrity: tampered rows fail to open instead of decrypting to garbage.
pub fn seal_payload(plaintext_json: &str) -> Result<String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    use base64::Engine as _;

    let dek = session_dek()?;
    let mut nonce_bytes = [0u8; 12];
    rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut nonce_bytes)
        .map_err(|e| anyhow::anyhow!("OS RNG failure: {e}"))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext_json.as_bytes())
        .map_err(|e| anyhow::anyhow!("payload seal failed: {e}"))?;

    let engine = base64::engine::general_purpose::STANDARD;
    Ok(serde_json::json!({
        "enc": SEAL_ALG,
        "v": SEAL_VERSION,
        "nonce": engine.encode(nonce_bytes),
        "ct": engine.encode(ct),
    })
    .to_string())
}

/// Open a stored session payload.
///
/// Sealed envelopes are decrypted and integrity-checked; anything else is a
/// legacy plaintext row (databases written before payload sealing) and is
/// parsed as-is. Callers re-seal on write, so plaintext ages out of the
/// database through normal use.
pub fn open_payload<T: DeserializeOwned>(stored: &str) -> Result<T> {
    let value: serde_json::Value = serde_json::from_str(stored)?;
    if value.get("enc").and_then(|v| v.as_str()) == Some(SEAL_ALG) {
        decrypt_envelope(&value)
    } else {
        Ok(serde_json::from_value(value)?)
    }
}

fn decrypt_envelope<T: DeserializeOwned>(envelope: &serde_json::Value) -> Result<T> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    use base64::Engine as _;

    let version = envelope.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != SEAL_VERSION {
        anyhow::bail!("unsupported sealed payload version: {version}");
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let nonce_bytes = engine
        .decode(envelope.get("nonce").and_then(|v| v.as_str()).unwrap_or(""))
        .context("sealed payload has invalid nonce")?;
    if nonce_bytes.len() != 12 {
        anyhow::bail!("sealed payload has wrong nonce length");
    }
    let ct = engine
        .decode(envelope.get("ct").and_then(|v| v.as_str()).unwrap_or(""))
        .context("sealed payload has invalid ciphertext")?;

    let dek = session_dek()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ct.as_ref())
        .map_err(|_| anyhow::anyhow!("sealed payload failed integrity check"))?;
    let json = String::from_utf8(pt).context("sealed payload is not valid UTF-8")?;
    Ok(serde_json::from_str(&json)?)
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

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

fn append_entry(entry: serde_json::Value) -> Result<()> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create audit log dir {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot open audit log {}", path.display()))?;
    writeln!(file, "{entry}")
        .with_context(|| format!("cannot write audit log {}", path.display()))?;
    Ok(())
}

fn utc_now_ts() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
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
    let prev_hash = last_entry_hash(&audit_log_path()?);
    let request_sha256 = sha256_hex(request_json);
    let ts = utc_now_ts();
    let entry_hash = sha256_hex(&format!(
        "{prev_hash}|{ts}|{session_id}|{model}|{endpoint}|{request_sha256}"
    ));

    append_entry(serde_json::json!({
        "ts": ts,
        "session_id": session_id,
        "model": model,
        "endpoint": endpoint,
        "request_chars": request_json.chars().count(),
        "request_sha256": request_sha256,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    }))
}

/// Append a generalized audit event: session lifecycle (`session_start`,
/// `session_end`), extension changes (`extension_added`), and future event
/// types. `details` carries small non-sensitive metadata; the hash chain
/// covers the JSON encoding of the entry as written, and verification
/// re-encodes the parsed entry, so any modification breaks the chain.
/// Best-effort: callers must not fail the operation because the audit write failed.
pub fn audit_event(
    event: &str,
    session_id: Option<&str>,
    details: &serde_json::Value,
) -> Result<()> {
    let prev_hash = last_entry_hash(&audit_log_path()?);
    let ts = utc_now_ts();
    let session_id = session_id.unwrap_or("");
    // Hashed in the exact encoding written to the file; verification
    // re-encodes the parsed entry, which round-trips deterministically.
    let details_json = serde_json::to_string(details)?;
    let entry_hash = sha256_hex(&format!(
        "{prev_hash}|{ts}|{event}|{session_id}|{details_json}"
    ));

    append_entry(serde_json::json!({
        "ts": ts,
        "event": event,
        "session_id": session_id,
        "details": details,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    }))
}

/// Recompute an entry's hash from its fields. Legacy `model_request` entries
/// (no `event` field) keep their original hash scheme so entries written by
/// earlier builds still verify.
fn recompute_entry_hash(entry: &serde_json::Value) -> Result<String> {
    let get = |field: &str| {
        entry
            .get(field)
            .and_then(|v| v.as_str())
            .with_context(|| format!("audit entry missing field '{field}'"))
    };
    let prev_hash = get("prev_hash")?;
    let ts = get("ts")?;

    if entry.get("event").is_none() {
        // Legacy model_request shape.
        let session_id = get("session_id")?;
        let model = get("model")?;
        let endpoint = get("endpoint")?;
        let request_sha256 = get("request_sha256")?;
        return Ok(sha256_hex(&format!(
            "{prev_hash}|{ts}|{session_id}|{model}|{endpoint}|{request_sha256}"
        )));
    }

    let event = get("event")?;
    let session_id = get("session_id")?;
    let details_json =
        serde_json::to_string(entry.get("details").unwrap_or(&serde_json::Value::Null))?;
    Ok(sha256_hex(&format!(
        "{prev_hash}|{ts}|{event}|{session_id}|{details_json}"
    )))
}

/// Verify the audit log's hash chain end to end.
///
/// Returns the number of entries verified. Fails on the first broken link
/// (a `prev_hash` that doesn't match the previous entry) or tampered entry
/// (an `entry_hash` that doesn't recompute), naming the offending line.
pub fn verify_audit_log() -> Result<usize> {
    let path = audit_log_path()?;
    let file = std::fs::File::open(&path)
        .with_context(|| format!("cannot open audit log {}", path.display()))?;
    let mut prev_hash = GENESIS_HASH.to_string();
    let mut count = 0usize;
    for (lineno, line) in BufReader::new(file).lines().enumerate() {
        let lineno = lineno + 1;
        let line = line.with_context(|| format!("cannot read audit log line {lineno}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: serde_json::Value = serde_json::from_str(&line)
            .with_context(|| format!("audit log line {lineno} is not valid JSON"))?;
        let entry_prev = entry
            .get("prev_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        if entry_prev != prev_hash {
            anyhow::bail!("audit log chain broken at line {lineno}: prev_hash mismatch");
        }
        let recomputed = recompute_entry_hash(&entry)
            .with_context(|| format!("cannot recompute hash for audit log line {lineno}"))?;
        let entry_hash = entry
            .get("entry_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        if recomputed != entry_hash {
            anyhow::bail!("audit log tamper detected at line {lineno}");
        }
        prev_hash = entry_hash.to_string();
        count += 1;
    }
    Ok(count)
}

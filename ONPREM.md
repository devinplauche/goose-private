# WarMachine On-Prem Build (DoD / CUI/ITAR)

WarMachine ships a dedicated **on-prem build variant** for environments that
handle CUI/ITAR data. Developer laptops run a WarMachine binary that can only
talk to an internal LLM server. The lockdown is **compiled in** — it is not a
setting, flag, or environment variable, so it cannot be switched off without
rebuilding the binary.

## Threat model

- Prompts, code, and tool output sent to the LLM may contain CUI/ITAR data.
- The binary must never transmit that data outside the controlled
  environment: no public LLM APIs, no cloud telemetry, no session sharing, no
  remote extension installs from outside the enclave.
- Every model request must leave a tamper-evident audit trail (supports
  NIST 800-171 3.3.1 audit logging).

## How the lockdown works

The `onprem` cargo feature (in the `warmachine`, `goose-providers`, and
`goose-cli` crates) bakes the policy in at compile time:

| Control | Mechanism |
|---|---|
| Endpoint | `WARMACHINE_ONPREM_BASE_URL` env var **at build time**. The build fails if it is unset, so an on-prem binary can never ship without an endpoint. `OPENAI_HOST` / `OPENAI_BASE_URL` overrides are ignored. |
| Network allowlist | `goose_providers::onprem::check_url_allowed()` gates `ApiClient` construction — every provider HTTP request funnels through it. Origins outside the allowlist are refused. Plain `http` is rejected for non-loopback hosts (CUI/ITAR must be encrypted in transit). |
| Extra origins | `WARMACHINE_ONPREM_EXTRA_HOSTS` (optional, comma-separated) allowlists additional origins, e.g. an internal observability collector. |
| Provider registry | Only the OpenAI-compatible provider is registered. Cloud providers, ACP CLIs, and custom/declarative providers are not registered at all. |
| Telemetry export | OTLP layers are compiled out. Langfuse is disabled unless its URL is on the allowlist. (Product telemetry was already permanently disabled.) |
| Session sharing | Nostr session publishing is disabled (default relays are public). |
| Remote MCP servers | `StreamableHttp` extension URIs must be on the allowlist. Unix-socket transports are local IPC and exempt. |
| Voice dictation | Cloud STT endpoints are not allowlisted, so dictation fails closed. |
| Audit log | Every model request appends a hash-chained entry; session start/end and extension installs are logged too (see below). |
| At-rest encryption | Session message payloads in `sessions.db` are sealed with AES-256-GCM (see below). |
| Secret storage | The OS keychain is mandatory: `WARMACHINE_DISABLE_KEYRING` is ignored and an unreachable keychain fails closed. |
| Tool approvals | Every shell/web tool call requires explicit human approval (see below). |

## Server requirements

- An **OpenAI-compatible** chat-completions endpoint
  (`POST {base}/chat/completions`, or with `/v1` prefix — both are handled),
  reachable from developer laptops.
- **TLS** with a certificate the laptops trust: either a public CA cert or an
  internal CA installed in the OS trust store. `https` is required (loopback
  excepted for local testing).
- Optional: **mTLS** client certificates — WarMachine already supports
  `tls_client_cert` / `tls_client_key` provider TLS config.
- The server should enforce its own authentication (API key or mTLS); the
  on-prem build sends whatever `OPENAI_API_KEY` is configured, but the
  endpoint itself is fixed.

## Building the on-prem binary

```bash
WARMACHINE_ONPREM_BASE_URL="https://llm.internal.example/v1" \
  cargo build --release -p goose-cli --features onprem
# optional extra origins:
WARMACHINE_ONPREM_EXTRA_HOSTS="https://otel.internal.example:4318" \
  WARMACHINE_ONPREM_BASE_URL="https://llm.internal.example/v1" \
  cargo build --release -p goose-cli --features onprem
```

Notes:

- `WARMACHINE_ONPREM_BASE_URL` is read **when compiling** `goose-providers`,
  not at runtime. Changing the endpoint means rebuilding.
- The desktop app must bundle this CLI binary (it shells out to it); a
  desktop build that bundles the standard binary is not an on-prem build.
- Verify the lockdown: point the binary at a public endpoint
  (e.g. `OPENAI_BASE_URL=https://api.openai.com`) — requests must fail with
  an allowlist error, and the provider list must show only the on-prem
  OpenAI-compatible provider.

## Audit log

Location: `~/.config/warmachine/audit.log` (one JSON object per line).

Two entry shapes, both hash-chained:

- **Model requests** (as before): `ts`, `session_id`, `model`, `endpoint`,
  `request_chars`, `request_sha256` (SHA-256 of the serialized request
  payload), `prev_hash`, `entry_hash`, where

  ```
  entry_hash = sha256(prev_hash | ts | session_id | model | endpoint | request_sha256)
  ```

- **Events**: `ts`, `event` (`session_start`, `session_end`,
  `extension_added`), `session_id`, `details` (small metadata, e.g.
  `{"name": ..., "kind": "stdio"}` for extensions), `prev_hash`,
  `entry_hash`, where

  ```
  entry_hash = sha256(prev_hash | ts | event | session_id | details_json)
  ```

The chain makes tampering or deletion detectable: each `prev_hash` must match
the previous `entry_hash`. Request *content* lives in the session database
(`sessions.db`); the audit log proves the sequence without duplicating
content. Audit writes are best-effort — a logging failure warns but never
breaks a request.

Verify the chain locally:

```bash
warmachine audit verify
# audit log verified: 128 entries, hash chain intact
```

**SIEM forwarding:** the client creates no new egress path — forward the
JSONL file with your existing log shipper (e.g. Filebeat, Splunk Universal
Forwarder, or `rsyslog` imfile) to your SIEM. Each line is a self-contained
JSON event; the `entry_hash`/`prev_hash` fields let the SIEM (or a later
`warmachine audit verify` run) detect gaps or tampering in transit.

## Session data

Conversation history stays in the local `sessions.db` on the laptop, but
message payloads are **encrypted at rest** in the on-prem build:

- Each `content_json` row is sealed with **AES-256-GCM** under a per-install
  256-bit data-encryption key (DEK). The sealed value is a self-describing
  JSON envelope (`{"enc":"aes-256-gcm","v":1,"nonce":..,"ct":..}`), so no
  schema migration was needed.
- The DEK is generated on first run and held in the **OS keychain** — it never
  touches disk. If the keychain is unreachable, session writes fail closed
  rather than writing plaintext.
- Databases written before sealing was introduced still read: legacy
  plaintext rows are parsed as-is and re-sealed on their next write, so
  plaintext ages out through normal use. GCM also integrity-protects each
  row: tampered rows fail to open instead of decrypting to garbage.
- Because payloads are sealed, keyword search (`session list --match`,
  chat-recall) decrypts candidates in memory and matches in Rust instead of
  in SQL. Results are identical; large histories are somewhat slower.

Combine with full-disk encryption on the laptops and your organization's
device policy for defense in depth.

## Keychain requirement

The on-prem build treats the OS keychain as mandatory infrastructure:

- `WARMACHINE_DISABLE_KEYRING` (env var or config) is **ignored**.
- API keys and the session-encryption DEK are stored only in the keychain.
- If the keychain daemon is unreachable, secret reads/writes **fail closed**
  with an error — the build will not silently fall back to the plaintext
  `secrets.yaml` file. On a fresh laptop image, make sure the Secret Service
  (Linux) / Keychain (macOS) / Credential Manager (Windows) is functional
  before first run.

## Tool approvals

On-prem builds are **default-deny** for tool execution: every shell or web
tool call requires explicit human approval in the CLI before it runs.
Pattern-based egress detection is bypassable (obfuscation, novel exfil
paths); approval is not.

Operational notes:

- Approvals are per tool call, in the interactive CLI. There is no
  pre-approval list or "allow always" escape hatch in the on-prem build.
- Headless use (recipes, `warmachine run`, scheduled jobs) will stall at the
  approval prompt with no one to answer it. If you run unattended workflows,
  route them through a supervised session or accept that tool calls block.
- A denied call is reported to the model as a tool error, not a crash — the
  session continues.

## CI

`.github/workflows/ci.yml` includes a `rust-check-onprem` job that compiles
(`cargo check --all-targets`) and lints (clippy, `-D warnings`) the on-prem
feature combination on every push, so the gated code cannot rot.

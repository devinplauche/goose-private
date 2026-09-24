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
| Audit log | Every model request appends a hash-chained entry (see below). |

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

Each entry records `ts`, `session_id`, `model`, `endpoint`, `request_chars`,
`request_sha256` (SHA-256 of the serialized request payload), `prev_hash`,
and `entry_hash`, where

```
entry_hash = sha256(prev_hash | ts | session_id | model | endpoint | request_sha256)
```

The chain makes tampering or deletion detectable: recompute the hashes over
the file and confirm each `prev_hash` matches the previous `entry_hash`.
Request *content* lives in the session database (`sessions.db`); the audit
log proves the sequence without duplicating content. Audit writes are
best-effort — a logging failure warns but never breaks a request.

## Session data

Conversation history stays in the local `sessions.db` on the laptop, exactly
as in the standard build. For CUI/ITAR handling, combine with full-disk
encryption on the laptops and your organization's device policy — WarMachine
does not add at-rest encryption to the session database itself.

## CI

`.github/workflows/ci.yml` includes a `rust-check-onprem` job that compiles
(`cargo check --all-targets`) and lints (clippy, `-D warnings`) the on-prem
feature combination on every push, so the gated code cannot rot.

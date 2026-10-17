# Customer-local shadow integration

The product name is **Kör**. Existing `SENTINEL_*` environment variables, `X-Sentinel-*` request headers and `els-*` artifact/contract identifiers remain stable for compatibility. They are integration identifiers, not the displayed product name. Renaming the product does not rotate keys, change the CSV schema or rewrite frozen model evidence.

The identity provider is intentionally unspecified. The implemented interface and transport are provider-neutral; no provider account, tenant credentials, real traffic or production MFA system was connected during development.

Optional `--tls-cert` and `--tls-key` server arguments require TLS 1.3. The CLI adapter's `--tls-ca` uses certificate and hostname verification and never falls back to HTTP. Default transport remains unencrypted loopback HTTP. [TLS configuration](crypto_inventory.md#local-tls-demonstration).

The fictional demo adds a current HMAC receipt (`/api/demo/proof`) and an employee-only resource (`/api/demo/resource`). These are token-scoped demo operations, not new trusted/customer API permissions. The experimental combined-context guard is demo-only; trusted ingestion keeps its baseline policy because regression found substantial benign overlap.

## Trust boundary

An adapter runs alongside the customer's IdP/application and validates the provider's authenticated event source. Only after validating provider signatures, issuer/audience, transport identity and outcome semantics should it derive a minimal event matching [event_contract.md](event_contract.md). Those provider-specific checks are **not** performed by the generic transport helper.

The risk server authenticates that configured producer using HMAC-SHA256. A valid signature proves possession of the shared producer key, not that an upstream provider assertion was correctly validated. A compromised adapter can falsify evidence. Use one process per tenant and distinct producer/reviewer keys; do not share keys across customers. The producer key cannot submit independent review labels or read metrics, and the reviewer key cannot ingest events. Browser requests cannot submit trusted outcomes.

Account/source identifiers are opaque and customer-generated, never raw names/IPs. Source correlation must use a bounded customer-side mapping or keyed pseudonym and expiry; a plain IP hash is not anonymization. Keep the two-minute correlation window meaningful across rotation boundaries. Neither this runtime nor its tests creates persistent device fingerprints. Actual managed-device/context evidence must come from trusted customer systems.

Trusted streams require 120 seconds of observation after startup/reset before scoring. Counters remain lower bounds during warmup, and supplied missing history still abstains afterward. This assumes complete ordered delivery; it is not a guarantee against upstream dropped events.

The historical 17/19-column CSVs lack verified outcomes and source tokens; do not treat them as live events or infer authentication success from their target labels.

## Local setup

Create a random shared secret in the local shell without printing it or putting its value in command arguments or a tracked file:

```bash
export SENTINEL_INGEST_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export SENTINEL_REVIEW_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 app/serve.py --port 8001 --disable-demo
```

The producer receives only `SENTINEL_INGEST_SECRET`; an independent reviewer receives only `SENTINEL_REVIEW_SECRET`, through customer secret management. The server holds both. Each accepted key is 64–128 hexadecimal characters. Missing/invalid keys disable their routes; equal keys reject server startup. Do not send keys to an AI conversation or paste them into a URL. Omit `--disable-demo` only when the anonymous fictional demonstration is wanted.

With the same environment, a trusted producer can pass **one already validated event** through stdin to:

```bash
python3 -m src.runtime.adapter --port 8001
```

The command reads until EOF, validates the complete allowlisted event schema **before opening a connection**, sends to loopback and prints only the derived response. Unknown fields, including credentials, fail locally without being transmitted. It does not contain an IdP connector, accept a password argument or retry submitted evidence automatically. Use `--review` for a minimal `{ "event_id": "<retained event UUID>", "label": "normal" }` record (or `suspicious`) produced by an independent reviewer; this schema is also validated before transport. Examples are shape descriptions, not literal valid events. `python3 -m src.runtime.adapter --port 8001 --metrics` reads aggregates with the reviewer key and does not read stdin.

## HTTP authentication

Only `application/json` is accepted, with one Content-Length, no transfer encoding, and at most 16 KiB. Total headers are limited to 16 KiB; ambiguous duplicate security headers, GET/HEAD bodies, Expect and non-origin-form targets are rejected. Duplicate JSON fields and nonfinite numbers are rejected. Sign the exact bytes transmitted:

```text
v1\n<request path>\n<unix seconds>\n<32 lowercase hex nonce>\n<body bytes>
```

Use HMAC-SHA256 with the UTF-8 secret string as key. Send lowercase hex digest in `X-Sentinel-Signature`, timestamp in `X-Sentinel-Timestamp`, nonce in `X-Sentinel-Nonce`. The path is `/api/events`, `/api/review` or `/api/metrics`; metrics accepts only `{}`. The adapter helper implements this format.

Signed requests more than 30 seconds from the server clock are rejected. This transport tolerance does not allow future event timestamps: any event ahead of the receiver clock is rejected without advancing ordering. Successful nonces remain reserved for 120 seconds. Duplicate retained event IDs and cross-account session-UUID reuse are rejected independently. Event order must be nondecreasing; a provider with out-of-order delivery needs a bounded local ordering buffer and must preserve original UTC event times. Do not retimestamp old events to bypass retention/replay checks.

Trusted routes reject browser Origin headers. Demo routes require `X-Sentinel-Demo: 1`, JSON and a matching Origin when present; they use independent random handles and cannot affect the trusted event stream. Host restrictions, no CORS, no-store responses and no request logging apply throughout.

## Shadow operation and review

All trusted responses specify `mode: shadow_only` and `enforcement: none`. The application does not lock accounts, invoke real MFA, send notifications or change customer access. The fictional Vela flow has a separate local demo verifier and a public demo MFA code.

`GET /api/status` exposes readiness/configuration flags only. Signed `POST /api/metrics` exposes numeric-score coverage, recommendations, score bins, fixed context subgroups, independently reviewed confusion counts and descriptive earlier/later window changes. It contains no event/account/session/source identifiers. MFA completion is never automatically a benign label. A reviewer may correct a label without double-counting the event. Retention limits apply to labels too.

## Admission and concurrency limits

The interactive fictional verifier separately applies exponential password backoff: `min(60, 2^(consecutive_incorrect_checks−1))` seconds. Snapshot field `login_retry_after_ms` is an integer in `[0,60000]`. Before the deadline, `/api/demo/attempt` returns HTTP 429 with `Retry-After` and `{ "code": "login_backoff", "retry_after_seconds": <1..60>, "error": <generic text> }`. It rejects before password comparison/reference lookup without sleeping a worker, adding an event, or extending the deadline. Monotonic time governs the wait. Correct password verification resets the streak; existing MFA/risk decisions still govern the fictional workspace.

This state is scoped to a demo handle and removed on reset/expiry. Session-token rotation and context changes do not reset it; synthetic scenario replay neither increases nor clears it. MFA retains its existing separate five-attempt challenge limit. The delay does not alter the 120-second analysis window, five-minute retention, model inputs or score calibration. Trusted `/api/events` accepts verified evidence after authentication has occurred; it must not delay or discard that evidence to implement login throttling. Real enforcement belongs upstream in the customer's login verifier, with account correlation across browser sessions and explicitly bounded retention. No such provider has been connected.

The local server admits at most 16 simultaneous HTTP workers, with a five-second idle socket timeout and an eight-second absolute connection deadline. Overload returns 503. Demo events have a 1,000-event budget; trusted events have a reserved 4,000-event budget, within a 5,000-event total. Full state rejects work with 429 instead of silently dropping evidence. Password-reference checking runs outside the shared ingestion mutex; reset/expiry invalidates an in-flight result.

Token buckets use a monotonic clock and fixed channel names, with no address tracking. Demo requests share a 240-operation burst with four operations/second refill; starting a demo has a separate 16-start burst with 0.5/second refill. Each demo has a 60-operation burst with one/second refill. A simulation consumes one operation per generated attempt. Authenticated producer and reviewer operations each have a separate 100-request burst with ten/second refill; invalid authentication has its own bucket and cannot consume either authenticated budget. Exhaustion returns 429; resetting demos does not reset process budgets. These finite limits bound this development process, not a distributed denial-of-service defense.

These short-window aggregates are an instrumentation foundation, not a completed customer pilot or a validated drift detector. Before enforcing decisions: obtain a fresh independently labelled cohort in the customer environment, define an observation period and acceptable false-alarm/recall/coverage targets, keep time/account/scenario validation independent, and measure burden for VPN/travel/new-device and missing-history groups. The current threshold-selection targets were infeasible, so every current trusted decision recommends review, with a numeric score only when evidence is sufficient for inference.

## Deployment limits

This is a loopback standard-library development server. It has bounded state, authentication and protocol tests, but is not a hardened production ingress, TLS terminator or full identity provider. Production adapter authentication, key rotation, network isolation, TLS, service supervision, deployment-level resource controls and operational retention must be implemented in the customer's deployment. Leave external exposure disabled until that integration is independently tested. Restarting the process clears ephemeral state; no customer events are written to disk.

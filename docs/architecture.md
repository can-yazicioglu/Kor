# Architecture

The current system has three explicit paths. They share customer-local artifacts but have separate evidence and decision semantics.

Both English interfaces retain a classic administration theme. The company security desk uses ink/ivory/brass, restrained beveled controls and a serif portal heading. Risk parameters, quality, actions and evidence remain visible. Chromium desktop/mobile flows and responsive screenshots were verified during the datathon update.

## 1. Server-owned Vela demonstration

```text
English company UI → same-origin local JSON request → fictional server verifier
                    → local password-reference flags → trusted-format event
                    → rolling runtime counters → original 11-feature model
                    → validation-fitted calibration + separate contextual policy
                    → current score / session peak / quality / recommendation
                    → server-checked public demo MFA → fictional workspace
```

Only the local demonstration accepts invented credential values. The browser clears fields immediately; the server compares the public account/password, checks the reference transiently and retains derived evidence only. No raw credential, submitted hash or request body is written to storage/logs. A raw input can exist briefly in process/network buffers; no physical memory-wiping guarantee is made.

The server, rather than a client boolean or a client score, owns the demo verification outcome and workspace decision. A random bearer handle identifies a five-minute isolated demo. The public MFA code is an illustration, not a real authentication factor. The workspace exposes no private company data. Simulations run fixed synthetic batches inside the local server.

The public password fixture uses a salted scrypt verifier (N=32768, r=8, p=3), with four concurrent verification slots. Submitted values and derived hashes are transient. After verification the server owns a fixed employee role and a grant lasting at most two minutes, bounded by demo expiry. `/api/demo/resource` checks that grant on every request. The employee role cannot access the fictional audit console; client role fields are rejected. Failure, reset or expiry revokes access.

Each demo also holds one current HMAC-SHA-256 decision receipt with a random per-demo key. Its payload includes only a counter, model version, score, action and window constant. Inspection verifies the original and an altered copy without changing the event stream. New decisions supersede older receipts; reset/expiry removes the key and current receipt. This is process-local integrity, not persistent audit logging, encryption or hardware attestation.

`GuardedRiskEngine` adds a separately versioned **demo-only** context rule for a successful password login combining a new device, unfamiliar network and unusual hour/velocity. It does not modify scores or frozen experiment code. Its high benign overlap is measured and disclosed, so the trusted stream still uses the original `RiskEngine`. [Rule regression and limitations](datathon_demo.md#tested-experimental-rule-and-its-tradeoff).

Each pending MFA response carries a fresh `mfa_challenge_id`. The browser returns it as `challenge_id` with the code, binding the check to that sign-in. An earlier challenge cannot authorize a newer pending login. Challenges expire at the earlier of two minutes after issue or the current two-minute session boundary; five failed code attempts exhaust a challenge. Password-reference checking runs outside the shared ingestion lock, while an in-flight marker prevents another operation from replacing its context. Reset or expiry invalidates an in-flight result.

The [evidence workbench](evidence_workbench.md) reads the existing expiring store. `src/runtime/insights.py` shares three volume rules with the live policy, compares their evidence over 30/60/120-second histories, and compares consecutive results only within one account/session. The service adds a count-only lifecycle inventory to demo snapshots under the bounded `els-insights-v1` contract. No identifiers or extra model inputs are added by these diagnostics. The browser validates the response and renders it as text; a token-scoped status refresh creates no event and extends no deadline. Diagnostics never authorize a workspace or modify model scores. Public status and trusted-ingestion responses remain unchanged.

## 2. General trusted event ingestion

```text
Customer IdP → provider-specific validating adapter → opaque event + producer HMAC
             → loopback ingestion → schema / timestamp / replay validation
             → ordered runtime → shadow recommendation + aggregate monitoring
Independent human reviewer → separate reviewer HMAC → review / aggregate metrics
```

The generic adapter transport is ready; a real provider-specific validator is not connected. The user selected a provider-neutral integration. The adapter strictly validates the permitted event or review schema before opening a network connection. HMAC binds the request path, fresh timestamp, random nonce and exact body. It authenticates the configured producer; it does not independently verify the upstream IdP. Each service instance serves one tenant. The browser cannot submit arbitrary trusted success/MFA events. [Transport and deployment boundary](runtime_integration.md).

`SENTINEL_INGEST_SECRET` authorizes only event production. A distinct `SENTINEL_REVIEW_SECRET` authorizes independent review and aggregate metrics; configuring identical keys is rejected. `GET /api/status` exposes readiness and configuration flags only, without traffic aggregates. Reviewer-authenticated `POST /api/metrics` exposes bounded shadow aggregates; `python3 -m src.runtime.adapter --metrics` requests them without reading standard input. No event, account, session or source identifiers are exposed in those metrics.

The event contract has explicit outcome and method, opaque account/session/source tokens, the 11 contextual fields, and two required but nullable password flags. It is a separate versioned interface; the fixed baseline CSV is not changed. No target label or attack metadata is accepted. Targets appear only in evaluation or independently authenticated feedback. [Exact contract](event_contract.md).

A newly started/reset trusted stream remains unscored until 120 seconds of server observation have elapsed; future timestamps cannot bypass warmup. Counts during that interval are lower bounds. The demo explicitly starts a fresh synthetic stream. Continuous delivery must still be ensured by the customer adapter.

The runtime derives account attempts, source account fan-out, account source fan-in, failure streaks and success-after-failure evidence from `(t−120 seconds, t]`. MFA is excluded from login attempt counts. Supplied longer-history aggregates are not reconstructed from an incomplete five-minute stream; absent history remains unknown. No real 30-day user history is assumed; historical profiles in the demo are explicitly synthetic. Source/account tokens and trusted context originate inside the customer environment, without raw-IP storage or permanent fingerprints.

Additional descriptive signals distinguish failed and successful account breadth at a source, failing sources against an account, account/source failure ratios, and same-account timing gaps. Empty denominators or insufficient gap support remain `null`; incomplete-window ratios describe only the observed sample, not complete-window lower bounds. These signals do not change the baseline CSV or enter the original model. Gap statistics have no action-policy effect. The exact fields and assumptions are in the [event contract](event_contract.md).

Events are globally nondecreasing in time. Any event timestamp ahead of the receiving server clock is rejected, even within the HMAC freshness allowance, without advancing the ordering watermark. A retained session UUID belongs to one account; cross-account reuse is rejected before risk state changes.

## Scores, quality and action

The original portable logistic model still receives exactly its 11 allowlisted features. Identifiers, outcomes, labels and password evidence never enter that trained model. A separate calibration mapping was fitted using only a validation-account partition. Threshold selection used a different account partition; within-validation source/episode overlap is disclosed in the results.

Current event score and retained session peak are distinct. Neither the calibrated synthetic event score nor a maximum over events is a proven customer attack probability. Missing context/artifacts yield no current score. A retained peak does not make a currently unknown event safe.

The selected decision targets are infeasible, so both thresholds are null. Numeric evidence remains visible when available, quality is limited, and the action conservatively recommends review. A lower numeric score is not automatic access approval. Sequence rules can elevate a recommendation using corroborating failure/source/context evidence without adding invented probability points. MFA/passkey verification never erases existing peak or unresolved sequence evidence.

Sequence policy `els-contextual-shadow-v2` requires failed-account breadth and a failure-dominated complete source window for spraying, and counts failing sources rather than all sources for distributed failures. A busy shared source or successful-source recovery alone therefore does not satisfy those rules. Repeated account failures and distributed failures remain visible alongside legitimate traffic. These narrower conditions are expected-behavior rules, not evidence of a measured false-positive improvement; a spray mixed with sufficient successful traffic may evade the source rule. The later offline tuning studies described below do not change this default policy.

Password reference membership is separate credential evidence. Failed weak-password submissions do not establish the account's actual password. A verified weak-reference password can support contextual review when combined with prior failures and a new unfamiliar context. Fixed +25/+10 bonuses are not used in the current server flow.

Trusted ingestion is shadow-only: no lockout, customer MFA action, email or access change. Aggregate monitoring includes coverage, recommendations, fixed-context subgroup alerts, score bins, descriptive earlier/later changes and independent-review confusion counts. These are not a completed pilot or validated drift detector.

## Offline tuning and guarded candidate integration

Two isolated studies trained 36 logistic candidates and 18 logistic/tree candidates on separate synthetic cohorts. Training, tuning, calibration, threshold selection and final evaluation have distinct account/session/source/episode groups and ordered time ranges. The fixed 17-column CSV and original model artifacts remain unchanged. [Methods and results](model_tuning.md).

The candidate interface supports the original eleven inputs plus ten causal prior-login features, derived from existing two-minute RAM history by the same function offline and online. Identifiers select groups but never become vector values; current outcome, future events, labels and attack metadata are excluded. No extra history store or retention extension is introduced. Inference reads bounded data-only JSON and needs no sklearn dependency in the server.

Candidate activation is explicit, local-demo-only and requires a qualified, intact release receipt. It never changes trusted ingestion. The new candidate passed aggregate synthetic gates but missed every scored suspicious-success example, so its release receipt is blocked and `--tuned-demo` fails closed. The normal launch continues to use the baseline and its unavailable-threshold review fallback. The candidate's alternative sequence policy is active only in offline evaluation and isolated compatibility tests.

## 3. Historical browser CSV analysis

`/` preserves the original 17-column ML view and 19-column V2 additive-password experiment. CSV import, grouping and historical scoring stay in browser memory. The page explicitly distinguishes itself from the current server flow. It cannot establish real authentication outcomes from CSV target labels. Existing model/data bindings and historical metrics remain reproducible.

## Operational boundaries

The server binds only to loopback, restricts Host, rejects arbitrary files/query-bearing API routes, applies a restrictive CSP and has no request logging, CORS or telemetry. `--disable-demo` disables anonymous demo mutations while retaining the authenticated shadow path. It is an optional deployment setting, not an authentication system for the static pages.

Optional certificate/key arguments enable TLS 1.3 without HTTP fallback. TLS handshakes run under bounded worker/deadline handling rather than blocking the accept loop. Same-origin checks use the actual server scheme, not forwarded headers. The adapter's `--tls-ca` verifies the certificate and hostname. [TLS and cryptographic inventory](crypto_inventory.md).

HTTP handling is bounded to 16 workers, an eight-second absolute connection deadline, a 16 KiB total header budget and a separate 16 KiB JSON-body cap. Duplicate security-sensitive headers and JSON fields, ambiguous transfer framing and non-origin request targets are rejected. An absolute deadline bounds trickled data as well as an idle read; it is not a general operating-system denial-of-service guarantee.

State is bounded to 32 demos and 500 events per demo, with separate retained-event quotas of 1,000 across demos and 4,000 for trusted ingestion, subject to the 5,000-event process cap. Global channel and per-demo token buckets bound request rates; demo traffic does not spend the trusted-ingestion bucket, and demo reset does not refill process-level buckets. Replay caches and retained state are bounded. Server cleanup runs approximately once a second; access expiry is checked synchronously. Retention remains five minutes. [Retention details](retention_policy.md).

The original dataset and trained model remain unchanged; new synthetic cohorts and checkpoints live in separate experiment directories. The server is a local development implementation, not a hardened production ingress or certified authentication service. Provider-specific validation, deployment security and an untouched customer-local pilot remain integration work. Python, DOM, real HTTP/TLS and desktop/mobile browser checks exercise the delivered boundaries; these checks do not constitute production certification. IBM Z execution and quantum-safe integration remain unverified target capabilities.

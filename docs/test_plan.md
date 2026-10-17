# Independent test plan

The acceptance boundary is a tested local prototype, not perfect detection or a production authentication service. Runtime and historical experiments have distinct policies. All scenarios below use invented credentials/tokens and synthetic context.

## Normal and suspicious scenarios

| Scenario | Expected evidence and behaviour |
|---|---|
| Normal familiar successful login | Server-verified outcome, finite calibrated score when complete, no sequence escalation; current unavailable thresholds explicitly recommend review |
| VPN/travel/new device without a failure pattern | No automatic sequence escalation from that context alone; model and conservative threshold fallback remain visible |
| One to three mistaken passwords then recovery | No claim that an unsuccessfully submitted weak password is the account password; no unconditional password bonus |
| Many failures against one account | Account streak/count rises within two minutes and raises the recommendation to review |
| Many accounts failing from one source, or several failing sources against one account | Failed-account breadth plus a failure-dominated complete source window supports spraying review; distinct failing sources support distributed-attempt review across session changes |
| Success following failures in unusual context | Corroborated sequence recommendation; trusted MFA records verification without erasing the peak or prior review evidence |

These are fresh adversarial software challenge cases. They are not a representative novel-customer benchmark and do not establish accuracy percentages. Test-only thresholds may isolate sequence logic; they are never exported as selected production thresholds.

Exercise the narrower `els-contextual-shadow-v2` rules with a busy shared office source serving many successful accounts plus one user's mistakes; successful sources that must not inflate distributed-failure evidence; and sustained account/distributed failures that must remain visible despite unrelated successful traffic. Test failed-account breadth and the exact 0.8 source-failure-ratio boundary. A spray diluted by sufficient successful traffic can fall below the source rule; record this limitation rather than claiming complete detection or an empirical false-positive reduction.

Check the [additional sequence signals](event_contract.md): account/source failure ratios, failed/successful account breadth, failing-source count, maximum per-source failures, median same-account gap, burst ratio and support count. Verify `(t−120,t]` boundaries, equal-timestamp gaps, MFA exclusion, `null` without denominators/support and explicit incomplete-window status. Observed ratios during warmup are not full-window lower bounds. Gap statistics do not change actions. No new numeric weights, model retraining or benchmark claims are introduced by these checks.

## Authentication and protocol controls

Verify the complete company controller → real local HTTP service → server credential check → risk engine → server MFA → fictional workspace flow, including incorrect code, no preceding login, cross-account evidence, session boundary, five-attempt exhaustion and missing artifacts. Each pending login returns `mfa_challenge_id`; the browser sends `challenge_id` with the code. An old challenge must not authorize a newer login. Browser claims of success or score must be rejected. Rejected requests must not rewrite an existing MFA challenge's immutable context.

Exercise HMAC body/path tampering, stale timestamps, replayed nonces/event IDs, wrong producer keys, browser Origins on trusted endpoints, cross-origin demo requests, foreign Host, duplicate JSON fields, nonfinite values, overlarge bodies and forbidden raw credential/target fields. Responses/logs must not echo inputs. A signed producer is not independent proof of correct upstream IdP validation.

Producer authority must allow `/api/events` only; separate reviewer authority must allow `/api/review` and `/api/metrics` only. Reject identical role keys and fail closed for unconfigured roles. `GET /api/status` must expose readiness/configuration only, without traffic aggregates. Verify `python3 -m src.runtime.adapter --metrics` uses the reviewer key and does not read stdin. The adapter must reject disallowed event/review fields before opening a socket, not merely rely on a receiving-server rejection. `--disable-demo` must reject anonymous demo mutations without disabling authenticated shadow ingestion.

Verify real-stream startup/119/120-second observation coverage and that future timestamps cannot bypass warmup. Reject any event ahead of the receiving clock, including one millisecond, without poisoning global ordering; HMAC freshness allowance must not relax event-time validation. A retained session UUID cannot be reused for another account. Verify strict `(t−120,t]` boundaries, MFA exclusion from login counts, context/account/session isolation, late-event rejection, reset idempotency, idle cleanup and async response cancellation. No-score and unavailable-threshold states must remain distinct.

## Capacity, concurrency and request framing

- Verify interactive wrong-password waits of 1/2/4/8/16/32/60/60 seconds using an injected monotonic clock. Reject just before each deadline; accept at the boundary. Correct passwords reset the streak while preserving MFA/review requirements. Early requests must not call the password checker, increment risk events or extend the delay. Check HTTP 429/Retry-After agreement, context/session rotation, reset/expiry, wall-clock changes and independent demo/trusted scopes. Synthetic event replay must not change interactive backoff. UI countdowns must disable submission, clear form values, recover after waiting, preserve prior risk evidence on a valid backoff response, and never resend credentials automatically.

- Enforce 32 demos, 500 events per demo, 1,000 retained demo events, 4,000 retained trusted events and a 5,000-event global cap. A full demo quota must leave the reserved trusted budget available; no overflow may silently discard current evidence.
- Test global channel and per-demo token buckets, bounded refill, and simulation batch costs. Resetting a demo must not reset process-level budgets; demo requests must not spend the trusted-ingestion bucket. Bound replay caches and retained state.
- Keep password-reference checking outside the shared ingestion lock. A deliberately delayed check must not block trusted ingestion; reset/expiry during the check must prevent a stale result from restoring deleted state or granting access.
- Enforce 16 HTTP workers, an eight-second absolute connection deadline, a 16 KiB total header budget and a separate 16 KiB body cap. Test trickled headers/bodies and excess connections; an idle timeout alone is insufficient.
- Reject duplicate security-sensitive headers, ambiguous transfer framing, bodies on GET/HEAD and non-origin request targets before dispatch. Errors must not expose request bodies, client addresses, credentials or traceback details.

These are bounded-prototype software checks, not production resilience certification or a load-tested deployment guarantee.

## Model and evaluation controls

Maintain the exact eleven-feature allowlist. Keep identity, timestamps, target/attack metadata, authentication outcomes and password flags outside the original model. Check baseline preservation, Python/JavaScript parity, policy checksum and exact model-file binding.

Preserve the baseline CSV and trained model. The default runtime's descriptive signals are separate from its original trained features and numeric calibration. New experiments must use isolated, versioned artifacts.

Fit calibration only on its validation-account partition; select thresholds only on the other partition. Recompute the partition independently of labels; enforce account/session separation and report episode/source overlap. Preserve infeasible/null thresholds instead of silently choosing 30/70. Report Brier, reliability bins, ECE, coverage and subgroup metrics with denominators and limitations. Existing test reuse is regression evaluation, not untouched validation.

Human-review labels alone drive pilot feedback metrics. MFA success is not an automatic benign label. Repeated/corrected reviews must not double-count; expired events cannot receive feedback. Reviewer-authenticated aggregate metrics must expose no event/account/session/source identifiers; public status must not expose those aggregates at all. Distribution changes are descriptive until a drift detector is separately validated. Overlapping sequence-context groups must not be summed as disjoint populations; distinguish sequence-only alerts from conservative threshold-fallback recommendations.

### Candidate tuning and release regression checks

- Independently verify protocol/source/data/model digests, baseline preservation, grouped chronological separation and frozen final-test consumption. Calibration and decision thresholds must not use final labels; report both scored-session metrics and total-session review workload.
- For the separate 21-input candidate, mutate identifier values, target/attack labels and the current outcome without changing the current vector. Check prefix causality, `(t−120,t]` boundaries, MFA exclusion and explicit gap support. Verify the shared offline/runtime extractor and displayed-score parity.
- Compare bounded JSON tree inference with sklearn, reject malformed/cyclic trees, invalid calibration and corrupted artifacts, and abstain on missing context. No executable model deserialization is allowed.
- Require model and full-runtime gates on both final cohorts. Check normal/VPN/travel/user-error subgroup denominators and all three required attack types independently. Success after failed attempts and suspicious success without preceding failures are distinct cases.
- Preserve the observed failure: the frozen v2 candidate detects zero scored suspicious-success sessions in both final cohorts. Aggregate gate success must not override this gap. The promotion command must reject it without writing a destination; normal startup must keep the baseline and explicit tuned startup must fail closed.
- Exercise the candidate against real local HTTP only by explicit test injection for compatibility. A passing integration test is not release qualification, real MFA verification or accuracy validation. No tests silently activate it for users or trusted ingestion.

The nonzero per-attack release guard was added after inspecting the consumed final tests; it is a stricter safety safeguard, not a predeclared statistical finding. Future studies need stronger predeclared per-attack targets and independently designed data. [Frozen findings](model_tuning.md).

## Privacy checklist

- No real credentials, raw IPs, customer files or account/password dumps in AI/repository/test fixtures.
- Demo-only credentials travel to loopback transiently; trusted ingress has no credential fields.
- No external lookup, credential retry, telemetry, access/body logs or browser persistence.
- Opaque source/account IDs are customer-generated; no persistent fingerprint or biometric collection.
- Five-minute bounded server state, CSV-specific retention and explicit cleanup semantics.
- Synthetic history, public-reference coverage, threshold infeasibility and fake MFA clearly labelled.
- No automatic account lockout or real shadow enforcement.

## Interface regression boundary

Preserve the classic 2010-style theme, existing IDs, labels, parameters and interactions when extending the interface. Keep current risk, retained peak, data quality/missing context, credential evidence, verification, review controls and historical analytics visible. The evidence workbench adds three panels below the existing company interface. Existing DOM tests cover behavior and preserved controls; do not mistake them for screenshot or layout tests.

Inspect 320, 768 and 1280 px widths for horizontal overflow, readable labels, wrapping identifiers, usable forms and visible keyboard focus. Check that only `aria-hidden` decoration is suppressed by the theme. Actual Chromium desktop/mobile flows and screenshots are now part of the datathon verification; screen-reader and broader cross-browser accessibility testing remain separate work.

## Evidence and privacy diagnostics

Verify the [workbench](evidence_workbench.md) with exact 30/60/120-second left boundaries, MFA exclusion, lost failure evidence and a spraying rule added when old successes leave the denominator. The shared live rules must match the 120-second replay before carried session floors; shorter rows must never rerun the two-minute ML model or change its score/action. Incomplete startup or evicted supporting history must prevent completeness claims. A baseline with no rules must not produce a shorter-history sufficiency claim.

Compare decisions only within one account and session, including interleaved accounts, session rotation and missing scores. No identifier or arbitrary raw input may enter the diagnostic response. Inspection must leave records, feedback labels, scores, deadlines and backoff unchanged. Refresh creates no event and exposes no public aggregate inventory; MFA expiry is still enforced. Check per-demo isolation and all clearing paths. Validate response sizes, fixed field/rule vocabularies, bounded counts and cross-field consistency before rendering. Expiry estimates must not claim physical erasure or a verified deletion receipt.

## Commands and remaining verification

The datathon extension adds receipt tamper/cross-scope/stale/reset tests, memory-hard verifier checks, bounded password capacity, per-request role enforcement, grant expiry, valid TLS/hostname checks, TLS 1.2 rejection and TLS adapter transport. Verify that the combined-context rule handles success without previous failures but remains disabled on trusted ingestion. Its high measured benign overlap must stay visible in the guide.

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s app/tests -p 'test_*.py' -v
pnpm --dir app test
pnpm --dir app exec playwright install --with-deps chromium
pnpm --dir app test:browser
python3 scripts/preflight.py
```

Use the project's configured Python environment for dependencies. Python discovery includes actual HTTP/TLS + DOM integration and focused runtime-hardening tests; regular JS tests isolate controller failures with stub responses. Playwright adds real Chromium desktop/mobile checks; screenshots are separately inspected. Provider-specific signatures/claims, actual MFA, deployment resilience, IBM Z execution and an untouched customer-local pilot remain to be tested after selecting the provider/environment. Passing the local suite does not certify production security or detection accuracy.

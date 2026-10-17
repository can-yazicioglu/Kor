# Security review — current integrated prototype

This review covers the local server-scored demo, authenticated shadow-event interface, contextual policy, calibration extension and isolated tuning studies. It is not production certification or demonstrated real-world effectiveness. The [initial branch audit](reviews/security_review_2026-10-17_initial.md) and historical CSV/model reports remain separate records.

## Implemented and verified boundaries

| Area | Current behaviour |
|---|---|
| Original model leakage | Exactly eleven model features; identity/target/outcome/password metadata excluded |
| Candidate leakage and release | Separate 21-input allowlist with prior-login features only; grouped/time-separated phases, frozen artifacts and bounded JSON inference; blocked candidate cannot be enabled through the release loader |
| Event trust | Provider-neutral adapter validates the exact schema before transport; HMAC producer authentication binds path, timestamp, nonce and body; browser outcome claims rejected |
| Role separation | Producer key cannot review/read metrics; distinct reviewer key cannot ingest events; equal keys reject startup |
| Credential/MFA decisions | Owned by the local fictional server verifier; public demo credentials only; random challenge ID binds MFA to the current successful login/session; stale challenges rejected |
| Failed-request context mutation | Fixed: rejected login/simulation cannot change an existing MFA challenge; challenge context is captured immutably and regression-tested |
| Password semantics | Failed weak-value submission does not reveal the account password; no fixed additive bonus in the current flow |
| Sequence evidence | Two-minute failure ratios, failed-account/source breadth, supported gap/burst statistics, streaks and corroborated context; successful shared-network traffic does not inflate failing-source/account counts |
| Missing evidence | Current score remains null; real streams have a 120-second startup observation requirement; no invented history or low-risk default |
| Threshold feasibility | Explicit unavailable thresholds, limited data quality and review recommendation; no silent 30/70 fallback |
| Calibration/artifact binding | Validation-account fitting/selection separation, integrity checks and exact policy-to-model-file binding |
| MFA evidence | Isolated by account/session; retains peak and unresolved sequence evidence; independent feedback labels required |
| HTTP boundaries | Loopback Host restriction, same-origin demo checks, browser-Origin rejection on trusted routes, duplicate security-header rejection, 16 KiB headers/strict JSON body, no credential echo/logs, bounded browser response streaming |
| Replay/expiry | Signature freshness, all future event times rejected, nonce/event duplicate rejection, account-bound session UUIDs, no late-event mutation, bounded retention and periodic idle cleanup |
| Capacity | 32 demo handles, 500 events/demo, separate 1,000 demo / 4,000 trusted budgets; 16 HTTP workers, eight-second absolute connection deadlines, bounded nonce cache and isolated admission buckets |
| Concurrency | Password checks outside the shared ingestion lock; reset/expiry cancels in-flight results; demo mutations can be disabled for shadow-only use |
| Interactive password throttling | Server-enforced exponential 1–60 second delay, monotonic deadline, HTTP 429/Retry-After before password checking; rejected early requests neither extend the delay nor manufacture risk events |
| Reset/async handling | Idempotent reset, stale UI results ignored, no automatic credential retries, server expiry authoritative |
| Pilot instrumentation | Reviewer-authenticated aggregate coverage/score/subgroup/feedback metrics; public status exposes readiness only; no automatic real enforcement |
| Evidence workbench | Identifier-free, token-scoped diagnostic response; fixed field/rule vocabularies and bounded values; same-account/session deltas; shared live volume rules; no extra retained history or change to scores/deadlines |
| Password verifier | Salted scrypt public fixture, four concurrent verification slots, no retained submitted-value hash |
| Resource authorization | Server-owned employee role, two-minute grant bounded by demo expiry, every request checked; restricted resource, extra role claims and stale grants denied |
| Decision receipt | One current HMAC-SHA-256 receipt and random per-demo key, domain separation, tamper/cross-scope/stale/reset checks; no persistent history |
| Optional TLS | TLS 1.3 only, certificate/hostname-verified adapter, actual-scheme Origin check, no silent HTTP fallback |
| Release comparison / CI | Deterministic SHA-256 runtime inventory, commit-pinned Actions, locked JS dependencies, actual Chromium desktop/mobile flows |

Checksums detect corruption, not authenticity. Shared HMAC authenticates a configured producer, not its upstream IdP implementation. Public dictionary hashes are not safe customer-password storage. The local demo remains synthetic and exposes no protected company resource.

The current hardening regression suite exercises stale MFA challenge replay, separate reviewer/producer permissions, adapter rejection before socket creation, reset races during password checking, reserved event budgets, invalid-authentication throttle isolation, ambiguous HTTP headers and slow request headers/bodies. The unchanged trained features and CSV baseline do not acquire extra identifiers or target leakage. New timing parameters are descriptive, with no invented numeric weight.

Design guidance reviewed: [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html), [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html), and [Python HTTP server deployment limitations](https://docs.python.org/3/library/http.server.html). Exponential throttling design was also checked against the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling). The controls tested here do not establish conformance or production certification.

Verification recorded on 2026-10-17: **200 Python discovery tests**, **16 static/HTTP server tests**, **111 JavaScript checks** and **8 actual Chromium desktop/mobile scenarios** passed. Python includes real HTTP/TLS, authorization, scrypt capacity, receipt tamper/expiry, causal feature extraction, model parity, split and release guards. Browser scenarios cover sign-in/MFA, resource denial, altered receipts, attacks, backoff, missing history, reset and keyboard navigation. Screenshots were inspected; document overflow was checked at 320/390/768/1280/1440 px. `git diff --check` passed. Original baseline/v2 CSV and password-reference hashes remain unchanged. The earlier isolated model experiments remain frozen; this extension did not retrain them. Dependency audits reported no known advisories for 20 installed Python packages and the locked JS dependency tree, with no skipped Python packages. These scans are database snapshots, not proof of absence of vulnerabilities. [Audit summary](../outputs/dependency_audit_summary.json).

Startup follow-up: an occupied port exposed a partially initialized cleanup worker, masking the bind error with `AttributeError`. Cleanup state is now initialized before binding, an unstarted worker is never joined, and later TLS/worker setup failure releases the bound socket. Three regression tests cover an occupied port, the CLI error without a traceback, and TLS startup socket cleanup. The server suite was checked on Python 3.13 and 3.14; the existing process on an occupied port is left running.

The workbench is explanatory instrumentation, not a novel-algorithm or accuracy claim. Shorter-window replay excludes context/MFA and carried session rules, and can gain a spraying alert when older successful traffic expires. Incomplete or evicted supporting histories are disclosed. Review fallback and unavailable score deltas remain explicit. Lifecycle counts are application-state observations, never physical-erasure attestations. Inspection tests verify that records, scores, labels and deadlines are not rewritten; reset/expiry and unverifiable responses clear the new UI evidence.

## Remaining findings, ordered by priority

**P1 — Tuned candidate misses a required attack scenario; release blocked.** Two studies evaluated 54 configurations on separate synthetic cohorts. V2 improved aggregate AP/Brier and passed its predeclared aggregate gates, but a subsequent attack-specific audit found **0/108 and 0/115** detections of scored suspicious-success sessions. This is distinct from success after preceding failures. A new, explicitly post-evaluation coverage guard rejects promotion, the release receipt is blocked, and the default remains the original model. Do not present aggregate gate success as MVP acceptance. A future study must predeclare per-attack targets and include independently designed, trustworthy context. [Full evidence](model_tuning.md).

**P1 — Decision targets remain infeasible.** The calibration/selection split cannot achieve the predefined MFA FPR ≤5% with recall ≥50%, or review FPR ≤1% with recall ≥25%. Both selected thresholds are null. The conservative runtime recommends review for every event; numeric scores remain available for complete contexts. This prevents an unsupported low-risk decision but is unsuitable for low-friction production use. Do not claim false alarms were solved.

**P1 — Combined-context safeguard has substantial benign overlap; demo-only.** A new rule handles successful password logins from a new device/unfamiliar network with unusual time or velocity without needing previous failures. Consumed-cohort regression matches 60/108 and 48/115 scored suspicious-success sessions, but also roughly 48–49% of benign VPN/new-device and 51–54% of benign travel/new-device sessions. It therefore remains a labelled demonstration experiment and is disabled on trusted ingestion. It does not qualify the blocked candidate or establish customer accuracy. [Measured tradeoff](datathon_demo.md#tested-experimental-rule-and-its-tradeoff).

**P1 — Real identity-provider and deployment verification are not connected.** The user chose a general interface because the provider is undecided. The generic helper only signs/transports events. A future customer-side adapter must authenticate provider signatures/issuer/audience, derive trustworthy outcomes/context, manage its keys and enforce tenant isolation. Optional TLS is implemented, but hardened production ingress, certificate operations and resource supervision are not validated. Trusted ingestion remains disabled without a configured secret and has no enforcement actions. IBM Z execution, Secure Execution attestation, HSM key custody and quantum-safe integration are not implemented claims.

The exponential password delay applies only within the fictional demo handle. Reset/new demos can start fresh; synthetic scenario replay is separate from interactive verification. A real deployment must enforce shared account throttling in its upstream verifier, independent of browser-controlled demo handles. The shadow ingestion interface cannot retroactively throttle a completed authentication. The 60-second cap is a prototype policy choice, not a validated usability/security optimum.

**P2 — Evaluation is synthetic and partly reused.** Baseline fit/validation/test accounts/sessions/sources/episodes remain disjoint, but the two internal validation partitions share 57 episodes and 57 sources. The existing test set was previously inspected, so new results are regression comparisons. Brier improved from 0.1156 to 0.0466 and ECE from 0.1785 to 0.0189; these do not establish real-world calibration. Fresh software challenge tests are not independent empirical customer accuracy validation. A new untouched, customer-local pilot is required.

**P2 — Generalization, coverage and reference limits remain.** Missing history abstains; the base regression still has 274 unscored sessions out of 811. The public password reference is limited, a near match is not confirmed breach exposure, and unknown/no-match are not safety guarantees. No full breach corpus, persistent fingerprinting or biometric tracking is introduced.

New tuning final cohorts were generated only after freezing the respective model and thresholds, with earlier cohorts audited for identity overlap. They are now consumed; all share the same generator. V2 scored about 67% of sessions. Its 0.20–0.35% false-positive rate applies only to scored normal sessions; including missing-context review produces roughly 33.4–33.6% normal-session escalation. These figures do not establish customer calibration or resolve missing-history costs. The prior baseline validation-overlap finding above still applies to the baseline, not the new phase design.

**P2 — Monitoring is a foundation, not a completed pilot.** Short-window, independently reviewed metrics and descriptive distribution changes are implemented. Reviews can be biased/incomplete; no automated retraining occurs. Statistical drift detection and durable aggregate pilot reporting need an explicit customer operating policy before deployment.

**P3 — Broader accessibility/platform review remains.** Chromium desktop/mobile flows, keyboard focus and selected responsive widths were checked visually. Screen-reader evaluation, other browsers and IBM Z operating environments remain unverified; these checks are not WCAG certification.

## Retention and demonstration

Company form values clear immediately and are processed only by the loopback verifier. Trusted events contain no credentials. No customer files/logs are persisted; cleanup is bounded and periodic, without a physical memory-wipe claim. [Retention](retention_policy.md) specifies limits.

The historical CSV page preserves the old +25/+10 experiment, which increased ≥30 session FPR from 30.91% to 43.78%. It is labelled historical and must not be confused with the current server policy. Neither old nor new results are proof of a real customer breach detector.

Follow [company_demo.md](company_demo.md) and [runtime_integration.md](runtime_integration.md). Present the scope, unresolved threshold target and provider integration explicitly. Do not describe the system as perfect, production-ready, a complete breach search or a deployed real-MFA service.

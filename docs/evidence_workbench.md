# Evidence and privacy workbench

The company demo includes three project-specific diagnostic views built from its existing short-lived event store. They make privacy and decision limitations inspectable. They are not a claim of research novelty, a new trained model, or an improvement in measured detection accuracy.

Run `python3 app/serve.py --port 8001`, open `http://127.0.0.1:8001/company.html`, and scroll to **Evidence & privacy workbench**. All text is English; the existing classic theme and sign-in controls remain.

## 1. History sensitivity

The same latest event is inspected using `(t−30,t]`, `(t−60,t]` and `(t−120,t]` histories. Counts include login successes/failures, never MFA checks. Only three existing volume rules are replayed:

| Rule | Unchanged condition |
|---|---|
| Repeated account failures | At least eight failures against the current account |
| Distributed failures | At least five failures against that account from at least three failing transient sources |
| Failure-dominant spraying | At least eight failed accounts on the current source, with a failure ratio of at least 0.8 in a complete window |

The live policy and diagnostic replay share one implementation of these conditions. The diagnostic rows identify rules lost or added relative to 120 seconds. Shorter windows can **add** a spraying rule when older successes leave its denominator. Counts remain lower bounds when startup observation or retained supporting history is incomplete; a refresh never retrospectively completes the latest event's observation window.

If the complete 120-second row has active rules, the panel reports the shortest **tested** window with exactly the same active rule set. It makes no sufficiency claim when the baseline has no rule or is incomplete. This describes one observation; it is not a recommendation to shorten retention. It excludes context/MFA rules and earlier session action floors, so it is not a reproduction of the entire live decision.

The trained model always retains its original two-minute feature meaning. There is no 30/60-second model prediction, threshold retuning, extra score bonus, exported dataset, or accuracy estimate. The synthetic stream's empty starting state is known; it is not an observed 30-day customer history.

**Demo:** reset, run Brute force, and inspect all three rows. The burst fits inside 30 seconds. Wait more than 60 seconds but less than 120, then submit the public correct password. The older burst remains in the 120-second row while shorter rows lose the repeated-failure rule. Refresh alone keeps the event-time anchor unchanged; a new login is needed to advance it. All time spent remains within the original five-minute demo lifetime.

## 2. Decision changes

The latest result is compared with the previous retained event for the **same account and session**. Interleaved accounts and rotated sessions never become that comparison baseline. The view shows current/previous scores and recommendations, changes in selected counts, missing-feature count, sequence floor, verification, credential evidence and event outcome. A missing score produces an unavailable delta, never a zero-based increase.

These are observed changes, not causal feature attribution. Other model inputs can change the score without changing one of the displayed fields. The current policy has no feasible action thresholds, so the panel explicitly explains the review fallback. A review recommendation alone does not establish an attack.

**Demo:** after Brute force, sign in as `demo / VelaDemo!42`, then complete the fictional MFA with `123456`. Compare the outcome and verification changes. Strong verification is separate from unresolved sequence evidence and does not erase the peak score.

## 3. Data lifetime

The server reports counts of retained event records, account/session/source map entries, human review labels, consecutive interactive failures, and whether an MFA challenge remains pending. Counts are scoped to the current demo handle. Map entries are not counts of unique physical people/devices or bytes; token copies can also appear within event records.

The inventory and diagnostic results are computed on demand. They do not create a second event history, persistent audit file, fingerprint, or password/hash store. The browser keeps only its current response in memory. `Refresh evidence` uses the existing token-scoped `POST /api/demo/status`; it creates no login event, retries no credentials, and extends neither the demo lifetime nor the MFA deadline. Public `GET /api/status` still exposes no activity inventory. The new diagnostics are not published on trusted ingestion or metrics endpoints.

Countdowns are estimates since the last server response. Reaching zero is described as expiry being due, not proof of deletion. Reset removes application references and starts an empty demo. Expiry, navigation and failed requests clear the displayed diagnostics. Python/browser garbage collection, OS memory, swap and upstream provider logs are not physically erased or attested by this panel. The existing [retention policy](retention_policy.md) remains authoritative.

## Verification

`tests/test_runtime_insights.py` covers exclusive window boundaries, lost and added rules, shared live-rule semantics, startup/aged-history gaps, same-account/session comparisons, missing scores, identifier-free read-only output, per-demo isolation, label/MFA lifecycle, non-extending refresh and reset/expiry.

`app/tests/insights.test.mjs` checks the bounded versioned response contract, unsupported fields/values, inconsistent deltas/windows, safe rendering, unknown states, countdown wording and clearing. The real local HTTP company test exercises delivery of the new asset, populated panels, token-scoped refresh, MFA changes, failure clearing and navigation cleanup. The full pre-existing model, privacy, protocol, backoff and UI suites remain regression checks. These are behavioral tests; visual browser layout and real-world detection performance are separate validation tasks.

> Historical initial audit, 17 October 2026. The observations, numbers and recommendations below describe the original branch snapshots, **not the current implementation**. See the [latest review](../security_review.md) for current results. This English translation does not reopen or reinterpret the initial findings.

# AI 4 — Security and independent validation report

**Project:** Kör
**Review date:** 17 October 2026
**Report branch:** `A4`, created from A1.
**Test plan:** [docs/test_plan.md](../test_plan.md)

## 1. Decision at the initial audit

**The integrated CSV → model → session-risk demo did not pass.** The A2 CSV was rejected by the A1 reader. The A3 notebook did not use the shared column names and contained no saved model/inference artifacts. A1's explicitly labelled mock screen could be presented without implying that a model was operating.

No raw customer records or external data transfer were found in the inspected files. The CSV had no matches for email, IP, private-key or common API-key patterns; the generator source created synthetic values. This was not an absolute anonymity/privacy guarantee for earlier commits outside the review, other environments or data provenance beyond the inspected files.

**No training, retraining, new data generation, model inference or dashboard changes were performed during this initial audit.** Notebook cells were not executed. Counts below are data/integration audit observations, not model-performance metrics. Only AI 4's two Markdown reports were created. A1/a2/a3 files were not changed and nothing was pushed to the remote repository.

## 2. Inspected deliveries and method

The following commits were inspected after `git fetch origin`. `A1` and `origin/A1` pointed to the same commit. `origin/main` contained only `LICENSE`, with no additional data/model delivery.

| Branch | Inspected commit | Delivery |
| --- | --- | --- |
| `A1` / `origin/A1` | `590802c718341cef62428a57dbb83561ff7a4d0e` | Architecture, demo, CSV reader, model adapter and tests |
| `origin/a2` | `ca44fccf96df108f8882d21b41e045b98df229dc` | CSV, synthetic generator and data documentation |
| `origin/a3` | `8fee079990f028cd0dcfe7d82350fa38b634f7cc` | Root-level `model_pipeline.ipynb` |

Source locations refer to these commits. Notebook cell numbers are the **one-based order of all cells**, including Markdown cells, not execution counts.

Checks were derived from the shared brief. Passing A1's own tests was not accepted as proof of integration: the actual delivered a2 file was passed directly to the A1 reader. The CSV was read locally only. Raw rows, account/session keys and matched-pattern values were not copied into the chat or report. The generator was inspected as source and was not executed.

The review covered tracked files at the branch tips. It did not verify the complete Git history, inaccessible customer environments, a real IdP, production cookies, a live network or physical memory erasure. No browser visual/end-to-end interaction test was performed. A2's external-data licensing claims were not researched again; this audit focused on data/model security.

## 3. Verified baseline counts

| Check | Result at the initial audit |
| --- | --- |
| CSV file | `data/mvp_synthetic_logins.csv`, 1,392,163 bytes |
| SHA-256 | `f95b83d0649a0adfad55ab7de9e75bf7f012f2594e3457c5a0795054a66b003d` |
| Header | Exact match to the shared 17 fields and their order |
| Events / labels | 10,000 events; 9,200 normal labels and 800 suspicious labels |
| Empty cells / records with extra cells | 0 / 0 |
| Unique events / sessions / accounts | 10,000 / 10,000 / 2,885 |
| Values outside synthetic key formats | 0 |
| CSV sensitive-pattern scan | 0 matches for email, IPv4, IPv6, private keys or common API keys |
| File scan across the three deliveries | 0 email/private-key/common-API-key matches across 18 + 5 + 2 tracked files |
| Basic negative-value, flag and failure-ratio checks | No domain violation in the inspected numeric/boolean fields |
| `attempts_2m > attempts_1h` | **30 rows**, all `suspicious_success` |
| A1 Python server checks | **7/7 passed** |
| A1 JavaScript contract checks | **17/17 passed** |
| Actual A2 file → A1 reader | **Rejected** with a row-2 `network_familiarity` error: “a non-negative number is expected” (English translation of the original message) |
| A3 notebook | 27 code cells; 0 saved execution counts and 0 saved outputs |
| A3 tracked model/metric artifact | None; only the notebook and licence were present |

The last two rows do not prove that the notebook had never been run elsewhere. They establish that **this commit did not deliver verifiable training/inference artifacts**.

## 4. Prioritized findings

No P0 issue was identified within this scope. P1 means an issue blocking the integrated demo or its basic reliability contract. P2 means a validation/privacy-coverage or robustness gap. Status distinguishes observed failures from future integration risks.

| ID | Priority | Finding | Initial status / owner |
| --- | --- | --- | --- |
| A4-01 | **P1** | A2 network-familiarity encoding was incompatible with the A1 reader | Reproduced · AI 1 + AI 2 |
| A4-02 | **P1** | A3 schema configuration was wrong; its baseline did not use the shared features | Confirmed by source/header inspection · AI 3 |
| A4-03 | **P2** | A3 excluded identifiers through a blacklist/uniqueness heuristic rather than an exact feature list | Code defect; no leakage in an actually trained model was observed · AI 3 |
| A4-04 | **P2** | Counter inconsistency and missing verification of actual rolling windows | 30 definite inconsistent records plus a documented synthetic-summary limitation · AI 2 |
| A4-05 | **P2** | Challenging normal contexts and missing history were insufficiently represented | Data coverage confirmed; false-alarm rate could not be measured · AI 2 + AI 3 |
| A4-06 | **P1** | A3's planned output could not satisfy A1's session/score/reason contract | Source contract mismatch; model outputs were also missing · AI 1 + AI 3 |
| A4-07 | **P2** | Notebook silently returned 50 when no threshold met the false-alarm constraint | Code path confirmed; not claimed to have occurred on the delivered data · AI 3 |
| A4-08 | **P2** | Deletion lifecycle was not implemented end to end; notebook persistence was not separately addressed | Design/implementation scope gap, not an observed raw-data leak · AI 1 + AI 3 |

### A4-01 — CSV encoding mismatch

**Evidence:** A2's generator at `src/data/generate_synthetic.py:136` produced `familiar/unfamiliar` strings for `network_familiarity`. The delivered CSV contained 7,434 `familiar` and 2,566 `unfamiliar` values. A1 `app/schema.js:14` treated the field as a ratio; `app/schema.js:87` rejected non-numeric values. The file was within the 2 MiB and 10,000-event limits, so size was not the reason for rejection.

**Impact:** Import stopped at the first data record, preventing the session view even with the delivered usable CSV. A1 unit tests had not covered this cross-branch mismatch.

**Recommendation:** Agree categorical versus numeric encoding in the shared data dictionary without changing column names/order. If retaining the A2 delivery, adapt the A1 reader and A3 categorical preprocessing contract. Do not silently map `familiar→1` without an explicit agreement. Acceptance requires the same fixed CSV's 10,000 records to pass the reader while scores remain pending when no model is available.

### A4-02 — Notebook configuration and baseline

**Evidence:** A3 cell 2, lines 23–27 used `TARGET='label'`, `TIME_COL='timestamp'` and `USER_COL='user_id'`. None existed in the CSV. Cell 4, lines 12–13 would therefore stop. The A3 branch alone did not contain a CSV either; its file guard would stop first if the file was absent. Combining the deliveries locally would not resolve the column-guard failure.

Four of the five baseline rules in cell 9 depended on absent fields: `failed_attempts_last_hour`, `is_new_device`, `is_new_country` and `ip_reputation_score`. Correcting only the three configuration names would leave a single active rule, `hour <= 5`, derived in cell 5. Because the score was normalized by the number of active rules, that one nighttime rule would produce **0 or 100**. This was a mathematical property of the code, not an executed model result.

**Impact:** Training could not begin as delivered. A superficial column rename would still not produce a baseline suited to the three attack scenarios: nighttime login alone could receive maximum risk, while two-minute intensity/spread would not contribute.

**Recommendation:** Map A3 configuration to `is_suspicious`, `event_ts_utc` and `account_token` without changing the shared schema. Baseline rules should use only existing features with agreed semantics. Missing required features must not be silently skipped. Check the N1–N3 counterexamples before evaluation. No correction or training was performed during this audit.

### A4-03 — Heuristic exclusion instead of an exact feature boundary

**Evidence:** A3 cell 2's `ID_COLS` did not explicitly name the three shared identifier fields. After `df.drop(...)`, cell 5 considered every remaining field and removed only text fields with uniqueness ratio `>0.5`. That decision was computed on all data before splitting. Cell 5 also added `hour/dayofweek`, which were absent from A1's 11-feature interface.

Event/session tokens were unique in the delivered CSV. With the three required configuration mappings corrected, `account_token` would be explicitly dropped and the uniqueness heuristic would also drop event/session tokens in this particular file. Therefore **the audit could not conclude that a model had been trained on identifiers**: no model existed and the original configuration did not run. Repeated sessions or identifiers interpreted as numeric by pandas might bypass the same protection. Excluding `is_suspicious` depended on correct `TARGET` configuration; `attack_type` was explicitly excluded.

**Impact:** A different valid CSV could place identifiers among training features. Test-set uniqueness could influence feature selection; fitting preprocessing on training data alone would not repair that earlier decision.

**Recommendation:** Use the same explicit feature list as A1 and verify that forbidden fields are absent from transformed model features. Test that changing identifiers/labels/metadata leaves features unchanged. Any additional timestamp-derived feature should be proposed as a separate interface change without altering the CSV schema; do not silently move to 13 features.

### A4-04 — Window and counter consistency

**Evidence:** A2 `src/data/generate_synthetic.py:275` independently sampled two-minute attempts from 1–3 and one-hour attempts from 1–8 for the same record. The delivered CSV had **30 records with `attempts_2m > attempts_1h`**; the first file line numbers were 1227, 1279, 1291, 1292 and 1382. Values/keys were not published here.

For the same account scope and end time, a two-minute window is a subset of a one-hour window, making those 30 records inconsistent. Brute-force counts were assigned before episode times (`:231–239`); spraying wrote the full episode account count to each record (`:249–258`). These were not rolling counters recalculated from prior events at each event time. A2 documentation also stated that the 24-hour ratio and geographic speed were sampled (`docs/synthetic_data.md:45`).

Because the CSV did not claim to contain every observed login, each mismatch between prior row counts and supplied counters was not labelled a separate defect or proven future-data leakage. **The definite finding was 30 subset inconsistencies; the remaining issue was lack of actual window verification.** Without source keys and login outcomes, spraying groups and failure ratios could not be independently reconstructed from that CSV.

**Recommendation:** Enforce `attempts_1h >= attempts_2m` within the same scope. Distinguish synthetic summaries from event-derived counters. If source/episode audit metadata is needed, keep it in a separate customer/synthetic-test manifest rather than adding fields to the fixed CSV or model inputs. Test the 120-second boundary, duplicate/late events and cookie renewal when the feature extractor is delivered.

### A4-05 — False alarms and challenging normal-context coverage

**Evidence:** All 9,200 negative examples had `hour_deviation` in 0–1 and `geo_velocity_kmh` in 0–250, with no missing features. The 1,495 `user_error` and 1,132 `vpn_new_device` examples were useful. However, VPN/new-device examples also occurred at usual hours, and only 379 records in that subgroup actually had `asn_category='vpn'`. There was no separate normal-travel scenario.

Brute-force examples had hour deviation 5–12 and 24-hour failure ratio 0.623–0.999; `suspicious_success` had hour deviation 5–12 and speed 500–5,994. These generator rules strongly separated classes. This was neither a model metric nor evidence of the prohibited target column being passed directly to the model. The concern was **an easier synthetic task and a narrow representation of real normal behaviour**.

**Impact:** Even a future high synthetic score would not establish false-alarm behaviour for VPN location jumps, travel, night shifts, new device plus new network or missing history. With no missing values, the data could not test A1's null policy or A3's imputation choice. A3 proposed median/most-frequent imputation; the shared contract needed to specify missingness representation and when scoring must abstain.

**Recommendation:** AI 2/AI 3 should plan separate challenging-normal evaluation groups; AI 4 did not generate data in this audit. Report subgroup support and false alarms for N1/N2/N3 when predictions are delivered. Do not claim absence of unnecessary travel alarms without N3 coverage. State that the CSV lacks a login-success result; `attack_type='suspicious_success'` is not independent proof of a successful login.

### A4-06 — Missing model output and session integration

**Evidence:** A1 `app/model-adapter.js:6` always returned `null`. Its validator required an **integer** `risk_score` in 0–100, `reasons` and `model_version`. `app/sessions.js` correlated results by the actual `session_token`.

A3 cell 7 multiplied probabilities by 100; cell 36 planned an output containing one-decimal model scores with `user_id`, `timestamp` and `label`. The planned CSV lacked `event_id/session_token`, event-level `reasons` and `model_version`. Explanation cells produced global coefficient/SHAP summaries rather than satisfying the session explanation contract. No tracked A3 output existed, so actual score range, correlation or accuracy could not be audited.

**Impact:** That export could not connect directly to A1. An account/time pair was not a reliable substitute for an event/session key. A1 would reject a directly supplied fractional score. Rederiving features in a new file or constructing reasons from the label would not solve the interface problem.

**Recommendation:** AI 1 + AI 3 should agree a customer-local inference contract. The model should accept only 11 features, with event/session correlation retained outside it. Define score conversion/rounding, threshold order, explanation method and model version together. Keep mock labels and “score pending” on CSV data until integration. A missing model does not establish a safe session.

### A4-07 — Infeasible threshold selection silently ignored

**Evidence:** A3 cell 14, lines 11–19 initialized `best_t=50` and considered only candidates 1–99. If no candidate met `FAR_TARGET`, it still returned 50 without identifying failed selection. Cell 9 also used `fillna(0)` to make missing baseline inputs inactive signals.

**Impact:** Reports could continue as if a threshold had been selected even when none satisfied the condition. The condition was not guaranteed on test data either; validation-selection failure also needed to remain visible. This path was not measured as having occurred on the delivered CSV.

**Recommendation:** Represent infeasibility explicitly as a result/error and remove the silent return to 50. Add contract tests for threshold endpoints, the no-alarm option and the case where every threshold fails. Missing signals must not be equated with normal behaviour. Actual false-alarm results require delivered AI 3 predictions.

### A4-08 — Deletion and notebook persistence

**Evidence:** A1 `app/main.js:159–165` released data references on reset; close/reload behaviour was documented. Neither automatic 120-second memory clearing nor a real cookie was implemented. `docs/architecture.md:51,60,146` described cookie TTL, source-context deletion and auxiliary one-hour/24-hour counters as **target design**, not an implemented production lifecycle.

A3 cell 4, line 10 used `display(df.head())` before validation, which would write records into notebook output. Cell 36 planned persistent `demo_risk_scores.csv` containing account identifier, timestamp and target label. These artifacts did not exist in that commit, so no present raw-sensitive-data leak was claimed. Reuse with customer records would require explicit retention, access and sharing boundaries for notebook/output folders.

**Impact:** It was not valid to claim “all data is deleted in two minutes” or “no records persist.” The two-minute analysis window, cookie lifetime and file retention are different concepts. Keeping A2's explicitly synthetic CSV in the repository was not by itself a customer-data deletion violation.

**Recommendation:** Document separate lifecycles for CSVs, notebook output, models, temporary source context and longer-window counters. Replace row previews with safe aggregate summaries and avoid identifier/label export unless necessary. Keep required identity correlation in a temporary customer-local layer. Test TTL expiry/deletion when the real feature service exists; a design description alone is not a passing result.

## 5. User, time and scenario leakage audit

**A1:** The explicit 11-feature list and `selectFeatures` excluded `event_id`, `session_token`, `account_token`, `is_suspicious`, `attack_type` and raw time from the model. Existing contract tests confirmed the boundary. Because A1 had no model, this was a feature-transfer-boundary check only.

**A3:** No actual training/test split or trained model had been delivered. To inspect the intended user-plus-time split in cell 6, a **read-only split diagnostic** was performed on the delivered CSV, assuming only that the three required field names were mapped correctly. The notebook was not changed; no training, inference or performance calculation was performed. The diagnostic used NumPy 2.3.5, seed 42, chronological sorting, 20% held-out users, a 0.70 time quantile and a 0.80 internal training/validation quantile.

| Provisional diagnostic | Result |
| --- | ---: |
| Fit / validation / test rows | 4,492 / 1,124 / 605 |
| Rows excluded for falling outside both conditions | 3,779 |
| Account intersection between training (fit + validation) and test | **0** |
| Account intersection between fit and validation | **727** |
| Gap between training end and test start | 1,410 seconds |
| Gap between fit end and validation start | 54 seconds |
| Identical complete 11-feature vectors shared by fit and test | 1 |
| Fit/validation overlap of brute-force clusters grouped by account and 120-second proximity | 0 |

This diagnostic was not the split of an actually trained model and required rechecking against the eventual version/order and execution outputs. The 727 shared accounts showed that fit/validation were not user-independent; **they did not establish training/test user leakage**. One identical feature vector can occur in low-detail synthetic normal records and alone is not evidence of a duplicated event or leakage.

The 1,410-second training/test gap in that snapshot was helpful for separating short attack episodes. However, the code imposed no explicit window gap or episode-grouping requirement. The CSV lacked source/episode identifiers, so spraying-episode independence could not be established fully; the fit/validation gap was only 54 seconds. Having the same `attack_type` classes in both sets is normal and alone is not scenario leakage. The relevant question is whether the same episode or easy generator template inflates a generalization claim.

Preprocessor pipelines were written to fit on the training portion, a positive design control. Feature selection based on identifier-like uniqueness over the entire dataset remained the separate A4-03 issue. A “fully leakage-free evaluation” conclusion required the actual split manifest and scenario predictions after model delivery.

## 6. Privacy and claim-check results

| Check | Initial decision | Reason |
| --- | --- | --- |
| Raw passwords / usernames / IPs / leaked lists | **No finding in inspected deliveries** | Fixed fields, synthetic generator code and pattern checks; no guarantee for provenance outside scope |
| Outbound data transfer from A1 | **Passed within the static implementation boundary** | Local File API reading, CSP `connect-src 'none'`, no external scripts/fonts/telemetry or upload endpoint |
| A1 access logs / cookies / persistent browser storage | **Passed within code/server-test scope** | Access logging disabled; no cookies or web storage used |
| Mouse/keyboard biometrics and persistent device fingerprints | **Absent from inspected code** | Search/form interactions were not recorded as behaviour |
| Identifier/label/model separation | **A1 passed; A3 needed hardening** | A1 allowlist; A3 blacklist/heuristic and non-working configuration |
| Assumption of real 30-day history | **Passed within documentation/source scope** | A2 history explicitly synthetic; A1 kept unknown values null |
| Actual 120-second counters and deletion | **Partly design; execution behaviour unverified** | No feature service/cookie; see A4-04 and A4-08 |
| False alarms for VPN/travel/new device/wrong password | **Unverified** | Limited data coverage and no delivered model/predictions |
| Automatic locking | **Absent from inspected application** | A1 displayed only MFA/review recommendations |
| Synthetic results presented as real success | **Not found in the inspected A1/A2 documents** | Explicit mock/synthetic notices. A3 had no metrics yet; future reports needed the same limitation. |

For A3, “actual CSV” meant **the synthetic file actually delivered by AI 2**, not a request for real customer records. No real records should be uploaded to an AI chat.

## 7. Demo test flow available at the initial audit

This section did not add application scenarios or generate data. The original mock screen had only four cards. It would have been incorrect to present all six independent scenarios as executed.

### Demo available in the original snapshot

1. Run `python3 app/serve.py` and open the local screen. Show the **MOCK** notice and explain that sample scores are not model results.
2. Show the brute-force mock score 86, spraying score 74 and new-context-success score 61 with their reasons. These illustrate S1/S2/S3 in the interface only; they are not attack-detection tests.
3. Explain that the usual-context score 18 is also mock. That card does not separately validate N1/N2/N3.
4. Select a session using risk filters/search. Confirm that actions are MFA/review recommendations, without automatic locking or real IdP actions.
5. Selecting the approved A2 synthetic CSV should reproduce the **A4-01 validation error** in that snapshot. The previous mock view should remain, and the error must not reveal a row value/token. Do not claim successful valid-data import until this negative integration finding is closed.
6. Show the data-contract and privacy views. Explain that the CSV is not uploaded and that “two minutes” is not an implemented deletion guarantee from a model/feature service.

### Acceptance tests proposed after data/model alignment

| Scenario | Initial data support | Proposed demo/validation condition |
| --- | --- | --- |
| N1 · wrong password | 1,495 `user_error`; no real success outcome | Inspect subgroup alarms after predictions arrive; do not automatically classify a short mistake sequence as an attack. |
| N2 · VPN | 379 VPN records within `vpn_new_device`, with VPNs also among other negatives | Evaluate the complete VPN subgroup separately and state the lack of normal high-location-jump cases in the initial data. |
| N3 · travel + new device + missing history | Complete scenario not represented | **Not verifiable at the initial audit.** Review when AI 2/AI 3 deliver an appropriate separate test. |
| S1 · brute force | 320 records in short same-account episodes | Independently verify actual 120-second counters and resilience to cookie renewal; large synthetic counts alone are insufficient. |
| S2 · password spraying | 240 records; no source identity | Do not claim end-to-end spraying detection without customer-local source correlation or a separate episode manifest. |
| S3 · suspicious successful login | 240 scenario labels; no independent login outcome | Verify success at the IdP; never use `attack_type` as a prediction input or explanation. |

After A4-01 is resolved, if no model is connected, every imported session must remain **score pending**. Changing labels must not change model features. Model errors/nulls or any unscorable event must not make its session appear low risk. Once a model is connected, its score must be 0–100, reasons must belong to the same scored event, and the action must remain MFA/review.

## 8. Reproduction and proposed closure sequence

The original A1 tests were run against the same source on the A4 branch:

```bash
python3 -m unittest discover -s app/tests -p 'test_*.py' -v
node app/tests/contracts.test.mjs
```

The Node.js command requires Node 20+; Node is not required to run the demo. JavaScript checks were executed on the same files using the available Node runtime tool. These commands do not train models or generate data.

Reproduce the historical CSV counts and subset inconsistency without printing row contents:

```bash
python3 - <<'PY'
import csv, hashlib, io, subprocess
ref = 'ca44fccf96df108f8882d21b41e045b98df229dc'
blob = subprocess.check_output(['git', 'show', ref + ':data/mvp_synthetic_logins.csv'])
rows = list(csv.DictReader(io.StringIO(blob.decode('utf-8-sig'))))
print('sha256:', hashlib.sha256(blob).hexdigest())
print('rows:', len(rows))
print('attempts_2m > attempts_1h:', sum(
    int(r['attempts_2m']) > int(r['attempts_1h']) for r in rows
))
PY
```

Expected historical result: the SHA-256 above, 10,000 rows and 30 inconsistent records. Dumping the entire CSV/notebook into a terminal or chat, or executing notebook training cells, was outside this audit.

**Proposed closure sequence at the initial audit:**

1. **AI 1 + AI 2:** Reconcile network-familiarity encoding and pass the A4-01 cross-branch test. Correct the 30 counter inconsistencies and document the data version.
2. **AI 3:** Fix schema names, use an explicit feature list and a suitable baseline, and retain missing-input/file guards. AI 4 does not train within this initial-audit task.
3. **AI 1 + AI 3:** Connect inference output, external identity correlation, reasons and version contracts. Publish no success/false-alarm rates before model delivery.
4. **AI 2 + AI 3:** Deliver challenging normal cases, the actual split manifest and scenario predictions. AI 4 then reevaluates N1–N3/S1–S3 and leakage checks.
5. **Integration owners:** Complete implementable retention/access policies for windows, cookies, temporary memory context and disk artifacts. Preserve model/synthetic-performance limitations in the demo and reports.

These changes were **recommendations in the initial report** and had not been applied to A1/a2/a3 code at that point. New commits or actual model outputs require an updated evidence scope, recorded separately in the current review.

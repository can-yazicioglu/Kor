# AI 3 — Modelling and synthetic evaluation

These results describe **only the held-out test split of the delivered synthetic generator**. They are not real customer performance, calibrated attack probabilities or proven real-world effectiveness. Generator templates appear in every split, so generalization beyond those templates has not been validated. This report evaluates the original 11-feature behaviour model; any additional password-risk policy is a separate application layer, not a trained input or part of these metrics.

## Reproduce

```bash
.venv/bin/python -m src.models.train
.venv/bin/python -m src.models.evaluate
.venv/bin/python -m unittest discover -s tests -p 'test_models.py' -v
```

Training stops before fitting if the delivered CSV or its checksum-matched synthetic manifest is missing. Evaluation uses the saved local model without retraining. `comparison_models.joblib` is a trusted artifact created by this project; do not load external pickle/joblib files. The browser uses only `models/demo_model.json`; customer CSV files are never uploaded. Python inference and the demo server check the model JSON checksum. This detects accidental corruption, not authenticity or a signature.

CSV SHA-256: `41383a34524cefb434a66608c74a6554bada4377968298c6d7b7a43e4168b625`.

## Feature and split boundaries

Inputs use an exact 11-feature allowlist. `event_id`, `event_ts_utc`, `session_token`, `account_token`, `is_suspicious`, `attack_type` and all manifest metadata are excluded. Identifiers are used only for split audits; the target is used only for supervised fitting and evaluation. Scaling is fitted only on `fit`; category vocabularies are fixed by the data contract. A row with any missing history or unsupported feature abstains. It is not assigned zero risk and no missing values are imputed. Exported medians are fit summaries only and are not used during inference.

| Split | Total rows | Scorable | Abstentions | Accounts | Episodes |
|---|---:|---:|---:|---:|---:|
| fit | 6000 | 4899 | 1101 | 342 | 1805 |
| validation | 2000 | 1625 | 375 | 115 | 584 |
| test | 2000 | 1631 | 369 | 116 | 598 |

Account, session, episode and synthetic source overlap is **zero** for every pair of splits. Chronology and a gap of at least 120 seconds are checked before fitting. The 30-day history is simulated only in the synthetic manifest; no real user history is assumed.

## Model comparison and thresholds

Rule baseline: at least 8 account attempts in 2 minutes and failure ratio at least 0.5 → 0.85; at least 8 distinct accounts in 2 minutes → 0.80; new device + unfamiliar network + at least 4 hours of deviation + location-change speed of at least 600 km/h → 0.75; otherwise → 0.05. The largest applicable score is used. A VPN or a new device alone does not trigger the rule baseline.

LR: C=1, balanced class weights, up to 2,000 iterations. RF: 160 trees, maximum depth 8, minimum leaf size 8, balanced class weights. Installed XGBoost: 150 trees, depth 3, learning rate 0.05; class weighting comes only from fit data. Seed 42; neither models nor hyperparameters are selected using holdout results.

Decision thresholds are selected on validation only, maximizing recall subject to each saved `max_fpr` / `min_recall` constraint and preferring lower FPR on ties. If no threshold is feasible, `feasible=false` and `threshold=null`; there is no silent 50-point fallback. Validation constraints are not guaranteed on the test split. PR-AUC here means `average_precision_score` (Average Precision), not trapezoidal area. Threshold metrics use only scorable rows in their denominators.

| Model | PR-AUC/AP | ROC-AUC | Precision | Recall | FPR | Threshold | TN / FP / FN / TP |
|---|---:|---:|---:|---:|---:|---:|---|
| rule_baseline | 0.4623 | 0.7073 | — | — | — | — | — |
| logistic_regression | 0.6265 | 0.9059 | 0.4457 | 0.5954 | 0.0647 | 0.7812 | 1403 / 97 / 53 / 78 |
| random_forest | 0.7290 | 0.9446 | 0.6040 | 0.6870 | 0.0393 | 0.6772 | 1441 / 59 / 41 / 90 |
| xgboost | 0.8089 | 0.9580 | 0.6012 | 0.7481 | 0.0433 | 0.7371 | 1435 / 65 / 33 / 98 |

Validation targets for this run: FPR ≤5.00%, recall ≥50.00%.

The rule baseline makes the same decisions under the existing 30/70 demo policies: precision **0.3571**, recall **0.4580**, FPR **0.0720**, TN / FP / FN / TP **1392 / 108 / 71 / 60**. These are predefined demo-policy metrics, not a selected validation threshold or a silent fallback after infeasibility. The comparison table retains missing threshold metrics because the validation constraints were infeasible.

## Demo model and explanations

**Logistic Regression** is selected for the demo because it runs locally in the browser using a small, inspectable JSON artifact. This deployment choice is not based on the best holdout metric. The 0–100 score is the class-weighted LR sigmoid output rounded with `floor(p*100+0.5)`; it must not be interpreted as the true probability of an attack. Explanations list the three largest positive feature contributions in log-odds units. They are neither SHAP values nor causal explanations.

Base behaviour-score policy: 0–29 monitor, 30–69 recommend MFA, 70–100 recommend MFA and review; there is no automatic account lock. This product policy is separate from the validation-selected benchmark threshold. Unscorable events require review rather than a low-risk assumption. On scorable test events, the FPR is 0.2607 at score ≥30 and 0.0967 at score ≥70.

Maximum held-out probability difference between portable Python inference and sklearn: `3.33e-16`. `outputs/parity_cases.json` checks JavaScript parity using feature-only selections from the actual delivered synthetic CSV and their expected results.

## Session-level demo audit

The metrics above are at **event** level. The demo session score is the maximum rounded event score. If any event is unscorable, the entire session abstains and requires review. For this independent evaluation only, the session target is the maximum event target. Abstaining sessions are excluded from the score-threshold denominator and are not counted as true negatives or missed attacks.

LR test sessions: 811 total, 537 scored, 274 abstained; 429 contain multiple events.

| Session policy | FPR | Recall | TN / FP / FN / TP |
|---|---:|---:|---|
| Score ≥30: MFA/review | 0.3091 | 0.9091 | 333 / 149 / 5 / 50 |
| Score ≥70: review | 0.1452 | 0.7273 | 412 / 70 / 15 / 40 |

## Challenging normal contexts and attack subgroups

The LR benchmark results below use the validation-selected threshold. Metrics without class support are shown as `—`. Abstentions are excluded from metrics and counted separately; they must not be counted as successful detections or true negatives. The ≥30/≥70 columns show event-level FPR under the base behaviour-score UI policy.

| Subgroup | Total | Scored | Abstentions | Benchmark FPR | Recall | ≥30 FPR | ≥70 FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| brute_force | 64 | 64 | 0 | — | 0.6406 | — | — |
| cold_start | 92 | 0 | 92 | — | — | — | — |
| night_shift | 147 | 127 | 20 | 0.0394 | — | 0.2598 | 0.0551 |
| normal | 791 | 706 | 85 | 0.0283 | — | 0.1827 | 0.0510 |
| password_spraying | 48 | 31 | 17 | — | 0.7097 | — | — |
| suspicious_success | 48 | 36 | 12 | — | 0.4167 | — | — |
| travel_new_device | 203 | 166 | 37 | 0.2289 | — | 0.5060 | 0.2892 |
| user_error | 368 | 331 | 37 | 0.0242 | — | 0.2266 | 0.0453 |
| vpn_new_device | 239 | 170 | 69 | 0.1529 | — | 0.4118 | 0.2294 |
| normal_with_vpn | 536 | 421 | 115 | 0.0736 | — | 0.2613 | 0.1211 |
| normal_new_device | 660 | 489 | 171 | 0.1820 | — | 0.4703 | 0.2495 |
| normal_unfamiliar_network | 651 | 558 | 93 | 0.1398 | — | 0.4283 | 0.1989 |

## Remaining limitations and artifacts

The CSV cannot independently establish a successful real IdP login; manifest `auth_success` is synthetic audit metadata only. Borderline attacks overlap with normal VPN and travel contexts. False alarms and missed examples remain. This prototype is not a production security control and has not been validated on real customer data. Probability calibration and drift monitoring are not implemented.

`outputs/evaluation.json` contains support, abstentions, subgroup metrics, confusion matrices and policy metrics for all compared models. `outputs/holdout_predictions.csv` contains only synthetic event correlation IDs, scores and status; it excludes accounts, sessions, timestamps, target labels and attack metadata. `models/comparison_models.joblib` supports local reevaluation. `models/demo_model.json` contains portable parameters without customer/event records. Synthetic development artifacts may remain in the repository; customer notebook/CSV/prediction exports are outside this workflow. Evaluation stops if the data or manifest checksum changes.

![Synthetic precision-recall comparison](../outputs/precision_recall.png)

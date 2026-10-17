# Password-risk policy evaluation

> Historical experiment: the current server demo separates credential weakness and uses no fixed +25/+10 bonus. This report preserves the earlier CSV policy for reproducibility. See [reliability results](reliability_results.md) and [architecture](architecture.md).

The password flags are a **separate heuristic policy**, not learned features or calibrated attack probabilities. The original 11-feature Logistic Regression model, coefficients and audited test split are unchanged. No retraining, threshold selection, new password lookup or data generation occurred during this evaluation. This is a comparison on synthetic data, not evidence of improved real-world detection.

```bash
.venv/bin/python -m src.models.evaluate_password_policy
```

The evaluator verifies the v2 CSV/manifest, baseline and reference checksums, exact preservation of the original 17 columns, unchanged event split metadata and agreement between saved LR predictions and portable inference. It evaluates only the existing test split. No submitted password or event-password hash is read or exported.

Model version: `els-lr-41383a34524c-s42`. V2 CSV SHA-256: `fc42e375321d8b957f732a250b11081f48199744c24777b182a59c65c381ad05`.

## Policy and support

An exact common-password reference match adds 25 points; a close variant adds 10; neither adds zero. Exact and near are mutually exclusive. The integer result is capped at 100. Missing base risk or unknown/contradictory password flags produce abstention rather than zero. Session risk is the maximum event score only if every event is scorable. A no-match result does not prove password safety. Reference membership does not prove account compromise.

Test flag support: exact 421, near 558, neither 1021, unknown/invalid 0.

The delivered fixture contains checked flags; unknown handling is tested separately. Synthetic password profiles were assigned independently of target/scenario, so normal logins can receive bonus points and suspicious logins can have no reference match.

## Existing holdout comparison

Precision, recall and FPR below exclude abstentions. Confusion matrices are TN / FP / FN / TP. Targets are event labels or, for sessions, the maximum event label used only for evaluation.

| Unit | Policy | Scored / total | Abstained | Threshold | Precision | Recall | FPR | TN / FP / FN / TP |
|---|---|---:|---:|---:|---:|---:|---:|---|
| event | Behaviour only | 1631 / 2000 | 369 | ≥30 | 0.2318 | 0.9008 | 0.2607 | 1109 / 391 / 13 / 118 |
| event | Behaviour only | 1631 / 2000 | 369 | ≥70 | 0.3777 | 0.6718 | 0.0967 | 1355 / 145 / 43 / 88 |
| event | Behaviour + password policy | 1631 / 2000 | 369 | ≥30 | 0.1781 | 0.9313 | 0.3753 | 937 / 563 / 9 / 122 |
| event | Behaviour + password policy | 1631 / 2000 | 369 | ≥70 | 0.3553 | 0.7405 | 0.1173 | 1324 / 176 / 34 / 97 |
| session | Behaviour only | 537 / 811 | 274 | ≥30 | 0.2513 | 0.9091 | 0.3091 | 333 / 149 / 5 / 50 |
| session | Behaviour only | 537 / 811 | 274 | ≥70 | 0.3636 | 0.7273 | 0.1452 | 412 / 70 / 15 / 40 |
| session | Behaviour + password policy | 537 / 811 | 274 | ≥30 | 0.1916 | 0.9091 | 0.4378 | 271 / 211 / 5 / 50 |
| session | Behaviour + password policy | 537 / 811 | 274 | ≥70 | 0.3413 | 0.7818 | 0.1722 | 399 / 83 / 12 / 43 |

Of 1631 events scorable under both policies, 797 increased, 834 were unchanged and 0 decreased. The adjusted score reached 100 for 78 events. Mean increase: 7.7768 points.

## False alarms and limitations

Adding only non-negative points can raise both recall and false alarms at the same fixed thresholds. That trade-off must not be reported as an unconditional improvement. The model already produces unnecessary alarms for some normal travel/new-device contexts; the overlay does not solve that limitation. No policy points or thresholds were tuned against these holdout results. MFA and review are recommendations, with no automatic locking.

| Normal subgroup | Scored / total | Base ≥30 FPR | Adjusted ≥30 FPR | Base ≥70 FPR | Adjusted ≥70 FPR |
|---|---:|---:|---:|---:|---:|
| night_shift | 127 / 147 | 0.2598 | 0.3701 | 0.0551 | 0.0551 |
| normal | 706 / 791 | 0.1827 | 0.2748 | 0.0510 | 0.0652 |
| travel_new_device | 166 / 203 | 0.5060 | 0.6024 | 0.2892 | 0.3072 |
| user_error | 331 / 368 | 0.2266 | 0.3807 | 0.0453 | 0.0785 |
| vpn_new_device | 170 / 239 | 0.4118 | 0.5647 | 0.2294 | 0.2706 |

Full support, abstention and subgroup metrics are in `outputs/password_policy_evaluation.json`. The original model comparison remains in `docs/model_results.md` and `outputs/evaluation.json`; neither is replaced by this policy evaluation.

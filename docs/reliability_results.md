# Reliability calibration and decision-policy evaluation

This change fits a separate sigmoid calibrator and selects session thresholds using **validation data only**. The original model, its 11 inputs, baseline dataset and password-risk policy were not modified. The existing test labels/results had already been inspected in earlier work: results here are a regression comparison, not an untouched pilot, a novel-scenario validation or proven real-world performance. A future untouched, authorized pilot remains necessary.

```bash
.venv/bin/python -m src.models.calibrate_reliability
```

## Calibration and selection protocol

Validation account tokens are deterministically hashed into two equal-sized account partitions (rounded down/up). Labels and predictions do not influence that partition. Calibration fitting and threshold selection share no accounts or sessions. Episode/source overlap within validation is disclosed below; the original fit/validation/test boundaries remain disjoint. Both subsets remain within the original validation time interval.

| Partition | Rows | Scorable events | Scorable positives | Accounts |
|---|---:|---:|---:|---:|
| calibration_fit | 1032 | 854 | 70 | 57 |
| threshold_selection | 968 | 771 | 67 | 58 |

Within-validation overlaps: accounts 0, sessions 0, episodes 57, sources 57. This is account-disjoint validation, not fully episode-independent validation. A stricter connected-component split left no positive examples in the threshold partition because one connected component contains most accounts. New independent validation cohorts are required to remove this limitation.

The calibrator is unweighted Logistic Regression on the original probability's logit (C=1, no class balancing). Probabilities are clipped to [1e-12, 1−1e-12] before conversion. The fitted mapping is `sigmoid(0.77954996 × logit(p) + (-2.05854084))`. The integer score remains `floor(100*p + 0.5)`. Calibration describes these synthetic distributions; it does not make the score a proven real-world attack probability.

Before inspecting this regression comparison, the selection constraints were fixed as MFA FPR ≤5% and recall ≥50%; review FPR ≤1% and recall ≥25%. Integer thresholds 0–100 are selected only on complete threshold-selection sessions, maximizing recall, then preferring lower FPR. Review must be at least the selected MFA threshold. If no candidate satisfies a constraint, its threshold is explicitly null. No 30/70 fallback is used.

| Action | Selected score threshold | Feasible | Selection FPR | Selection recall |
|---|---:|---|---:|---:|
| mfa | unavailable | False | — | — |
| review | unavailable | False | — | — |

Missing calibration or behaviour context produces no score. If MFA selection is unavailable, scores below any available review threshold require manual review; a valid calibrated numeric score is retained and threshold availability is reported separately. If both thresholds are unavailable every decision requires review. `review_unscored` is reserved for missing model/policy/context rather than missing decision thresholds. If only review selection is unavailable, the feasible MFA threshold can still recommend MFA. These actions never lock an account automatically.

## Event-level probability reliability

Brier score is the mean squared probability error (lower is better). ECE uses 10 predeclared equal-width probability bins; it depends on binning and finite support. Both exclude unscorable events. The JSON report records counts, mean probability and observed positive rate for every bin. The calibration-fit row is an in-sample diagnostic, not a generalization result.

| Data | Scorable | Brier before | Brier after | ECE before | ECE after |
|---|---:|---:|---:|---:|---:|
| Calibration fit (in-sample) | 854 | 0.1039 | 0.0494 | 0.1536 | 0.0190 |
| Threshold selection | 771 | 0.1211 | 0.0612 | 0.1531 | 0.0346 |
| Previously inspected test | 1631 | 0.1156 | 0.0466 | 0.1785 | 0.0189 |

## Existing test regression comparison

Before uses the original uncalibrated 30/70 behaviour policy. After uses the validation-fitted calibrator and its validation-selected thresholds. This comparison changes both calibration and decision policy; it must not attribute all decision changes to calibration alone. The password bonus is excluded here and remains a separately evaluated heuristic. Sessions use the maximum event probability/rounded score and abstain if any event is unscorable. A maximum of event probabilities is a risk aggregate, not a calibrated probability that at least one event is malicious. Threshold metrics exclude abstentions.

| Unit | Policy | Action | Threshold | Scored / total | Abstained | Precision | Recall | FPR | TN / FP / FN / TP |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| event | before | mfa | 30 | 1631 / 2000 | 369 | 0.2318 | 0.9008 | 0.2607 | 1109 / 391 / 13 / 118 |
| event | before | review | 70 | 1631 / 2000 | 369 | 0.3777 | 0.6718 | 0.0967 | 1355 / 145 / 43 / 88 |
| event | after | mfa | unavailable | 1631 / 2000 | 369 | — | — | — | — |
| event | after | review | unavailable | 1631 / 2000 | 369 | — | — | — | — |
| session | before | mfa | 30 | 537 / 811 | 274 | 0.2513 | 0.9091 | 0.3091 | 333 / 149 / 5 / 50 |
| session | before | review | 70 | 537 / 811 | 274 | 0.3636 | 0.7273 | 0.1452 | 412 / 70 / 15 / 40 |
| session | after | mfa | unavailable | 537 / 811 | 274 | — | — | — | — |
| session | after | review | unavailable | 537 / 811 | 274 | — | — | — | — |

After-policy session action counts: monitor=0, mfa=0, review=537, review_unscored=274.

## Limits and runtime binding

A lower false-alarm rate can come with lower recall. Small subgroup and session counts limit precision of estimates. The positive sigmoid mapping preserves the original probability ranking; it cannot create new separation between attacks and normal contexts. Calibration and threshold feasibility on validation do not guarantee the same FPR/recall on this test split, new scenarios or customer traffic. This work does not establish independence from the generator's scenario templates. Novel-scenario challenge tests and an untouched pilot are separate requirements, not satisfied by reusing these test labels.

`models/reliability_policy.json` contains only the calibration parameters, selected thresholds, aggregate selection evidence and model/data bindings. Runtime helpers use the standard library, verify the integrity checksum and reject missing/mismatched policy files. The checksum detects accidental corruption, not authenticity. The baseline model version is unchanged and the policy has its own version. The artifact also contains numeric/categorical reference histograms computed only from the original validation rows. They support distribution monitoring but do not define a validated drift-alert threshold. `outputs/reliability_evaluation.json` preserves full reliability bins, subgroup metrics, support and abstention counts.

# Model tuning experiment

**Release blocked after the attack-specific audit.** The aggregate result below is preserved as originally measured; it does not authorize activation. The required suspicious-success scenario had zero detections among 108 and 115 scored sessions. See [the release decision](../../docs/model_tuning.md) and [attack breakdown](reports/attack_breakdown.json). The default remains the original model, and the explicit tuned-demo option refuses this candidate.

**Synthetic-only evaluation.** All new cohorts use the existing authored generator; independence of random draws does not establish generalization to customer traffic.

Frozen winner: `tuned_sequence`. Holdout labels were not used to choose it.
Original aggregate-only qualification: **True**. Final release eligibility: **False**.

| Final cohort | Model | Scored sessions / total | Session AP | Event Brier | MFA FPR / recall | Review FPR / recall |
|---|---|---:|---:|---:|---:|---:|
| holdout_a | current_deployed | 4358 / 6482 | 0.7091 | 0.0459 | 1.0000 / 1.0000 | 1.0000 / 1.0000 |
| holdout_a | tuned_base | 4358 / 6482 | 0.8877 | 0.0312 | 0.0033 / 0.6532 | 0.0023 / 0.6532 |
| holdout_a | tuned_sequence | 4358 / 6482 | 0.9061 | 0.0275 | 0.0020 / 0.6554 | 0.0008 / 0.6554 |
| holdout_b | current_deployed | 4385 / 6549 | 0.6839 | 0.0462 | 1.0000 / 1.0000 | 1.0000 / 1.0000 |
| holdout_b | tuned_base | 4385 / 6549 | 0.8506 | 0.0320 | 0.0043 / 0.6270 | 0.0013 / 0.6270 |
| holdout_b | tuned_sequence | 4385 / 6549 | 0.8667 | 0.0296 | 0.0035 / 0.6636 | 0.0003 / 0.6636 |

FPR/recall above include the actual contextual runtime policy on fully scored sessions. Unknown sessions still require review; total-session workload, subgroup denominators, model-only metrics and Wilson intervals are reported in `reports/final_evaluation.json`.

## Promotion checks

- All predeclared synthetic gates passed. Production approval is not implied.

The two final cohorts are now consumed. Repeating these seeds is reproduction, not a new blind evaluation. Do not use their results to select a runner-up or retune thresholds.

Models, source hashes, phase assignments and targets were fixed in `protocol.json` and `frozen.json` before final cohort generation. The original CSV, baseline model, calibration policy and historical viewer were preserved.

The new sequence variant uses ten causal prior-login features. It never reads the current outcome, target, scenario or identifier as an ML input. Shared feature extraction is exercised in offline preparation and the real runtime, with exact displayed-score parity required.

These checks do not cover real identity-provider behavior, unrepresented attack types, production latency, missing-history resolution or independently collected customer outcomes. Wilson intervals are descriptive under a binomial-session assumption; common generator bias and residual correlations remain.

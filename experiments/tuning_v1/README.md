# Model tuning experiment

**Synthetic-only evaluation.** All new cohorts use the existing authored generator; independence of random draws does not establish generalization to customer traffic.

Frozen winner: `tuned_sequence`. Holdout labels were not used to choose it.
Demo promotion eligible: **False**.

| Final cohort | Model | Scored sessions / total | Session AP | Event Brier | MFA FPR / recall | Review FPR / recall |
|---|---|---:|---:|---:|---:|---:|
| holdout_a | current_deployed | 3277 / 4864 | 0.7259 | 0.0470 | 1.0000 / 1.0000 | 1.0000 / 1.0000 |
| holdout_a | tuned_base | 3277 / 4864 | 0.7784 | 0.0419 | 0.0550 / 0.7018 | 0.0051 / 0.5602 |
| holdout_a | tuned_sequence | 3277 / 4864 | 0.8571 | 0.0347 | 0.0611 / 0.8012 | 0.0068 / 0.6988 |
| holdout_b | current_deployed | 3288 / 4876 | 0.7254 | 0.0459 | 1.0000 / 1.0000 | 1.0000 / 1.0000 |
| holdout_b | tuned_base | 3288 / 4876 | 0.7577 | 0.0411 | 0.0651 / 0.6914 | 0.0058 / 0.5519 |
| holdout_b | tuned_sequence | 3288 / 4876 | 0.8429 | 0.0343 | 0.0593 / 0.7685 | 0.0071 / 0.6706 |

FPR/recall above include the actual contextual runtime policy on fully scored sessions. Unknown sessions still require review; total-session workload, subgroup denominators, model-only metrics and Wilson intervals are reported in `reports/final_evaluation.json`.

## Promotion checks

- holdout_a: model_decisions/mfa missed uncertainty-aware targets
- holdout_a: model_decisions/review missed uncertainty-aware targets
- holdout_a: runtime_scored_decisions/mfa missed uncertainty-aware targets
- holdout_a: runtime_scored_decisions/review missed uncertainty-aware targets
- holdout_a: user_error/mfa false-positive limit exceeded
- holdout_a: travel_new_device/mfa false-positive limit exceeded
- holdout_a: travel_new_device/review false-positive limit exceeded
- holdout_b: model_decisions/mfa missed uncertainty-aware targets
- holdout_b: model_decisions/review missed uncertainty-aware targets
- holdout_b: runtime_scored_decisions/mfa missed uncertainty-aware targets
- holdout_b: runtime_scored_decisions/review missed uncertainty-aware targets
- holdout_b: user_error/mfa false-positive limit exceeded
- holdout_b: user_error/review false-positive limit exceeded
- holdout_b: travel_new_device/mfa false-positive limit exceeded
- holdout_b: travel_new_device/review false-positive limit exceeded

The two final cohorts are now consumed. Repeating these seeds is reproduction, not a new blind evaluation. Do not use their results to select a runner-up or retune thresholds.

Models, source hashes, phase assignments and targets were fixed in `protocol.json` and `frozen.json` before final cohort generation. The original CSV, baseline model, calibration policy and historical viewer were preserved.

The new sequence variant uses ten causal prior-login features. It never reads the current outcome, target, scenario or identifier as an ML input. Shared feature extraction is exercised in offline preparation and the real runtime, with exact displayed-score parity required.

These checks do not cover real identity-provider behavior, unrepresented attack types, production latency, missing-history resolution or independently collected customer outcomes. Wilson intervals are descriptive under a binomial-session assumption; common generator bias and residual correlations remain.

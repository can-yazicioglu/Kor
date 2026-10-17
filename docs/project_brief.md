# Kör — project brief

## Problem and purpose

Identify suspicious login sessions while minimizing retained identity data. Show a 0–100 risk score with reasons and recommend additional verification or human review. Never automatically lock an account. All user-facing software and project documentation are English.

## Current prototype scope

- Brute force, password spraying, distributed attempts and suspicious success after failures.
- English Vela company demo in a classic 2010-style theme, with server-owned public demo credentials/MFA and fictional workspace.
- Customer-local general event ingestion, authenticated producer requests, bounded sequence/source analysis and shadow recommendations.
- Original 11-feature model, validation-fitted score calibration, explicit unavailable thresholds, separate current/peak scores and data quality.
- Bounded local common-password reference; credential evidence is contextual and separate from behaviour risk.
- Independent human-review feedback, aggregate monitoring and fresh adversarial test scenarios.
- Historical CSV analysis preserving the original 17-column schema and separately versioned 19-column experiment.
- Completed, isolated model-tuning experiments, including a 21-input nonlinear candidate. The candidate is blocked because its final attack-specific audit missed every scored suspicious-success session; it is not the active demo or trusted model. See [the tuning report](model_tuning.md).

The identity provider is not selected. The generic event interface and transport are implemented; real provider verification and customer pilot data are not connected. Current calibration improved probability error on an already inspected synthetic regression set, but desired low-false-alarm thresholds remain infeasible. Every current runtime decision therefore recommends review, and missing evidence remains unscored. This is not production readiness or proven effectiveness.

## Privacy and evidence

No real credentials, raw IPs, customer records or leaked account files are uploaded to AI. No persistent fingerprint or mouse/keyboard biometrics are collected. The demo accepts invented credentials transiently on the loopback verifier; the trusted event API accepts no credentials. Customer events and inference stay in the customer environment.

Opaque identifiers support correlation only; the model receives only its eleven contextual features. Current stream counters use `(t−120 seconds, t]`. No actual 30-day customer history is assumed. The demo warm-up and dataset history are explicitly synthetic; unknown real history stays unknown.

## Outside the delivered scope

A production IdP, real passkey ceremony/TOTP enrollment, real MFA enforcement, external alerts, exhaustive breach-corpus search, cross-customer event aggregation, persistent biometrics, production hosting and a real customer pilot. The prepared trusted adapter must receive verified provider events; it does not make upstream authentication trustworthy by itself.

See [architecture.md](architecture.md), [runtime_integration.md](runtime_integration.md) and [reliability_results.md](reliability_results.md).

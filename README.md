# Ephemeral Login Sentinel

A customer-local prototype that explains session risk on a **0–100 scale**, recommends MFA or human review, and never automatically locks an account. The application and documentation are in English.

The current Vela demonstration uses a **local server verifier**, calibrated behaviour scores, rolling attempt/source analysis, separate credential-weakness evidence and explicit data quality. A general authenticated event interface supports a future identity-provider adapter in **shadow mode**. No real identity provider or customer pilot is connected.

Prepared for the **IBM Z Datathon security/privacy theme**: [four-minute demo and judging brief](docs/datathon_demo.md), [threat model](docs/threat_model.md), and [cryptographic inventory](docs/crypto_inventory.md). The classic ink/ivory/brass security desk demonstrates CIA controls, HMAC receipt tampering, server-side resource authorization and expiring state. IBM Z hardware execution and quantum-safe integration are planned, not claimed.

## Run the current demo

Python 3.10+ is sufficient; runtime uses the standard library and included artifacts. No API key, package installation or internet access is needed.

```bash
python3 scripts/preflight.py
python3 app/serve.py --port 8001
```

Restart an older server first. Open **http://127.0.0.1:8001/company.html**. Both pages use a simple 2010-style navy/gray interface with compact forms and bordered panels; existing parameters, controls and displays are preserved.

- Public demo account: **demo / VelaDemo!42**.
- Public demo MFA code: **123456**. The local server checks it; it is not real MFA security.
- Use **Brute force**, then sign in correctly and complete MFA. Review remains recommended.
- Use **Distributed attempts** or **Password spraying** to compare source/account counters.
- Try VPN, travel, a new device or **Missing history**. Missing context remains unscored.
- Try a common password or variation: weakness is shown separately, with **no automatic +25/+10 bonus** in the current flow.
- Incorrect interactive passwords trigger a server-enforced **1 → 2 → 4 → 8 → 16 → 32 → 60 second** wait, capped at 60 seconds. The form shows a countdown; it never resubmits credentials automatically. A verified password resets this delay, while risk/MFA decisions still apply.
- Review the latest synthetic event as normal/suspicious to exercise feedback. Labels do not train the model or change access.
- Open **Evidence & privacy workbench** below the sign-in panels: compare 30/60/120-second rule evidence, see changes within one account session, and inspect the expiring in-memory inventory. **Refresh evidence** creates no event and does not extend retention. [Walkthrough and limitations](docs/evidence_workbench.md).
- In **Security lab**, test an altered HMAC decision receipt. The original verifies; the changed score is rejected without changing live evidence.
- After demo MFA, open the **Employee resource**, then **Try restricted console**. The server checks each request; the public employee fixture never receives an administrator role. Grants expire within two minutes and reset removes them.
- **Load suspicious-success example** prepares a new-device/new-network/unusual-context login without failures. Its separate rule is explicitly demo-only: consumed synthetic cohorts show high benign overlap, so it is disabled on trusted ingestion. [Measured tradeoff](docs/datathon_demo.md#tested-experimental-rule-and-its-tradeoff).

Credentials entered here travel only to this loopback server and are used transiently. Use invented demo values only. Forms clear immediately; no credentials or event-password hashes are retained or logged. The fictional workspace contains no protected company resources.

The fixed public credential is checked against a salted **scrypt** verifier, with at most four concurrent checks. HMAC receipt keys are randomly generated per demo and removed on reset/expiry. Default transport is unencrypted loopback HTTP; optional **TLS 1.3** and a certificate-verifying adapter are available. [TLS setup and crypto boundaries](docs/crypto_inventory.md#local-tls-demonstration).

The password delay belongs to the current demo and clears on demo reset/expiry. Synthetic scenario buttons replay events and neither clear nor increase the interactive-password delay. The two-minute analysis window and five-minute retention remain fixed. Trusted ingestion is still advisory; a real login provider must enforce its own shared account throttling before verification.

## What the score and actions mean

The original 11-feature logistic model supplies the behaviour estimate. A separate sigmoid mapping was fitted on one validation-account partition; decision thresholds were searched on another. Trusted ingestion remains unscored during its first 120 seconds of observation; its counters are explicitly lower bounds. The current score and retained session peak are separate. Neither is a proven real-world attack probability.

**The predefined decision targets were not met.** Neither MFA FPR ≤5% / recall ≥50% nor review FPR ≤1% / recall ≥25% had a feasible threshold. Both thresholds are explicitly unavailable. Complete events still receive a calibrated score, with limited decision support and a conservative **review recommendation**; there is no hidden 30/70 fallback. Consequently, the demo currently recommends review even for normal complete-context logins and demonstrates MFA before opening the fictional workspace. This is an unresolved usability/performance limitation, not an improvement in false alarms.

Independent sequence rules identify repeated failures, failures across transient sources, spraying, success after failures in unusual contexts, and repeated MFA failures. They can raise the recommended action; they do not manufacture calibrated probability points. MFA/passkey verification is separate evidence and never erases the recorded peak or unresolved sequence evidence.

Additional two-minute signals distinguish failed accounts/sources from successful traffic, measure account/source failure ratios, and report attempt gaps and burst density with sample support. Spraying requires at least eight failed accounts and a source failure ratio of at least 0.8 in a complete window; distributed failures require at least three failing sources and five failures. Ordinary successful users sharing a network do not inflate those failure counts. These changes pass targeted behavior tests, but do not establish improved real-world accuracy. Timing signals remain descriptive until validated. The CSV and trained model feature set are unchanged.

The synthetic regression comparison improved event probability error: Brier **0.1156 → 0.0466**, ECE **0.1785 → 0.0189**. These are previously inspected test results, not an untouched real-world evaluation. [Full results and limitations](docs/reliability_results.md).

## General identity-provider integration

The provider is not selected yet. The prepared adapter boundary accepts only verified, opaque events from a customer-side producer. It does not accept browser claims of successful authentication or ingest raw credentials.

- `POST /api/events`: authenticated outcome/context ingestion, recommendations only.
- `POST /api/review`: independent human-review labels, authenticated with a separate reviewer key.
- `POST /api/metrics`: aggregate coverage, score distribution, subgroup alerts and feedback metrics; reviewer key required.
- `GET /api/status`: readiness/configuration flags only; no activity or review aggregates.
- HMAC signatures bind the path, timestamp, nonce and body; replay, stale requests, unexpected fields and invalid context are rejected.
- Ingestion is disabled until a customer-held `SENTINEL_INGEST_SECRET` is configured. Review/metrics need a different `SENTINEL_REVIEW_SECRET`. No secret is included in this repository.

Use `--disable-demo` when running only trusted shadow ingestion. The server bounds concurrent connections, request duration and body/header sizes, separates demo/trusted event capacity, and rate-limits operations without storing IPs. MFA challenges are bound to the current sign-in. Adapter schema validation occurs before any request is sent.

See the [integration guide](docs/runtime_integration.md) and [event contract](docs/event_contract.md). The loopback development server is not a production deployment or an identity provider. A selected provider still needs an adapter that validates its events and derives context inside the customer environment.

## Historical CSV analysis

**http://127.0.0.1:8001/** preserves the original browser-only CSV experiments for reproducibility and is visibly labelled historical.

- `data/mvp_synthetic_logins.csv`: original 17 columns and 10,000 synthetic events.
- `data/mvp_synthetic_logins_v2.csv`: original fields plus exact/near password-reference flags; the old +25/+10 experiment remains visible only in this historical viewer.
- CSVs stay in browser memory. Neither CSV contains verified live IdP outcomes, so neither can reproduce the new trusted event stream or establish the actual account password.

The public reference contains 12,526 entries from two pinned password-only dictionaries. It is bounded common-password coverage, not an exhaustive breach search. An unsuccessful weak-password submission does not establish that the account's real password is weak. [Source provenance and license](docs/password_sources.md).

## Development and verification

Two completed tuning studies are documented in [model tuning and release decision](docs/model_tuning.md). The second candidate improves ranking and passes aggregate synthetic targets, but detects **0/108 and 0/115 scored suspicious-success sessions** in its final attack audit. It is blocked from activation. The default demo and trusted-ingestion model remain unchanged; `--tuned-demo` rejects the blocked release. Candidate artifacts, fixed protocols and reproducible evidence are retained under `experiments/`. These experiments do not establish real-world performance.

The recorded development environment uses Python 3.13 and Node.js 24.

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-optional.txt
npm install --global pnpm@12.14.0
pnpm --dir app install --frozen-lockfile
python -m unittest discover -s tests -v
python -m unittest discover -s app/tests -p 'test_*.py' -v
pnpm --dir app test
pnpm --dir app exec playwright install --with-deps chromium
pnpm --dir app test:browser
python scripts/preflight.py
```

Python discovery includes the company controller against a real ephemeral HTTP server, authenticated ingestion, replay/tamper checks, expiry, MFA, TLS 1.3, authorization and calibration integrity. LinkeDOM checks behaviour and wire contracts. Playwright separately exercises actual Chromium desktop/mobile sign-in, attack replay, receipt tampering, resource denial, reset, keyboard navigation and overflow. Screenshots were visually reviewed. CI uses pinned action commits and runs the same suites plus release-file verification.

The release manifest is a SHA-256 comparison, not a signature. After reviewing intentional runtime changes, maintainers rebuild it with `python scripts/preflight.py --write-manifest`; normal users should verify the committed manifest. Rebuilding a checksum does not qualify the blocked candidate.

Reproduce evaluations without retraining the baseline:

```bash
python -m src.models.evaluate_password_policy
python -m src.models.calibrate_reliability
```

To rebuild the baseline, use `python src/data/generate_synthetic.py --rows 10000 --seed 42 --attack-rate 0.08`, then `python -m src.models.train` and `python -m src.models.evaluate`. Rebuild dependent artifacts after changing a model/dataset. `python -m src.data.extend_password_flags` re-fetches the two pinned public dictionaries in memory to create checked synthetic examples; this reproduction step needs internet access.

## Further documentation

- [Architecture](docs/architecture.md) and [project scope](docs/project_brief.md)
- [Company demo walkthrough](docs/company_demo.md)
- [Evidence and privacy workbench](docs/evidence_workbench.md)
- [Model tuning experiments and blocked release](docs/model_tuning.md)
- [Security review](docs/security_review.md), [test plan](docs/test_plan.md) and [retention](docs/retention_policy.md)
- [Original model results](docs/model_results.md), [old password-policy results](docs/password_policy_results.md) and [synthetic data](docs/synthetic_data.md)
- [Datathon demo](docs/datathon_demo.md), [CIA threat model](docs/threat_model.md), [cryptographic inventory](docs/crypto_inventory.md) and [security policy](SECURITY.md)

No real credentials, raw IPs, customer files, persistent fingerprints or mouse/keyboard biometrics belong in this repository or an AI conversation. Customer processing remains local. License: [LICENSE](LICENSE); third-party reference attribution is retained under `third_party/passwords/`.

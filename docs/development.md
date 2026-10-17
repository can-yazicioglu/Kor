# Development and reproduction

The included demo runs with Python 3.10+ and the standard library. The recorded full development/CI environment uses **Python 3.13 and Node.js 24**. Run commands from the repository root.

## Install test and training dependencies

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-optional.txt
npm install --global pnpm@12.14.0
pnpm --dir app install --frozen-lockfile
pnpm --dir app exec playwright install --with-deps chromium
```

On Windows, activate with `.venv\Scripts\activate` in Command Prompt. Training dependencies are not needed for normal demo inference.

## Verify the application

```bash
python -m unittest discover -s tests -v
python -m unittest discover -s app/tests -p 'test_*.py' -v
pnpm --dir app test
pnpm --dir app test:browser
python scripts/preflight.py
```

Python coverage includes real ephemeral HTTP requests, signed ingestion, replay/tamper checks, retention, MFA, authorization, TLS 1.3 and model artifact integrity. JavaScript checks cover rendering and response contracts. Playwright exercises Chromium desktop/mobile sign-in, attack replay, receipt tampering, resource denial, reset, keyboard navigation and viewport overflow. Browser tests start isolated local servers on ports 18331 and 18332.

The [GitHub Actions workflow](../.github/workflows/tests.yml) runs these suites with pinned action commits. Current recorded totals and residual risks are in the [security review](security_review.md). Passing tests are not a production security certification.

## Release-file verification

`python scripts/preflight.py` compares 55 runtime files to the committed SHA-256 manifest, checks artifact readiness and ensures the blocked candidate is not activated. A checksum is not an authenticity signature.

After reviewing intentional runtime changes, maintainers may rebuild the manifest:

```bash
python scripts/preflight.py --write-manifest
```

Do not regenerate it just to hide unexpected changes. A new checksum never qualifies an otherwise blocked model. Documentation, screenshots and recording scripts are outside this runtime manifest.

## Models and historical experiments

The default model remains the original 11-feature logistic model. Its score calibration and unavailable action thresholds are explained in [reliability results](reliability_results.md). To reproduce known evaluations without retraining the baseline:

```bash
python -m src.models.evaluate_password_policy
python -m src.models.calibrate_reliability
```

These commands can rewrite evaluation artifacts; run them in a separate checkout when comparing a frozen release. The historical browser CSV page preserves an old additive password-score experiment, separate from the current login flow.

Two completed tuning studies preserve protocols, datasets, source snapshots and model artifacts in `experiments/`. The second candidate improved synthetic ranking but missed all scored suspicious-success sessions in both final cohorts. Its release is blocked and `--tuned-demo` rejects it. Follow [model tuning](model_tuning.md) for reproduction into a **new output directory**; reusing inspected seeds is reproduction, not new validation.

To intentionally regenerate the original baseline in a separate checkout:

```bash
python src/data/generate_synthetic.py --rows 10000 --seed 42 --attack-rate 0.08
python -m src.models.train
python -m src.models.evaluate
python -m src.data.extend_password_flags
```

The final command fetches two pinned public password-only dictionaries in memory. It requires internet; ordinary demo use does not. Rebuilding data/model files also requires reviewing dependent artifacts and the manifest. Do not overwrite frozen experiment evidence or silently change the shared CSV schema.

## Capture repository visuals

See [media provenance and recording commands](media/README.md). Captures use the real local UI with public synthetic fixtures. No customer browser profile, credentials or data should appear in screenshots, recordings, issues or AI conversations.

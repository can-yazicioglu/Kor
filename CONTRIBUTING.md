# Contributing to Kör

Start with the [project brief](docs/project_brief.md), [architecture](docs/architecture.md) and [development guide](docs/development.md). This is a synthetic research prototype with explicit unresolved model limitations.

## Keep the project boundaries intact

- Use invented fixtures only. Do not submit real usernames, passwords, IPs, customer exports, authentication tokens or leaked account records.
- Preserve the shared 17-column CSV contract. Propose schema changes separately and keep identifiers, target labels and attack metadata out of model inputs.
- Preserve the two-minute analysis window and documented expiry semantics. Do not add persistent tracking, browser telemetry or hidden retention.
- Keep authentication, authorization, risk score and policy recommendations separate. Do not add automatic account locking.
- Report coverage and attack-specific failures beside aggregate model metrics. Synthetic performance is not real-world validation.
- Do not activate a blocked candidate, overwrite frozen evaluations or regenerate checksums to conceal unexplained changes.

## Submit a change

1. Create a branch with one coherent improvement.
2. Explain the concrete problem and resulting behavior. Update affected docs and run relevant checks from the [development guide](docs/development.md).
3. For UI changes, inspect desktop/mobile behavior with public fixtures. For security or model changes, include the failure cases and remaining limitations.
4. Open a pull request describing the change, verification and any retention/schema impact. CI runs the full suite.

Documentation and presentation improvements do not require model retraining. Runtime changes that intentionally alter manifest-covered files require reviewed manifest regeneration.

For a security issue, follow [SECURITY.md](SECURITY.md); do not publish credentials or exploitation details in a public issue. Source is MIT licensed; retain third-party attribution when reusing reference material.

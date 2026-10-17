# Security policy

Kör is a local research prototype. Use invented demo credentials only. Customer identity-provider integration, production operations and IBM Z hardware execution have not been validated.

Report vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting if available, or request a private reporting channel without posting exploit details or sensitive records in a public issue. Never include customer passwords, raw IPs, account lists, signing keys or real authentication logs. A minimal synthetic reproduction is sufficient.

The public `demo` account, demonstration password and `123456` code are deliberately published fixtures. They do not protect real resources. Producer and reviewer secrets, TLS private keys and ephemeral receipt keys must never be committed. Ignore rules cover common local secret/key files; they are not a complete secret scanner.

The active model has unavailable action thresholds and recommends review. The newer tuned candidate remains blocked by its release checks. Do not remove those checks to obtain a more attractive demonstration. The combined-context rule is a demo experiment with substantial benign overlap and is disabled on trusted ingestion.

See [threat model](docs/threat_model.md), [security review](docs/security_review.md), [retention](docs/retention_policy.md) and [cryptographic inventory](docs/crypto_inventory.md). No certification, quantum-safety or production-readiness claim is made.

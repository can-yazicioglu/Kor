# Datathon threat model

## Assets and trust boundaries

The assets are the risk model/policy, short-lived derived events, public-demo authorization state, customer producer/reviewer keys and the trustworthiness of displayed decisions. The browser is untrusted. The local server and its OS are trusted for this prototype. A customer adapter must validate IdP evidence before signing the exact allowlisted event contract. One process represents one tenant.

No raw customer identity or password crosses the event interface. The only credential form is the fictional loopback demo. This intentionally separates a demonstrated login flow from real customer authentication.

| Threat | Implemented boundary | Evidence / remaining risk |
|---|---|---|
| Forged success or administrator claim | Server verifier, sign-in-bound challenge, exact request fields, fixed employee role | Direct resource requests before verification, extra role fields, cross-handle requests and restricted resources are tested |
| Modified decision or signed event | HMAC-SHA-256 with domain separation; path/body/timestamp/nonce binding for ingestion | Tamper and replay tests. A compromised server/key can forge messages; a MAC is not public-key nonrepudiation |
| Model replacement or accidental corruption | Exact artifact/model binding, bounded JSON inference, release checksums, blocked-candidate gate | Checksums require a trusted reference. They cannot authenticate a malicious replacement of code and manifest together |
| Data disclosure | Bounded derived RAM records, allowlisted responses, no access/body logs, optional verified TLS 1.3 | HTTP default is loopback only and unencrypted. OS/process buffers are not securely wiped |
| Excessive work | Request/event budgets, deadlines, worker caps, four scrypt slots, exponential delay | Public demo reset can start a new password streak. Upstream real-account throttling remains the IdP's job |
| Replay / stale authorization | Nonces, event IDs, MFA challenge binding, two-minute resource grant, five-minute demo scope | A stolen bearer handle can use its still-valid scope. Browser XSS/OS compromise remain relevant |
| Broken object-level authorization | Workspace grant checked on every resource request; employee can never request audit-console content | Only fictional resources exist. No claim of a complete enterprise RBAC system |
| ML leakage / unsupported confidence | Exact feature allowlist, prior-only sequence features, separated synthetic phases, missing-context abstention | Same-generator bias, consumed final tests and missing history limit inference |
| False positives / evasion | Explain score, context and verification separately; human review; no automatic lockout | Current baseline reviews all; tuned candidate misses a required scenario; the demo context rule has high benign overlap |
| Supply-chain changes | Dependency lockfile, commit-pinned CI actions, deterministic release inventory | No hardware-rooted signing or independently trusted build attestation |

## CIA and access control

Confidentiality minimizes what is collected and retained; optional TLS protects configured transport. Integrity authenticates signed messages and current demo receipts. Availability limits work and memory, but does not establish high availability or DDoS resistance. Authentication and authorization are additional controls: verification is not equivalent to permission, and every resource access is checked independently.

## Abuse cases to demonstrate

1. Submit an incorrect public-fixture password repeatedly; wait times double and early retries do not create events.
2. Send a modified signed event, reuse a nonce, or attempt to review with the producer key; the trusted API rejects it.
3. Alter the current receipt's score; HMAC verification fails without modifying live evidence.
4. Request the workspace before MFA, or the audit console after MFA; the service denies the unauthorized request.
5. Reset or expire the demo; old handles, resource grants and receipt verification scope are unavailable.
6. Remove required context; risk remains unknown and access is not granted by a fabricated low score.

These are software-control tests, not evidence that all attacks can be detected. There is no real customer data, production IdP, IBM Z attestation or post-quantum implementation in this demonstration.

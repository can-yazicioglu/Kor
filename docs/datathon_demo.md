# IBM Z Datathon demonstration

## Pitch

Kör helps notice suspicious sign-ins while minimizing identity exposure. It computes a local AI risk score, shows what evidence is missing, and recommends verification or review instead of automatically locking users out. Short-lived state, authenticated ingestion and explicit model-release gates make security and responsible data use part of the architecture.

The differentiator is the combined evidence workflow: current score versus retained peak, prior-only attempt signals, a 30/60/120-second rule comparison, expiring state inventory, an authenticated decision receipt and a model rejection visible to the presenter. These are implemented engineering choices, not a claim that each algorithm is novel.

Reviewed Chromium views: [desktop portal](screenshots/desktop.png), [security lab](screenshots/security-desk.png), [mobile verification](screenshots/mobile.png). Screenshots contain public synthetic fixtures only.

## Start and present

```bash
python3 scripts/preflight.py
python3 app/serve.py --port 8001
```

Open `http://127.0.0.1:8001/company.html`. `/datathon.html` contains the English presentation guide. No account, API key, remote inference or installation is needed for the standard-library runtime. Use only `demo / VelaDemo!42` and demo MFA `123456`.

| Time | Action | What to say and inspect |
|---|---|---|
| 0:00–0:40 | Fill public credentials, sign in, complete demo MFA | The server verifies; the browser cannot grant access. Normal logins currently retain a review recommendation because selected ML thresholds are unavailable |
| 0:40–1:25 | Reset; replay brute force. Reset; replay spraying | One-account failures versus failed-account breadth. A synthetic replay is not an actual attack against an external service |
| 1:25–2:00 | Reset; load suspicious-success example; sign in | Successful password verification is not proof of benign context. The clearly labelled demo-only context rule can ask for verification with no prior failures |
| 2:00–2:40 | Test altered receipt in Security lab | HMAC verifies the current original and rejects an altered score. No event, deadline, key or score is changed by inspection |
| 2:40–3:15 | Complete MFA; employee resource; restricted console | Employee resource permitted; administrator resource denied by the server. Login and permission are distinct |
| 3:15–4:00 | Inspect evidence; reset | Two-minute reasoning window, five-minute demo retention, removal of grants/receipt key/state. Physical memory wiping is not claimed |

Use the standard flow first; optional TLS instructions are in [crypto inventory](crypto_inventory.md). A self-signed certificate needs local trust setup. Do not spend presentation time bypassing certificate warnings.

## Tested experimental rule and its tradeoff

The rule requires successful password verification plus a new device, unfamiliar network and unusual hour or travel velocity. It changes the recommendation floor, never the numeric model score. A VPN, ordinary travel or new device **alone** is insufficient. These simple checks do not imply that combined benign changes are safe from alerts.

Regression on the already-consumed v2 synthetic cohorts found:

| Scored-session group | Cohort A rule matches | Cohort B rule matches |
|---|---:|---:|
| Suspicious success | 60 / 108 (55.56%) | 48 / 115 (41.74%) |
| Benign VPN/new device | 663 / 1,353 (49.00%) | 632 / 1,326 (47.66%) |
| Benign travel/new device | 191 / 378 (50.53%) | 209 / 388 (53.87%) |

The high benign overlap is material. **The rule is enabled only in the fictional demonstration; trusted ingestion keeps the original policy.** It is not a validated fix for the blocked ML candidate. These are descriptive rule-match rates, not new independent accuracy estimates or full-policy FPR. The baseline review fallback still applies. [Machine-readable regression](../outputs/context_guard_regression.json).

## Theme alignment and honest IBM Z boundary

- **Secure AI/ML:** allowlisted inputs, grouped synthetic evaluation, separate calibration/selection, frozen artifacts and a rejected release when a required scenario is missed.
- **Privacy-aware threat detection:** customer-local processing, opaque transient identifiers, no raw credentials/IP logs or permanent fingerprinting, bounded RAM.
- **Identity/access management:** authenticated outcome producer, separate reviewer key, expiring demo grant, per-request authorization and sign-in-bound demonstration MFA.
- **Security by design:** CIA controls, HMAC message integrity, scrypt verification, optional TLS, bounded work and a documented threat model.

IBM describes Secure Execution for Linux, cryptographic hardware and protected execution capabilities in [IBM Z Security](https://www.ibm.com/products/z/security). The intended architecture places inference and state beside customer identity infrastructure on Linux on IBM Z, then integrates platform-managed cryptography and verifies the deployment. **This repository has not been run or attested on IBM Z; no Crypto Express, Telum or quantum-safe integration is claimed.** [Migration inventory](crypto_inventory.md).

The team's private Hack2skill dashboard was not accessible through the public browsing tool. This work uses the challenge brief supplied by the user. Submission eligibility, mandatory IBM runtime/dataset requirements and judging deadlines must be checked in the team's dashboard; no application was submitted by this code change.

## What remains unresolved

The model is synthetic-only. The baseline's action thresholds remain unavailable. The newer candidate missed all 223 scored suspicious-success sessions and remains blocked. Missing context produces significant review workload, and the new combined-context rule also has high benign overlap. A customer-local independently labelled pilot, verified IdP context, platform deployment and per-attack acceptance targets are required before making real effectiveness claims. [Training evidence](model_tuning.md).

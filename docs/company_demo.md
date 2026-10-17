# Vela company demonstration

Run `python3 app/serve.py --port 8001` and open http://127.0.0.1:8001/company.html. Restart an older server to load the current endpoints. The English interface represents a fictional company and uses a compact, classic 2010-style administration theme. Existing controls, parameters and displays remain, including current risk, session peak, data quality, credential evidence and review. The added **Evidence & privacy workbench** appears below the sign-in panels.

## Presentation sequence

1. **Baseline:** fill `demo / VelaDemo!42` and submit. The server verifies the public credentials, computes the current calibrated score and shows the session peak and data quality. Current action thresholds are infeasible, so a complete normal login also recommends review and demonstrates MFA. Use `123456` to enter the fictional workspace. Never claim this is a low-false-alarm deployment.
2. **Brute force:** reset, run the 20-attempt simulation, then sign in correctly. Show repeated failures and the recommended review. An incorrect MFA code must not grant access; the public correct code opens only the fake workspace. Review and peak evidence remain.
3. **Distributed attempts:** reset and run 12 attempts targeting one account through distinct short-lived source tokens. Compare sources/account counters with brute force.
4. **Password spraying:** reset and run 18 failures against distinct accounts from one source. Compare accounts/source counters.
5. **Credential evidence:** reset, try the common-password or variation button, then submit. The wrong demo password fails authentication. The local reference result is visible, but it is not evidence of the account's actual password and adds no fixed numeric points.
6. **Benign and missing contexts:** reset between VPN, travel, new-device and missing-history examples. Context alone does not trigger the sequence rules. The current model-threshold fallback can still recommend review. Missing history produces an unknown current score; it never becomes zero.
7. **Human feedback:** label the latest synthetic event normal/suspicious. This updates retained demo review metrics only; it does not train a model or change access. Trusted-stream aggregates require the separately authenticated reviewer workflow described below. `GET /api/status` returns readiness and configuration flags only.
8. **Reset/expiry:** reset clears the server demo and creates a new handle. State expires after five minutes. The MFA challenge expires at the earlier of two minutes after issue or the current two-minute session boundary; at most five failed code attempts are accepted. A new sign-in is needed after challenge expiry. Each pending sign-in returns `mfa_challenge_id`; the browser sends it as `challenge_id` with the code. Reusing a challenge from an earlier login must not open the workspace.
9. **Exponential password delay:** manually enter an invented incorrect password, wait for the displayed countdown, and repeat. The waits are 1, 2, 4, 8, 16, 32, 60 seconds and remain capped at 60. The server rejects early requests with HTTP 429 and `Retry-After`; early requests are not verified, do not add login events and do not extend the waiting period. After waiting, a correct password resets the delay but still follows the normal MFA/review decision. No credentials are retried automatically.
10. **Evidence workbench:** compare the three history rows after a burst, then after a new sign-in more than 60 seconds later. Inspect which rules lose evidence, how the same session's decision changed, and the current data inventory. Refresh does not add an event or prolong retention. See the [workbench guide](evidence_workbench.md) for the distinction between rule replay and the live two-minute model.

The delay measures consecutive incorrect **interactive password checks** in the current demo, independently of the two-minute risk window. Waiting alone does not reset that streak. Changing context or rotating the short session token does not reset it. Reset/expiry removes the entire demo, including its delay. The scenario buttons are synthetic event replay; they do not perform password verification or affect the interactive delay. Different demo handles remain isolated, so this is not a deployed cross-browser account-throttling system.

All scenario buttons execute bounded synthetic batches inside the local server. They do not attack a remote service or send a wordlist anywhere. Source/account tokens, context and the nineteen prior observations assumed by the demo's historical failure ratio are invented; they are not measured customer history. The fresh synthetic stream can score immediately. A newly started trusted stream has a separate, mandatory 120-second observation period before scoring.

The current sequence rules distinguish a busy shared source from many failed accounts on a failure-dominated source, and distinguish sources that actually failed from sources that only succeeded. Failure ratios, failed-account/source breadth and supported timing-gap statistics are derived locally; gap statistics are descriptive only. These are narrower rules without numeric score weights, retraining or a measured accuracy improvement. They are not a complete attack detector. See the [event contract](event_contract.md) for exact conditions and edge cases.

The browser clears fields on submission, sends the invented credentials only to the local verifier and renders server-authorized results. Failed requests show unknown risk and no workspace access. A lost/aborted response may have been processed by the server; there is no automatic credential retry. Server expiry remains authoritative even if a tab closes before reset completes.

## Separate trusted review and operational limits

The ingestion producer and independent reviewer use distinct HMAC keys. With the reviewer key configured locally as `SENTINEL_REVIEW_SECRET`, read trusted aggregate metrics with:

```bash
python3 -m src.runtime.adapter --metrics --port 8001
```

This command signs `POST /api/metrics` and does not read standard input. The producer key cannot read these metrics or submit review labels. The adapter validates event/review schemas before network access. Key setup and provider-specific validation belong to the [runtime integration guide](runtime_integration.md); do not paste keys or real customer events into an AI conversation.

For a shadow-only service, start `python3 app/serve.py --port 8001 --disable-demo`. Anonymous demo mutations then return an error; the static UI is still served. This setting is optional and is not used for the presentation sequence above.

Retained-event quotas are 1,000 across demos, 4,000 for trusted ingestion and 5,000 globally, with at most 32 demos and 500 events per demo. Global and per-demo token buckets also limit repeated actions; a reset does not refill global limits. Capacity/rate failures must remain explicit instead of silently dropping evidence. HTTP handling has 16 workers, an eight-second absolute connection deadline, and separate 16 KiB header/body budgets. Replay caches are bounded, duplicate sensitive headers are rejected, password checking runs outside the shared ingestion lock, and reset/expiry cancels its pending result. These safeguards do not make the local development server production-certified.

The historical CSV viewer at `/` retains the older 17/19-column views and +25/+10 policy for comparison. It does not implement the current verified event workflow. The baseline CSV and trained model are unchanged. Actual company/HTTP tests are behavioral checks, not real-world performance evidence. No visual browser rendering was available in this environment; responsive layout and appearance still require a browser review.

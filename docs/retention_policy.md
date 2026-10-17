# Retention and deletion

This policy distinguishes synthetic development files, historical CSV memory, current demo state and trusted shadow events. Reference release is not physical memory wiping.

| Data | Retention | Removal |
|---|---|---|
| Historical imported CSV and derived cards | Selected 5/10/15 minutes in browser memory | Expiry checks, reset, page departure; suspended tabs recheck on return |
| Demo username/password/MFA code | Transient request/verification only | Form cleared immediately; server does not store/log raw values or event-password hashes |
| Demo handle, derived context/events/results | Hard five-minute demo lifetime; 500 events per demo; 32 demos | Synchronous expiry on access, explicit reset and server cleanup |
| Trusted events, result/peak and human-review labels | Rolling five minutes | Ingest/snapshot/feedback expiry and server cleanup |
| Successful signed-request nonces | 120 seconds; at most 10,000 | Server cleanup; new requests rejected at capacity |
| All retained events across demos and trusted stream | At most 5,000; separate 1,000 demo / 4,000 trusted budgets | New work rejected at capacity; no silent event dropping to undercount attacks |
| MFA challenge binding | One random challenge ID per pending sign-in; at most 120 seconds and five failed checks | Replaced by the next valid login/simulation, consumed on success/exhaustion, reset or expiry |
| Admission counters | Fixed process-level channel buckets; one bucket per live demo | Process buckets reset on restart, demo bucket removed on expiry/reset; no client addresses or credential data |
| Interactive password backoff | Failure count and monotonic retry deadline per demo; delay capped at 60 seconds | Successful password verification resets it; demo reset/expiry removes it, within the unchanged five-minute lifetime |
| Current decision receipt | One allowlisted payload, MAC and random per-demo key in RAM; no identity fields or retained chain | New decision replaces it. Reset/expiry removes key and receipt references within the five-minute scope; no physical wiping claim |
| Demo authorization | Fixed employee role derived from server state and an expiry time | Resource checks enforce at most 120 seconds, bounded by demo expiry; new failed verification, reset and expiry revoke the grant |
| Public credential verifier | Published fixture salt and scrypt verifier in source | Deliberate static demo fixture, not a hash of a collected customer password; no submitted-password hash is retained |
| Evidence workbench response | On-demand aggregate diagnostics; only the current response is held in browser memory within the same demo lifetime | Replaced on refresh; cleared on reset, expiry, departure or unverifiable response; no second server history |
| Public model/policy/reference, synthetic CSV/evaluation artifacts | Versioned development files | Explicit project artifact management; never customer records |

The server cleanup daemon checks about once per second. An idle server therefore releases expired application references when the cleanup thread next runs, subject to scheduler/process availability. Access checks enforce expiry immediately; stopped/suspended processes cannot promise wall-clock memory wiping. Restart clears all event/handle/feedback state.

Two-minute counts use the exclusive left boundary `(t−120,t]`; demo sessions rotate after two minutes. An active source stays correlated across the rolling window; its token rotates after two minutes of inactivity and is always deleted at the five-minute demo deadline. MFA expires at the earlier of two minutes from challenge creation or the session boundary, with at most five failed code attempts; a stale challenge ID cannot validate a later sign-in. Human-review labels expire with their event. Long-window aggregates may be supplied by a trusted customer adapter, but this runtime does not invent a 24-hour history from five minutes of retained data.

No cookies, local/session storage, IndexedDB, external analytics, remote password lookup or customer export files are created. Company requests go to the same loopback server; CSV import remains browser-only. The browser attempts reset on page departure, but delivery is not guaranteed, so server TTL is authoritative. A failed/aborted response does not prove the request was never processed. Credentials are never automatically retried.

The evidence workbench's 30/60/120-second rows are analytical views at the latest event's timestamp, not new retention settings. Refreshing its token-scoped inventory extends no deadline. Displayed countdowns estimate when application-state expiry is due; they do not attest to physical memory erasure. Identity map entry counts can overlap identifiers retained in event records and must not be described as distinct people or devices.

The prototype stores public reference hashes, which provide no confidentiality for dictionary entries. They are not customer password hashes. Real IdP verifier/password storage and customer-side aggregate retention are outside this process and require their own explicit policies. The generic signed transport does not itself erase upstream provider logs.

# Integration decisions — baseline closure

**Historical scope:** this note records the baseline integration closure on 17 October 2026, before the later password-risk extension. The provisional encoding assumptions in the first AI 1 delivery were reconciled after the request to complete all missing work. **At this baseline closure, no CSV column was added, removed or renamed.** The first failure record is in the [initial historical audit](reviews/security_review_2026-10-17_initial.md); see the [latest review](security_review.md) for the current state.

| Topic | Baseline decision |
| --- | --- |
| Network familiarity | Categorical `familiar/unfamiliar`, not numeric; the CSV reader, Python and JavaScript share the vocabulary |
| Hour deviation | Circular hour distance, 0–12 hours |
| Short window | `(t−120 seconds,t]`; an earlier record at the same timestamp is known, and future events are excluded |
| Counter scope | Attempts are per account; distinct accounts are grouped by a temporary shared source |
| Success/source/episode verification | Synthetic audit manifest outside the fixed CSV; none of these fields is a model input |
| Missing history | Empty CSV cell, null in the application; inference abstains rather than assigning zero |
| Model input | Exact 11-feature allowlist; identifiers, raw time, target and scenario are excluded |
| Model output | Actually trained logistic JSON; integer risk, contribution explanations and version |
| Identity correlation | Application layer outside the model; maximum event score only when every session event is scorable |
| Threshold | UI 30/70; a separate validation benchmark threshold with explicit feasibility |
| Retention | Browser CSV state expires after 5/10/15 minutes; source files and synthetic artifacts have separate policies |
| Model corruption | Contract and checksum checks; error/null does not mean low risk |

Real IdP success, customer source keys, production cookies and real history integration were outside the local baseline prototype. The model can produce false alarms; evaluation limitations for normal travel and new devices are documented in the model results report. Later extensions must be read in the current architecture and security review rather than inferred from this historical closure note.

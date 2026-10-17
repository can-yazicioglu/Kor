# Synthetic login data and versioned password flags

All login records are synthetic. No customer record, real username, password, IP address, precise location or persistent device fingerprint is used. Reported model measurements describe this authored simulation, not proven real-world effectiveness.

## Baseline: unchanged 17-column contract

```bash
python3 src/data/generate_synthetic.py --rows 10000 --seed 42 --attack-rate 0.08 \
  --start-utc 2025-01-01T00:00:00Z --output data/mvp_synthetic_logins.csv
python3 -m unittest discover -s tests -p 'test_data.py' -v
```

The standard-library generator is deterministic and offline. Row count, seed, attack rate and timezone-aware start are configurable. `round(rows * attack_rate)` determines the exact positive count. Very small datasets may not support every scenario or model training.

The delivered baseline contains **10,000 events, 800 suspicious labels, 4,036 sessions and 573 accounts**. Its SHA-256 remains:

```text
41383a34524cefb434a66608c74a6554bada4377968298c6d7b7a43e4168b625
```

The exact baseline schema is:

```text
event_id,event_ts_utc,session_token,account_token,attempts_2m,attempts_1h,distinct_accounts_2m,failed_ratio_24h,hour_deviation,typical_weekday,geo_velocity_kmh,network_familiarity,asn_category,device_managed,device_new,is_suspicious,attack_type
```

Only the 11 columns from `attempts_2m` through `device_new` are model features. IDs are grouping keys, time controls chronology, `is_suspicious` is the target, and `attack_type` is evaluation metadata. None of that metadata or the sidecar is joined into model inputs.

| Feature | Meaning |
| --- | --- |
| `attempts_2m` | Observed events for the same account in `(t−120 seconds,t]`, including the current event. Cookie rotation does not reset it. |
| `attempts_1h` | Same-account events in `(t−3600 seconds,t]`; never smaller than the two-minute count. |
| `distinct_accounts_2m` | Distinct accounts sharing a transient source key in `(t−120 seconds,t]`. |
| `failed_ratio_24h` | Failure fraction among previously known synthetic outcomes from the last 24 hours; current outcome excluded; empty when unknown. |
| `hour_deviation` | Shortest circular hour distance from a simulated preferred hour, `[0,12]`; empty without a profile. |
| `typical_weekday` | `0/1` against the synthetic preferred-day set; empty without a profile. |
| `geo_velocity_kmh` | Nonnegative simulated context sampled without coordinates; may be empty. VPN jumps are not physical travel evidence. |
| `network_familiarity` | `familiar`, `unfamiliar`, or empty; not a numeric 0–1 encoding. |
| `asn_category` | `residential`, `business`, `cloud`, `vpn`, `unknown`; no ASN number. |
| `device_managed`, `device_new` | `0/1` or empty; no device identifier. |

Empty means unknown, never zero or safe. **1,845 events** have missing features; **8,155** have complete model context. For tied timestamps, CSV order is causal ingestion order: later tied events are not visible yet. The two-minute window excludes an event exactly 120 seconds earlier.

## Baseline scenarios

| Scenario | Events | Target |
| --- | ---: | ---: |
| Ordinary login | 3,955 | 0 |
| User error followed by success | 1,840 | 0 |
| VPN/new device, including a shared source | 1,196 | 0 |
| Travel/new device | 1,013 | 0 |
| Night shift | 736 | 0 |
| Cold start with missing context | 460 | 0 |
| Brute force | 320 | 1 |
| Password spraying | 240 | 1 |
| Suspicious successful login | 240 | 1 |

Benign records include high velocity, unusual hours, new devices and unfamiliar networks. Feature distributions overlap between classes; about 3% of episodes in either class additionally lose context. Every split includes all scenarios and complete controls outside the dedicated cold-start regime. These are authored distributions, not measured customer frequencies.

## Audit sidecar, chronology and history

`data/mvp_synthetic_logins.manifest.json` binds the CSV hash and maps each event to `split`, `scenario`, `episode_id`, `source_token` and `auth_success`. These are audit metadata, never features. Successful outcomes for the suspicious-success scenario can therefore be independently checked without changing the fixed CSV.

| Split | Events | Observed UTC range | Complete events |
| --- | ---: | --- | ---: |
| `fit` | 6,000 | 1–8 January 2025 | 4,899 |
| `validation` | 2,000 | 11–18 January 2025 | 1,625 |
| `test` | 2,000 | 21–28 January 2025 | 1,631 |

Accounts, episodes, sessions and transient sources are disjoint across splits. Time blocks are sequential with gaps greater than 120 seconds. Thresholds use validation data; test data does not select model settings. Scenario *types* appear in every split deliberately; this does not test entirely unseen attack types.

Preferred hours/days simulate a **30-day baseline**, not a real account history. Profile cutoffs precede their split, including non-midnight start times. Cold-start profiles have no history. The sidecar includes 3,129 explicitly synthetic warmup outcomes before the observed timeline. They are at least 3,601 seconds before the split start, so they support the 24-hour ratio without affecting one-hour attempt counts. Subsequent ratios use only prior observed outcomes.

Session and source keys are used for less than 120 seconds in the simulation. The generator is not a live cookie, identity-provider or TTL service. The persistent CSV/manifest are intentionally retained synthetic fixtures. Real deployments need separate lifetimes for transient source correlation, one-hour count summaries and 24-hour outcome summaries. A two-minute analysis window does not mean that every artifact is deleted after two minutes.

## Explicit v2: two password-reference flags

The later user-authorized extension is a separate file, **not a silent change to the original schema**:

```bash
.venv/bin/python -m src.security.build_password_reference
.venv/bin/python -m src.data.extend_password_flags --seed 42
.venv/bin/python -m unittest discover -s tests -p 'test_password_security.py' -v
```

`data/mvp_synthetic_logins_v2.csv` keeps the original 17 values byte-for-byte at the field level and appends:

```text
password_in_blocklist,password_near_blocklist
```

Flags are `0/1`, mutually exclusive, and computed by the actual offline checker. The versioned dataset contains **1,997 exact matches, 3,008 near matches and 4,995 unmatched events**. Normal events include 1,850 exact and 2,770 near matches; suspicious events include 415 unmatched records. The flags therefore do not encode the target label.

V2 CSV SHA-256:

```text
fc42e375321d8b957f732a250b11081f48199744c24777b182a59c65c381ad05
```

The generator independently samples one profile per session, with 20% exact, 30% near and 50% unmatched probabilities. It fetches only the two pinned public dictionary sources, checks their hashes against the reference, creates ephemeral synthetic candidates, runs the real checker, then immediately drops candidate references. No raw, normalized or hashed event password is written to CSV, sidecar or logs. Deterministic profiles are test inputs, not a claim about customer password distributions.

`data/mvp_synthetic_logins_v2.manifest.json` binds the baseline CSV/manifest, v2 CSV and reference hashes. `password_profiles` records only the profile category, checker match type and two flags for each session. Existing event groups/splits are retained. It records that the additional risk is an **unvalidated policy overlay**, not a new trained feature or a revised model metric. The existing 11-feature model and baseline hash are unchanged.

Reference sources, license, exact/near matching, unknown handling and the +25/+10 bonus are documented in [password_sources.md](password_sources.md). A reference match does not prove an account breach; no match does not imply safety. Missing/corrupt references produce unknown results in the checker, while fixture generation stops rather than fabricating `0/0`.

## Verification

`tests/test_data.py` independently recomputes rolling counts and prior-outcome ratios, checks exact schema/cardinality, multi-event sessions, account/episode/source/time separation, profile cutoffs, missing context, seed reproducibility and synthetic identifier formats.

`tests/test_password_security.py` covers exact/NFKC/case/leet/suffix/single-edit matching, candidate bounds, corrupt/missing references, invalid inputs, source exclusions, delivered reference integrity, unchanged baseline fields and actual-checker use during deterministic extension generation. Source research and exclusions are recorded in [data_source_audit.md](data_source_audit.md).

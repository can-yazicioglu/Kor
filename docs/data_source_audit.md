# Login-data and password-reference source audit

Research and verification date: **17 October 2026**. Publisher pages, schemas and license text were checked. No external login datasets, PCAPs, raw authentication logs or account breach dumps were imported. The baseline login dataset remains entirely synthetic.

## Login and attack datasets considered

| Primary source | License/access statement | Fit and decision |
| --- | --- | --- |
| [Login Data Set for Risk-Based Authentication, Zenodo](https://zenodo.org/records/6782156) | CC BY 4.0; publication attribution requested. | Synthesized login features derived from real behavior, including success and takeover labels. Publisher warns against production use. Schema and identity/network fields do not match this MVP. Archive not downloaded. |
| [IAM-UEBA, Zenodo](https://zenodo.org/records/22871318) | CC BY 4.0; re-identification prohibited. | Anonymized real IAM events with stable tokens and mixed activity. No ground-truth attack labels. Not imported. |
| [Splunk O365 Distributed Spray](https://research.splunk.com/attack_data/ce5ee9b2-8247-4744-99c3-fc943e3437d0/) | [Attack Data repository: Apache 2.0](https://github.com/splunk/attack_data/blob/master/LICENSE). | Simulated distributed spraying against 30 accounts; publisher states tenant details were replaced. Useful scenario reference, but raw logs do not provide the fixed feature schema or normal controls. Not downloaded. |
| [LANL Comprehensive Multi-Source Events](https://csr.lanl.gov/data/cyber1/) | Publisher waives copyright and related rights where possible; usage-purpose form and citation request. | De-identified authentication and red-team events over 58 days. Different enterprise telemetry and feature scope; failed events are restricted to accounts with at least one success in the dataset. Not imported. |
| [LANL Unified Host and Network Dataset](https://csr.lanl.gov/data/2017/) | Publisher waives copyright and related rights where possible; citation request. | Host authentication outcomes and network data; not the web-session RBA schema. Some system values are not de-identified. Not imported. |
| [CIC-IDS2017, UNB](https://www.unb.ca/cic/datasets/ids-2017.html) | Researcher access and publication citation stated; standard redistribution license not established by that page. | FTP/SSH and web brute-force scenarios, primarily network flows/PCAP. Does not supply the required account/session feature contract. Not downloaded. |
| [LogHub OpenSSH](https://github.com/logpai/loghub/tree/master/OpenSSH) | [License](https://github.com/logpai/loghub/blob/master/LICENSE) permits research/academic use with attribution and retained notice. | Raw SSH logs; repository states that logs are not sanitized/anonymized where possible. Not suitable for importing raw records into this privacy boundary. Not downloaded. |

These sources inform scope and limitations. None supplies all required fields and controls in the fixed 17-column schema. The local generator creates all baseline events independently; no source row, account, address, password or precise location is copied into it. Synthetic evaluation is not evidence of real-world effectiveness.

## Isolated model-tuning cohorts

The later authorized tuning work generated 74,000 events in `experiments/tuning_v1` and 94,000 in `experiments/tuning_v2` using the existing authored generator. Each cohort retains the fixed 17-column schema in compressed CSV plus synthetic provenance/outcome metadata. No external records were imported. Separate phase dates and identifiers are audited against prior cohorts; only earlier login outcomes supply the candidate's added sequence features. The original baseline and password-extension CSV files remain unchanged. New random draws still share generator assumptions and do not establish real-customer effectiveness. [Results and blocked release](model_tuning.md).

## Explicitly authorized password-reference extension

The later extension adds two password-only public dictionaries from the MIT-licensed SecLists repository. This is a distinct, documented expansion beyond the original MVP exclusion. It does **not** combine leaked account records with login events.

Only two pinned common-password files and their license are fetched. Raw lists are processed in memory; only deduplicated exact/normalized SHA-256 indexes and attribution are retained. Current coverage is 12,526 exact entries. Sources, license, exclusions, integrity, offline matching behavior and limitations are documented in [password_sources.md](password_sources.md).

The baseline `data/mvp_synthetic_logins.csv` remains unchanged. The separate `data/mvp_synthetic_logins_v2.csv` adds `password_in_blocklist` and `password_near_blocklist` flags computed by the actual local checker using invented ephemeral profiles. It retains normal matched examples and suspicious unmatched examples. No event password, normalized event password or event-password hash is stored. Existing model training and reported metrics do not include these flags.

A common-list hit is not evidence that a particular user's password was breached. A miss is not proof of password strength or safety. No external password API, email lookup, customer upload or account breach database is used.

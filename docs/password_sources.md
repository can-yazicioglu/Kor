# Public password references and local matching

> Current runtime note: matching remains local, now in the loopback verifier for the company demo. The +25/+10 values below describe the retained historical browser/CSV experiment; the current server policy uses separate contextual credential evidence. See [architecture](architecture.md).

This extension uses a limited public common-password reference to add a **separate demo policy signal**. A match means that the submitted value, or a supported variation, resembles this reference. It does not establish that a particular account was breached. No match does not establish that a password is safe.

## Sources actually used

Research and verification date: **17 October 2026**. Both password-only files come from [SecLists](https://github.com/danielmiessler/SecLists), pinned to commit `1cb6ade5539246c326986193d67954a2855581f6`:

| Source | Public reference | Scope |
| --- | --- | --- |
| Common passwords | [10k-most-common.txt](https://github.com/danielmiessler/SecLists/blob/1cb6ade5539246c326986193d67954a2855581f6/Passwords/Common-Credentials/10k-most-common.txt) | A bounded common-password dictionary, not account records. |
| Xato common passwords | [xato-net-10-million-passwords-10000.txt](https://github.com/danielmiessler/SecLists/blob/1cb6ade5539246c326986193d67954a2855581f6/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt) | The 10,000-entry excerpt, not a download of ten million records. |
| License | [Pinned SecLists MIT license](https://github.com/danielmiessler/SecLists/blob/1cb6ade5539246c326986193d67954a2855581f6/LICENSE) | Copyright and license text retained in `third_party/passwords/SecLists-LICENSE.txt`. |

The builder fetches only these two files and their repository license. It excludes empty, overlength, control-character, email-like, IP-like and colon-separated values. It never downloads usernames, email/password dumps, account breach records or stolen databases. Public plaintext lists exist only in the builder's process memory and are not retained as project files.

Source URLs, pinned commit, raw-source SHA-256, accepted/excluded counts and license attribution are recorded in `third_party/passwords/provenance.json` and the reference JSON. The resulting `data/password_reference.json` contains **12,526 distinct exact hashes** and **12,378 distinct normalized hashes**, and is **1,671,053 bytes**. Reference SHA-256:

```text
97f0dde1d7814565a6aa8feb20819e977a7c8961f2408c5a1cd3aaf37513e398
```

These are unsalted hashes of **public dictionary entries**, not stored user-password hashes. They provide a compact lookup index, not confidentiality or secure authentication storage. A public dictionary hash can be reconstructed from the public source. Submitted values and their hashes are not logged or persisted.

## Guidance and limits

[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver) requires comparing prospective passwords against a blocklist during password establishment/change and comparing the entire password. It also calls for rate limiting. It does not validate this project's login-risk bonus or approximate-match algorithm. NIST's authentication normalization guidance is separate from this demo's NFKC-based similarity heuristic.

[OWASP's Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-strength-controls) recommends preventing common or previously breached passwords and links SecLists, while noting that other top-password lists may not be current. The two selected lists are limited historical references; their coverage and freshness are not comprehensive.

[Have I Been Pwned's official Pwned Passwords documentation](https://haveibeenpwned.com/API/v3#PwnedPasswords) describes a separate breached-password service. This project **does not call that service**, download its corpus, send hash prefixes, or perform account/email lookups. A SecLists match must never be labeled a verified HIBP hit or a confirmed account breach.

## Rebuild and local check

From the repository root:

```bash
.venv/bin/python -m src.security.build_password_reference
.venv/bin/python -m src.security.password_check
.venv/bin/python -m src.data.extend_password_flags
.venv/bin/python -m unittest discover -s tests -p 'test_password_security.py' -v
```

The reference builder and versioned synthetic extension fetch pinned **public** dictionary files. The checker itself runs offline and reads a password from a hidden local prompt; `--stdin` is available for controlled local automation. There is deliberately no command-line password argument. Use invented demonstration values. Do not paste real credentials into an AI conversation or store them in shell history.

## Matching contract

`src/security/password_check.py` and the browser implementation follow this order:

1. Reject unsupported/missing inputs or an unavailable/corrupt reference as **unknown**. The supported input length is 1–256 Unicode codepoints. Unknown flags and bonus are `null`, never an implicit safe result.
2. Compute SHA-256 of the exact submitted UTF-8 bytes. An exact hit produces `password_in_blocklist=1`, `password_near_blocklist=0` and a **+25** policy bonus.
3. Otherwise normalize with NFKC, lowercase, then map `4/@→a`, `0→o`, `1/!/|→i`, `3→e`, `5/$→s`, `7/+→t`. Compare its SHA-256 with the normalized reference.
4. If needed, remove a trailing 1–4-character suffix matching `[0-9!@#$%^&*?._-]{1,4}$` from the **raw** input. Require at least four remaining Unicode codepoints, normalize, and compare.
5. If needed, for the original normalized value matching `[a-z0-9]{6,32}`, try unique single-character deletions, insertions, substitutions and adjacent swaps. Insert/substitute alphabet: lowercase ASCII letters then digits. The order is deterministic, with at most 5,000 candidates.
6. A near hit produces `password_in_blocklist=0`, `password_near_blocklist=1` and **+10**. Neither hit produces `0/0` and **+0**, accompanied by the limited-coverage warning.

The exact and near flags are mutually exclusive. The check is not substring search, a full edit-distance search, a password-strength estimator, or a replacement for authentication. Similarity can produce false positives and false negatives. Authentication must continue to verify the original secret according to the identity provider's own rules; this heuristic never changes that secret.

## Model and policy boundary

The existing 11-feature model, training data and evaluation results remain unchanged. The two flags are added only in the explicitly versioned 19-column synthetic CSV. The policy overlay is `min(100, base_model_score + bonus)` when a base score exists. An unknown model score remains unknown. The +25/+10 values are authored demo settings; they are not learned weights or empirically calibrated risk. No automatic account lockout is added.

The reference includes a canonical SHA-256 integrity field for accidental corruption detection. This is not a digital signature or proof of source authenticity. Updating the reference is an explicit rebuild operation; live login checks never contact an external service.

# Cryptographic inventory and migration boundary

| Use | Current primitive / configuration | Key or material lifecycle | Important boundary |
|---|---|---|---|
| Public demo password verifier | `hashlib.scrypt`, N=32768, r=8, p=3, 32-byte output | Published fixture salt and verifier; submitted values/derived hashes transient | Not a real account database. SHA-256 alone is not password storage |
| Trusted request authentication | HMAC-SHA-256, distinct producer/reviewer keys; timestamp/nonce/body/path binding | Customer-held environment secrets, no repository keys | Authentication/integrity, not encryption. Plan managed rotation and secure provisioning for deployment |
| Current decision receipt | HMAC-SHA-256 with a separate random 256-bit key per demo and domain prefix | One current receipt + key in RAM, reset/expiry removes references within five minutes | Old receipt, altered payload and other demo key fail. No durable audit log or compromised-host protection |
| Artifact integrity | SHA-256 over canonical JSON / release bytes | Public digests in versioned files | Corruption comparison; not digital signatures or provenance authentication by itself |
| Password reference lookup | SHA-256 public dictionary indexes | Pinned public reference file | Dictionary index only; not secure storage for customer passwords or a confirmed breach search |
| Optional transport | Python/OpenSSL TLS server, minimum TLS 1.3; verified CA/hostname in CLI adapter | Certificate/private key supplied locally; `.pem`/`.key` ignored | Default loopback HTTP is unencrypted. No insecure TLS-client bypass or silent HTTP fallback |

The scrypt parameters are one of the configurations listed in the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt). The application bounds concurrent verification to four slots. That choice and the public fixture are not a production capacity assessment. Role enforcement follows deny-by-default and per-request checks described by the [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

## Local TLS demonstration

Create a temporary self-signed fixture outside committed files:

```bash
mkdir -p .local/tls
chmod 700 .local/tls
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout .local/tls/key.pem -out .local/tls/cert.pem -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
chmod 600 .local/tls/key.pem
python3 app/serve.py --port 8443 --tls-cert .local/tls/cert.pem --tls-key .local/tls/key.pem
```

The browser needs a locally trusted certificate; the generated self-signed fixture is not automatically trusted. Use a properly issued/trusted certificate for a presentation that requires browser HTTPS. Do not disable browser verification as a deployment practice. The CLI can explicitly trust this fixture:

```bash
# Requires an independently configured reviewer secret in the environment.
python3 -m src.runtime.adapter --metrics --port 8443 --tls-ca .local/tls/cert.pem
```

Tests use a temporary CA-trusted local certificate, perform hostname verification, reject TLS 1.2 and mismatched HTTP origins, and exercise the signed adapter over TLS. [Python SSL API](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.minimum_version).

## IBM Z / quantum-safe plan, not an implemented claim

The inventory above is a migration starting point. TLS version alone does not establish post-quantum security, and hashing is not encryption. The sample RSA certificate is classical. No post-quantum signature/key exchange, HSM-backed key operations or hardware attestation has been executed here.

For an IBM Z deployment, assess customer-local Linux execution, Secure Execution isolation, Crypto Express / managed key custody, and the actual TLS and certificate providers. Record algorithms and key ownership, then test provider-supported migration and hybrid/PQC interoperability on available hardware. Do not invent a cryptographic scheme or label the current demo quantum-safe. IBM describes inventory and crypto agility as migration steps in [IBM Z Quantum-safe Security](https://www.ibm.com/products/z/quantum-safe); platform capabilities are described in [IBM Z Security](https://www.ibm.com/products/z/security). These are target capabilities, not evidence of this project's integration.

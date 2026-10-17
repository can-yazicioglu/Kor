// Fixed, identifier-free assurance contract. All text comes from validated fields.
const bad = () => new Error('Unsupported assurance response.');
export function validateAssurance(value) {
  if (!value || value.version !== 'els-assurance-v1' ||
      !['loopback_http', 'tls13_loopback'].includes(value.transport) ||
      value.password_verifier !== 'scrypt-n32768-r8-p3') throw bad();
  const receipt = value.receipt, auth = value.authorization;
  if (!receipt || receipt.algorithm !== 'HMAC-SHA-256' || !['pending', 'verified', 'invalid'].includes(receipt.status) ||
      !Number.isInteger(receipt.counter) || receipt.counter < 0 || receipt.counter > 500 ||
      (receipt.status === 'pending' ? receipt.digest !== null || receipt.counter !== 0 :
        typeof receipt.digest !== 'string' || !/^[a-f0-9]{64}$/.test(receipt.digest) || receipt.counter < 1)) throw bad();
  if (!auth || !['employee', 'anonymous'].includes(auth.role) ||
      typeof auth.workspace_allowed !== 'boolean' || auth.audit_allowed !== false ||
      !Number.isInteger(auth.expires_in_ms) || auth.expires_in_ms < 0 || auth.expires_in_ms > 120000 ||
      auth.workspace_allowed !== (auth.role === 'employee') ||
      (!auth.workspace_allowed && auth.expires_in_ms !== 0)) throw bad();
  return value;
}

export function validateSecurityTest(value) {
  if (!value || typeof value.original_verified !== 'boolean' || typeof value.altered_verified !== 'boolean' ||
      value.algorithm !== 'HMAC-SHA-256' || typeof value.scope !== 'string' || value.scope.length > 200) throw bad();
}

export function renderAssurance(document, assurance, test = null) {
  const set = (id, text) => { const node = document.getElementById(id); if (node) node.textContent = text; };
  set('receipt-status', !assurance ? 'No verified response' : assurance.receipt.status === 'pending' ? 'Waiting for a decision' :
    assurance.receipt.status === 'verified' ? 'Current decision verified' : 'Integrity check failed');
  set('receipt-digest', assurance?.receipt.digest ?? 'A decision creates an ephemeral HMAC receipt.');
  set('access-role', assurance?.authorization.role ?? 'Unknown');
  set('access-ttl', assurance?.authorization.workspace_allowed ? `Grant expires within ${Math.ceil(assurance.authorization.expires_in_ms / 1000)} seconds of this response.` : 'No active workspace grant.');
  set('transport-status', !assurance ? 'Not checked' : assurance.transport === 'tls13_loopback' ? 'TLS 1.3 · loopback' : 'Local HTTP · loopback only');
  set('proof-result', !test ? 'Record an event, then test an altered copy of its receipt.' :
    test.original_verified && !test.altered_verified ? 'PASS · Original verified. Altered score rejected. Live evidence unchanged.' :
      'FAIL · Receipt checks did not match the expected outcome.');
}

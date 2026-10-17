import assert from 'node:assert/strict';
import { parseHTML } from 'linkedom';
import { validateAssurance, validateSecurityTest, renderAssurance } from '../assurance.js';
import { readFile } from 'node:fs/promises';
const value = { version:'els-assurance-v1', transport:'loopback_http', password_verifier:'scrypt-n32768-r8-p3',
  receipt:{ status:'verified', algorithm:'HMAC-SHA-256', counter:1, digest:'a'.repeat(64) },
  authorization:{ role:'employee', workspace_allowed:true, audit_allowed:false, expires_in_ms:120000 } };
let checks = 0;
validateAssurance(value); checks++;
for (const mutate of [v => v.authorization.role='administrator', v => v.authorization.audit_allowed=true,
  v => v.authorization.expires_in_ms=120001, v => v.receipt.digest='<script>',
  v => v.transport='quantum-safe', v => v.receipt.counter=501, v => v.authorization.workspace_allowed=false]) {
  const bad=structuredClone(value); mutate(bad); assert.throws(() => validateAssurance(bad)); checks++;
}
assert.throws(() => validateSecurityTest({ original_verified:'true', altered_verified:false })); checks++;
const { document }=parseHTML(await readFile(new URL('../company.html',import.meta.url),'utf8'));
renderAssurance(document,value,{ original_verified:true, altered_verified:false });
assert.match(document.getElementById('proof-result').textContent,/Altered score rejected/);
assert.match(document.getElementById('transport-status').textContent,/Local HTTP/); checks++;
renderAssurance(document,null);
assert.match(document.getElementById('receipt-status').textContent,/No verified response/);
assert.equal(document.getElementById('access-role').textContent,'Unknown'); checks++;
console.log(`${checks} assurance validation and rendering checks passed.`);

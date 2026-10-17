// DOM behavior and service-contract simulation, not visual or real-browser QA.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseHTML } from 'linkedom';
const html = await readFile(new URL('../company.html', import.meta.url), 'utf8');
const { window, document } = parseHTML(html);
globalThis.window = window; globalThis.document = document;
const $ = id => document.getElementById(id);
Object.defineProperty($('login-context'), 'value', { value: 'familiar', writable: true });
const realTimeout = globalThis.setTimeout;
let time = 1_800_000_000_000, nextTimer = 0, checks = 0;
let monotonic = 0;
Object.defineProperty(performance, 'now', { value: () => monotonic, configurable: true });
const timers = new Map();
Date.now = () => time;
globalThis.setTimeout = (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, at: time + delay }); return id; };
globalThis.clearTimeout = id => timers.delete(id);
globalThis.setInterval = () => 0;
const unavailable = process.argv.includes('--unavailable');
const referenceUnavailable = process.argv.includes('--reference-unavailable');
const readiness = { model_ready: !unavailable, policy_ready: !unavailable, reference_ready: !referenceUnavailable };
const requests = [];
const response = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
let tokenIndex = 0, currentToken, lastSnapshot, eventIndex = 0, failNext = false, deferNext = false, deferred, forceResponse = null;
let backoffNext = false;
const empty = () => ({ latest: null, total: 0, timeline: [], remaining_ms: 300000, login_retry_after_ms: 0, allowed_access: false, mfa_required: false, status: readiness, mode: 'synthetic_demo' });
function eventSnapshot({ success = false, context = 'familiar', match = 'none', amount = 1, kind = null, verified = 'password_verified' } = {}) {
  const unknown = unavailable || referenceUnavailable || context === 'cold_start';
  const risk = unknown ? null : kind ? 84 : context === 'unfamiliar' ? 48 : 12;
  const result = {
    event_id: 'unit-event-' + (++eventIndex), score: risk, peak_score: unknown ? null : Math.max(lastSnapshot?.latest?.peak_score ?? 0, risk), base_score: risk,
    reasons: unknown ? ['Some required context is unavailable.'] : ['Server-derived synthetic behavior signal.'],
    action: unknown || risk >= 70 ? 'review' : risk >= 30 ? 'mfa' : 'monitor', action_label: unknown ? 'Review unknown context' : risk >= 70 ? 'MFA + review recommended' : risk >= 30 ? 'MFA recommended' : 'Continue monitoring',
    data_quality: { level: unknown ? 'insufficient' : context === 'new_device' ? 'limited' : 'sufficient', missing_features: unknown ? ['hour_deviation', 'network_familiarity'] : [] },
    signals: { attempts_2m: kind === 'spray' ? 1 : amount, distinct_accounts_2m: kind === 'spray' ? amount : 1, distinct_sources_2m: kind === 'distributed' ? 12 : 1, consecutive_failures: success ? 0 : amount, success_after_failures: success && (lastSnapshot?.total ?? 0) > 0 },
    credential_risk: { status: referenceUnavailable ? 'unknown' : 'checked', match: referenceUnavailable ? 'unknown' : match },
    verification: success ? verified : 'not_verified', policy_version: 'unit-policy', model_version: 'unit-model', success,
  };
  return { latest: result, total: (lastSnapshot?.total ?? 0) + amount, timeline: [{ event_id: result.event_id, event_type: success ? 'login_success' : 'login_failure', score: risk }], remaining_ms: 300000, login_retry_after_ms: 0,
    allowed_access: success && risk !== null && risk < 30, mfa_required: success && risk !== null && risk >= 30, mfa_challenge_id: success && risk !== null && risk >= 30 ? 'a'.repeat(32) : null, status: readiness, mode: 'synthetic_demo' };
}
globalThis.fetch = async (url, options) => {
  const body = JSON.parse(options.body);
  // Tests use only public/fixture inputs. Production code never logs requests.
  requests.push({ url, options, body });
  if (backoffNext) {
    backoffNext = false;
    return new Response(JSON.stringify({ code: 'login_backoff', retry_after_seconds: 4 }), {
      status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '4' },
    });
  }
  if (failNext) { failNext = false; return { ok: false, text: async () => 'private-server-error-do-not-display' }; }
  const operation = url.split('/').at(-1);
  let result;
  if (operation === 'start') { currentToken = 'unit-demo-token-' + (++tokenIndex); lastSnapshot = empty(); result = { demo_token: currentToken, snapshot: lastSnapshot, status: readiness, mode: 'synthetic_demo' }; }
  else if (operation === 'reset') { result = {}; }
  else if (operation === 'attempt') {
    result = eventSnapshot({ success: body.password === 'VelaDemo!42', context: body.context, match: body.password === 'password' ? 'exact' : body.password === 'pASsW0rD!!' ? 'near' : 'none' });
  } else if (operation === 'simulate') result = eventSnapshot({ context: body.context, kind: body.kind, amount: { brute: 20, spray: 18, distributed: 12 }[body.kind] });
  else if (operation === 'mfa') { result = { ...lastSnapshot, allowed_access: body.code === '123456', mfa_required: body.code !== '123456', mfa_challenge_id: body.code === '123456' ? null : lastSnapshot.mfa_challenge_id, latest: { ...lastSnapshot.latest, verification: body.code === '123456' ? 'mfa_verified' : 'password_verified' } }; }
  else if (operation === 'feedback') result = { ...lastSnapshot, feedback_summary: { [body.label]: 1 } };
  else assert.fail('Unbounded endpoint');
  if (forceResponse) { result = forceResponse(result); forceResponse = null; }
  if (operation !== 'reset' && operation !== 'start') lastSnapshot = result;
  if (deferNext && operation === 'attempt') {
    deferNext = false;
    return await new Promise(resolve => { deferred = () => resolve(response(result)); });
  }
  return response(result);
};
const dispatch = (id, type = 'click') => $(id).dispatchEvent(new window.Event(type, { bubbles: true, cancelable: true }));
const waitFor = async predicate => { for (let i = 0; i < 300; i++) { if (predicate()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail('UI operation did not settle'); };
const settle = () => waitFor(() => !$('sign-in').disabled);
const login = async (password = 'VelaDemo!42', username = 'demo') => {
  $('username').value = username; $('password').value = password; dispatch('login-form', 'submit');
  assert.equal($('password').value, ''); await settle();
};
const reset = async () => { dispatch('reset-company'); await settle(); };
await import('../company.js');
await settle();
assert.equal(document.documentElement.lang, 'en');
assert.equal(requests.length, 1); assert.equal(requests[0].url, './api/demo/start');
assert.equal($('workspace-panel').hidden, true);
assert.match($('scope-copy').textContent, /local customer verifier/);
checks++;
if (unavailable || referenceUnavailable) {
  assert.match($('company-model-status').textContent, /unavailable/);
  await login();
  assert.equal($('risk-score').textContent, '—');
  assert.equal($('workspace-panel').hidden, true);
  assert.equal($('mfa-panel').hidden, true);
  assert.match($('data-quality').textContent, /Insufficient/);
  assert.match($('login-feedback').textContent, /has not granted access/);
  console.log('2 company DOM checks passed (' + (referenceUnavailable ? 'reference unavailable' : 'model unavailable') + '; no visual verification).');
  process.exit(0);
}
assert.match($('company-model-status').textContent, /ready/);
await login();
assert.equal($('workspace-panel').hidden, false);
assert.equal($('risk-score').textContent, '12'); assert.equal($('session-peak').textContent, '12');
assert.match($('verification-status').textContent, /verified by local server/);
assert.equal(requests.at(-1).body.username, 'demo');
checks++;
dispatch('sign-out'); await settle();
assert.equal($('workspace-panel').hidden, true);
assert.equal($('event-total').textContent, '0 EVENTS');
assert.deepEqual(requests.slice(-2).map(item => item.url), ['./api/demo/reset', './api/demo/start']);
checks++;
const requestCount = requests.length;
await login('private-unit-password', 'private-unit-username');
assert.equal(requests.length, requestCount);
assert.equal(document.toString().includes('private-unit'), false);
assert.equal(JSON.stringify(requests).includes('private-unit'), false);
checks++;
forceResponse = value => ({ ...value, allowed_access: false, mfa_required: false });
await login();
assert.equal($('workspace-panel').hidden, true); // Correct public password is not a browser permission.
assert.match($('login-feedback').textContent, /has not granted access/);
checks++;
await reset(); dispatch('run-brute'); await settle();
assert.equal($('event-total').textContent, '20 EVENTS'); assert.equal($('attempt-count').textContent, '20');
assert.match($('risk-action').textContent, /MFA \+ review/);
assert.equal(requests.at(-1).url, './api/demo/simulate'); assert.equal(requests.at(-1).body.kind, 'brute');
await login();
assert.equal($('risk-score').textContent, '12'); assert.equal($('session-peak').textContent, '84');
assert.equal($('workspace-panel').hidden, false); // A high historical peak cannot freeze the current decision.
checks++;
await reset(); $('login-context').value = 'unfamiliar'; await login();
assert.equal($('mfa-panel').hidden, false);
forceResponse = value => ({ ...value, allowed_access: false, mfa_required: true, mfa_challenge_id: 'a'.repeat(32), latest: { ...value.latest, verification: 'password_verified' } });
$('mfa-code').value = '123456'; dispatch('mfa-form', 'submit'); assert.equal($('mfa-code').value, ''); await settle();
assert.equal($('workspace-panel').hidden, true); // Even the public correct code does not override server denial.
$('mfa-code').value = '123456'; dispatch('mfa-form', 'submit'); await settle();
assert.equal($('workspace-panel').hidden, false); assert.match($('verification-status').textContent, /MFA verified by local server/);
checks++;
for (const context of ['vpn', 'travel', 'new_device', 'cold_start']) {
  await reset(); $('login-context').value = context; await login();
  assert.equal(requests.at(-1).body.context, context);
  if (context === 'cold_start') { assert.equal($('risk-score').textContent, '—'); assert.equal($('workspace-panel').hidden, true); assert.match($('data-quality-note').textContent, /Missing context/); }
}
checks++;
await reset(); dispatch('run-spray'); await settle(); assert.equal($('account-count').textContent, '18');
await reset(); dispatch('run-distributed'); await settle(); assert.equal($('source-count').textContent, '12');
assert.equal($('event-total').textContent, '12 EVENTS');
checks++;
dispatch('feedback-suspicious'); await settle();
assert.equal(requests.at(-1).url, './api/demo/feedback'); assert.equal(requests.at(-1).body.label, 'suspicious');
assert.match($('feedback-status').textContent, /Access decisions are unchanged/);
assert.equal($('workspace-panel').hidden, true);
checks++;
await reset(); await login('password'); assert.match($('password-match').textContent, /Exact reference match/);
assert.equal($('credential-strength').textContent, 'Weakness signal');
assert.equal($('risk-score').textContent, $('base-risk-score').textContent);
assert.match($('password-check-note').textContent, /no fixed score is added/);
await login('pASsW0rD!!'); assert.match($('password-match').textContent, /Close variation/);
checks++;

await reset();
forceResponse = value => ({ ...value, login_retry_after_ms: 1000 });
$('password').value = 'synthetic-wrong'; dispatch('login-form', 'submit');
await waitFor(() => !$('fill-demo').disabled);
assert.equal($('sign-in').disabled, true);
assert.match($('login-backoff').textContent, /Wait 1s/);
const beforeBlockedSubmit = requests.length;
$('password').value = 'VelaDemo!42'; dispatch('login-form', 'submit');
assert.equal($('password').value, '');
assert.equal(requests.length, beforeBlockedSubmit);
time += 5000; document.dispatchEvent(new window.Event('visibilitychange'));
assert.equal($('sign-in').disabled, true, 'Wall-clock changes cannot end the local monotonic countdown');
monotonic += 1000; document.dispatchEvent(new window.Event('visibilitychange'));
assert.equal($('sign-in').disabled, false);
assert.equal($('login-backoff').hidden, true);
assert.equal(requests.length, beforeBlockedSubmit, 'Countdown completion never resubmits a password');
await login();
checks++;

const scoreBeforeThrottle = $('risk-score').textContent;
backoffNext = true;
$('password').value = 'VelaDemo!42'; dispatch('login-form', 'submit');
await waitFor(() => !$('fill-demo').disabled);
assert.equal($('sign-in').disabled, true);
assert.match($('login-backoff').textContent, /Wait 4s/);
assert.match($('login-feedback').textContent, /was not checked/);
assert.equal($('workspace-panel').hidden, true);
assert.equal($('risk-score').textContent, scoreBeforeThrottle, 'Known throttling does not erase earlier risk evidence');
await reset();
assert.equal($('login-backoff').hidden, true);
assert.equal($('event-total').textContent, '0 EVENTS');
checks++;

failNext = true; await login();
assert.equal($('risk-score').textContent, '—'); assert.equal($('workspace-panel').hidden, true);
assert.match($('login-feedback').textContent, /Risk is unknown/);
assert.equal(document.toString().includes('private-server-error'), false);
checks++;
await reset(); deferNext = true;
$('password').value = 'VelaDemo!42'; dispatch('login-form', 'submit');
await waitFor(() => typeof deferred === 'function');
assert.equal($('password').value, ''); const release = deferred; deferred = null;
await reset(); release(); await new Promise(resolve => realTimeout(resolve, 20));
assert.equal($('event-total').textContent, '0 EVENTS'); assert.equal($('workspace-panel').hidden, true);
checks++;
await login(); $('password').value = 'unsent-private-unit';
const startsBeforeExpiry = requests.filter(item => item.url.endsWith('/start')).length;
time += 300000; document.dispatchEvent(new window.Event('visibilitychange'));
await new Promise(resolve => realTimeout(resolve, 20));
assert.equal($('password').value, ''); assert.equal($('workspace-panel').hidden, true);
assert.equal($('sign-in').disabled, true);
assert.equal(requests.filter(item => item.url.endsWith('/start')).length, startsBeforeExpiry);
assert.match($('simulation-status').textContent, /Time expired/);
checks++;
await reset(); deferNext = true; $('password').value = 'VelaDemo!42'; dispatch('login-form', 'submit');
await waitFor(() => typeof deferred === 'function');
const leaveRelease = deferred; deferred = null;
window.dispatchEvent(new window.Event('pagehide')); leaveRelease();
await new Promise(resolve => realTimeout(resolve, 20));
assert.equal($('event-total').textContent, '0 EVENTS'); assert.equal($('workspace-panel').hidden, true);
assert.equal($('password').value, ''); assert.equal($('sign-in').disabled, true);
checks++;
await reset();
forceResponse = value => ({ ...value, allowed_access: true, latest: { ...value.latest, score: null } });
await login();
assert.equal($('workspace-panel').hidden, true); assert.equal($('risk-score').textContent, '—');
checks++;
for (const { url, options } of requests) {
  assert.match(url, /^\.\/api\/demo\/(start|attempt|simulate|mfa|reset|feedback)$/);
  assert.equal(options.method, 'POST');
  assert.equal(options.headers['Content-Type'], 'application/json'); assert.equal(options.headers['X-Sentinel-Demo'], '1');
  assert.equal(options.credentials, 'omit'); assert.equal(options.cache, 'no-store'); assert.equal(options.redirect, 'error');
}
assert.equal(document.querySelectorAll('input[name]').length, 0);
assert.equal(document.querySelector('#cancel-simulation'), null);
assert.equal(timers.size, 0);
checks++;
console.log(checks + ' company DOM checks passed (local server contract; no visual verification).');

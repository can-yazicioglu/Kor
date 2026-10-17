import { createReliabilityApi, LoginBackoffError, AccessDeniedError } from './reliability-api.js';
import { renderInsights, updateInsightLifetime } from './insights.js';
import { renderAssurance } from './assurance.js';

// The server owns credentials, rolling counters, risk, policy and MFA decisions.
// Browser panels are a presentation layer, never an authentication boundary.
const $ = id => document.getElementById(id);
const request = createReliabilityApi();
const emptySnapshot = () => ({ latest: null, total: 0, timeline: [], remaining_ms: 300000, allowed_access: false, mfa_required: false, login_retry_after_ms: 0 });
let snapshot = emptySnapshot();
let demoToken = null, controller = null, generation = 0, deadline = null, busy = false;
let serviceStatus = null, requestFailed = false;
let loginRetryAt = 0;
let insightsReceivedAt = 0;
const makeNode = (tag, text, className = '') => {
  const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
};
function feedback(message, tone = '') {
  $('login-feedback').textContent = message; $('login-feedback').dataset.tone = tone;
}
function clearCredentials() { $('username').value = 'demo'; $('password').value = ''; $('mfa-code').value = ''; }
function showPanel(name) { for (const panel of ['login', 'mfa', 'workspace']) $(panel + '-panel').hidden = panel !== name; }
function setBusy(value) {
  busy = value;
  for (const id of ['sign-in', 'mfa-submit', 'run-brute', 'run-spray', 'run-distributed', 'fill-demo', 'fill-common', 'fill-similar', 'login-context', 'refresh-insights', 'prepare-unusual', 'open-resource', 'try-restricted']) {
    $(id).disabled = value || !demoToken;
  }
  for (const id of ['feedback-normal', 'feedback-suspicious']) $(id).disabled = value || !demoToken || !snapshot.latest || requestFailed;
  $('sign-in').disabled = value || !demoToken || performance.now() < loginRetryAt;
  $('check-receipt').disabled = value || !demoToken || !snapshot.latest || requestFailed;
}
function invalidate() {
  generation++;
  controller?.abort(); controller = null;
  loginRetryAt = 0;
  clearCredentials();
  $('resource-result').textContent = 'The public employee fixture never receives administrator access.';
}
function updateLifetime() {
  const left = deadline === null ? null : Math.max(0, deadline - Date.now());
  $('demo-lifetime').textContent = left === null ? 'No active server session.' : 'Server session expires in ' + Math.ceil(left / 60000) + ' min';
  updateInsightLifetime(document, requestFailed ? null : snapshot.insights, Math.max(0, performance.now() - insightsReceivedAt));
  if (snapshot.allowed_access && snapshot.assurance &&
      performance.now()-insightsReceivedAt >= snapshot.assurance.authorization.expires_in_ms) {
    snapshot = { ...snapshot, allowed_access:false, assurance:{ ...snapshot.assurance,
      authorization:{ role:'anonymous', workspace_allowed:false, audit_allowed:false, expires_in_ms:0 } } };
    showPanel('login');
    $('resource-result').textContent = 'The displayed workspace grant expired. Sign in again; the server checks every resource request.';
    renderAssurance(document, snapshot.assurance);
  }
  updateLoginDelay();
}
function updateLoginDelay() {
  const seconds = Math.max(0, Math.ceil((loginRetryAt-performance.now())/1000));
  const note = $('login-backoff');
  note.hidden = seconds === 0;
  const message = seconds ? `Wait ${seconds}s before another sign-in. Repeated incorrect passwords double the delay, up to 60s.` : '';
  if (note.textContent !== message) note.textContent = message;
  setBusy(busy);
}
const verificationLabels = {
  not_verified: 'Not verified', password_verified: 'Password verified by local server',
  mfa_verified: 'Demo MFA verified by local server', passkey_verified: 'Passkey verified by local server',
};
function render() {
  const result = snapshot.latest;
  $('event-total').textContent = snapshot.total + ' EVENTS';
  $('risk-score').textContent = result?.score === null || !result || requestFailed ? '—' : String(result.score);
  $('session-peak').textContent = result?.peak_score === null || !result || requestFailed ? '—' : String(result.peak_score);
  $('risk-label').textContent = requestFailed ? 'Unknown risk' : !result ? 'No attempts yet' : result.score === null ? 'Unknown risk' : result.action_label;
  $('live-risk').dataset.level = requestFailed || result?.score === null ? 'pending' : !result ? 'idle' : result.action === 'review' ? 'high' : result.action === 'mfa' ? 'medium' : 'low';
  $('risk-fill').style.width = (!requestFailed && result?.score !== null ? result?.score ?? 0 : 0) + '%';
  $('risk-action').textContent = requestFailed ? 'Review service availability. No access granted.' : result?.action_label ?? 'Start with a demonstration sign-in.';
  $('live-reasons').replaceChildren();
  const reasons = requestFailed ? ['The last request could not be verified. Unknown risk is not treated as safe.'] :
    !result ? ['The local server scores each attempt and independently checks access.'] :
    result.reasons.length ? result.reasons : ['No explanation was returned by the server.'];
  for (const reason of reasons) $('live-reasons').append(makeNode('li', reason));
  const signals = result?.signals;
  for (const [id, key] of [['attempt-count', 'attempts_2m'], ['account-count', 'distinct_accounts_2m'], ['source-count', 'distinct_sources_2m'], ['failure-count', 'consecutive_failures']]) {
    $(id).textContent = requestFailed || signals?.[key] === null || signals?.[key] === undefined ? '—' : String(signals[key]);
  }
  $('success-after-failures').textContent = requestFailed || signals?.success_after_failures === null || signals?.success_after_failures === undefined ? 'Unknown' : signals.success_after_failures ? 'Yes' : 'No';
  const quality = result?.data_quality;
  $('data-quality').textContent = requestFailed ? 'Unknown' : quality ? quality.level.charAt(0).toUpperCase() + quality.level.slice(1) : 'Not evaluated';
  $('data-quality-note').textContent = requestFailed ? 'No verified service response is available.' : quality?.missing_features.length ?
    'Missing context: ' + quality.missing_features.join(', ') + '. Missing context is not assumed safe.' :
    quality?.action_threshold_available === false ? 'No validated action threshold is available. Human review is the conservative fallback; a low numeric score is not an access decision.' :
    quality ? 'Available context was assessed by the server. Synthetic context is not real user history.' : 'Context quality will be shown after the first attempt.';
  $('verification-status').textContent = requestFailed ? 'Verification unavailable' : verificationLabels[result?.verification] ?? 'Not verified';
  $('policy-version').textContent = result && !requestFailed ? 'Policy: ' + result.policy_version + ' · Model: ' + result.model_version : 'No evaluated policy result yet.';
  const credential = result?.credential_risk;
  $('base-risk-score').textContent = requestFailed || result?.base_score === null || !result ? '—' : String(result.base_score);
  $('password-match').textContent = requestFailed ? 'Unknown' : !credential ? 'Not checked' : credential.status !== 'checked' ? 'Unknown' :
    ({ exact: 'Exact reference match', near: 'Close variation', none: 'No reference match', unknown: 'Unknown' })[credential.match];
  $('credential-strength').textContent = requestFailed || !credential || credential.status !== 'checked' ? 'Unknown' : credential.match === 'none' ? 'No listed match' : 'Weakness signal';
  $('password-check-note').textContent = 'Credential weakness is separate from behavioral risk; no fixed score is added. A bounded reference set cannot prove a password safe. Checks run only on the local customer server.';
  $('attempt-timeline').replaceChildren();
  const eventLabels = { login_success: 'Password accepted', login_failure: 'Sign-in failed', mfa_success: 'Demo MFA accepted', mfa_failure: 'Demo MFA failed' };
  for (const event of snapshot.timeline) {
    const item = makeNode('li', '');
    item.append(makeNode('span', event.event_type.endsWith('success') ? '✓' : '·'), makeNode('span', eventLabels[event.event_type] ?? 'Synthetic demo event'), makeNode('strong', event.score === null ? '—' : String(event.score)));
    $('attempt-timeline').append(item);
  }
  if (!snapshot.total) $('attempt-timeline').append(makeNode('li', 'No server-recorded attempts yet.', 'empty-event'));
  const summary = snapshot.feedback_summary;
  $('feedback-status').textContent = summary && typeof summary === 'object' ? 'Synthetic review labels recorded by the local server.' : 'Label the latest synthetic event for review. This does not change access.';
  renderInsights(document, requestFailed ? null : snapshot.insights);
  renderAssurance(document, requestFailed ? null : snapshot.assurance, requestFailed ? null : snapshot.security_test);
  $('context-guard-status').textContent = requestFailed || !result?.context_guard ?
    'The context safeguard is evaluated after a server-verified login. It does not add score points.' :
    result.context_guard.triggered ? 'Context safeguard triggered: a successful password login combines a new device, unfamiliar network and unusual context. Additional verification recommended.' :
    result.context_guard.carried ? 'Earlier context evidence is retained in this two-minute session; verification does not erase it.' :
    'No combined-context safeguard triggered. This is not proof that the login is safe.';
  updateLifetime(); setBusy(busy);
}
function serviceText() {
  const ready = serviceStatus && ['model_ready', 'policy_ready', 'reference_ready'].every(key => serviceStatus[key]);
  $('company-model-status').textContent = ready ? 'Local server ready · model, policy and reference available' :
    demoToken ? 'Some risk checks are unavailable · the server remains authoritative' : 'Local verification service unavailable · reset to reconnect';
}
function applySnapshot(value) {
  snapshot = value;
  insightsReceivedAt = performance.now();
  loginRetryAt = value.login_retry_after_ms ? performance.now()+value.login_retry_after_ms : 0;
  requestFailed = false;
  deadline = Math.min(deadline ?? Infinity, Date.now() + value.remaining_ms);
  if (value.status) serviceStatus = value.status;
  render();
}
function showOutcome() {
  // No client-side password comparison, score threshold or code can grant access.
  if (requestFailed) { showPanel('login'); return; }
  if (snapshot.allowed_access === true) {
    $('welcome-note').textContent = 'The local server authorized this synthetic workspace. ' + (snapshot.latest?.action === 'review' ? 'Security review remains recommended.' : 'No real company resources are exposed.');
    showPanel('workspace');
  } else if (snapshot.mfa_required === true) {
    $('mfa-feedback').textContent = 'The local server requires demo MFA. Code verification and access decisions stay on the server.';
    showPanel('mfa'); $('mfa-code').focus();
  } else {
    showPanel('login');
    feedback(snapshot.latest?.success ? 'Credentials verified, but the server has not granted access. Review the context and service status.' : 'The local server did not authorize this sign-in.', 'error');
  }
}
function failClosed(message = 'The local service could not verify this request. Risk is unknown; no access is granted.') {
  requestFailed = true;
  snapshot = { ...snapshot, allowed_access: false, mfa_required: false, insights: undefined };
  showPanel('login'); feedback(message, 'error'); render();
}
function expireIfNeeded() {
  if (deadline === null || Date.now() < deadline) return false;
  const token = demoToken;
  invalidate(); demoToken = null; deadline = null; serviceStatus = null; snapshot = emptySnapshot(); requestFailed = true;
  $('simulation-status').textContent = 'Time expired. Local form and view were cleared. Reset to start a new server session.';
  failClosed('The demo session expired. Reset the demo to reconnect.'); setBusy(false); serviceText();
  if (token) request('reset', { demo_token: token }, { keepalive: true }).catch(() => {});
  return true;
}
async function begin() {
  const current = ++generation;
  controller = new AbortController(); setBusy(true);
  $('company-model-status').textContent = 'Connecting to the local verification service…';
  try {
    const started = await request('start', {}, { signal: controller.signal });
    if (current !== generation) return;
    demoToken = started.demo_token; serviceStatus = started.status;
    applySnapshot(started.snapshot); serviceText(); feedback('Use public demo credentials only. Verification runs on the local server.');
  } catch {
    if (current === generation) { demoToken = null; failClosed(); serviceText(); }
  } finally { if (current === generation) { controller = null; setBusy(false); } }
}
async function perform(operation, payload) {
  if (expireIfNeeded() || busy || !demoToken) return;
  if (operation === 'attempt' && performance.now() < loginRetryAt) { updateLoginDelay(); return; }
  const current = ++generation;
  controller = new AbortController(); setBusy(true);
  try {
    const result = await request(operation, { demo_token: demoToken, ...payload }, { signal: controller.signal });
    if (current !== generation || expireIfNeeded()) return;
    applySnapshot(operation === 'resource' ? result.snapshot : result); serviceText();
    if (operation === 'resource') $('resource-result').textContent = result.resource.message;
    if (operation === 'feedback') $('feedback-status').textContent = 'Synthetic review label saved. Access decisions are unchanged.';
    else if (['status', 'proof', 'resource'].includes(operation)) {
      if (!snapshot.allowed_access && !snapshot.mfa_required) showPanel('login');
    } else showOutcome();
    if (operation === 'simulate') $('simulation-status').textContent = 'The local server replayed synthetic events. No remote login attempts were made. Replay does not change the interactive sign-in delay.';
  } catch (error) {
    if (current === generation) {
      if (error instanceof AccessDeniedError && operation === 'resource') {
        $('resource-result').textContent = error.message;
      } else if (error instanceof LoginBackoffError && operation === 'attempt') {
        loginRetryAt = performance.now()+error.retryAfterMs;
        snapshot = { ...snapshot, allowed_access: false, mfa_required: false, mfa_challenge_id: null };
        showPanel('login');
        feedback('This sign-in was not checked because the waiting period is still active.');
        updateLoginDelay();
      } else failClosed();
    }
  } finally { if (current === generation) { controller = null; setBusy(false); } }
}
async function resetDemo() {
  const previous = demoToken;
  invalidate(); demoToken = null; deadline = null; snapshot = emptySnapshot(); requestFailed = false; serviceStatus = null;
  showPanel('login'); $('login-context').value = 'familiar'; render(); setBusy(true);
  $('simulation-status').textContent = 'Clearing the local server session…';
  const current = generation;
  try {
    if (previous) await request('reset', { demo_token: previous });
    if (current !== generation) return;
    $('simulation-status').textContent = 'Previous server state deleted. Starting a fresh synthetic session.';
    await begin();
  } catch {
    if (current === generation) { failClosed('The local view was cleared, but server deletion could not be confirmed. Server state expires after five minutes. Reset to reconnect.'); setBusy(false); serviceText(); }
  }
}
$('login-form').addEventListener('submit', event => {
  event.preventDefault();
  const body = { username: $('username').value.trim(), password: $('password').value, context: $('login-context').value };
  clearCredentials();
  if (body.username !== 'demo' || !body.password || body.password.length > 256) {
    feedback('Only the public demo account is supported. Never enter real credentials.', 'error'); return;
  }
  perform('attempt', body);
});
$('mfa-form').addEventListener('submit', event => {
  event.preventDefault(); const code = $('mfa-code').value; $('mfa-code').value = '';
  if (!snapshot.mfa_required || !/^\d{6}$/.test(code)) { $('mfa-feedback').textContent = 'Enter the six-digit demo code. The server performs verification.'; return; }
  perform('mfa', { code, challenge_id: snapshot.mfa_challenge_id });
});
for (const [id, password] of [['fill-demo', 'VelaDemo!42'], ['fill-common', 'password'], ['fill-similar', 'pASsW0rD!!']]) $(id).addEventListener('click', () => {
  if (expireIfNeeded() || busy || !demoToken) return;
  $('username').value = 'demo'; $('password').value = password; showPanel('login'); $('sign-in').focus();
});
for (const [id, kind] of [['run-brute', 'brute'], ['run-spray', 'spray'], ['run-distributed', 'distributed']]) $(id).addEventListener('click', () => {
  if (expireIfNeeded() || busy || !demoToken) return;
  clearCredentials(); showPanel('login'); $('simulation-status').textContent = 'Running a bounded synthetic batch on the local server…';
  perform('simulate', { kind, context: $('login-context').value });
});
for (const [id, label] of [['feedback-normal', 'normal'], ['feedback-suspicious', 'suspicious']]) $(id).addEventListener('click', () => {
  if (snapshot.latest && !requestFailed) perform('feedback', { event_id: snapshot.latest.event_id, label });
});
function returnToLogin() { if (expireIfNeeded() || busy) return; clearCredentials(); showPanel('login'); feedback('Back to the sign-in form. The server keeps the two-minute context until expiry.'); }
$('sign-out').addEventListener('click', resetDemo);
$('back-to-login').addEventListener('click', returnToLogin);
$('login-context').addEventListener('change', returnToLogin);
$('reset-company').addEventListener('click', resetDemo);
$('refresh-insights').addEventListener('click', () => perform('status', {}));
$('check-receipt').addEventListener('click', () => perform('proof', {}));
$('open-resource').addEventListener('click', () => perform('resource', { resource:'workspace' }));
$('try-restricted').addEventListener('click', () => perform('resource', { resource:'audit_console' }));
$('prepare-unusual').addEventListener('click', () => {
  if (expireIfNeeded() || busy || !demoToken) return;
  $('login-context').value = 'unusual_success';
  $('username').value = 'demo'; $('password').value = 'VelaDemo!42';
  showPanel('login'); $('sign-in').focus();
  feedback('Synthetic unusual-success example loaded. Press Sign in to verify it on the server.');
});
window.addEventListener('pagehide', () => {
  const token = demoToken;
  invalidate(); demoToken = null; deadline = null; snapshot = emptySnapshot(); requestFailed = true;
  showPanel('login'); render(); setBusy(false);
  if (token) request('reset', { demo_token: token }, { keepalive: true }).catch(() => {});
});
window.addEventListener('pageshow', () => { if (!expireIfNeeded()) updateLifetime(); });
document.addEventListener('visibilitychange', () => { if (!expireIfNeeded()) updateLifetime(); });
setInterval(() => { if (!expireIfNeeded()) updateLifetime(); }, 1000);
render(); begin();

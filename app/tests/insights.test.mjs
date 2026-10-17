// Pure contract and DOM checks. No model training or empirical performance claims.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseHTML } from 'linkedom';
import { validateInsights, renderInsights, updateInsightLifetime } from '../insights.js';
import { validateSnapshot, createReliabilityApi } from '../reliability-api.js';

const { document } = parseHTML(await readFile(new URL('../company.html', import.meta.url), 'utf8'));
const $ = id => document.getElementById(id);
const empty = () => ({ version: 'els-insights-v1', latest_event_age_seconds: null,
  history_sensitivity: null, decision_delta: null,
  lifecycle: { events: 0, review_labels: 0, account_mappings: 0, session_mappings: 0, source_mappings: 0,
    expires_in_ms: 300000, pending_mfa: false, mfa_expires_in_ms: null, interactive_failures: 0 } });
const active = () => ({ ...empty(), latest_event_age_seconds: 4,
  lifecycle: { ...empty().lifecycle, events: 9, account_mappings: 1, session_mappings: 1, source_mappings: 1 },
  history_sensitivity: { anchor: 'latest_event', smallest_matching_window_seconds: 120,
    rows: [30, 60, 120].map(window => ({ window_seconds: window, account_attempts: window === 120 ? 9 : 1,
      account_failures: window === 120 ? 8 : 0, failed_sources: window === 120 ? 1 : 0,
      source_failed_accounts: window === 120 ? 1 : 0, source_failure_ratio: window === 120 ? 8 / 9 : 0,
      observation_complete: true, rules: window === 120 ? ['account_failures'] : [],
      lost_rules: window === 120 ? [] : ['account_failures'], gained_rules: [] })) },
  decision_delta: { has_previous: true, previous_score: 70, current_score: 60, score_delta: -10,
    previous_action: 'review', current_action: 'review', basis: 'threshold_unavailable_review', changes: [
      { field: 'verification', before: 'password_verified', after: 'mfa_verified' },
      { field: 'mfa_failures_2m', before: 1, after: 2 },
    ] },
});
let checks = 0;
validateInsights(empty()); renderInsights(document, empty());
assert.equal($('history-rows').children.length, 0);
assert.match($('lifetime-inventory').textContent, /Event records/);
assert.match($('lifetime-countdown').textContent, /300s/);
checks++;

validateInsights(active()); renderInsights(document, active());
assert.equal($('history-rows').children.length, 3);
assert.match($('history-rows').textContent, /Lost: Repeated account failures/);
assert.match($('history-summary').textContent, /120s is the shortest tested/);
assert.match($('decision-summary').textContent, /70 → 60 · change -10/);
assert.match($('decision-basis').textContent, /no validated action threshold/);
assert.match($('decision-changes').textContent, /Password verified → MFA verified/);
checks++;

const unknown = active();
unknown.decision_delta.previous_score = null; unknown.decision_delta.score_delta = null;
validateInsights(unknown); renderInsights(document, unknown);
assert.match($('decision-summary').textContent, /Unscored → 60 · change unavailable/);
assert.doesNotMatch($('decision-summary').textContent, /change \+60/);
checks++;

for (const mutate of [
  value => { value.decision_delta.changes[0].after = '<img src=x onerror=alert(1)>'; },
  value => { value.decision_delta.current_action = ['review']; },
  value => { value.account_token = 'unexpected-private-field'; },
  value => { value.history_sensitivity.rows[0].account_failures = 5001; },
  value => { value.history_sensitivity.rows[0].lost_rules = []; },
  value => { value.history_sensitivity.rows[0].source_failure_ratio = NaN; },
  value => { value.history_sensitivity.smallest_matching_window_seconds = 30; },
  value => { value.decision_delta.score_delta = 60; },
  value => { value.decision_delta.has_previous = false; },
  value => { value.lifecycle.pending_mfa = true; },
  value => { value.lifecycle.expires_in_ms = 300001; },
]) {
  const malformed = active(); mutate(malformed); assert.throws(() => validateInsights(malformed));
}
assert.equal(document.querySelector('#decision-changes img'), null);
checks++;

const expires = active(); expires.lifecycle.pending_mfa = true; expires.lifecycle.mfa_expires_in_ms = 60000;
validateInsights(expires); updateInsightLifetime(document, expires, 61000);
assert.match($('lifetime-countdown').textContent, /239s/);
assert.match($('lifetime-countdown').textContent, /0s until expiry is due/);
updateInsightLifetime(document, expires, 300000);
assert.match($('lifetime-countdown').textContent, /Expiry is due/);
assert.doesNotMatch($('lifetime-countdown').textContent, /deleted|erased/);
checks++;

renderInsights(document, null);
assert.equal($('history-rows').children.length, 0);
assert.equal($('decision-changes').children.length, 0);
assert.equal($('lifetime-inventory').children.length, 0);
assert.match($('history-summary').textContent, /unavailable/);
assert.match($('lifetime-countdown').textContent, /No current server inventory/);
checks++;

const snapshot = { latest: null, total: 0, timeline: [], remaining_ms: 300000, login_retry_after_ms: 0,
  allowed_access: false, mfa_required: false, mfa_challenge_id: null, insights: empty() };
validateSnapshot(snapshot);
assert.throws(() => validateSnapshot({ ...snapshot, insights: active() }));
assert.throws(() => validateSnapshot({ ...snapshot, insights: { ...empty(), lifecycle: { ...empty().lifecycle, expires_in_ms: 200000 } } }));
checks++;

let calls = 0;
const request = createReliabilityApi(async (url, options) => {
  calls++; assert.equal(url, './api/demo/status');
  assert.deepEqual(JSON.parse(options.body), { demo_token: 'public-fixture-handle-0000' });
  return new Response(JSON.stringify(snapshot), { headers: { 'Content-Type': 'application/json' } });
});
assert.equal((await request('status', { demo_token: 'public-fixture-handle-0000' })).total, 0);
assert.equal(calls, 1);
checks++;
console.log(checks + ' evidence and privacy DOM/contract checks passed (no visual verification).');

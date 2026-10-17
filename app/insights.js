// Identifier-free diagnostics. These never grant access or alter a risk score.
const rules = {
  account_failures: 'Repeated account failures',
  distributed_failures: 'Distributed failures',
  source_spraying: 'Failure-dominant spraying',
};
const actions = { monitor: 'Monitor', mfa: 'MFA recommended', review: 'Review recommended' };
const verification = { not_verified: 'Not verified', password_verified: 'Password verified', mfa_verified: 'MFA verified', passkey_verified: 'Passkey verified' };
const credentials = { not_password_authentication: 'No password authentication', verified_password_weakness: 'Verified weakness', attempted_value_only: 'Failed submitted value only', no_weakness_established: 'No weakness established' };
const outcomes = { login_success: 'Sign-in accepted', login_failure: 'Sign-in failed', mfa_success: 'MFA accepted', mfa_failure: 'MFA failed' };
const fields = {
  attempts_2m: 'Account attempts', account_failures_2m: 'Account failures',
  distinct_failed_sources_2m: 'Failing sources', source_failed_accounts_2m: 'Failed accounts on source',
  mfa_failures_2m: 'MFA failures', missing_features: 'Missing features',
  sequence_action_floor: 'Sequence recommendation', verification: 'Verification',
  credential_evidence: 'Credential evidence', outcome: 'Event outcome',
};
const vocab = { sequence_action_floor: actions, verification, credential_evidence: credentials, outcome: outcomes };
const owns = (object, key) => typeof key === 'string' && Object.hasOwn(object, key);
const count = value => Number.isInteger(value) && value >= 0 && value <= 5000;
const score = value => value === null || Number.isInteger(value) && value >= 0 && value <= 100;
const finite = (value, max) => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= max;
const keys = (value, names) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === names.split(' ').sort().join(',');
const ruleList = value => Array.isArray(value) && value.length <= 3 && new Set(value).size === value.length && value.every(name => owns(rules, name));
const sameSet = (a, b) => a.length === b.length && a.every(name => b.includes(name));

export function validateInsights(value) {
  const invalid = () => { throw new Error('Unsupported diagnostic response.'); };
  if (!keys(value, 'version history_sensitivity decision_delta latest_event_age_seconds lifecycle') || value.version !== 'els-insights-v1') invalid();
  const life = value.lifecycle;
  if (!keys(life, 'events review_labels account_mappings session_mappings source_mappings expires_in_ms pending_mfa mfa_expires_in_ms interactive_failures') ||
      !['events', 'review_labels', 'account_mappings', 'session_mappings', 'source_mappings', 'interactive_failures'].every(name => count(life[name])) ||
      life.review_labels > life.events || !finite(life.expires_in_ms, 300000) || typeof life.pending_mfa !== 'boolean' ||
      (life.pending_mfa ? !finite(life.mfa_expires_in_ms, Math.min(120000, life.expires_in_ms)) : life.mfa_expires_in_ms !== null)) invalid();
  if (life.events === 0) {
    if (value.history_sensitivity !== null || value.decision_delta !== null || value.latest_event_age_seconds !== null) invalid();
    return value;
  }
  if (!finite(value.latest_event_age_seconds, 300)) invalid();
  const history = value.history_sensitivity;
  if (!keys(history, 'anchor rows smallest_matching_window_seconds') || history.anchor !== 'latest_event' || !Array.isArray(history.rows) || history.rows.length !== 3) invalid();
  const windows = [30, 60, 120];
  for (const [index, row] of history.rows.entries()) {
    if (!keys(row, 'window_seconds account_attempts account_failures failed_sources source_failed_accounts source_failure_ratio observation_complete rules lost_rules gained_rules') ||
        row.window_seconds !== windows[index] || !['account_attempts', 'account_failures', 'failed_sources', 'source_failed_accounts'].every(name => count(row[name])) ||
        row.account_failures > row.account_attempts || row.failed_sources > row.account_failures ||
        row.source_failure_ratio !== null && !finite(row.source_failure_ratio, 1) || typeof row.observation_complete !== 'boolean' ||
        ![row.rules, row.lost_rules, row.gained_rules].every(ruleList)) invalid();
  }
  const baseline = history.rows[2];
  for (const row of history.rows) {
    if (!sameSet(row.lost_rules, baseline.rules.filter(name => !row.rules.includes(name))) ||
        !sameSet(row.gained_rules, row.rules.filter(name => !baseline.rules.includes(name)))) invalid();
  }
  const smallest = baseline.observation_complete && baseline.rules.length ? history.rows.find(row => row.observation_complete && sameSet(row.rules, baseline.rules))?.window_seconds ?? null : null;
  if (history.smallest_matching_window_seconds !== smallest) invalid();
  const delta = value.decision_delta;
  if (!keys(delta, 'has_previous previous_score current_score score_delta previous_action current_action basis changes') || typeof delta.has_previous !== 'boolean' ||
      !score(delta.previous_score) || !score(delta.current_score) || !owns(actions, delta.current_action) ||
      (delta.has_previous ? !owns(actions, delta.previous_action) : delta.previous_action !== null || delta.previous_score !== null) ||
      !['unscored_review', 'threshold_unavailable_review', 'model_and_sequence'].includes(delta.basis) ||
      !Array.isArray(delta.changes) || delta.changes.length > 10 || new Set(delta.changes.map(change => change?.field)).size !== delta.changes.length) invalid();
  const difference = delta.has_previous && delta.previous_score !== null && delta.current_score !== null ? delta.current_score - delta.previous_score : null;
  if (delta.score_delta !== difference || !delta.has_previous && delta.changes.length) invalid();
  for (const change of delta.changes) {
    if (!keys(change, 'field before after') || !owns(fields, change.field) || change.before === change.after) invalid();
    const valid = item => owns(vocab, change.field) ? owns(vocab[change.field], item) : count(item) && (change.field !== 'missing_features' || item <= 11);
    if (!valid(change.before) || !valid(change.after)) invalid();
  }
  return value;
}

const ruleText = names => names.length ? names.map(name => rules[name]).join('; ') : 'None';
const scoreText = value => value === null ? 'Unscored' : String(value);
const changeText = (field, value) => owns(vocab, field) ? vocab[field][value] : String(value);

export function renderInsights(document, value) {
  const $ = id => document.getElementById(id);
  const node = (tag, text) => { const result = document.createElement(tag); result.textContent = text; return result; };
  $('history-rows').replaceChildren(); $('decision-changes').replaceChildren(); $('lifetime-inventory').replaceChildren();
  $('insights-age').textContent = value?.latest_event_age_seconds === null || !value ? 'No evaluated event.' : `Latest event was ${Math.floor(value.latest_event_age_seconds)}s old at refresh.`;
  $('history-summary').textContent = value ? 'Record a sign-in to compare observed history.' : 'Diagnostics unavailable. Refresh or reconnect to the local server.';
  $('decision-summary').textContent = value ? 'No evaluated event yet.' : 'No verified diagnostic response.';
  $('decision-basis').textContent = '';
  if (value?.history_sensitivity) {
    const history = value.history_sensitivity;
    for (const row of history.rows) {
      const tr = document.createElement('tr');
      const heading = node('th', `${row.window_seconds}s${row.window_seconds === 120 ? ' · live' : ''}`); heading.scope = 'row'; tr.append(heading);
      tr.append(node('td', `${row.account_failures} / ${row.account_attempts}`), node('td', String(row.failed_sources)),
        node('td', `${row.source_failed_accounts} (${row.source_failure_ratio === null ? '—' : Math.round(row.source_failure_ratio * 100) + '%'})`));
      const detail = node('td', ruleText(row.rules));
      if (row.lost_rules.length) detail.append(node('small', 'Lost: ' + ruleText(row.lost_rules)));
      if (row.gained_rules.length) detail.append(node('small', 'Added: ' + ruleText(row.gained_rules)));
      if (!row.observation_complete) detail.append(node('small', 'Incomplete observation; counts are lower bounds.'));
      tr.append(detail); $('history-rows').append(tr);
    }
    $('history-summary').textContent = history.smallest_matching_window_seconds === null ?
      'No complete, active 120s rule set to match. No shorter-window sufficiency claim can be made.' :
      `${history.smallest_matching_window_seconds}s is the shortest tested window preserving the current three-rule result. This is one observation, not a safe retention recommendation.`;
  }
  if (value?.decision_delta) {
    const delta = value.decision_delta;
    $('decision-summary').textContent = delta.has_previous ?
      `${scoreText(delta.previous_score)} → ${scoreText(delta.current_score)}${delta.score_delta === null ? ' · change unavailable' : ' · change ' + (delta.score_delta > 0 ? '+' : '') + delta.score_delta}. ${actions[delta.previous_action]} → ${actions[delta.current_action]}.` :
      `First retained event in this account session: ${scoreText(delta.current_score)} · ${actions[delta.current_action]}.`;
    $('decision-basis').textContent = {
      unscored_review: 'Review fallback: the event could not be scored. Unknown is not low risk.',
      threshold_unavailable_review: 'Review fallback: this score has no validated action threshold. A review recommendation alone does not prove an attack.',
      model_and_sequence: 'The calibrated score and sequence rules determine the recommendation.',
    }[delta.basis];
    for (const change of delta.changes) $('decision-changes').append(node('li', `${fields[change.field]}: ${changeText(change.field, change.before)} → ${changeText(change.field, change.after)}`));
    if (delta.has_previous && !delta.changes.length) $('decision-changes').append(node('li', 'No change in the tracked evidence fields. Other model inputs can still change the score.'));
  }
  if (value) {
    const life = value.lifecycle;
    const rows = [
      ['Event records (opaque IDs + signals)', life.events],
      ['Account / session / source map entries', `${life.account_mappings} / ${life.session_mappings} / ${life.source_mappings}`],
      ['Human review labels', life.review_labels],
      ['Consecutive interactive failures', life.interactive_failures],
      ['Pending demo MFA challenge', life.pending_mfa ? 'Yes' : 'No'],
    ];
    for (const [label, count] of rows) { $('lifetime-inventory').append(node('dt', label), node('dd', String(count))); }
  }
  updateInsightLifetime(document, value, 0);
}

export function updateInsightLifetime(document, value, elapsedMs) {
  const target = document.getElementById('lifetime-countdown');
  if (!value) { target.textContent = 'No current server inventory.'; return; }
  const left = Math.max(0, Math.ceil((value.lifecycle.expires_in_ms - elapsedMs) / 1000));
  const mfa = value.lifecycle.pending_mfa ? ` MFA challenge: ${Math.max(0, Math.ceil((value.lifecycle.mfa_expires_in_ms - elapsedMs) / 1000))}s until expiry is due.` : '';
  target.textContent = left ? `Application state expires in approximately ${left}s.${mfa}` : 'Expiry is due. Refresh to confirm server availability.';
}

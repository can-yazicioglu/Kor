import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { CSV_COLUMNS, FEATURE_COLUMNS, parseCSV, selectFeatures, recommendation } from '../schema.js';
import { createPredictor, validateModel, loadModel, predictRisk, getModelStatus } from '../model-adapter.js';
import { buildSessions } from '../sessions.js';
import { createRetention } from '../lifecycle.js';

const root = new URL('../../', import.meta.url);
const read = path => readFile(new URL(path, root), 'utf8');
const model = JSON.parse(await read('models/demo_model.json'));
const parity = JSON.parse(await read('outputs/parity_cases.json'));
const csvText = await read('data/mvp_synthetic_logins.csv');
const events = parseCSV(csvText);
const predictor = createPredictor(model);
let count = 0;
const check = async (name, action) => { await action(); count++; };

await check('Actual delivered CSV accepted unchanged', () => {
  assert.equal(events.length, 10000);
  assert.deepEqual(Object.keys(events[0]), CSV_COLUMNS);
  assert.ok(events.every(event => event.attempts_2m <= event.attempts_1h));
  assert.ok(events.some(event => event.network_familiarity === 'familiar'));
  assert.ok(events.some(event => event.network_familiarity === 'unfamiliar'));
});
await check('Python exported predictions and explanations match JavaScript', () => {
  assert.equal(parity.model_version, model.model_version);
  assert.ok(parity.cases.length >= 12);
  for (const item of parity.cases) {
    const result = predictor(item.features);
    if (item.expected === null) assert.equal(result, null);
    else {
      assert.equal(result.risk_score, item.expected.risk_score);
      assert.equal(result.model_version, item.expected.model_version);
      assert.deepEqual(result.reasons, item.expected.reasons);
    }
  }
});
const complete = events.find(event => predictor(selectFeatures(event)) !== null);
assert.ok(complete, 'Actual delivered CSV must contain scorable events');
await check('Changing all metadata cannot change scores/reasons', () => {
  const original = predictor(selectFeatures(complete));
  const changed = { ...complete, event_id: 'different', session_token: 'different', account_token: 'different',
    event_ts_utc: '2020-01-01T00:00:00Z', is_suspicious: 1 - complete.is_suspicious, attack_type: 'changed' };
  assert.deepEqual(predictor(selectFeatures(changed)), original);
  assert.equal(predictor({ ...selectFeatures(complete), is_suspicious: 1 }), null);
});
await check('Missing any feature and unknown categories abstain', () => {
  for (const feature of FEATURE_COLUMNS) assert.equal(predictor({ ...selectFeatures(complete), [feature]: null }), null);
  assert.equal(predictor({ ...selectFeatures(complete), network_familiarity: 'new-category' }), null);
  assert.equal(predictor({ ...selectFeatures(complete), asn_category: 'new-category' }), null);
  for (const value of [NaN, Infinity, -1, '5']) assert.equal(predictor({ ...selectFeatures(complete), attempts_2m: value }), null);
  assert.equal(predictor({ ...selectFeatures(complete), attempts_2m: 0 }), null);
  assert.equal(predictor({ ...selectFeatures(complete), geo_velocity_kmh: Number.MAX_SAFE_INTEGER + 1 }), null);
  assert.equal(predictor({ ...selectFeatures(complete), attempts_2m: complete.attempts_1h + 1 }), null);
});
await check('Entire CSV groups into max-risk sessions with abstentions preserved', async () => {
  const sessions = await buildSessions(events, predictor);
  assert.equal(sessions.length, new Set(events.map(event => event.session_token)).size);
  let pending = 0;
  for (const session of sessions) {
    const predictions = session.events.map(event => predictor(selectFeatures(event)));
    if (predictions.includes(null)) {
      assert.equal(session.score, null);
      assert.equal(recommendation(session.score).level, 'pending');
      pending++;
    } else {
      assert.equal(session.score, Math.max(...predictions.map(item => item.risk_score)));
      assert.deepEqual(session.reasons, predictor(selectFeatures(session.scoredEvent)).reasons);
    }
  }
  assert.ok(pending > 0, 'Missing-history events must not be silently scored');
});
await check('Corrupt model and feature order cannot score', () => {
  for (const mutate of [
    m => { m.feature_columns[0] = 'is_suspicious'; },
    m => { m.preprocessing.numeric[0].scale = 0; },
    m => { m.coefficients.pop(); },
    m => { m.missing_policy = 'zero'; },
    m => { m.transformed_feature_order.reverse(); },
    m => { m.preprocessing.categorical[0].categories.push('familiar'); },
    m => { m.preprocessing.categorical[0].categories.reverse(); },
    m => { m.unknown_category_policy = 'ignore'; },
    m => { m.synthetic_only = false; },
    m => { m.score_semantics = 'calibrated'; },
    m => { m.score_rounding = 'ceil'; },
    m => { m.explanation_semantics = 'causality'; },
    m => { delete m.artifact_integrity; },
    m => { m.artifact_integrity.digest = 'broken'; },
    m => { m.threshold_policy.review_score = 80; },
  ]) {
    const invalid = structuredClone(model); mutate(invalid);
    assert.throws(() => validateModel(invalid));
  }
});
await check('Artifact loads only with local GET and failed fetch removes scorer', async () => {
  await loadModel(async (url, options) => {
    assert.equal(url, './demo-model.json'); assert.equal(options.method, 'GET');
    assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
    assert.equal(options.cache, 'no-store'); assert.equal(options.body, undefined);
    return { ok: true, text: async () => JSON.stringify(model) };
  });
  assert.equal(getModelStatus().state, 'ready');
  assert.deepEqual(predictRisk(selectFeatures(complete)), predictor(selectFeatures(complete)));
  await loadModel(async () => ({ ok: false }));
  assert.equal(getModelStatus().state, 'unavailable');
  assert.equal(predictRisk(selectFeatures(complete)), null);
  await loadModel(async () => ({ ok: true, text: async () => '{invalid' }));
  assert.equal(getModelStatus().state, 'unavailable');
});
await check('Slow prior model load cannot replace latest result', async () => {
  let release;
  const slow = loadModel(() => new Promise(resolve => { release = resolve; }));
  const latest = await loadModel(async () => ({ ok: false }));
  assert.equal(latest.state, 'unavailable');
  release({ ok: true, text: async () => JSON.stringify(model) }); await slow;
  assert.equal(getModelStatus().state, 'unavailable');
});
await check('Expiry, early reset, sleeping tab and upper bound', () => {
  let now = 1000, expired = 0, callback, cancelled = 0;
  const retention = createRetention({ now: () => now, onExpire: () => expired++,
    schedule: fn => { callback = fn; return 7; }, cancel: () => cancelled++ });
  retention.start(5); now += 299999; assert.equal(retention.check(), false);
  now++; callback(); assert.equal(expired, 1); assert.equal(retention.remaining(), null);
  retention.start(15); retention.clear(); now += 1000000; retention.check(); assert.equal(expired, 1);
  retention.start(1); now += 120000; assert.equal(retention.check(), true); assert.equal(expired, 2);
  for (const minutes of [0, 16, 1.5, NaN]) assert.throws(() => retention.start(minutes));
  assert.ok(cancelled >= 3);
});
await check('Reset aborts pending session construction', async () => {
  let active = true;
  await assert.rejects(() => buildSessions(events, predictor, { active: () => active, yieldControl: async () => { active = false; } }), /iptal/);
});
console.log(`${count} JavaScript model/CSV/lifecycle integration checks passed; ${parity.cases.length} Python parity cases.`);

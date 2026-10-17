// AI 1 contract tests. Minimal fixed test inputs, never a training/evaluation dataset.
import assert from 'node:assert/strict';
import { CSV_COLUMNS, V2_COLUMNS, PASSWORD_COLUMNS, FEATURE_COLUMNS, MAX_BYTES, parseCSV, selectFeatures, recommendation } from '../schema.js';
import { predictRisk, validatePrediction } from '../model-adapter.js';
import { buildSessions } from '../sessions.js';

export async function runContractTests() {
  const checks = [];
  const check = async (name, fn) => { await fn(); checks.push(name); };
  const header = CSV_COLUMNS.join(',');
  const base = {
    event_id: 'unit-event', event_ts_utc: '2026-01-01T00:00:00Z', session_token: 'unit-session', account_token: '',
    attempts_2m: '1', attempts_1h: '3', distinct_accounts_2m: '1', failed_ratio_24h: '', hour_deviation: '',
    typical_weekday: '', geo_velocity_kmh: '', network_familiarity: '', asn_category: '', device_managed: '',
    device_new: '', is_suspicious: '', attack_type: '',
  };
  const quote = value => `"${String(value).replaceAll('"', '""')}"`;
  const line = (overrides = {}) => CSV_COLUMNS.map(name => quote(({ ...base, ...overrides })[name])).join(',');
  const csv = (overrides = {}) => `${header}\n${line(overrides)}`;
  const event = (overrides = {}) => parseCSV(csv(overrides))[0];
  const prediction = score => ({ risk_score: score, reasons: ['Contract test.'], model_version: 'unit-test-only' });

  await check('Legacy17, V2 19 and eleven ML features remain explicit', () => {
    assert.equal(CSV_COLUMNS.length, 17);
    assert.equal(V2_COLUMNS.length, 19);
    assert.deepEqual(V2_COLUMNS.slice(0, 17), CSV_COLUMNS);
    assert.deepEqual(V2_COLUMNS.slice(17), PASSWORD_COLUMNS);
    assert.equal(FEATURE_COLUMNS.length, 11);
    assert.deepEqual(FEATURE_COLUMNS, ['attempts_2m', 'attempts_1h', 'distinct_accounts_2m', 'failed_ratio_24h', 'hour_deviation', 'typical_weekday', 'geo_velocity_kmh', 'network_familiarity', 'asn_category', 'device_managed', 'device_new']);
  });
  await check('BOM, CRLF, quotes and commas parse correctly', () => {
    const parsed = parseCSV(`\uFEFF${header}\r\n${line({ asn_category: 'unit,"category"' })}\r\n`);
    assert.equal(parsed[0].asn_category, 'unit,"category"');
    assert.equal(parsed[0].attempts_2m, 1);
  });
  await check('Missing history is not zero and an empty account is supported', () => {
    const parsed = event();
    assert.equal(parsed.account_token, null);
    for (const name of ['hour_deviation', 'failed_ratio_24h', 'network_familiarity', 'geo_velocity_kmh', 'device_new']) assert.equal(parsed[name], null);
  });
  await check('Legacy booleans normalize; V2 flags strictly use0/1/unknown', () => {
    const parsed = event({ device_new: 'TRUE', device_managed: 'false', typical_weekday: '1' });
    assert.equal(parsed.device_new, 1); assert.equal(parsed.device_managed, 0); assert.equal(parsed.typical_weekday, 1);
    const v2 = flags => parseCSV(`${V2_COLUMNS.join(',')}\n${line()},${flags}`)[0];
    assert.equal(v2('1,0').password_in_blocklist, 1);
    assert.equal(v2('0,1').password_near_blocklist, 1);
    assert.equal(v2(',').password_in_blocklist, null);
    assert.equal(v2(',').password_near_blocklist, null);
    assert.throws(() => v2('1,1'), /cannot both/);
    for (const flags of ['true,0', '0,false', '2,0', '-1,0']) assert.throws(() => v2(flags), /0, 1 or/);
    assert.equal(Object.hasOwn(parsed, 'password_in_blocklist'), false);

  });
  await check('Extra, missing and reordered columns are rejected', () => {
    assert.throws(() => parseCSV(`${header},extra\n${line()},x`), /header/);
    assert.throws(() => parseCSV(`${CSV_COLUMNS.slice(1).join(',')}\n${line()}`), /header/);
    assert.throws(() => parseCSV(`${[...CSV_COLUMNS].reverse().join(',')}\n${line()}`), /header/);
    assert.throws(() => parseCSV(`${header}\n1,2`), /17 fields/);
    assert.throws(() => parseCSV(`${header},${[...PASSWORD_COLUMNS].reverse().join(',')}\n${line()},0,0`), /header/);
    assert.throws(() => parseCSV(`${V2_COLUMNS.join(',')}\n${line()},0`), /19 fields/);
  });
  await check('Invalid quotes and empty input are rejected', () => {
    assert.throws(() => parseCSV(`${header}\n"unterminated`), /Unclosed/);
    assert.throws(() => parseCSV(`${header}\n"closed"junk`), /quoting/);
    assert.throws(() => parseCSV(header), /no events/);
    assert.throws(() => parseCSV(`${header}\n${','.repeat(16)}`), /event_id/);
  });
  await check('Duplicate events and file/row limits are enforced', () => {
    assert.throws(() => parseCSV(`${header}\n${line()}\n${line()}`), /duplicate/);
    assert.throws(() => parseCSV('x'.repeat(MAX_BYTES + 1)), /2 MiB/);
    assert.throws(() => parseCSV(`${header}\n${'x\n'.repeat(10001)}`), /10,000/);
  });
  await check('Invalid calendar dates, nonUTC times and overflow are rejected', () => {
    for (const date of ['2026-02-30T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00+01:00', '2026-13-01T00:00:00Z', 'not-a-date']) {
      assert.throws(() => event({ event_ts_utc: date }), /event_ts_utc/);
    }
    assert.equal(event({ event_ts_utc: '2024-02-29T23:59:59.125Z' }).event_ts_utc, '2024-02-29T23:59:59.125Z');
  });
  await check('Invalid numbers, ratios and flags are rejected', () => {
    for (const value of ['-1', '1.5', 'Infinity', 'NaN', '0x10', '9007199254740992']) assert.throws(() => event({ attempts_2m: value }), /attempts_2m/);
    assert.throws(() => event({ failed_ratio_24h: '1.1' }), /failed_ratio_24h/);
    assert.equal(event({ network_familiarity: 'unfamiliar' }).network_familiarity, 'unfamiliar');
    assert.equal(event({ network_familiarity: 'unseen-category' }).network_familiarity, 'unseen-category');
    assert.throws(() => event({ hour_deviation: '12.01' }), /hour_deviation/);
    assert.throws(() => event({ attempts_2m: '4', attempts_1h: '3' }), /cannot exceed/);
    assert.throws(() => event({ device_new: 'yes' }), /device_new/);
  });
  await check('Errors do not echo cell contents', () => {
    try { event({ attempts_2m: 'unit-secret-never-echo' }); assert.fail(); }
    catch (error) { assert.equal(error.message.includes('unit-secret-never-echo'), false); }
  });
  await check('Identity, time, labels and password flags stay outside the ML features', () => {
    const first = selectFeatures(event({ is_suspicious: '0', attack_type: 'unit-a' }));
    const second = selectFeatures(event({ event_id: 'changed', session_token: 'changed', account_token: 'changed', event_ts_utc: '2026-01-02T00:00:00Z', is_suspicious: '1', attack_type: 'unit-b' }));
    assert.deepEqual(first, second);
    assert.deepEqual(Object.keys(first), FEATURE_COLUMNS);
    assert.deepEqual(selectFeatures({ ...event(), password_in_blocklist: 1, password_near_blocklist: 0 }), first);
  });
  await check('An unavailable model cannot produce scores', async () => {
    assert.equal(await predictRisk(selectFeatures(event())), null);
    const result = await buildSessions([event()], predictRisk);
    assert.equal(result[0].score, null);
    assert.equal(result[0].mock, false);
    assert.equal(recommendation(result[0].score).level, 'pending');
  });
  await check('Model outputs must satisfy the contract', () => {
    for (const score of [-1, 101, 69.9, Infinity, NaN, '90']) assert.throws(() => validatePrediction(prediction(score)), /contract/);
    assert.throws(() => validatePrediction({ ...prediction(50), model_version: '' }), /contract/);
    assert.throws(() => validatePrediction({ ...prediction(50), reasons: [123] }), /contract/);
    assert.throws(() => validatePrediction({ ...prediction(50), reasons: ['x'.repeat(241)] }), /contract/);
    assert.equal(validatePrediction(prediction(100)).risk_score, 100);
  });
  await check('Sessions take maximum risk and the latest event on ties', async () => {
    const events = [event(), event({ event_id: 'unit-2', event_ts_utc: '2026-01-01T00:00:01Z', attempts_2m: '2' }), event({ event_id: 'unit-3', event_ts_utc: '2026-01-01T00:00:02Z', attempts_2m: '3' })];
    const result = await buildSessions(events, async features => {
      assert.deepEqual(Object.keys(features), FEATURE_COLUMNS);
      return { ...prediction(features.attempts_2m === 1 ? 20 : 80), reasons: [String(features.attempts_2m)] };
    });
    assert.equal(result.length, 1); assert.equal(result[0].score, 80);
    assert.equal(result[0].scoredEvent.event_id, 'unit-3');
    assert.deepEqual(result[0].reasons, ['3']);
  });
  await check('A single unscored event makes the entire session pending', async () => {
    const events = [event(), event({ event_id: 'unit-2', attempts_2m: '2' })];
    for (const response of ['throw', 'null', 'invalid']) {
      const result = await buildSessions(events, async features => {
        if (features.attempts_2m === 1) return prediction(90);
        if (response === 'throw') throw new Error('unit-only');
        return response === 'null' ? null : prediction(101);
      });
      assert.equal(result[0].score, null); assert.equal(result[0].scoredEvent, null);
      assert.deepEqual(result[0].reasons, []); assert.equal(result[0].unscored, 1);
    }
  });
  await check('Separate sessions sort by latest UTC event', async () => {
    const result = await buildSessions([event(), event({ event_id: 'unit-2', session_token: 'second', event_ts_utc: '2026-01-02T00:00:00Z' })], predictRisk);
    assert.deepEqual(result.map(session => session.id), ['second', 'unit-session']);
  });
  await check('Threshold boundaries are explicit with no locking actions', () => {
    assert.equal(recommendation(null).level, 'pending');
    for (const score of [0, 29]) assert.equal(recommendation(score).level, 'low');
    for (const score of [30, 69]) assert.equal(recommendation(score).level, 'medium');
    for (const score of [70, 100]) assert.equal(recommendation(score).level, 'high');
    for (let score = 0; score <= 100; score++) assert.doesNotMatch(recommendation(score).action, /lock/i);
  });
  return checks;
}

const results = await runContractTests();
console.log(`${results.length} JavaScript contract checks passed.`);

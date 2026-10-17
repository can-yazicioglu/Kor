// AI 1 contract tests. Minimal fixed test inputs, never a training/evaluation dataset.
import assert from 'node:assert/strict';
import { CSV_COLUMNS, FEATURE_COLUMNS, MAX_BYTES, parseCSV, selectFeatures, recommendation } from '../schema.js';
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
  const prediction = score => ({ risk_score: score, reasons: ['Sözleşme testi.'], model_version: 'unit-test-only' });

  await check('Sabit başlık 17 sütun, allowlist 11 özellik içerir', () => {
    assert.equal(CSV_COLUMNS.length, 17);
    assert.equal(FEATURE_COLUMNS.length, 11);
    assert.deepEqual(FEATURE_COLUMNS, ['attempts_2m', 'attempts_1h', 'distinct_accounts_2m', 'failed_ratio_24h', 'hour_deviation', 'typical_weekday', 'geo_velocity_kmh', 'network_familiarity', 'asn_category', 'device_managed', 'device_new']);
  });
  await check('BOM, CRLF, tırnak ve virgül ayrıştırılır', () => {
    const parsed = parseCSV(`\uFEFF${header}\r\n${line({ asn_category: 'unit,"category"' })}\r\n`);
    assert.equal(parsed[0].asn_category, 'unit,"category"');
    assert.equal(parsed[0].attempts_2m, 1);
  });
  await check('Eksik geçmiş sıfır olmaz, boş hesap desteklenir', () => {
    const parsed = event();
    assert.equal(parsed.account_token, null);
    for (const name of ['hour_deviation', 'failed_ratio_24h', 'network_familiarity', 'geo_velocity_kmh', 'device_new']) assert.equal(parsed[name], null);
  });
  await check('Boolean kodlama normalleştirilir', () => {
    const parsed = event({ device_new: 'TRUE', device_managed: 'false', typical_weekday: '1' });
    assert.equal(parsed.device_new, 1); assert.equal(parsed.device_managed, 0); assert.equal(parsed.typical_weekday, 1);
  });
  await check('Ek, eksik ve sırası değişen sütun reddedilir', () => {
    assert.throws(() => parseCSV(`${header},extra\n${line()},x`), /başlığı/);
    assert.throws(() => parseCSV(`${CSV_COLUMNS.slice(1).join(',')}\n${line()}`), /başlığı/);
    assert.throws(() => parseCSV(`${[...CSV_COLUMNS].reverse().join(',')}\n${line()}`), /başlığı/);
    assert.throws(() => parseCSV(`${header}\n1,2`), /17 alan/);
  });
  await check('Hatalı tırnak ve boş veri reddedilir', () => {
    assert.throws(() => parseCSV(`${header}\n"unterminated`), /kapanmamış/);
    assert.throws(() => parseCSV(`${header}\n"closed"junk`), /tırnak/);
    assert.throws(() => parseCSV(header), /gösterilecek olay yok/);
    assert.throws(() => parseCSV(`${header}\n${','.repeat(16)}`), /event_id/);
  });
  await check('Yinelenen olay ve boyut/satır sınırı uygulanır', () => {
    assert.throws(() => parseCSV(`${header}\n${line()}\n${line()}`), /yinelenen/);
    assert.throws(() => parseCSV('x'.repeat(MAX_BYTES + 1)), /2 MiB/);
    assert.throws(() => parseCSV(`${header}\n${'x\n'.repeat(10001)}`), /10.000/);
  });
  await check('Geçersiz takvim, UTC dışı ve taşan saat reddedilir', () => {
    for (const date of ['2026-02-30T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00+01:00', '2026-13-01T00:00:00Z', 'not-a-date']) {
      assert.throws(() => event({ event_ts_utc: date }), /event_ts_utc/);
    }
    assert.equal(event({ event_ts_utc: '2024-02-29T23:59:59.125Z' }).event_ts_utc, '2024-02-29T23:59:59.125Z');
  });
  await check('Geçersiz sayı, oran ve flag reddedilir', () => {
    for (const value of ['-1', '1.5', 'Infinity', 'NaN', '0x10', '9007199254740992']) assert.throws(() => event({ attempts_2m: value }), /attempts_2m/);
    assert.throws(() => event({ failed_ratio_24h: '1.1' }), /failed_ratio_24h/);
    assert.equal(event({ network_familiarity: 'unfamiliar' }).network_familiarity, 'unfamiliar');
    assert.equal(event({ network_familiarity: 'unseen-category' }).network_familiarity, 'unseen-category');
    assert.throws(() => event({ hour_deviation: '12.01' }), /hour_deviation/);
    assert.throws(() => event({ attempts_2m: '4', attempts_1h: '3' }), /aşamaz/);
    assert.throws(() => event({ device_new: 'yes' }), /device_new/);
  });
  await check('Hatalar hücre içeriğini yansıtmaz', () => {
    try { event({ attempts_2m: 'unit-secret-never-echo' }); assert.fail(); }
    catch (error) { assert.equal(error.message.includes('unit-secret-never-echo'), false); }
  });
  await check('Kimlikler, zaman ve etiketler model girdisine sızmaz', () => {
    const first = selectFeatures(event({ is_suspicious: '0', attack_type: 'unit-a' }));
    const second = selectFeatures(event({ event_id: 'changed', session_token: 'changed', account_token: 'changed', event_ts_utc: '2026-01-02T00:00:00Z', is_suspicious: '1', attack_type: 'unit-b' }));
    assert.deepEqual(first, second);
    assert.deepEqual(Object.keys(first), FEATURE_COLUMNS);
  });
  await check('Model bağlı değilken gerçek puan üretilmez', async () => {
    assert.equal(await predictRisk(selectFeatures(event())), null);
    const result = await buildSessions([event()], predictRisk);
    assert.equal(result[0].score, null);
    assert.equal(result[0].mock, false);
    assert.equal(recommendation(result[0].score).level, 'pending');
  });
  await check('Model sonuçları sözleşmeye uymalı', () => {
    for (const score of [-1, 101, 69.9, Infinity, NaN, '90']) assert.throws(() => validatePrediction(prediction(score)), /sözleşme/);
    assert.throws(() => validatePrediction({ ...prediction(50), model_version: '' }), /sözleşme/);
    assert.throws(() => validatePrediction({ ...prediction(50), reasons: [123] }), /sözleşme/);
    assert.throws(() => validatePrediction({ ...prediction(50), reasons: ['x'.repeat(241)] }), /sözleşme/);
    assert.equal(validatePrediction(prediction(100)).risk_score, 100);
  });
  await check('Oturumda maksimum puan, eşitlikte son olay seçilir', async () => {
    const events = [event(), event({ event_id: 'unit-2', event_ts_utc: '2026-01-01T00:00:01Z', attempts_2m: '2' }), event({ event_id: 'unit-3', event_ts_utc: '2026-01-01T00:00:02Z', attempts_2m: '3' })];
    const result = await buildSessions(events, async features => {
      assert.deepEqual(Object.keys(features), FEATURE_COLUMNS);
      return { ...prediction(features.attempts_2m === 1 ? 20 : 80), reasons: [String(features.attempts_2m)] };
    });
    assert.equal(result.length, 1); assert.equal(result[0].score, 80);
    assert.equal(result[0].scoredEvent.event_id, 'unit-3');
    assert.deepEqual(result[0].reasons, ['3']);
  });
  await check('Tek olay hatası oturumun tamamını puansız bırakır', async () => {
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
  await check('Ayrı oturumlar en son UTC olayına göre sıralanır', async () => {
    const result = await buildSessions([event(), event({ event_id: 'unit-2', session_token: 'second', event_ts_utc: '2026-01-02T00:00:00Z' })], predictRisk);
    assert.deepEqual(result.map(session => session.id), ['second', 'unit-session']);
  });
  await check('Eşik sınırları açık, kilitleme aksiyonu yok', () => {
    assert.equal(recommendation(null).level, 'pending');
    for (const score of [0, 29]) assert.equal(recommendation(score).level, 'low');
    for (const score of [30, 69]) assert.equal(recommendation(score).level, 'medium');
    for (const score of [70, 100]) assert.equal(recommendation(score).level, 'high');
    for (let score = 0; score <= 100; score++) assert.doesNotMatch(recommendation(score).action, /kilit|lock/i);
  });
  return checks;
}

const results = await runContractTests();
console.log(`${results.length} JavaScript sözleşme kontrolü geçti.`);

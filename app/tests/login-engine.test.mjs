import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createLoginSimulation, DEMO_TTL_MS, SESSION_TTL_MS, MAX_DEMO_EVENTS } from '../login-engine.js';
import { createPredictor } from '../model-adapter.js';
import { FEATURE_COLUMNS } from '../schema.js';
import { assessmentFromFlags } from '../password-risk.js';

const artifact = JSON.parse(readFileSync(new URL('../../models/demo_model.json', import.meta.url), 'utf8'));
const predict = createPredictor(artifact);
let clock = 1_800_000_000_000, sequence = 0, count = 0;
const make = (scorer = predict) => {
  const engine=createLoginSimulation({predict:scorer,now:()=>clock,randomId:()=>'test-session-'+ ++sequence});
  return {...engine,attempt:input=>engine.attempt({passwordAssessment:assessmentFromFlags(0,0),...input})};
};
const sim = make();
const normal = sim.attempt({ success: true });
assert.ok(normal.score < 30);
assert.deepEqual(Object.keys(normal.features), FEATURE_COLUMNS);
assert.equal(normal.features.failed_ratio_24h, 2 / 19);
count++;

sim.reset();
let result;
for (let i = 0; i < 20; i++) { result = sim.attempt({ success: false }); clock += 180; }
assert.equal(result.features.attempts_2m, 20);
assert.equal(result.features.attempts_1h, 20);
assert.equal(result.features.distinct_accounts_2m, 1);
assert.equal(result.features.failed_ratio_24h, 21 / 38);
assert.ok(result.score >= 70);
assert.ok(sim.attempt({ success: true }).score >= 70);
count++;

sim.reset();
for (let account = 0; account < 18; account++) result = sim.attempt({ success: false, account });
assert.equal(result.features.attempts_2m, 1);
assert.equal(result.features.distinct_accounts_2m, 18);
assert.ok(result.score >= 70);
const otherSource = sim.attempt({ success: true, account: 19, context: 'unfamiliar' });
assert.equal(otherSource.features.distinct_accounts_2m, 1);
count++;

sim.reset();
assert.ok(sim.attempt({ success: true, context: 'unfamiliar' }).score >= 30);
count++;

const successRun = make(), failRun = make();
const good = successRun.attempt({ success: true }), bad = failRun.attempt({ success: false });
assert.deepEqual(good.features, bad.features);
assert.equal(good.score, bad.score);
assert.equal(successRun.attempt({ success: true }).features.failed_ratio_24h, 2 / 20);
assert.equal(failRun.attempt({ success: true }).features.failed_ratio_24h, 3 / 20);
count++;

sim.reset();
const first = sim.attempt({ success: false });
clock += SESSION_TTL_MS - 1;
assert.equal(sim.attempt({ success: false }).features.attempts_2m, 2);
clock += 1;
const boundary = sim.attempt({ success: true });
assert.equal(boundary.features.attempts_2m, 2); // t-120 excluded; t-1 included.
assert.equal(boundary.features.attempts_1h, 3);
assert.notEqual(boundary.sessionId, first.sessionId);
count++;

let inputKeys;
const inspected = make(features => { inputKeys = Object.keys(features); return predict(features); });
assert.throws(() => inspected.attempt({ success: true, password: 'unit-only' }));
assert.throws(() => inspected.attempt({ success: true, username: 'unit-only' }));
for (const input of [{success:'yes'}, {success:true,account:64}, {success:true,context:'__proto__'}]) assert.throws(() => inspected.attempt(input));
inspected.attempt({ success: true });
assert.deepEqual(inputKeys, FEATURE_COLUMNS);
assert.equal(JSON.stringify(inspected.snapshot()).includes('unit-only'), false);
count++;

let calls = 0;
const maximum = make(() => ({ risk_score: ++calls === 1 ? 90 : 10, reasons: ['Peak event contribution'], model_version: 'test' }));
maximum.attempt({ success: false });
const repeated = maximum.attempt({ success: true });
assert.equal(repeated.score, 90);
assert.equal(repeated.eventScore, 10);
repeated.score = 0; repeated.reasons[0] = 'Mutated';
assert.equal(maximum.snapshot().latest.score, 90);
assert.equal(maximum.snapshot().latest.reasons[0], 'Peak event contribution');
count++;

let unavailable = true;
const uncertain = make(features => unavailable ? null : predict(features));
assert.equal(uncertain.attempt({ success: true }).score, null);
unavailable = false;
assert.equal(uncertain.attempt({ success: true }).score, null);
clock += SESSION_TTL_MS;
assert.notEqual(uncertain.attempt({ success: true }).score, null);
const malformed = make(() => ({ risk_score: NaN }));
assert.equal(malformed.attempt({ success: true }).score, null);
const throwing = make(() => { throw Error('unit-only'); });
assert.equal(throwing.attempt({ success: true }).score, null);
count++;

sim.reset(); sim.attempt({ success: true });
clock += DEMO_TTL_MS;
assert.equal(sim.checkExpiry(), true);
assert.equal(sim.snapshot().total, 0);
assert.equal(sim.snapshot().latest, null);
assert.equal(sim.snapshot().remainingMs, null);
count++;

const capped = make(() => null);
for (let i = 0; i < MAX_DEMO_EVENTS; i++) capped.attempt({ success: false });
assert.throws(() => capped.attempt({ success: false }), /500/);
capped.reset();
assert.equal(capped.snapshot().total, 0);
count++;

const backwards = make();
backwards.attempt({ success: false });
clock -= 1;
assert.throws(() => backwards.attempt({ success: false }), /clock/);
count++;
console.log(count + ' interactive login engine checks passed.');

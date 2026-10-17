import { selectFeatures, recommendation } from './schema.js';
import { validatePrediction } from './model-adapter.js';
import { applyPasswordRisk, validateAssessment } from './password-risk.js';

// Seven frozen synthetic features from the delivered CSV; no fingerprinting.
// Counters and previous-outcome ratios come from the interactive demo stream.
export const CONTEXTS = Object.freeze({
  familiar: Object.freeze({ hour_deviation: 0.768611, typical_weekday: 0,
    geo_velocity_kmh: 98.41, network_familiarity: 'familiar', asn_category: 'residential',
    device_managed: 0, device_new: 0 }),
  unfamiliar: Object.freeze({ hour_deviation: 3.611667, typical_weekday: 1,
    geo_velocity_kmh: 31.92, network_familiarity: 'unfamiliar', asn_category: 'cloud',
    device_managed: 0, device_new: 1 }),
});
export const DEMO_TTL_MS = 5 * 60 * 1000;
export const SESSION_TTL_MS = 120 * 1000;
export const MAX_DEMO_EVENTS = 500;

// Does not accept credentials. account is a bounded demo slot and success is
// only the boolean result of the toy login check outside this module.
export function createLoginSimulation({ predict, now = Date.now, randomId = () => crypto.randomUUID() }) {
  let events = [], sessions = new Map(), warmup = new Map(), deadline = null, latest = null;
  function reset() {
    events = []; sessions.clear(); warmup.clear(); deadline = null; latest = null;
  }
  function checkExpiry() {
    if (deadline !== null && now() >= deadline) { reset(); return true; }
    return false;
  }
  function attempt(input) {
    if (!input || Object.keys(input).some(key => !['account', 'success', 'context', 'passwordAssessment'].includes(key))) {
      throw new Error('Only a demo outcome, context, and password-check flags are accepted.');
    }
    const { account = 0, success, context = 'familiar' } = input;
    if (!Number.isInteger(account) || account < 0 || account > 63 || typeof success !== 'boolean' || !Object.hasOwn(CONTEXTS, context)) {
      throw new Error('Invalid demo context.');
    }
    checkExpiry();
    const time = now();
    if (!Number.isFinite(time) || (events.length && time < events.at(-1).time)) throw new Error('The demo clock changed; reset the session.');
    if (events.length >= MAX_DEMO_EVENTS) throw new Error('The 500-attempt limit was reached. Reset the demo.');
    if (deadline === null) deadline = time + DEMO_TTL_MS;
    // Explicit synthetic warm-up: 19 outcomes two hours before the demo,
    // outside count windows. This is not real customer history.
    if (!warmup.has(account)) warmup.set(account, context === 'familiar' ? 2 : 0);
    const prior = events.filter(event => event.account === account);
    const recent = events.filter(event => event.time > time - SESSION_TTL_MS);
    const features = selectFeatures({ ...CONTEXTS[context],
      attempts_2m: recent.filter(event => event.account === account).length + 1,
      attempts_1h: prior.filter(event => event.time > time - 3600000).length + 1,
      distinct_accounts_2m: new Set([...recent.filter(event => event.context === context).map(event => event.account), account]).size,
      failed_ratio_24h: (warmup.get(account) + prior.filter(event => !event.success).length) / (19 + prior.length),
    });
    const passwordAssessment = validateAssessment(input.passwordAssessment);
    let basePrediction = null, prediction = null;
    try { basePrediction = validatePrediction(predict(features)); prediction = applyPasswordRisk(basePrediction, passwordAssessment); } catch { /* Unavailable is never low risk. */ }
    let session = sessions.get(account);
    if (!session || time - session.started >= SESSION_TTL_MS) {
      session = { id: randomId(), started: time, score: null, reasons: [], unscored: false, version: null };
      sessions.set(account, session);
    }
    if (prediction === null) session.unscored = true;
    else if (session.score === null || prediction.risk_score >= session.score) {
      session.score = prediction.risk_score; session.reasons = [...prediction.reasons]; session.version = prediction.model_version;
    }
    const score = session.unscored ? null : session.score;
    const result = { success, score, baseScore: basePrediction?.risk_score ?? null, passwordAssessment,
      passwordBonus: passwordAssessment.bonus, eventScore: prediction?.risk_score ?? null, reasons: session.unscored ? [] : [...session.reasons],
      modelVersion: session.unscored ? null : session.version, sessionId: session.id, features: { ...features },
      action: recommendation(score), number: events.length + 1, time };
    // Append the outcome only AFTER scoring: no current/future outcome leakage.
    events.push({ account, context, success, time, number: result.number, score });
    latest = result;
    return structuredClone(result);
  }
  function snapshot() {
    checkExpiry();
    return structuredClone({ latest, total: events.length, remainingMs: deadline === null ? null : Math.max(0, deadline - now()),
      timeline: events.slice(-8).reverse().map(({ success, number, score }) => ({ success, number, score })) });
  }
  return { attempt, snapshot, reset, checkExpiry };
}

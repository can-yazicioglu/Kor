import { FEATURE_COLUMNS } from './schema.js';

// Only a local, trained artifact is loaded. CSV rows never leave this process.
// Unknown/missing inputs abstain; stored medians are never used to invent history.
// serve.py verifies the Python-canonical artifact checksum before delivery.
// This is a corruption guard, not proof of authenticity or a signed model.
export const MODEL_URL = './demo-model.json';
const CATEGORICAL = ['network_familiarity', 'asn_category'];
const CATEGORY_VALUES = { network_familiarity: ['familiar', 'unfamiliar'], asn_category: ['residential', 'business', 'cloud', 'vpn', 'unknown'] };
const NUMERIC = FEATURE_COLUMNS.filter(name => !CATEGORICAL.includes(name));
const LABELS = {
  attempts_2m: 'Login attempts in 2 minutes', attempts_1h: 'Login attempts in 1 hour',
  distinct_accounts_2m: 'Distinct accounts in 2 minutes', failed_ratio_24h: 'Failure ratio over 24 hours',
  hour_deviation: 'Deviation from usual login hour', typical_weekday: 'Usual weekday context',
  geo_velocity_kmh: 'Location change speed', network_familiarity: 'Network familiarity',
  asn_category: 'Network category', device_managed: 'Managed device status', device_new: 'New device context',
};
const equal = (a, b) => Array.isArray(a) && a.length === b.length && a.every((value, index) => value === b[index]);
const finite = value => typeof value === 'number' && Number.isFinite(value);
const contractError = () => new Error('The local model file does not match the contract. Scoring is disabled.');
let predictor = null;
let loadGeneration = 0;
let status = { state: 'idle', version: null };

export function validateModel(model) {
  if (!model || model.schema_version !== 'els-logistic-v1' ||
      model.synthetic_only !== true ||
      model.score_semantics !== 'uncalibrated_synthetic_probability' ||
      model.score_rounding !== 'floor(probability * 100 + 0.5)' ||
      model.explanation_semantics !== 'additive_log_odds_contribution_not_causality' ||
      model.artifact_integrity?.algorithm !== 'sha256' ||
      model.artifact_integrity?.canonicalization !== 'python_json_sort_keys_utf8_excluding_artifact_integrity' ||
      model.artifact_integrity?.purpose !== 'accidental_corruption_not_authenticity' ||
      !/^[0-9a-f]{64}$/.test(model.artifact_integrity?.digest ?? '') ||
      model.missing_policy !== 'abstain' || model.unknown_category_policy !== 'abstain' ||
      typeof model.model_version !== 'string' || !model.model_version.trim() || model.model_version.length > 80 ||
      !equal(model.feature_columns, FEATURE_COLUMNS) || !Array.isArray(model.preprocessing?.numeric) ||
      !Array.isArray(model.preprocessing?.categorical) ||
      !equal(model.preprocessing.numeric.map(item => item.name), NUMERIC) ||
      !equal(model.preprocessing.categorical.map(item => item.name), CATEGORICAL) ||
      !finite(model.intercept) || model.threshold_policy?.mfa_score !== 30 || model.threshold_policy?.review_score !== 70) {
    throw contractError();
  }
  const order = [...NUMERIC];
  for (const item of model.preprocessing.numeric) {
    if (!finite(item.median) || !finite(item.mean) || !finite(item.scale) || item.scale <= 0) throw contractError();
  }
  for (const item of model.preprocessing.categorical) {
    if (!equal(item.categories, CATEGORY_VALUES[item.name]) || !item.categories.length || item.categories.length > 64 ||
        new Set(item.categories).size !== item.categories.length ||
        item.categories.some(value => typeof value !== 'string' || !value || value.length > 64)) throw contractError();
    order.push(...item.categories.map(value => `${item.name}=${value}`));
  }
  if (!equal(model.transformed_feature_order, order) || !Array.isArray(model.coefficients) ||
      model.coefficients.length !== order.length || !model.coefficients.every(finite)) throw contractError();
  return model;
}

export function createPredictor(rawModel) {
  // Defensive copy so outside mutation cannot alter an already validated predictor.
  const model = validateModel(JSON.parse(JSON.stringify(rawModel)));
  return features => {
    if (!features || !equal(Object.keys(features).sort(), [...FEATURE_COLUMNS].sort())) return null;
    if (FEATURE_COLUMNS.some(name => features[name] === null || features[name] === undefined)) return null;
    const vector = [];
    const owners = [];
    for (const item of model.preprocessing.numeric) {
      const value = features[item.name];
      if (!finite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) return null;
      if (['attempts_2m', 'attempts_1h', 'distinct_accounts_2m'].includes(item.name) && (!Number.isSafeInteger(value) || value < 1)) return null;
      if (['typical_weekday', 'device_managed', 'device_new'].includes(item.name) && value !== 0 && value !== 1) return null;
      if (item.name === 'failed_ratio_24h' && value > 1 || item.name === 'hour_deviation' && value > 12) return null;
      vector.push((value - item.mean) / item.scale);
      owners.push(item.name);
    }
    if (features.attempts_2m > features.attempts_1h) return null;
    for (const item of model.preprocessing.categorical) {
      if (!item.categories.includes(features[item.name])) return null;
      for (const category of item.categories) {
        vector.push(features[item.name] === category ? 1 : 0);
        owners.push(item.name);
      }
    }
    const contributions = Object.fromEntries(FEATURE_COLUMNS.map(name => [name, 0]));
    let logit = model.intercept;
    vector.forEach((value, index) => {
      const contribution = value * model.coefficients[index];
      logit += contribution;
      contributions[owners[index]] += contribution;
    });
    if (!Number.isFinite(logit)) return null;
    const probability = logit >= 0 ? 1 / (1 + Math.exp(-logit)) : Math.exp(logit) / (1 + Math.exp(logit));
    const strongest = FEATURE_COLUMNS.filter(name => contributions[name] > 0)
      .sort((a, b) => contributions[b] - contributions[a]).slice(0, 3);
    const reasons = strongest.map(name => `${LABELS[name]}: positive model contribution (+${contributions[name].toFixed(2)})`);
    if (!reasons.length) reasons.push('Combined feature assessment');
    return validatePrediction({
      risk_score: Math.min(100, Math.max(0, Math.floor(probability * 100 + 0.5))),
      reasons, model_version: model.model_version,
    });
  };
}

export async function loadModel(fetcher = globalThis.fetch) {
  const generation = ++loadGeneration;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  predictor = null;
  status = { state: 'loading', version: null };
  try {
    const response = await fetcher(MODEL_URL, { method: 'GET', cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal });
    if (!response.ok) throw contractError();
    const text = await response.text();
    if (text.length > 512 * 1024) throw contractError();
    const model = JSON.parse(text);
    if (generation !== loadGeneration) return getModelStatus();
    predictor = createPredictor(model);
    status = { state: 'ready', version: model.model_version };
  } catch {
    if (generation === loadGeneration) {
      predictor = null;
      status = { state: 'unavailable', version: null };
    }
  } finally { clearTimeout(timeout); }
  return getModelStatus();
}

export const getModelStatus = () => ({ ...status });
export function predictRisk(features) { return predictor ? predictor(features) : null; }

export function validatePrediction(result) {
  if (result === null) return null;
  if (!result || !Number.isInteger(result.risk_score) || result.risk_score < 0 || result.risk_score > 100 ||
      typeof result.model_version !== 'string' || !result.model_version.trim() || result.model_version.length > 80 ||
      !Array.isArray(result.reasons) || result.reasons.length > 6 ||
      result.reasons.some(reason => typeof reason !== 'string' || !reason.trim() || reason.length > 240)) {
    throw new Error('The model response does not match the contract. The session was not scored.');
  }
  return { risk_score: result.risk_score, reasons: [...result.reasons], model_version: result.model_version };
}

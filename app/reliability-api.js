// Company demo transport only. No analytics CSV, storage, request logs or retries.
import { validateInsights } from './insights.js';
import { validateAssurance, validateSecurityTest } from './assurance.js';
const OPERATIONS = new Set(['start', 'attempt', 'simulate', 'mfa', 'reset', 'feedback', 'status', 'proof', 'resource']);
const score = value => value === null || Number.isInteger(value) && value >= 0 && value <= 100;
const count = value => Number.isSafeInteger(value) && value >= 0 && value <= 1000000;
const text = (value, max = 240) => typeof value === 'string' && value.length <= max;
const invalid = () => new Error('The local verification service returned an unsupported response.');
const tokenValid = token => typeof token === 'string' && /^[A-Za-z0-9_-]{16,160}$/.test(token);
const challengeValid = token => typeof token === 'string' && /^[a-f0-9]{32}$/.test(token);
const MAX_RESPONSE_BYTES = 512 * 1024;

export class LoginBackoffError extends Error {
  constructor(seconds) {
    super('Wait before the next sign-in attempt.');
    this.retryAfterMs = seconds * 1000;
  }
}

export class AccessDeniedError extends Error {
  constructor() { super('Server denied access. The employee demo role cannot access the audit console. Sign in and complete verification for the workspace.'); }
}

async function readBoundedJson(response) {
  if (!response.headers.get('Content-Type')?.startsWith('application/json') || !response.body?.getReader) throw invalid();
  const length = response.headers.get('Content-Length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
    await response.body.cancel();
    throw invalid();
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw invalid();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

export function validateSnapshot(value) {
  if (!value || !count(value.total) || !Number.isFinite(value.remaining_ms) || value.remaining_ms < 0 || value.remaining_ms > 300000 ||
      typeof value.allowed_access !== 'boolean' || typeof value.mfa_required !== 'boolean' ||
      !Array.isArray(value.timeline) || value.timeline.length > 1000 ||
      value.allowed_access && value.mfa_required) throw invalid();
  if (!Number.isInteger(value.login_retry_after_ms) || value.login_retry_after_ms < 0 || value.login_retry_after_ms > 60000 ||
      value.allowed_access && value.login_retry_after_ms !== 0) throw invalid();
  if (value.mfa_required ? !challengeValid(value.mfa_challenge_id) : value.mfa_challenge_id != null) throw invalid();
  for (const event of value.timeline) {
    if (!text(event.event_id, 160) || !text(event.event_type, 64) || !score(event.score)) throw invalid();
  }
  if (value.latest !== null) {
    const result = value.latest;
    if (!result || !text(result.event_id, 160) || !score(result.score) || !score(result.peak_score) || !score(result.base_score) ||
        !Array.isArray(result.reasons) || result.reasons.length > 12 || result.reasons.some(reason => !text(reason, 500)) ||
        !['monitor', 'mfa', 'review'].includes(result.action) || !text(result.action_label) ||
        !['sufficient', 'limited', 'insufficient'].includes(result.data_quality?.level) ||
        !Array.isArray(result.data_quality?.missing_features) || result.data_quality.missing_features.length > 50 ||
        result.data_quality.missing_features.some(name => !text(name, 80)) ||
        !['checked', 'unknown'].includes(result.credential_risk?.status) ||
        !['exact', 'near', 'none', 'unknown'].includes(result.credential_risk?.match) ||
        !['not_verified', 'password_verified', 'mfa_verified', 'passkey_verified'].includes(result.verification) ||
        !text(result.policy_version, 100) || !text(result.model_version, 100) || typeof result.success !== 'boolean') throw invalid();
    for (const name of ['attempts_2m', 'distinct_accounts_2m', 'distinct_sources_2m', 'consecutive_failures']) {
      if (result.signals?.[name] !== null && !count(result.signals?.[name])) throw invalid();
    }
    if (result.signals?.success_after_failures !== null && typeof result.signals?.success_after_failures !== 'boolean') throw invalid();
    if (value.allowed_access && (result.score === null || !result.success || !['password_verified', 'mfa_verified', 'passkey_verified'].includes(result.verification))) throw invalid();
  } else if (value.allowed_access || value.mfa_required) throw invalid();
  if (value.insights !== undefined) {
    validateInsights(value.insights);
    const insight = value.insights;
    if (insight.lifecycle.events !== value.total || insight.lifecycle.expires_in_ms !== value.remaining_ms ||
        insight.lifecycle.pending_mfa !== value.mfa_required ||
        (value.latest === null ? insight.decision_delta !== null :
          insight.decision_delta?.current_score !== value.latest.score || insight.decision_delta?.current_action !== value.latest.action)) throw invalid();
  }
  if (value.assurance !== undefined) {
    validateAssurance(value.assurance);
    if (value.assurance.authorization.workspace_allowed !== value.allowed_access ||
        value.assurance.receipt.counter !== value.total) throw invalid();
  }
  if (value.security_test !== undefined) validateSecurityTest(value.security_test);
  return value;
}

export function createReliabilityApi(fetcher = globalThis.fetch) {
  return async function request(operation, body, { signal, keepalive = false } = {}) {
    if (!OPERATIONS.has(operation) || !body || typeof body !== 'object') throw invalid();
    if (operation !== 'start' && !tokenValid(body.demo_token)) throw invalid();
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    const timeout = setTimeout(abort, 8000);
    try {
      const response = await fetcher(`./api/demo/${operation}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Sentinel-Demo': '1' },
        body: JSON.stringify(body), credentials: 'omit', cache: 'no-store', redirect: 'error',
        signal: controller.signal, keepalive,
      });
      if (!response.ok) {
        if (response.status === 403 && operation === 'resource') {
          const failure = await readBoundedJson(response);
          if (failure?.code === 'demo_access_denied') throw new AccessDeniedError();
        }
        if (response.status === 429 && operation === 'attempt') {
          const failure = await readBoundedJson(response);
          if (failure?.code === 'login_backoff' && Number.isInteger(failure.retry_after_seconds) &&
              failure.retry_after_seconds >= 1 && failure.retry_after_seconds <= 60) {
            throw new LoginBackoffError(failure.retry_after_seconds);
          }
        }
        await response.body?.cancel(); throw invalid();
      }
      const value = await readBoundedJson(response);
      if (operation === 'resource') {
        validateSnapshot(value?.snapshot);
        if (!value.snapshot.allowed_access || value.resource?.id !== 'workspace' || value.resource.classification !== 'fictional_demo' ||
            !text(value.resource.message, 200)) throw invalid();
        return value;
      }
      if (operation === 'reset') {
        if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length) throw invalid();
        return value;
      }
      if (operation === 'start') {
        if (!tokenValid(value?.demo_token) || value.mode !== 'synthetic_demo' ||
            ['model_ready', 'policy_ready', 'reference_ready'].some(name => typeof value.status?.[name] !== 'boolean')) throw invalid();
        validateSnapshot(value.snapshot);
        return value;
      }
      return validateSnapshot(value);
    } catch (error) {
      controller.abort();
      if (error instanceof LoginBackoffError || error instanceof AccessDeniedError) throw error;
      // Do not reflect a server response, URL, input value or native exception.
      throw new Error('The local verification service is unavailable. Risk is unknown; access is not granted.');
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
    }
  };
}

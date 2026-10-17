import assert from 'node:assert/strict';
import { createReliabilityApi, validateSnapshot, LoginBackoffError } from '../reliability-api.js';

const handle = 'fixture-demo-handle-0000000000';
const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const empty = { latest: null, total: 0, timeline: [], remaining_ms: 300000, login_retry_after_ms: 0, allowed_access: false, mfa_required: false, mfa_challenge_id: null };
const errorPattern = /Risk is unknown; access is not granted/;
let checks = 0;

let calls = 0;
const request = createReliabilityApi(async (path, options) => {
  calls++;
  assert.equal(path, './api/demo/start');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  assert.equal(options.cache, 'no-store');
  return json({ demo_token: handle, snapshot: empty, mode: 'synthetic_demo', status: { model_ready: true, policy_ready: true, reference_ready: true } });
});
assert.equal((await request('start', {})).demo_token, handle);
assert.equal(calls, 1);
checks++;

calls = 0;
await assert.rejects(createReliabilityApi(async () => {
  calls++; return new Response('private-response-value', { status: 503 });
})('attempt', { demo_token: handle, password: 'public-test-value' }), error => {
  assert.match(error.message, errorPattern);
  assert.doesNotMatch(error.message, /private-response|public-test/);
  return true;
});
assert.equal(calls, 1, 'Credentials are never retried automatically');
checks++;

let cancelled = false, sent = 0;
const oversized = new ReadableStream({
  pull(controller) { sent++; controller.enqueue(new Uint8Array(65536)); },
  cancel() { cancelled = true; },
});
await assert.rejects(createReliabilityApi(async () => new Response(oversized, {
  headers: { 'Content-Type': 'application/json' },
}))('reset', { demo_token: handle }), errorPattern);
assert.equal(cancelled, true);
assert.ok(sent <= 10, 'Streaming response must stop as soon as the byte budget is exceeded');
checks++;

cancelled = false;
await assert.rejects(createReliabilityApi(async () => new Response(new ReadableStream({
  cancel() { cancelled = true; },
}), { headers: { 'Content-Type': 'application/json', 'Content-Length': '524289' } }))('reset', { demo_token: handle }), errorPattern);
assert.equal(cancelled, true);
checks++;

await assert.rejects(createReliabilityApi(async () => new Response('{}', { headers: { 'Content-Type': 'text/html' } }))('reset', { demo_token: handle }), errorPattern);
checks++;

await assert.rejects(createReliabilityApi(async () => new Response(new Uint8Array([123, 34, 255, 34, 58, 49, 125]), {
  headers: { 'Content-Type': 'application/json' },
}))('reset', { demo_token: handle }), errorPattern);
checks++;

assert.throws(() => validateSnapshot({ ...empty, allowed_access: true }));
assert.throws(() => validateSnapshot({ ...empty, mfa_required: true, mfa_challenge_id: 'not-an-opaque-challenge' }));
assert.throws(() => validateSnapshot({ ...empty, mfa_challenge_id: 'a'.repeat(32) }));
assert.equal(validateSnapshot(empty), empty);
checks++;

const controller = new AbortController();
controller.abort();
await assert.rejects(createReliabilityApi(async (_path, options) => {
  assert.equal(options.signal.aborted, true);
  throw new Error('private transport exception');
})('reset', { demo_token: handle }, { signal: controller.signal }), errorPattern);
checks++;

await assert.rejects(createReliabilityApi(async () => new Response(JSON.stringify({
  code: 'login_backoff', retry_after_seconds: 8, error: 'untrusted-server-prose',
}), { status: 429, headers: { 'Content-Type': 'application/json' } }))('attempt', { demo_token: handle }), error => {
  assert.ok(error instanceof LoginBackoffError);
  assert.equal(error.retryAfterMs, 8000);
  assert.doesNotMatch(error.message, /untrusted-server-prose/);
  return true;
});
checks++;

for (const seconds of [-1, 0, 61, 1.5, '8', null]) {
  await assert.rejects(createReliabilityApi(async () => new Response(JSON.stringify({
    code: 'login_backoff', retry_after_seconds: seconds,
  }), { status: 429, headers: { 'Content-Type': 'application/json' } }))('attempt', { demo_token: handle }), error => {
    assert.equal(error instanceof LoginBackoffError, false);
    assert.match(error.message, errorPattern);
    return true;
  });
}
checks++;

for (const value of [-1, 60001, .5, null, undefined]) {
  assert.throws(() => validateSnapshot({ ...empty, login_retry_after_ms: value }));
}
assert.equal(validateSnapshot({ ...empty, login_retry_after_ms: 60000 }).login_retry_after_ms, 60000);
checks++;
console.log(checks + ' bounded transport and response validation checks passed.');

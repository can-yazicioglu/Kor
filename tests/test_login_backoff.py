"""Exponential login throttling without sleeping or storing credential data."""
from datetime import datetime, timezone
import http.client
import importlib.util
import json
from pathlib import Path
import secrets
import threading
import unittest
from unittest.mock import patch
import uuid

from src.runtime.service import APIError, CONTEXTS, RuntimeService, sign_payload

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('kor_backoff_http', ROOT/'app/serve.py')
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


class LoginBackoffTests(unittest.TestCase):
    def setUp(self):
        self.wall, self.monotonic = 1800000000., 1000.
        self.secret = secrets.token_hex(32)
        self.runtime = RuntimeService(now=lambda: self.wall, rate_now=lambda: self.monotonic, secret=self.secret)
        self.token = self.runtime.demo_request('start', {})['demo_token']

    def advance(self, seconds):
        self.wall += seconds
        self.monotonic += seconds

    def attempt(self, password='synthetic-wrong-value', token=None, **extra):
        return self.runtime.demo_request('attempt', dict(demo_token=token or self.token,
                  username='demo', password=password, context='familiar', **extra))

    def test_failures_double_delay_until_sixty_second_cap(self):
        for expected in (1, 2, 4, 8, 16, 32, 60, 60, 60):
            with self.subTest(expected=expected):
                result = self.attempt()
                self.assertEqual(result['login_retry_after_ms'], expected*1000)
                self.assertFalse(result['allowed_access'])
                self.advance(expected)
        self.assertEqual(result['total'], 9)

    def test_early_retry_never_checks_password_adds_event_or_extends_delay(self):
        first = self.attempt()
        retry_at = self.runtime.demos[self.token]['login_retry_at']
        self.advance(.25)
        with patch.object(self.runtime.checker, 'check') as checker:
            for password in ('synthetic-wrong-value', 'VelaDemo!42'):
                with self.assertRaises(APIError) as caught:
                    self.attempt(password)
                self.assertEqual(caught.exception.status, 429)
                self.assertEqual(caught.exception.code, 'login_backoff')
                self.assertEqual(caught.exception.retry_after, 1)
            checker.assert_not_called()
        snapshot = self.runtime.demo_request('status', {'demo_token': self.token})
        self.assertEqual(snapshot['total'], 1)
        self.assertEqual(snapshot['latest'], first['latest'])
        self.assertEqual(snapshot['login_retry_after_ms'], 750)
        self.assertEqual(self.runtime.demos[self.token]['login_retry_at'], retry_at)
        self.assertEqual(self.runtime.demos[self.token]['login_failures'], 1)

    def test_exact_deadline_allows_password_and_success_resets_failure_streak(self):
        previous = self.attempt()
        self.advance(.999)
        with self.assertRaises(APIError):
            self.attempt('VelaDemo!42')
        self.advance(.001)
        verified = self.attempt('VelaDemo!42')
        self.assertTrue(verified['latest']['success'])
        self.assertEqual(verified['login_retry_after_ms'], 0)
        self.assertGreaterEqual(verified['latest']['peak_score'], previous['latest']['peak_score'])
        # Correct password still obeys the existing risk/MFA access decision.
        self.assertTrue(verified['mfa_required'])
        self.assertFalse(verified['allowed_access'])
        self.assertEqual(self.attempt()['login_retry_after_ms'], 1000)

    def test_wall_clock_jump_does_not_bypass_monotonic_delay(self):
        self.attempt()
        self.wall += 30
        with self.assertRaises(APIError) as caught:
            self.attempt('VelaDemo!42')
        self.assertEqual(caught.exception.code, 'login_backoff')
        self.monotonic += 1
        self.assertEqual(self.attempt('VelaDemo!42')['login_retry_after_ms'], 0)

    def test_reset_expiry_and_demo_isolation_bound_state(self):
        self.attempt()
        other = self.runtime.demo_request('start', {})['demo_token']
        self.assertEqual(self.attempt(token=other)['login_retry_after_ms'], 1000)
        self.runtime.demo_request('reset', {'demo_token': self.token})
        self.assertNotIn(self.token, self.runtime.demos)
        self.advance(300)
        with self.assertRaises(APIError) as caught:
            self.attempt(token=other)
        self.assertEqual(caught.exception.status, 410)
        self.assertNotIn(other, self.runtime.demos)
        fresh = self.runtime.demo_request('start', {})['demo_token']
        self.assertEqual(self.attempt(token=fresh)['login_retry_after_ms'], 1000)

    def test_invalid_requests_do_not_manufacture_login_failures(self):
        with self.assertRaises(APIError):
            self.attempt(success=True)
        snapshot = self.runtime.demo_request('status', {'demo_token': self.token})
        self.assertEqual(snapshot['total'], 0)
        self.assertEqual(snapshot['login_retry_after_ms'], 0)
        self.assertEqual(self.attempt()['login_retry_after_ms'], 1000)

    def test_context_change_and_session_rotation_do_not_reset_backoff_streak(self):
        self.attempt()
        demo = self.runtime.demos[self.token]
        first_session, expiry = demo['sessions'][0][0], demo['deadline']
        self.advance(121)
        result = self.runtime.demo_request('attempt', {'demo_token': self.token, 'username': 'demo',
                                         'password': 'synthetic-wrong-value', 'context': 'vpn'})
        self.assertNotEqual(demo['sessions'][0][0], first_session)
        self.assertEqual(demo['deadline'], expiry)
        self.assertEqual(result['latest']['signals']['attempts_2m'], 1)
        self.assertEqual(result['login_retry_after_ms'], 2000)

    def test_synthetic_replay_cannot_clear_or_extend_interactive_delay(self):
        self.attempt()
        replay = self.runtime.demo_request('simulate', {'demo_token': self.token, 'kind': 'brute', 'context': 'familiar'})
        self.assertEqual(replay['login_retry_after_ms'], 1000)
        with self.assertRaises(APIError) as caught:
            self.attempt('VelaDemo!42')
        self.assertEqual(caught.exception.code, 'login_backoff')
        self.advance(1)
        self.assertEqual(self.attempt()['login_retry_after_ms'], 2000)

    def test_demo_delay_does_not_throttle_trusted_evidence_ingestion(self):
        self.attempt()
        for _ in range(2):
            event = {'event_id': str(uuid.uuid4()),
                     'event_ts_utc': datetime.fromtimestamp(self.wall, timezone.utc).isoformat().replace('+00:00','Z'),
                     'account_token': 'acct_'+'a'*32, 'session_token': str(uuid.uuid4()), 'source_token': 'source_'+'b'*32,
                     'event_type': 'login_failure', 'auth_method': 'password',
                     'features': dict(CONTEXTS['familiar'], attempts_2m=1, attempts_1h=2, distinct_accounts_2m=1, failed_ratio_24h=.1),
                     'password_in_blocklist': 0, 'password_near_blocklist': 0}
            body = json.dumps(event).encode()
            timestamp, nonce = str(int(self.wall)), secrets.token_hex(16)
            headers = {'X-Sentinel-Timestamp': timestamp, 'X-Sentinel-Nonce': nonce,
                       'X-Sentinel-Signature': sign_payload(self.secret, timestamp, nonce, body)}
            result = self.runtime.trusted_request('events', body, headers)
            self.assertEqual(result['enforcement'], 'none')
        self.assertEqual(self.runtime.trusted.snapshot()['retained_events'], 2)

    def test_http_retry_after_matches_bounded_json_without_credential_echo(self):
        self.attempt()
        server = serve.DemoServer(('127.0.0.1', 0), serve.DemoHandler, runtime=self.runtime)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
        try:
            client.request('POST', '/api/demo/attempt', body=json.dumps({'demo_token': self.token,
                           'username': 'demo', 'password': 'private-test-marker', 'context': 'familiar'}),
                           headers={'Content-Type': 'application/json', 'X-Sentinel-Demo': '1'})
            response = client.getresponse()
            body = response.read().decode()
            self.assertEqual(response.status, 429)
            self.assertEqual(response.getheader('Retry-After'), '1')
            self.assertEqual(json.loads(body)['retry_after_seconds'], 1)
            self.assertNotIn('private-test-marker', body)
            self.assertNotIn('private-test-marker', repr(self.runtime.demos))
        finally:
            client.close()
            server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()

"""Security regressions at real transport and state-isolation boundaries.

Only public synthetic demo credentials and invented opaque event identifiers are
used. Concurrency checks use bounded events rather than sustained load.
"""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from src.runtime import adapter
from src.runtime.service import APIError, CONTEXTS, RuntimeService, sign_payload

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sentinel_hardening_server', ROOT/'app/serve.py')
serve = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(serve)


class Clock:
    def __init__(self):
        self.value = 1800000000.

    def __call__(self):
        return self.value


@contextmanager
def local_server(runtime, handler=None, **options):
    server = serve.DemoServer(('127.0.0.1', 0), handler or serve.DemoHandler,
                              runtime=runtime, **options)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class RuntimeHardeningTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.producer_key = secrets.token_hex(32)
        self.reviewer_key = secrets.token_hex(32)
        self.runtime = RuntimeService(now=self.clock, rate_now=self.clock,
                                      secret=self.producer_key, review_secret=self.reviewer_key)

    def event(self, **updates):
        value = {
            'event_id': str(uuid.uuid4()),
            'event_ts_utc': datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            'account_token': 'acct_'+secrets.token_hex(16),
            'session_token': str(uuid.uuid4()), 'source_token': 'source_'+secrets.token_hex(16),
            'event_type': 'login_failure', 'auth_method': 'password',
            'features': dict(CONTEXTS['familiar'], attempts_2m=1, attempts_1h=1,
                             distinct_accounts_2m=1, failed_ratio_24h=.1),
            'password_in_blocklist': 0, 'password_near_blocklist': 0,
        }
        value.update(updates)
        return value

    def signed(self, operation, payload, key=None):
        body = json.dumps(payload, separators=(',', ':')).encode()
        timestamp, nonce = str(int(self.clock())), secrets.token_hex(16)
        headers = {'X-Sentinel-Timestamp': timestamp, 'X-Sentinel-Nonce': nonce,
                   'X-Sentinel-Signature': sign_payload(key or self.producer_key, timestamp, nonce,
                                                       body, path='/api/'+operation)}
        return body, headers

    def trusted(self, operation, payload, key=None):
        body, headers = self.signed(operation, payload, key)
        return self.runtime.trusted_request(operation, body, headers)

    def demo(self, operation, **data):
        return self.runtime.demo_request(operation, data)

    def assert_api_error(self, status, callback):
        with self.assertRaises(APIError) as caught:
            callback()
        self.assertEqual(caught.exception.status, status)

    def test_ingestion_and_review_authority_are_separate(self):
        event = self.event()
        self.trusted('events', event)
        review = {'event_id': event['event_id'], 'label': 'normal'}
        self.assert_api_error(401, lambda: self.trusted('review', review, self.producer_key))
        self.assert_api_error(401, lambda: self.trusted('metrics', {}, self.producer_key))
        self.assert_api_error(401, lambda: self.trusted('events', self.event(), self.reviewer_key))
        self.trusted('review', review, self.reviewer_key)
        metrics = self.trusted('metrics', {}, self.reviewer_key)
        serialized = json.dumps(metrics)
        self.assertNotIn(event['account_token'], serialized)
        self.assertNotIn(event['source_token'], serialized)
        self.assertNotIn(self.producer_key, serialized)

    def test_producer_key_does_not_enable_an_unconfigured_reviewer(self):
        self.runtime = RuntimeService(now=self.clock, rate_now=self.clock, secret=self.producer_key)
        self.trusted('events', self.event())
        self.assert_api_error(503, lambda: self.trusted('metrics', {}, self.producer_key))

    def test_public_status_does_not_disclose_shadow_aggregates(self):
        self.trusted('events', self.event())
        with local_server(self.runtime) as server:
            client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
            try:
                client.request('GET', '/api/status')
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                value = json.loads(response.read())
            finally:
                client.close()
        self.assertIn('status', value)
        for forbidden in ('shadow', 'retained_events', 'feedback', 'active_demo_count', 'event_id'):
            self.assertNotIn('"'+forbidden+'":', json.dumps(value))

    def test_old_mfa_challenge_cannot_authorize_a_new_pending_login(self):
        token = self.demo('start')['demo_token']
        def login():
            return self.demo('attempt', demo_token=token, username='demo',
                             password='VelaDemo!42', context='familiar')
        old = login()['mfa_challenge_id']
        new = login()['mfa_challenge_id']
        self.assertRegex(old, r'^[0-9a-f]{32}$')
        self.assertRegex(new, r'^[0-9a-f]{32}$')
        self.assertNotEqual(old, new)
        for _ in range(5):
            self.assert_api_error(409, lambda: self.demo('mfa', demo_token=token,
                                  challenge_id=old, code='123456'))
        accepted = self.demo('mfa', demo_token=token, challenge_id=new, code='123456')
        self.assertTrue(accepted['allowed_access'])
        self.assertEqual(accepted['latest']['verification'], 'mfa_verified')
        self.assertIsNone(accepted['mfa_challenge_id'])

    def test_demo_capacity_does_not_consume_reserved_trusted_capacity(self):
        with patch('src.runtime.service.MAX_DEMO_EVENTS', 2), \
             patch('src.runtime.service.MAX_TRUSTED_EVENTS', 3), \
             patch('src.runtime.service.MAX_TOTAL_EVENTS', 5):
            token = self.demo('start')['demo_token']
            for _ in range(2):
                self.demo('attempt', demo_token=token, username='demo', password='wrong', context='familiar')
                self.clock.value += 2  # Finish the 1s/2s interactive-password delays.
            self.assert_api_error(429, lambda: self.demo('attempt', demo_token=token,
                                  username='demo', password='wrong', context='familiar'))
            for _ in range(3):
                self.trusted('events', self.event())
            self.assertEqual(self.runtime.trusted.snapshot()['retained_events'], 3)
            self.assert_api_error(429, lambda: self.trusted('events', self.event()))

    def test_password_check_does_not_hold_global_ingestion_lock(self):
        token = self.demo('start')['demo_token']
        checking, release, ingested = threading.Event(), threading.Event(), threading.Event()
        errors = []
        original = self.runtime.checker.check
        def controlled_check(password):
            checking.set()
            if not release.wait(2):
                raise AssertionError('Password-check test did not release its worker.')
            return original(password)
        def attempt():
            try:
                self.demo('attempt', demo_token=token, username='demo', password='wrong', context='familiar')
            except Exception as error:
                errors.append(error)
        def ingest():
            try:
                self.trusted('events', self.event())
                ingested.set()
            except Exception as error:
                errors.append(error)
        with patch.object(self.runtime.checker, 'check', side_effect=controlled_check):
            demo_thread = threading.Thread(target=attempt, daemon=True)
            trusted_thread = threading.Thread(target=ingest, daemon=True)
            demo_thread.start()
            try:
                self.assertTrue(checking.wait(1))
                trusted_thread.start()
                self.assertTrue(ingested.wait(.5), 'A demo password check blocked trusted ingestion.')
            finally:
                release.set()
                demo_thread.join(timeout=2)
                if trusted_thread.ident is not None:
                    trusted_thread.join(timeout=2)
        self.assertEqual(errors, [])

    def test_adapter_rejects_disallowed_fields_before_opening_a_socket(self):
        cases = [([], self.event(password='synthetic-private-marker')),
                 (['--review'], {'event_id': str(uuid.uuid4()), 'label': 'normal', 'password': 'synthetic-private-marker'}),
                 (['--review'], {'event_id': 'not-a-uuid', 'label': 'normal'}),
                 (['--review'], {'event_id': str(uuid.uuid4()), 'label': 'automatic-success'})]
        for arguments, payload in cases:
            with self.subTest(arguments=arguments, fields=list(payload)):
                stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()), encoding='utf-8')
                output, error = io.StringIO(), io.StringIO()
                with patch.object(sys, 'argv', ['adapter', *arguments]), patch.object(sys, 'stdin', stdin), \
                     patch.dict(os.environ, {'SENTINEL_INGEST_SECRET': self.producer_key,
                                             'SENTINEL_REVIEW_SECRET': self.reviewer_key}), \
                     patch.object(adapter.http.client, 'HTTPConnection') as connection, \
                     redirect_stdout(output), redirect_stderr(error):
                    with self.assertRaises(SystemExit) as caught:
                        adapter.main()
                self.assertNotEqual(caught.exception.code, 0)
                connection.assert_not_called()
                self.assertNotIn('synthetic-private-marker', output.getvalue()+error.getvalue())

    def test_metrics_adapter_uses_reviewer_secret_and_needs_no_stdin(self):
        # The subprocess signs with its real wall clock, so use the same clock
        # boundary here instead of this class's deliberately fixed unit clock.
        runtime = RuntimeService(secret=self.producer_key, review_secret=self.reviewer_key)
        with local_server(runtime) as server:
            environment = dict(os.environ, SENTINEL_REVIEW_SECRET=self.reviewer_key)
            environment.pop('SENTINEL_INGEST_SECRET', None)
            result = subprocess.run([sys.executable, '-m', 'src.runtime.adapter', '--metrics',
                                     '--port', str(server.server_port)], input=b'', capture_output=True,
                                    timeout=5, cwd=ROOT, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIsInstance(json.loads(result.stdout), dict)
        self.assertNotIn(self.reviewer_key, (result.stdout+result.stderr).decode())

    def test_identical_role_secrets_and_disabled_demo_are_rejected(self):
        with self.assertRaises(ValueError):
            RuntimeService(secret=self.producer_key, review_secret=self.producer_key)
        self.runtime = RuntimeService(now=self.clock, rate_now=self.clock, secret=self.producer_key,
                                      review_secret=self.reviewer_key, demo_enabled=False)
        self.assert_api_error(403, lambda: self.demo('start'))
        self.trusted('events', self.event())

    def test_restart_does_not_reset_process_start_budget_and_clock_refill_is_bounded(self):
        for _ in range(16):
            token = self.demo('start')['demo_token']
            self.demo('reset', demo_token=token)
        self.assertEqual(len(self.runtime.demos), 0)
        self.assert_api_error(429, lambda: self.demo('start'))
        self.clock.value += 2
        token = self.demo('start')['demo_token']
        self.assert_api_error(429, lambda: self.demo('start'))
        self.demo('reset', demo_token=token)

    def test_demo_operation_throttle_does_not_spend_trusted_request_budget(self):
        token = self.demo('start')['demo_token']
        for _ in range(60):
            self.demo('status', demo_token=token)
        self.assert_api_error(429, lambda: self.demo('status', demo_token=token))
        self.trusted('events', self.event())
        self.clock.value += 1
        self.assertEqual(self.demo('status', demo_token=token)['total'], 0)

    def test_invalid_authentication_cannot_consume_authenticated_operation_budgets(self):
        invalid_body, invalid_headers = self.signed('events', self.event(), self.reviewer_key)
        for _ in range(100):
            self.assert_api_error(401, lambda: self.runtime.trusted_request('events', invalid_body, invalid_headers))
        self.assert_api_error(429, lambda: self.runtime.trusted_request('events', invalid_body, invalid_headers))
        event = self.event()
        self.trusted('events', event)
        self.trusted('review', {'event_id': event['event_id'], 'label': 'normal'}, self.reviewer_key)
        self.trusted('metrics', {}, self.reviewer_key)
        self.assertEqual(self.runtime.trusted.snapshot()['retained_events'], 1)

    def test_reviewer_throttle_does_not_consume_producer_budget(self):
        for _ in range(100):
            self.trusted('metrics', {}, self.reviewer_key)
        self.assert_api_error(429, lambda: self.trusted('metrics', {}, self.reviewer_key))
        self.trusted('events', self.event())
        self.assertEqual(self.runtime.trusted.snapshot()['retained_events'], 1)

    def test_reset_cancels_password_check_without_restoring_deleted_demo(self):
        token = self.demo('start')['demo_token']
        checking, release = threading.Event(), threading.Event()
        errors = []
        original = self.runtime.checker.check
        def controlled_check(password):
            checking.set()
            if not release.wait(2):
                raise AssertionError('Password-check test did not release its worker.')
            return original(password)
        def attempt():
            try:
                self.demo('attempt', demo_token=token, username='demo', password='VelaDemo!42', context='familiar')
            except APIError as error:
                errors.append(error.status)
        with patch.object(self.runtime.checker, 'check', side_effect=controlled_check):
            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            try:
                self.assertTrue(checking.wait(1))
                self.assertEqual(self.demo('reset', demo_token=token), {})
            finally:
                release.set()
                worker.join(timeout=2)
        self.assertEqual(errors, [410])
        self.assertNotIn(token, self.runtime.demos)

    def raw_request(self, server, request):
        with socket.create_connection(('127.0.0.1', server.server_port), timeout=2) as client:
            client.sendall(request)
            response = b''
            try:
                while chunk := client.recv(4096):
                    response += chunk
            except ConnectionResetError:
                pass
            return response

    def test_ambiguous_headers_get_bodies_and_non_origin_targets_are_rejected(self):
        with local_server(self.runtime) as server:
            host = f'127.0.0.1:{server.server_port}'
            base = [('Host', host), ('Content-Type', 'application/json'),
                    ('X-Sentinel-Demo', '1'), ('Content-Length', '2')]
            for name, value in [('Host', host), ('Content-Type', 'application/json'),
                                ('X-Sentinel-Demo', '1'), ('Origin', f'http://{host}'),
                                ('Sec-Fetch-Site', 'same-origin')]:
                headers = base.copy()
                if not any(key == name for key, _ in headers):
                    headers.append((name, value))
                headers.append((name, value))
                request = 'POST /api/demo/start HTTP/1.1\r\n'+''.join(f'{key}: {item}\r\n' for key, item in headers)+'\r\n{}'
                with self.subTest(duplicate=name):
                    response = self.raw_request(server, request.encode())
                    self.assertRegex(response.split(b'\r\n', 1)[0], rb'^HTTP/1\.[01] 4\d\d ')
            for target, extra, body in [('/api/status', 'Content-Length: 1\r\n', 'x'),
                                         ('http:/api/status', '', '')]:
                with self.subTest(target=target, body=bool(body)):
                    response = self.raw_request(server, f'GET {target} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n{body}'.encode())
                    self.assertRegex(response.split(b'\r\n', 1)[0], rb'^HTTP/1\.[01] 4\d\d ')

    def test_header_size_budget_rejects_large_header_before_dispatch(self):
        with local_server(self.runtime) as server:
            request = f'GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nX-Padding: '+('x'*17000)+'\r\n\r\n'
            response = self.raw_request(server, request.encode())
            self.assertRegex(response.split(b'\r\n', 1)[0], rb'^HTTP/1\.[01] 4\d\d ')

    def test_worker_budget_rejects_excess_connections_without_spawning_handlers(self):
        entered, release = threading.Event(), threading.Event()
        state, guard = {'started': 0}, threading.Lock()
        class HeldHandler(serve.DemoHandler):
            def handle(self):
                with guard:
                    state['started'] += 1
                    if state['started'] == 2:
                        entered.set()
                release.wait(2)
        sockets = []
        with local_server(self.runtime, HeldHandler, max_workers=2, request_deadline=1) as server:
            try:
                for _ in range(2):
                    sockets.append(socket.create_connection(('127.0.0.1', server.server_port), timeout=1))
                self.assertTrue(entered.wait(1))
                excess = socket.create_connection(('127.0.0.1', server.server_port), timeout=1)
                sockets.append(excess)
                try:
                    result = excess.recv(512)
                except ConnectionResetError:
                    result = b''
                self.assertTrue(result == b'' or b'503' in result or b'429' in result)
                with guard:
                    self.assertEqual(state['started'], 2)
            finally:
                release.set()
                for connection in sockets:
                    connection.close()

    def test_absolute_deadline_stops_trickled_headers_and_bodies(self):
        for incomplete in ('header', 'body'):
            with self.subTest(incomplete=incomplete), local_server(self.runtime, request_deadline=.35) as server:
                client = socket.create_connection(('127.0.0.1', server.server_port), timeout=1.5)
                host = f'Host: 127.0.0.1:{server.server_port}\r\n'
                if incomplete == 'header':
                    initial = ('POST /api/demo/start HTTP/1.1\r\n'+host+'X-Padding: ').encode()
                else:
                    initial = ('POST /api/demo/start HTTP/1.1\r\n'+host+
                               'Content-Type: application/json\r\nX-Sentinel-Demo: 1\r\nContent-Length: 100\r\n\r\n').encode()
                stopped = threading.Event()
                def trickle():
                    for _ in range(14):
                        if stopped.wait(.08):
                            return
                        try:
                            client.sendall(b'x')
                        except OSError:
                            return
                client.sendall(initial)
                sender = threading.Thread(target=trickle, daemon=True)
                sender.start()
                started = time.monotonic()
                try:
                    try:
                        response = client.recv(512)
                    except ConnectionResetError:
                        response = b''
                    self.assertLess(time.monotonic()-started, 1.0)
                    self.assertNotIn(b' 200 ', response)
                finally:
                    stopped.set()
                    client.close()
                    sender.join(timeout=1)


if __name__ == '__main__':
    unittest.main()

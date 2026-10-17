"""Boundary tests: serving local assets must not expose customer files or APIs."""
import contextlib
import errno
import http.client
import importlib.util
import io
import json
import os
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
import threading
import unittest
from unittest import mock
from html.parser import HTMLParser

APP = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sentinel_serve', APP / 'serve.py')
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []
        self.ids = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if 'id' in attributes:
            self.ids.append(attributes['id'])
        if tag in ('script', 'img'):
            self.assets.append(attributes['src'])
        if tag == 'link':
            self.assets.append(attributes['href'])


class DemoServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = serve.DemoServer(('127.0.0.1', 0), serve.DemoHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path='/', method='GET', headers=None, body=None):
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            client.request(method, path, body=body, headers=headers or {})
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            client.close()

    def test_occupied_port_preserves_bind_error_and_running_server(self):
        with self.assertRaises(OSError) as error:
            serve.DemoServer(('127.0.0.1', self.server.server_port), serve.DemoHandler)
        self.assertEqual(error.exception.errno, errno.EADDRINUSE)
        self.assertEqual(self.request('/company.html')[0], 200)

    def test_cli_occupied_port_has_actionable_error_without_traceback(self):
        env = {key: value for key, value in os.environ.items()
               if key not in ('SENTINEL_INGEST_SECRET', 'SENTINEL_REVIEW_SECRET')}
        result = subprocess.run(
            [sys.executable, str(APP / 'serve.py'), '--port', str(self.server.server_port)],
            cwd=APP.parent, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f'Port {self.server.server_port} is already in use', result.stderr)
        self.assertIn('--port', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(self.request('/company.html')[0], 200)

    def test_tls_startup_failure_closes_bound_socket(self):
        context = mock.Mock()
        context.wrap_socket.side_effect = ssl.SSLError('synthetic TLS setup failure')
        with self.assertRaises(ssl.SSLError):
            serve.DemoServer(('127.0.0.1', 0), serve.DemoHandler, tls_context=context)
        failed_socket = context.wrap_socket.call_args.args[0]
        self.assertEqual(failed_socket.fileno(), -1)

    def test_main_assets_and_mime(self):
        for route, (_, mime) in serve.ASSETS.items():
            with self.subTest(route=route):
                status, headers, body = self.request(route)
                self.assertEqual(status, 200)
                self.assertEqual(headers['Content-Type'], mime)
                self.assertTrue(body)

    def test_privacy_headers_and_no_cookie(self):
        _, headers, _ = self.request()
        self.assertIn("connect-src 'self'", headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertNotIn('Set-Cookie', headers)
        self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_repository_and_unknown_paths_are_not_served(self):
        for path in ['/../README.md', '/%2e%2e/README.md', '/.git/config', '/serve.py', '/tests/test_server.py', '/data.csv', '/models/demo_model.json', '/outputs/parity_cases.json', '/docs/architecture.md', '/?token=unit-only']:
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_upload_and_foreign_host_rejected(self):
        self.assertEqual(self.request('/upload', 'POST', body='unit-only')[0], 501)
        self.assertEqual(self.request(headers={'Host': 'untrusted.example'})[0], 403)

    def test_only_model_artifact_is_served(self):
        expected = serve.MODEL_FILE.read_bytes()
        status, headers, body = self.request('/demo-model.json')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Content-Type'], 'application/json; charset=utf-8')
        self.assertEqual(body, expected)
        self.assertEqual(self.request('/demo-model.json', 'HEAD')[2], b'')
        for path in ['/demo-model.json?token=private', '/models/demo_model.json', '/demo-model.json/../README.md']:
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request('/demo-model.json', 'POST', body='private')[0], 501)

    def test_missing_model_is_a_controlled_unavailable_response(self):
        with mock.patch.object(serve, 'MODEL_FILE', APP / '__not_a_real_model__.json'):
            status, _, body = self.request('/demo-model.json')
            self.assertEqual(status, 503)
            self.assertEqual(body, b'Model unavailable.')

    def test_password_reference_is_local_and_read_only(self):
        status, headers, body = self.request('/password-reference.json')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Content-Type'], 'application/json; charset=utf-8')
        self.assertEqual(json.loads(body)['schema_version'], 'els-password-reference-v1')
        self.assertEqual(self.request('/password-reference.json', 'HEAD')[2], b'')
        self.assertEqual(self.request('/password-reference.json', 'POST', body='unit-only')[0], 501)
        self.assertEqual(self.request('/password-reference.json?password=unit-only')[0], 404)
        self.assertEqual(self.request('/data/mvp_synthetic_logins_v2.csv')[0], 404)

    def test_password_reference_corruption_and_contract_fail_closed(self):
        original = json.loads(serve.REFERENCE_FILE.read_bytes())
        changed = json.loads(json.dumps(original))
        changed['exact_sha256'][0] = '0' * 64
        incompatible = json.loads(json.dumps(original))
        incompatible['normalization']['unicode'] = 'NFC'
        serve._reference_module.seal_reference(incompatible)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'reference.json'
            for value in [changed, incompatible]:
                path.write_text(json.dumps(value))
                with mock.patch.object(serve, 'REFERENCE_FILE', path):
                    status, _, body = self.request('/password-reference.json')
                    self.assertEqual(status, 503)
                    self.assertEqual(body, b'Password reference unavailable.')
            with mock.patch.object(serve, 'REFERENCE_FILE', path.parent / 'missing.json'):
                self.assertEqual(self.request('/password-reference.json')[0], 503)

    def test_corrupt_or_missing_artifact_digest_fails_closed(self):
        original = json.loads(serve.MODEL_FILE.read_bytes())
        changed = json.loads(json.dumps(original))
        changed['coefficients'][0] += 0.5  # Finite and structurally valid; digest remains old.
        missing = json.loads(json.dumps(original))
        del missing['artifact_integrity']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'model.json'
            for body in [json.dumps(changed).encode(), json.dumps(missing).encode(),
                         b'{invalid', b'x' * (serve.MAX_MODEL_BYTES + 1)]:
                with self.subTest(size=len(body)):
                    path.write_bytes(body)
                    with mock.patch.object(serve, 'MODEL_FILE', path):
                        status, _, response = self.request('/demo-model.json')
                    self.assertEqual(status, 503)
                    self.assertEqual(response, b'Model unavailable.')

    def test_malformed_target_and_missing_asset_fail_without_request_logging(self):
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            status, _, body = self.request('http://[', headers={'Host': f'127.0.0.1:{self.server.server_port}'})
            self.assertEqual(status, 400)
            self.assertEqual(body.strip(), b'Request not supported.')
            with mock.patch.dict(serve.ASSETS, {'/missing.js': ('__missing__.js', 'text/javascript')}):
                self.assertEqual(self.request('/missing.js')[0], 503)
            self.server.handle_error(None, ('private-client-example', 12345))
        self.assertEqual(captured.getvalue(), '')

    def test_head_has_no_body(self):
        status, _, body = self.request(method='HEAD')
        self.assertEqual(status, 200)
        self.assertEqual(body, b'')

    def test_no_access_log(self):
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.request('/unit-only-private-name')
        self.assertEqual(captured.getvalue(), '')

    def test_html_references_only_served_local_assets(self):
        for page in ['index.html', 'company.html']:
            with self.subTest(page=page):
                parser = AssetParser()
                parser.feed((APP / page).read_text())
                self.assertEqual(len(parser.ids), len(set(parser.ids)))
                for asset in parser.assets:
                    self.assertTrue(asset.startswith('./'))
                    self.assertIn('/' + asset[2:], serve.ASSETS)


if __name__ == '__main__':
    unittest.main()

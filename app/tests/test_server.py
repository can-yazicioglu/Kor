"""Boundary tests: serving local assets must not expose customer files or APIs."""
import contextlib
import http.client
import importlib.util
import io
from pathlib import Path
import threading
import unittest
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
        cls.server = serve.ThreadingHTTPServer(('127.0.0.1', 0), serve.DemoHandler)
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

    def test_main_assets_and_mime(self):
        for route, (_, mime) in serve.ASSETS.items():
            with self.subTest(route=route):
                status, headers, body = self.request(route)
                self.assertEqual(status, 200)
                self.assertEqual(headers['Content-Type'], mime)
                self.assertTrue(body)

    def test_privacy_headers_and_no_cookie(self):
        _, headers, _ = self.request()
        self.assertIn("connect-src 'none'", headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertNotIn('Set-Cookie', headers)
        self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_repository_and_unknown_paths_are_not_served(self):
        for path in ['/../README.md', '/%2e%2e/README.md', '/.git/config', '/serve.py', '/tests/test_server.py', '/data.csv', '/docs/architecture.md', '/?token=unit-only']:
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_upload_and_foreign_host_rejected(self):
        self.assertEqual(self.request('/upload', 'POST', body='unit-only')[0], 501)
        self.assertEqual(self.request(headers={'Host': 'untrusted.example'})[0], 403)

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
        parser = AssetParser()
        parser.feed((APP / 'index.html').read_text())
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        for asset in parser.assets:
            self.assertTrue(asset.startswith('./'))
            self.assertIn('/' + asset[2:], serve.ASSETS)


if __name__ == '__main__':
    unittest.main()

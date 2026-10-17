#!/usr/bin/env python3
"""Loopback-only, dependency-free static demo server. No CSV upload endpoint."""
import argparse
import hashlib
import hmac
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
MODEL_FILE = ROOT.parent / 'models' / 'demo_model.json'
MAX_MODEL_BYTES = 512 * 1024
ASSETS = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/index.html': ('index.html', 'text/html; charset=utf-8'),
    '/styles.css': ('styles.css', 'text/css; charset=utf-8'),
    '/main.js': ('main.js', 'text/javascript; charset=utf-8'),
    '/schema.js': ('schema.js', 'text/javascript; charset=utf-8'),
    '/sessions.js': ('sessions.js', 'text/javascript; charset=utf-8'),
    '/model-adapter.js': ('model-adapter.js', 'text/javascript; charset=utf-8'),
    '/lifecycle.js': ('lifecycle.js', 'text/javascript; charset=utf-8'),
    '/mock-view.js': ('mock-view.js', 'text/javascript; charset=utf-8'),
    '/icon.svg': ('icon.svg', 'image/svg+xml'),
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self'; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)



def verify_model_artifact(body):
    """Catch accidental corruption; a recomputed checksum is NOT authenticity.

    Kept standard-library-only so the demo server never needs ML dependencies.
    Canonicalization matches src/models/train.py exactly. The browser then checks
    the feature, policy and numeric contracts before allowing inference.
    """
    if len(body) > MAX_MODEL_BYTES:
        raise ValueError('Model unavailable.')
    artifact = json.loads(body)
    if not isinstance(artifact, dict):
        raise ValueError('Model unavailable.')
    integrity = artifact.get('artifact_integrity')
    if (not isinstance(integrity, dict)
            or integrity.get('algorithm') != 'sha256'
            or integrity.get('canonicalization') != 'python_json_sort_keys_utf8_excluding_artifact_integrity'
            or integrity.get('purpose') != 'accidental_corruption_not_authenticity'
            or not isinstance(integrity.get('digest'), str)
            or re.fullmatch(r'[0-9a-f]{64}', integrity['digest']) is None):
        raise ValueError('Model unavailable.')
    payload = {key: value for key, value in artifact.items() if key != 'artifact_integrity'}
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode('utf-8')
    digest = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(digest, integrity['digest']):
        raise ValueError('Model unavailable.')


class DemoServer(ThreadingHTTPServer):
    def handle_error(self, _request, _client_address):
        # The base server logs client addresses on unhandled transport failures.
        # This local demo intentionally has no request/error telemetry.
        pass


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        # No access log: client addresses, URLs, and file names are not recorded.
        pass

    def end_headers(self):
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        super().end_headers()

    def send_error(self, code, message=None, explain=None):
        self.respond(code, 'text/plain; charset=utf-8', b'Request not supported.\n')

    def respond(self, status, mime, body, head=False):
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def serve_asset(self, head=False):
        # Reject remote Host headers (including DNS rebinding), queries and arbitrary files.
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if self.headers.get('Host') not in allowed:
            self.respond(403, 'text/plain', b'Loopback access only.', head)
            return
        try:
            path = urlsplit(self.path)
        except ValueError:
            self.respond(400, 'text/plain', b'Request not supported.', head)
            return
        if path.path == '/demo-model.json' and not path.query and not path.netloc:
            try:
                with MODEL_FILE.open('rb') as stream:
                    body = stream.read(MAX_MODEL_BYTES + 1)
                verify_model_artifact(body)
            except (OSError, ValueError, TypeError, UnicodeError):
                self.respond(503, 'text/plain; charset=utf-8', b'Model unavailable.', head)
                return
            self.respond(200, 'application/json; charset=utf-8', body, head)
            return
        asset = ASSETS.get(path.path) if not path.query and not path.netloc else None
        if asset is None:
            self.respond(404, 'text/plain', b'Not found.', head)
            return
        file, mime = asset
        try:
            body = (ROOT / file).read_bytes()
        except OSError:
            self.respond(503, 'text/plain', b'Asset unavailable.', head)
            return
        self.respond(200, mime, body, head)

    def do_GET(self):
        self.serve_asset()

    def do_HEAD(self):
        self.serve_asset(head=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Port must be between 1 and 65535.')
    try:
        server = DemoServer(('127.0.0.1', args.port), DemoHandler)
    except OSError:
        parser.exit(1, 'Port kullanılamıyor. --port ile başka bir yerel port seçin.\n')
    print(f'Ephemeral Login Sentinel · http://127.0.0.1:{args.port}', flush=True)
    print('Yerel demo: CSV tarayıcıda işlenir; yalnızca model dosyası yerelden okunur. Ctrl+C ile durdurun.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()

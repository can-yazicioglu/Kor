#!/usr/bin/env python3
"""Loopback-only static demo, local verifier and authenticated shadow-event API."""
import argparse
import errno
import importlib.util
import hashlib
import hmac
import json
import re
import os
import sys
import threading
import socket
import ssl
from http.client import LineTooLong
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from src.runtime.service import RuntimeService, APIError, MAX_BODY, strict_json
MODEL_FILE = ROOT.parent / 'models' / 'demo_model.json'
MAX_MODEL_BYTES = 512 * 1024
REFERENCE_FILE = ROOT.parent / 'data' / 'password_reference.json'
MAX_REFERENCE_BYTES = 4 * 1024 * 1024
_reference_spec = importlib.util.spec_from_file_location(
    'kor_password_check', ROOT.parent / 'src' / 'security' / 'password_check.py')
_reference_module = importlib.util.module_from_spec(_reference_spec)
_reference_spec.loader.exec_module(_reference_module)
ASSETS = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/index.html': ('index.html', 'text/html; charset=utf-8'),
    '/company.html': ('company.html', 'text/html; charset=utf-8'),
    '/company.css': ('company.css', 'text/css; charset=utf-8'),
    '/company.js': ('company.js', 'text/javascript; charset=utf-8'),
    '/reliability-api.js': ('reliability-api.js', 'text/javascript; charset=utf-8'),
    '/insights.js': ('insights.js', 'text/javascript; charset=utf-8'),
    '/assurance.js': ('assurance.js', 'text/javascript; charset=utf-8'),
    '/datathon.html': ('datathon.html', 'text/html; charset=utf-8'),
    '/password-risk.js': ('password-risk.js', 'text/javascript; charset=utf-8'),
    '/login-engine.js': ('login-engine.js', 'text/javascript; charset=utf-8'),
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



def verify_model_artifact(body, max_bytes=MAX_MODEL_BYTES):
    """Catch accidental corruption; a recomputed checksum is NOT authenticity.

    Kept standard-library-only so the demo server never needs ML dependencies.
    Canonicalization matches src/models/train.py exactly. The browser then checks
    the feature, policy and numeric contracts before allowing inference.
    """
    if len(body) > max_bytes:
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
    daemon_threads = True

    def __init__(self, *args, runtime=None, max_workers=16, request_deadline=8.0, tls_context=None, **kwargs):
        self.runtime = runtime if runtime is not None else RuntimeService(
            secret=os.environ.get('SENTINEL_INGEST_SECRET'), review_secret=os.environ.get('SENTINEL_REVIEW_SECRET'))
        self.request_deadline = request_deadline
        self._workers = threading.BoundedSemaphore(max_workers)
        # TCPServer calls our server_close() if binding fails during its
        # constructor, before a cleanup thread can have been started.
        self._cleanup_stop = threading.Event()
        self._cleanup_thread = None
        super().__init__(*args, **kwargs)
        try:
            self.scheme = 'https' if tls_context else 'http'
            if tls_context:
                # Handshake runs in a bounded worker under the connection deadline,
                # never in the single accept loop.
                self.socket = tls_context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)
            self.runtime.transport = 'tls13_loopback' if tls_context else 'loopback_http'
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self._cleanup_thread.start()
        except BaseException:
            self.server_close()
            raise

    def process_request(self, request, client_address):
        if not self._workers.acquire(blocking=False):
            try:
                request.settimeout(.1)
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\nConnection: close\r\n\r\n')
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._workers.release()

    def _cleanup_loop(self):
        while not self._cleanup_stop.wait(1):
            with self.runtime.lock:
                self.runtime.cleanup()

    def server_close(self):
        self._cleanup_stop.set()
        if self._cleanup_thread is not None and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)
        super().server_close()

    def handle_error(self, _request, _client_address):
        # The base server logs client addresses on unhandled transport failures.
        # This local demo intentionally has no request/error telemetry.
        pass


class HeaderBudget:
    def __init__(self, stream, budget=16*1024):
        self.stream, self.remaining = stream, budget

    def readline(self, limit=-1):
        line = self.stream.readline(min(limit if limit >= 0 else self.remaining+1, self.remaining+1))
        self.remaining -= len(line)
        if self.remaining < 0:
            raise LineTooLong('request headers')
        return line


class DemoHandler(BaseHTTPRequestHandler):
    def version_string(self):
        return 'KorLocal'

    def setup(self):
        super().setup()
        self.connection.settimeout(5)
        self._deadline_timer = threading.Timer(self.server.request_deadline, self._expire_connection)
        self._deadline_timer.daemon = True
        self._deadline_timer.start()

    def _expire_connection(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self._deadline_timer.cancel()
        super().finish()

    def parse_request(self):
        stream = self.rfile
        self.rfile = HeaderBudget(stream)
        try:
            parsed = super().parse_request()
        finally:
            self.rfile = stream
        if not parsed:
            return False
        singletons = ('Host', 'Origin', 'Content-Type', 'Content-Length', 'Transfer-Encoding',
                      'Expect', 'X-Sentinel-Demo', 'Sec-Fetch-Site',
                      'X-Sentinel-Timestamp', 'X-Sentinel-Nonce', 'X-Sentinel-Signature')
        if any(len(self.headers.get_all(name, [])) > 1 for name in singletons):
            self.send_error(400)
            return False
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if self.headers.get('Host') not in allowed:
            self.send_error(403)
            return False
        if (len(self.raw_requestline) > 4096 or not self.path.startswith('/') or self.path.startswith('//') or
            '#' in self.path or self.headers.get('Transfer-Encoding') is not None or
            self.headers.get('Expect') is not None or
            self.command in ('GET', 'HEAD') and self.headers.get('Content-Length') not in (None, '0')):
            self.send_error(400)
            return False
        return True

    def log_message(self, _format, *_args):
        # No access log: client addresses, URLs, and file names are not recorded.
        pass

    def end_headers(self):
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        super().end_headers()

    def send_error(self, code, message=None, explain=None):
        self.respond(code, 'text/plain; charset=utf-8', b'Request not supported.\n')

    def respond(self, status, mime, body, head=False, retry_after=None):
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        if retry_after is not None:
            self.send_header('Retry-After', str(retry_after))
        self.end_headers()
        if not head and self.command != 'HEAD':
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
        if path.path == '/api/status' and not path.query and not path.netloc and not path.fragment:
            body = json.dumps(self.server.runtime.status(), allow_nan=False).encode()
            self.respond(200, 'application/json; charset=utf-8', body, head)
            return
        if path.path == '/password-reference.json' and not path.query and not path.netloc:
            try:
                with REFERENCE_FILE.open('rb') as stream:
                    body = stream.read(MAX_REFERENCE_BYTES + 1)
                verify_model_artifact(body, MAX_REFERENCE_BYTES)
                reference = json.loads(body)
                _reference_module.validate_reference(reference)
            except (OSError, ValueError, TypeError, UnicodeError):
                self.respond(503, 'text/plain; charset=utf-8', b'Password reference unavailable.', head)
                return
            self.respond(200, 'application/json; charset=utf-8', body, head)
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

    def do_POST(self):
        try:
            allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            host = self.headers.get('Host')
            if host not in allowed or len(self.headers.get_all('Host', [])) != 1:
                raise APIError(403, 'Loopback access only.')
            try:
                path = urlsplit(self.path)
            except ValueError:
                raise APIError(400, 'Invalid request target.') from None
            if path.query or path.netloc or path.fragment:
                raise APIError(400, 'Invalid request target.')
            is_demo = path.path.startswith('/api/demo/')
            is_trusted = path.path in ('/api/events','/api/review','/api/metrics')
            if not is_demo and not is_trusted:
                raise APIError(501, 'Request not supported.')
            origin = self.headers.get('Origin')
            if is_demo:
                if (self.headers.get('X-Sentinel-Demo') != '1' or
                    (origin is not None and origin != f'{self.server.scheme}://{host}') or
                    self.headers.get('Sec-Fetch-Site') == 'cross-site'):
                    raise APIError(403, 'Same-origin demonstration requests only.')
            elif origin is not None:
                raise APIError(403, 'Trusted events require a server adapter.')
            if (self.headers.get('Content-Type') != 'application/json' or
                self.headers.get('Transfer-Encoding') is not None or
                len(self.headers.get_all('Content-Length', [])) != 1):
                raise APIError(400, 'A bounded JSON body is required.')
            length = self.headers.get('Content-Length', '')
            if not re.fullmatch(r'[0-9]{1,6}', length):
                raise APIError(400, 'Invalid body length.')
            length = int(length)
            if length > MAX_BODY:
                raise APIError(413, 'Request body too large.')
            body = self.rfile.read(length)
            if len(body) != length:
                raise APIError(400, 'Incomplete body.')
            if is_demo:
                data = strict_json(body)
                body = None
                result = self.server.runtime.demo_request(path.path.removeprefix('/api/demo/'), data)
            else:
                for name in ('X-Sentinel-Timestamp','X-Sentinel-Nonce','X-Sentinel-Signature'):
                    if len(self.headers.get_all(name, [])) != 1:
                        raise APIError(401, 'Event authentication failed.')
                result = self.server.runtime.trusted_request(path.path[5:], body, self.headers)
            self.respond(200, 'application/json; charset=utf-8', json.dumps(result, allow_nan=False).encode())
        except APIError as error:
            payload = {'error': str(error)}
            if error.code is not None:
                payload['code'] = error.code
            if error.retry_after is not None:
                payload['retry_after_seconds'] = error.retry_after
            self.respond(error.status, 'application/json; charset=utf-8', json.dumps(payload).encode(), retry_after=error.retry_after)
        except (TimeoutError, OSError):
            self.close_connection = True
        except Exception:
            # Do not expose credentials, event cells, identifiers or tracebacks.
            self.respond(503, 'application/json; charset=utf-8', b'{"error":"Risk service unavailable."}')


def create_tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(cert), str(key))
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--disable-demo', action='store_true', help='Disable anonymous demo mutations for shadow ingestion')
    parser.add_argument('--tls-cert', type=Path, help='Local PEM certificate; requires --tls-key; enables TLS 1.3 only')
    parser.add_argument('--tls-key', type=Path, help='Private PEM key outside the repository; never committed')
    models = parser.add_mutually_exclusive_group()
    models.add_argument('--tuned-demo', dest='tuned_demo', action='store_true', help='Require a qualified synthetic release; rejected candidates cannot be enabled; trusted ingestion keeps the baseline')
    models.add_argument('--baseline-demo', dest='tuned_demo', action='store_false', help='Use the historical logistic model and unavailable-threshold fallback in the company demo')
    parser.set_defaults(tuned_demo=False)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Port must be between 1 and 65535.')
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error('--tls-cert and --tls-key must be supplied together.')
    try:
        tls_context = create_tls_context(args.tls_cert,args.tls_key) if args.tls_cert else None
        runtime = RuntimeService(secret=os.environ.get('SENTINEL_INGEST_SECRET'),
                                 review_secret=os.environ.get('SENTINEL_REVIEW_SECRET'), demo_enabled=not args.disable_demo,
                                 tuned_demo=args.tuned_demo and not args.disable_demo)
        server = DemoServer(('127.0.0.1', args.port), DemoHandler, runtime=runtime, tls_context=tls_context)
    except ssl.SSLError:
        parser.exit(1, 'TLS certificate/key could not be loaded. No plaintext fallback was started.\n')
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            parser.exit(1, f'Port {args.port} is already in use. Use your existing demo or choose a different --port.\n')
        parser.exit(1, 'Local port or TLS files unavailable. Check --port and configured file paths.\n')
    except ValueError:
        parser.exit(1, 'Invalid runtime configuration. Role keys must be distinct; --tuned-demo requires a qualified intact release.\n')
    print(f'Kör · {server.scheme}://127.0.0.1:{args.port}/company.html', flush=True)
    print('Local demo: company credentials are checked transiently on this local server; CSV stays in your browser. Trusted adapters run in shadow mode. Stop with Ctrl+C.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()

"""Local adapter transport. Provider-specific verification must occur upstream.

Reads one allowlisted event or human-review record from stdin, authenticates the
request with an environment-held secret, and sends it only to loopback. Never
accepts a provider credential or raw password as an event field.
"""
import argparse
import http.client
import json
import os
import re
import secrets
import ssl
import sys
import time
import uuid
from src.runtime.service import MAX_BODY, sign_payload, strict_json
from src.runtime.risk import validate_event


def validate_review(value):
    if set(value) != {'event_id', 'label'} or value['label'] not in ('normal', 'suspicious'):
        raise ValueError('Invalid review contract.')
    if not isinstance(value['event_id'], str) or not uuid.UUID(value['event_id']).int:
        raise ValueError('Invalid review identifier.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8001)
    parser.add_argument('--tls-ca', help='Trusted local CA/certificate file; require verified TLS 1.3, with no plaintext fallback')
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument('--review', action='store_true', help='Send independently reviewed normal/suspicious label')
    operation.add_argument('--metrics', action='store_true', help='Read aggregate shadow metrics using the reviewer key')
    args = parser.parse_args()
    key_name = 'SENTINEL_REVIEW_SECRET' if args.review or args.metrics else 'SENTINEL_INGEST_SECRET'
    secret = os.environ.get(key_name, '')
    if not 1 <= args.port <= 65535 or not re.fullmatch(r'[0-9a-fA-F]{64,128}',secret):
        parser.exit(1, f'A valid port and {key_name} (64–128 hex characters) are required.\n')
    body = b'{}' if args.metrics else sys.stdin.buffer.read(MAX_BODY+1)
    if len(body)>MAX_BODY:
        parser.exit(1, 'Event exceeds the local request limit.\n')
    try:
        value = strict_json(body)
        if args.review:
            validate_review(value)
        elif not args.metrics:
            validate_event(value)
        timestamp, nonce = str(int(time.time())), secrets.token_hex(16)
        path = '/api/metrics' if args.metrics else '/api/review' if args.review else '/api/events'
        headers = {'Content-Type':'application/json','X-Sentinel-Timestamp':timestamp,
                   'X-Sentinel-Nonce':nonce, 'X-Sentinel-Signature':sign_payload(secret,timestamp,nonce,body,path=path)}
        if args.tls_ca:
            context = ssl.create_default_context(cafile=args.tls_ca)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            connection = http.client.HTTPSConnection('127.0.0.1',args.port,timeout=5,context=context)
        else:
            connection = http.client.HTTPConnection('127.0.0.1',args.port,timeout=5)
        try:
            connection.request('POST',path,body=body,headers=headers)
            response = connection.getresponse()
            response_body = response.read(256*1024+1)
            if len(response_body) > 256*1024:
                raise ValueError
            value = strict_json(response_body)
        finally:
            connection.close()
        if response.status != 200:
            raise ValueError
        # Local caller receives derived result only. No request or secret is echoed.
        print(json.dumps(value,allow_nan=False))
    except (ValueError, TypeError, KeyError, OSError, http.client.HTTPException):
        parser.exit(1, 'Local shadow ingestion failed. Check readiness and the event contract.\n')


if __name__ == '__main__':
    main()

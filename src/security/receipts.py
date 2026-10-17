"""One current HMAC receipt per expiring demo; no permanent audit history.

Integrity inside a trusted running process, not nonrepudiation, encryption,
hardware attestation or protection against a compromised server.
"""
import copy
import hashlib
import hmac
import json
import secrets


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


class DecisionReceipt:
    def __init__(self):
        self._key = secrets.token_bytes(32)
        self._latest = None
        self._counter = 0

    def clear(self):
        self._key = None
        self._latest = None
        self._counter = 0

    def issue(self, result):
        if self._key is None:
            raise ValueError('Receipt scope has expired.')
        self._counter += 1
        payload = {'version':'els-decision-receipt-v1', 'counter':self._counter,
                   'score':result['score'], 'action':result['action'],
                   'model_version':result['model_version'], 'window_seconds':120}
        signature = hmac.new(self._key, b'els-receipt-v1\x00'+canonical(payload), hashlib.sha256).hexdigest()
        self._latest = {'payload':payload, 'mac':signature}

    def verify(self, receipt):
        if self._key is None or self._latest is None:
            return False
        try:
            if not isinstance(receipt,dict) or set(receipt) != {'payload','mac'} or not isinstance(receipt['mac'],str):
                return False
            expected = hmac.new(self._key,b'els-receipt-v1\x00'+canonical(receipt['payload']),hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected,receipt['mac']) and hmac.compare_digest(receipt['mac'],self._latest['mac'])
        except (ValueError,TypeError,RecursionError):
            return False

    def current(self):
        return copy.deepcopy(self._latest)

    def inspect(self):
        return {'status':'pending' if self._latest is None else 'verified' if self.verify(self._latest) else 'invalid',
                'algorithm':'HMAC-SHA-256', 'counter':self._counter,
                'digest':self._latest['mac'] if self._latest else None}

    def tamper_check(self):
        if self._latest is None:
            raise ValueError('Record a decision before checking its receipt.')
        altered = self.current()
        altered['payload']['score'] = 0 if altered['payload']['score'] != 0 else 100
        return {'original_verified':self.verify(self.current()),
                'altered_verified':self.verify(altered), 'algorithm':'HMAC-SHA-256',
                'scope':'Current decision only; the server holds the ephemeral verification key.'}

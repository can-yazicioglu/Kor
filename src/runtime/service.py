"""Bounded local demonstration and authenticated shadow-ingestion service.

The demo verifier is fictional. Real events require a configured adapter secret;
no browser-supplied outcome is accepted on the trusted ingestion channel.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import secrets
import threading
import time
import uuid

from src.models.core import FEATURES, validate_artifact
from src.models.calibrate_reliability import validate_policy
from src.security.password_check import PasswordChecker
from src.runtime.risk import RiskEngine
from src.runtime.context_guard import GuardedRiskEngine
from src.security.demo_auth import verify_demo_password
from src.security.receipts import DecisionReceipt

ROOT = Path(__file__).resolve().parents[2]
TTL = 300
MAX_DEMOS = 32
MAX_ATTEMPTS = 500
MAX_TOTAL_EVENTS = 5000
MAX_DEMO_EVENTS = 1000
MAX_TRUSTED_EVENTS = 4000
MAX_BODY = 16 * 1024
MAX_LOGIN_DELAY = 60
CONTEXTS = {
    'familiar': dict(hour_deviation=.768611, typical_weekday=0, geo_velocity_kmh=98.41,
                     network_familiarity='familiar', asn_category='residential', device_managed=0, device_new=0),
    'unfamiliar': dict(hour_deviation=3.611667, typical_weekday=1, geo_velocity_kmh=31.92,
                       network_familiarity='unfamiliar', asn_category='cloud', device_managed=0, device_new=1),
    'vpn': dict(hour_deviation=.5, typical_weekday=1, geo_velocity_kmh=0,
                network_familiarity='familiar', asn_category='vpn', device_managed=1, device_new=0),
    'travel': dict(hour_deviation=3, typical_weekday=1, geo_velocity_kmh=700,
                   network_familiarity='unfamiliar', asn_category='residential', device_managed=1, device_new=0),
    'new_device': dict(hour_deviation=.5, typical_weekday=1, geo_velocity_kmh=0,
                       network_familiarity='familiar', asn_category='residential', device_managed=0, device_new=1),
    'cold_start': dict(hour_deviation=None, typical_weekday=None, geo_velocity_kmh=None,
                       network_familiarity=None, asn_category='unknown', device_managed=None, device_new=None),
    'unusual_success': dict(hour_deviation=7, typical_weekday=0, geo_velocity_kmh=1800,
                           network_familiarity='unfamiliar', asn_category='cloud', device_managed=0, device_new=1),
}


class APIError(ValueError):
    def __init__(self, status, message, *, code=None, retry_after=None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.retry_after = retry_after


class RateLimiter:
    """Fixed channel buckets; no addresses, identifiers or request data retained."""
    def __init__(self, now=time.monotonic):
        self.now = now
        self.buckets = {}

    def clear(self):
        self.buckets.clear()

    def take(self, channel, capacity, refill, cost=1):
        now = self.now()
        tokens, previous = self.buckets.get(channel, (capacity, now))
        tokens = min(capacity, tokens + max(0, now-previous)*refill)
        self.buckets[channel] = (tokens, now)
        if tokens < cost:
            raise APIError(429, 'Request rate limit reached. Try again later.')
        self.buckets[channel] = (tokens-cost, now)


def strict_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key.')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('Nonfinite JSON value.')
    try:
        value = json.loads(body, object_pairs_hook=pairs, parse_constant=invalid)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise APIError(400, 'Invalid JSON request.') from None


def sign_payload(secret, timestamp, nonce, body, path='/api/events'):
    return hmac.new(secret.encode(), b'v1\n' + path.encode() + b'\n' + timestamp.encode() + b'\n' + nonce.encode() + b'\n' + body,
                    hashlib.sha256).hexdigest()


def exact_keys(value, keys):
    if set(value) != set(keys):
        raise APIError(400, 'Unexpected request fields.')


def _load_json(path, limit, with_digest=False):
    with Path(path).open('rb') as stream:
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise ValueError('Artifact too large.')
    value = strict_json(body)
    return (value, hashlib.sha256(body).hexdigest()) if with_digest else value


class RuntimeService:
    def __init__(self, *, now=time.time, rate_now=time.monotonic, secret=None, review_secret=None,
                 demo_enabled=True, model_path=None, policy_path=None, reference_path=None,
                 tuned_demo=False, tuned_model_dir=None):
        self.now = now
        self.lock = threading.RLock()
        self.limiter = RateLimiter(rate_now)
        self._password_slots = threading.BoundedSemaphore(4)
        self.transport = 'loopback_http'
        self.demo_enabled = demo_enabled
        self.demo_candidate = None
        if tuned_demo:
            from src.models.tuned_runtime import validate as validate_candidate
            folder = Path(tuned_model_dir) if tuned_model_dir is not None else ROOT/'models'
            try:
                release = _load_json(folder/'tuned_release.json', 16*1024)
                candidate, candidate_digest = _load_json(folder/'tuned_model.json', 512*1024, with_digest=True)
                validate_candidate(candidate)
                if (release.get('schema_version') != 'els-tuned-demo-release-v1' or
                    release.get('scope') != 'synthetic_demo_only' or release.get('eligible_for_demo_promotion') is not True or
                    release.get('post_evaluation_mvp_check') != 'passed' or
                    not isinstance(release.get('attack_breakdown_sha256'), str) or
                    re.fullmatch(r'[0-9a-f]{64}', release['attack_breakdown_sha256']) is None or
                    release.get('model_sha256') != candidate_digest or release.get('model_version') != candidate['model_version'] or
                    release.get('protocol_digest') != candidate['protocol_digest'] or
                    any(value is None for value in candidate['thresholds'].values())):
                    raise ValueError
                self.demo_candidate = candidate
            except (OSError,ValueError,TypeError,KeyError,OverflowError):
                raise ValueError('The tuned demo release is missing, unqualified or corrupted.') from None
        self.secret = secret if isinstance(secret, str) and re.fullmatch(r'[0-9a-fA-F]{64,128}', secret) else None
        self.review_secret = review_secret if isinstance(review_secret, str) and re.fullmatch(r'[0-9a-fA-F]{64,128}', review_secret) else None
        if self.secret and self.review_secret and hmac.compare_digest(self.secret, self.review_secret):
            raise ValueError('Ingestion and review require distinct secrets.')
        self.model = self.policy = None
        model_digest = None
        try:
            model, model_digest = _load_json(model_path or ROOT/'models/demo_model.json', 512*1024, with_digest=True)
            self.model = validate_artifact(model)
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            pass
        try:
            self.policy = _load_json(policy_path or ROOT/'models/reliability_policy.json', 512*1024)
            validate_policy(self.policy, self.model)
            if self.policy['base_model_sha256'] != model_digest:
                raise ValueError('Policy model binding differs.')
        except (OSError, ValueError, TypeError, KeyError):
            self.policy = None
        try:
            self.checker = PasswordChecker.from_file(reference_path or ROOT/'data/password_reference.json')
        except (OSError, ValueError, TypeError, KeyError):
            self.checker = PasswordChecker(None)
        self.simulation_assessment = self.checker.check('password')
        # The context guard is a demonstrator hypothesis, with substantial
        # benign overlap in consumed synthetic cohorts. Do not enable it on
        # the customer-facing shadow stream without a separate release study.
        self.trusted = RiskEngine(self.model, self.policy, now=now, event_mode='trusted_idp')
        self.demos = {}
        self.nonces = {}

    def cleanup(self):
        now = self.now()
        for token in [token for token, demo in self.demos.items() if now >= demo['deadline']]:
            removed = self.demos.pop(token)
            removed['engine'].reset()
            removed['receipt'].clear()
        self.nonces = {nonce: deadline for nonce, deadline in self.nonces.items() if deadline > now}
        self.trusted.snapshot()  # Runtime expires old events and reviewed labels.

    def readiness(self):
        # Engine validates artifact binding and calibration before declaring readiness.
        return {'model_ready': self.model is not None,
                'policy_ready': bool(getattr(self.trusted, 'policy_ready', False)),
                'reference_ready': self.checker.ready}

    def status(self):
        with self.lock:
            return {'mode': 'shadow_only', 'status': self.readiness(),
                    'ingestion_enabled': self.secret is not None,
                    'review_enabled': self.review_secret is not None, 'demo_enabled': self.demo_enabled,
                    'enforcement': 'none', 'retention_seconds': TTL}

    def start(self):
        self.cleanup()
        if len(self.demos) >= MAX_DEMOS:
            raise APIError(429, 'Local demo capacity reached. Wait for expiry.')
        token = secrets.token_urlsafe(32)
        self.demos[token] = {'engine': GuardedRiskEngine(self.model, self.policy, now=self.now, candidate=self.demo_candidate),
            'deadline': self.now()+TTL, 'accounts': {}, 'sessions': {}, 'sources': {},
            'events': [], 'latest': None, 'allowed_access': False, 'mfa_required': False,
            'pending_mfa': None, 'checking': None, 'limiter': RateLimiter(self.limiter.now), 'context': 'familiar',
            'login_failures': 0, 'login_retry_at': 0, 'authorization_until':0,
            'receipt':DecisionReceipt()}
        return {'demo_token': token, 'snapshot': self._snapshot(self.demos[token]),
                'status': self.readiness(), 'mode': 'synthetic_demo'}

    def _demo(self, token):
        self.cleanup()
        if not isinstance(token, str) or token not in self.demos:
            raise APIError(410, 'Demo expired or unavailable. Start a new demo.')
        return self.demos[token]

    def _snapshot(self, demo):
        if demo['allowed_access'] and self.now() >= demo['authorization_until']:
            demo['allowed_access'] = False
        if demo['pending_mfa'] and self.now() >= demo['pending_mfa']['deadline']:
            demo['pending_mfa'] = None
            demo['mfa_required'] = False
            demo['allowed_access'] = False
        remaining_ms = max(0, math.floor((demo['deadline']-self.now())*1000))
        inspection = demo['engine'].inspect_latest()
        insights = {'version': 'els-insights-v1',
                    'history_sensitivity': inspection['history_sensitivity'],
                    'decision_delta': inspection['decision_delta'],
                    'latest_event_age_seconds': inspection['latest_event_age_seconds'],
                    'lifecycle': {**inspection['inventory'],
                        'account_mappings': len(demo['accounts']), 'session_mappings': len(demo['sessions']),
                        'source_mappings': len(demo['sources']), 'expires_in_ms': remaining_ms,
                        'pending_mfa': demo['pending_mfa'] is not None,
                        'mfa_expires_in_ms': min(remaining_ms, max(0, math.floor((demo['pending_mfa']['deadline']-self.now())*1000))) if demo['pending_mfa'] else None,
                        'interactive_failures': demo['login_failures']}}
        return {'latest': demo['latest'], 'total': len(demo['events']),
                'timeline': [{'event_id': e['event_id'], 'event_type': e['event_type'], 'score': e['score']}
                             for e in reversed(demo['events'][-8:])],
                'remaining_ms': remaining_ms, 'insights': insights,
                'allowed_access': demo['allowed_access'], 'mfa_required': demo['mfa_required'],
                'mfa_challenge_id': demo['pending_mfa']['challenge_id'] if demo['pending_mfa'] else None,
                'login_retry_after_ms': self._login_wait_ms(demo),
                'feedback_summary': demo['engine'].snapshot(), 'status': self.readiness(),
                'mode': 'synthetic_demo', 'source_label': 'Local server · synthetic identity provider',
                'assurance':{'version':'els-assurance-v1', 'transport':self.transport,
                    'password_verifier':'scrypt-n32768-r8-p3', 'receipt':demo['receipt'].inspect(),
                    'authorization':{'role':'employee' if demo['allowed_access'] else 'anonymous',
                        'workspace_allowed':demo['allowed_access'], 'audit_allowed':False,
                        'expires_in_ms':max(0,math.floor((demo['authorization_until']-self.now())*1000)) if demo['allowed_access'] else 0}}}

    def _login_wait_ms(self, demo):
        # Monotonic time prevents wall-clock jumps from bypassing the delay.
        return min(MAX_LOGIN_DELAY*1000, max(0, math.ceil((demo['login_retry_at']-self.limiter.now())*1000)))

    def _record(self, demo, outcome, context, assessment, account=0, source=0, method='password'):
        if self.now() >= demo['deadline']:
            self.cleanup()
            raise APIError(410, 'Demo expired. Start a new demo.')
        self._capacity(1)
        if len(demo['events']) >= MAX_ATTEMPTS:
            raise APIError(429, 'Demo event limit reached. Reset the demo.')
        now = self.now()
        account_token = demo['accounts'].setdefault(account, 'acct_'+secrets.token_hex(16))
        session = demo['sessions'].get(account)
        if not session or now-session[1] >= 120:
            session = (str(uuid.uuid4()), now)
            demo['sessions'][account] = session
        source_entry = demo['sources'].get(source)
        if not source_entry or now-source_entry[1] >= 120:
            source_entry = ('source_'+secrets.token_hex(16), now)
        # Keep an active source correlated across a moving window. Fixed wall-clock
        # rotation would split one source and fabricate distributed-source evidence.
        demo['sources'][source] = (source_entry[0], now)
        prior = [e for e in demo['events'] if e['account'] == account and e['event_type'].startswith('login_')]
        features = dict(CONTEXTS[context], attempts_2m=1, attempts_1h=len(prior)+int(outcome.startswith('login_')), distinct_accounts_2m=1,
                        failed_ratio_24h=(2+sum(e['event_type']=='login_failure' for e in prior))/(19+len(prior)))
        if context == 'cold_start':
            features['attempts_1h'] = features['failed_ratio_24h'] = None
        event = {'event_id': str(uuid.uuid4()), 'event_ts_utc': datetime.fromtimestamp(now, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),
            'account_token': account_token, 'session_token': session[0], 'source_token': source_entry[0],
            'event_type': outcome, 'auth_method': method, 'features': features,
            'password_in_blocklist': assessment['password_in_blocklist'] if method == 'password' else None,
            'password_near_blocklist': assessment['password_near_blocklist'] if method == 'password' else None}
        try:
            result = demo['engine'].ingest(event)
        except ValueError:
            raise APIError(400, 'Event could not be evaluated.') from None
        result = {**result, 'event_id': event['event_id'], 'success': outcome in ('login_success','mfa_success')}
        # Only identifiers, outcome and derived evidence are retained. Never credentials/hashes.
        demo['events'].append({'event_id': event['event_id'], 'event_type': outcome,
                               'account': account, 'score': result['score']})
        demo['latest'] = result
        demo['receipt'].issue(result)
        return result

    def _capacity(self, added, kind='demo'):
        demo_total = sum(len(demo['events']) for demo in self.demos.values())
        trusted_total = self.trusted.snapshot()['retained_events']
        total = demo_total + trusted_total
        channel_full = demo_total + added > MAX_DEMO_EVENTS if kind == 'demo' else trusted_total + added > MAX_TRUSTED_EVENTS
        if total + added > MAX_TOTAL_EVENTS or channel_full:
            raise APIError(429, 'Local event capacity reached. Wait for expiry.')

    def _attempt(self, data):
        """Keep expensive password checks outside the shared ingestion mutex.

        Only a random in-flight marker is retained. Reset/expiry cancels the
        result, and another operation cannot replace its context mid-flight.
        """
        exact_keys(data, ['demo_token', 'username', 'password', 'context'])
        password, username = data.pop('password'), data.pop('username')
        context = data['context']
        if not isinstance(context, str) or context not in CONTEXTS:
            raise APIError(400, 'Unknown demonstration context.')
        if username != 'demo' or not isinstance(password, str) or not 1 <= len(password) <= 256 or any(0xD800 <= ord(c) <= 0xDFFF for c in password):
            raise APIError(400, 'Use the public demo account and a synthetic password.')
        with self.lock:
            demo = self._demo(data['demo_token'])
            if demo['checking']:
                raise APIError(409, 'Verification is already in progress.')
            wait_ms = self._login_wait_ms(demo)
            if wait_ms:
                # Reject before password comparison/reference lookup. Repeated
                # early requests do not extend the deadline or create events.
                raise APIError(429, 'Wait before the next sign-in attempt.', code='login_backoff',
                               retry_after=math.ceil(wait_ms/1000))
            demo['limiter'].take('operations', 60, 1)
            self._capacity(1)
            marker = secrets.token_hex(16)
            demo['checking'] = marker
        acquired = self._password_slots.acquire(blocking=False)
        try:
            if not acquired:
                raise APIError(429, 'Password verification capacity reached. Try again later.')
            success = verify_demo_password(password)
            assessment = self.checker.check(password)
            password = username = None
            with self.lock:
                if self._demo(data['demo_token']) is not demo or demo['checking'] != marker:
                    raise APIError(409, 'Verification was cancelled.')
                demo['allowed_access'] = demo['mfa_required'] = False
                demo['authorization_until'] = 0
                demo['pending_mfa'] = None
                result = self._record(demo, 'login_success' if success else 'login_failure', context, assessment)
                if success:
                    demo['login_failures'] = 0
                    demo['login_retry_at'] = 0
                else:
                    demo['login_failures'] += 1
                    delay = min(MAX_LOGIN_DELAY, 2 ** min(demo['login_failures']-1, 6))
                    demo['login_retry_at'] = self.limiter.now()+delay
                demo['context'] = context
                if success and result['score'] is not None and self.checker.ready:
                    if result['action'] == 'monitor':
                        demo['allowed_access'] = True
                        demo['authorization_until'] = min(self.now()+120,demo['deadline'])
                    else:
                        demo['mfa_required'] = True
                        demo['pending_mfa'] = {'deadline': min(self.now()+120, demo['sessions'][0][1]+120),
                            'challenge_id': secrets.token_hex(16), 'assessment': assessment, 'attempts': 0, 'context': context}
                return self._snapshot(demo)
        finally:
            if acquired:
                self._password_slots.release()
            password = username = None
            with self.lock:
                if demo['checking'] == marker:
                    demo['checking'] = None

    def demo_request(self, operation, data):
        with self.lock:
            if not self.demo_enabled:
                raise APIError(403, 'The demonstration API is disabled.')
            self.limiter.take('demo', 240, 4)
        if operation == 'attempt':
            return self._attempt(data)
        with self.lock:
            if operation == 'start':
                exact_keys(data, [])
                self.limiter.take('start', 16, .5)
                return self.start()
            fields = {'simulate': ['demo_token','kind','context'], 'mfa': ['demo_token','code','challenge_id'],
                      'reset': ['demo_token'], 'status': ['demo_token'],
                      'proof':['demo_token'], 'resource':['demo_token','resource'],
                      'feedback': ['demo_token','event_id','label']}
            if operation not in fields:
                raise APIError(404, 'Unknown demo operation.')
            exact_keys(data, fields[operation])
            if operation == 'reset':
                if not isinstance(data['demo_token'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,160}', data['demo_token']):
                    raise APIError(400, 'Invalid demo handle.')
                self.cleanup()
                removed = self.demos.pop(data['demo_token'], None)
                if removed:
                    removed['engine'].reset()
                    removed['receipt'].clear()
                return {}
            demo = self._demo(data['demo_token'])
            if demo['checking']:
                raise APIError(409, 'Verification is already in progress.')
            demo['limiter'].take('operations', 60, 1)
            if operation == 'status':
                return self._snapshot(demo)
            if operation == 'proof':
                if demo['latest'] is None:
                    raise APIError(409, 'Record a synthetic sign-in first.')
                return {**self._snapshot(demo), 'security_test':demo['receipt'].tamper_check()}
            if operation == 'resource':
                snapshot = self._snapshot(demo)
                # Browser-provided role claims are excluded by exact_keys.
                # This public fixture never receives an administrator role.
                if data['resource'] != 'workspace' or not demo['allowed_access']:
                    raise APIError(403, 'This demo role cannot access the requested resource.', code='demo_access_denied')
                return {'snapshot':snapshot, 'resource':{'id':'workspace', 'classification':'fictional_demo',
                        'message':'Employee workspace authorized by the server. No private company data is present.'}}
            if operation == 'feedback':
                try:
                    demo['engine'].feedback(data['event_id'], data['label'])
                except (ValueError, TypeError):
                    raise APIError(400, 'Review label could not be recorded.') from None
                return self._snapshot(demo)
            if operation == 'simulate':
                context = data['context']
                if not isinstance(context, str) or context not in CONTEXTS:
                    raise APIError(400, 'Unknown demonstration context.')
                kind = data['kind']
                if kind not in ('brute','spray','distributed'):
                    raise APIError(400, 'Unknown demonstration scenario.')
                total = {'brute':20, 'spray':18, 'distributed':12}[kind]
                if len(demo['events'])+total > MAX_ATTEMPTS:
                    raise APIError(429, 'Demo event limit reached. Reset the demo.')
                self._capacity(total)
                demo['limiter'].take('operations', 60, 1, total-1)
                self.limiter.take('demo', 240, 4, total-1)
                demo['allowed_access'] = demo['mfa_required'] = False
                demo['authorization_until'] = 0
                demo['pending_mfa'] = None
                for index in range(total):
                    self._record(demo, 'login_failure', context, self.simulation_assessment,
                                 account=index if kind=='spray' else 0, source=index if kind=='distributed' else 0)
                demo['context'] = context
                return self._snapshot(demo)
            if operation == 'mfa':
                pending = demo['pending_mfa']
                if not pending or self.now() >= pending['deadline']:
                    demo['pending_mfa'] = None
                    demo['mfa_required'] = demo['allowed_access'] = False
                    raise APIError(409, 'Verification expired. Sign in again.')
                if (not isinstance(data['challenge_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', data['challenge_id']) or
                        not hmac.compare_digest(data['challenge_id'], pending['challenge_id'])):
                    raise APIError(409, 'Verification belongs to a different sign-in.')
                if not isinstance(data['code'], str) or not re.fullmatch(r'[0-9]{6}', data['code']):
                    raise APIError(400, 'A six-digit demonstration code is required.')
                success = hmac.compare_digest(data.pop('code'), '123456')
                pending['attempts'] += 1
                result = self._record(demo, 'mfa_success' if success else 'mfa_failure', pending['context'], pending['assessment'], method='totp')
                demo['allowed_access'] = success and result['score'] is not None and self.checker.ready
                demo['authorization_until'] = min(self.now()+120,demo['deadline']) if demo['allowed_access'] else 0
                if success or pending['attempts'] >= 5:
                    demo['pending_mfa'] = None
                    demo['mfa_required'] = False
                return self._snapshot(demo)

    def trusted_request(self, operation, body, headers):
        with self.lock:
            if operation not in ('events', 'review', 'metrics'):
                raise APIError(404, 'Unknown ingestion operation.')
            key = self.secret if operation == 'events' else self.review_secret
            if not key:
                raise APIError(503, 'This trusted operation is not configured.')
            timestamp = headers.get('X-Sentinel-Timestamp','')
            nonce = headers.get('X-Sentinel-Nonce','')
            signature = headers.get('X-Sentinel-Signature','')
            if (not re.fullmatch(r'[0-9]{1,12}', timestamp) or abs(self.now()-int(timestamp))>30 or
                    not re.fullmatch(r'[0-9a-f]{32}',nonce) or not re.fullmatch(r'[0-9a-f]{64}',signature) or
                    not hmac.compare_digest(sign_payload(key,timestamp,nonce,body,path='/api/'+operation),signature)):
                self.limiter.take('invalid_auth', 100, 10)
                raise APIError(401, 'Event authentication failed.')
            self.limiter.take('trusted_events' if operation == 'events' else 'trusted_review', 100, 10)
            self.cleanup()
            if nonce in self.nonces:
                raise APIError(409, 'Duplicate signed request.')
            if len(self.nonces) >= 10000:
                raise APIError(429, 'Signed request capacity reached.')
            data = strict_json(body)
            try:
                if operation == 'events':
                    self._capacity(1, kind='trusted')
                    result = self.trusted.ingest(data)
                elif operation == 'review':
                    exact_keys(data, ['event_id','label'])
                    result = self.trusted.feedback(data['event_id'], data['label'])
                elif operation == 'metrics':
                    exact_keys(data, [])
                    result = self.trusted.snapshot()
                else:
                    raise APIError(404, 'Unknown ingestion operation.')
            except APIError:
                raise
            except (ValueError, TypeError, KeyError):
                raise APIError(400, 'Event or review violates the trusted contract.') from None
            self.nonces[nonce] = self.now()+120
            return {'mode':'shadow_only', 'enforcement':'none', 'result':result}

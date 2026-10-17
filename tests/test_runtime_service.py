"""Real local HTTP tests for server-owned demo outcomes and signed shadow events."""
import contextlib
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import io
import json
from pathlib import Path
import secrets
import threading
import tempfile
from unittest.mock import patch
import unittest
import uuid

from src.runtime.service import RuntimeService, sign_payload, strict_json, APIError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('kor_service_test_server', ROOT/'app/serve.py')
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


class Clock:
    def __init__(self): self.value = 1800000000.
    def __call__(self): return self.value


class RuntimeHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clock = Clock()
        cls.secret = secrets.token_hex(32)
        cls.review_secret = secrets.token_hex(32)
        cls.runtime = RuntimeService(now=cls.clock, rate_now=cls.clock, secret=cls.secret, review_secret=cls.review_secret)
        cls.server = serve.DemoServer(('127.0.0.1',0),serve.DemoHandler,runtime=cls.runtime)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def setUp(self):
        with self.runtime.lock:
            self.clock.value = 1800000000.
            self.runtime.demos.clear(); self.runtime.nonces.clear(); self.runtime.trusted.reset(); self.runtime.limiter.clear()

    def request(self,path,data=None,headers=None,raw=None,method='POST'):
        if path == '/api/demo/mfa' and isinstance(data, dict) and 'challenge_id' not in data:
            pending = self.runtime.demos.get(data.get('demo_token'), {}).get('pending_mfa')
            data = {**data, 'challenge_id': pending['challenge_id'] if pending else '0'*32}
        body = raw if raw is not None else json.dumps(data or {}).encode()
        defaults = {'Content-Type':'application/json','X-Sentinel-Demo':'1'}
        defaults.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        try:
            connection.request(method,path,body=None if method=='GET' else body,headers=defaults)
            response = connection.getresponse()
            text = response.read().decode()
            try: value = json.loads(text)
            except ValueError: value = text
            return response.status, value
        finally: connection.close()

    def demo(self,operation,**data):
        status,value = self.request('/api/demo/'+operation,data)
        self.assertEqual(status,200,value)
        return value

    def event(self,**changes):
        value = {'event_id':str(uuid.uuid4()), 'event_ts_utc':datetime.fromtimestamp(self.clock(),timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),
            'account_token':'acct_'+'a'*32,'session_token':str(uuid.uuid4()),'source_token':'source_'+'b'*32,
            'event_type':'login_failure','auth_method':'password',
            'features':{
                'attempts_2m':1,'attempts_1h':1,'distinct_accounts_2m':1,'failed_ratio_24h':.1,
                'hour_deviation':.5,'typical_weekday':1,'geo_velocity_kmh':0,
                'network_familiarity':'familiar','asn_category':'business','device_managed':1,'device_new':0},
            'password_in_blocklist':0,'password_near_blocklist':0}
        value.update(changes)
        return value

    def signed(self,body,path='/api/events',timestamp=None,nonce=None):
        raw = json.dumps(body,separators=(',',':')).encode()
        timestamp = str(int(self.clock()) if timestamp is None else timestamp)
        nonce = nonce or secrets.token_hex(16)
        return raw, {'X-Sentinel-Timestamp':timestamp,'X-Sentinel-Nonce':nonce,
                     'X-Sentinel-Signature':sign_payload(self.secret if path == '/api/events' else self.review_secret,timestamp,nonce,raw,path=path)}

    def test_start_and_status_are_bounded_and_read_only(self):
        start = self.demo('start')
        self.assertTrue(all(start['status'].values()),start['status'])
        self.assertFalse(start['snapshot']['allowed_access'])
        self.assertIsNone(start['snapshot']['latest'])
        status,value=self.request('/api/status',method='GET')
        self.assertEqual(status,200)
        self.assertEqual(value['enforcement'],'none')
        self.assertNotIn(start['demo_token'],json.dumps(value))

    def test_server_checks_credentials_and_does_not_retain_them(self):
        token=self.demo('start')['demo_token']
        response=self.demo('attempt',demo_token=token,username='demo',password='unit-private-wrong',context='familiar')
        self.assertFalse(response['allowed_access'])
        self.assertFalse(response['latest']['success'])
        self.assertNotIn('unit-private-wrong',json.dumps(response))
        self.assertNotIn('unit-private-wrong',repr(self.runtime.demos))
        status,value=self.request('/api/demo/attempt',{'demo_token':token,'username':'demo','password':'VelaDemo!42','context':'familiar','success':True})
        self.assertEqual(status,400)
        self.assertNotIn('VelaDemo',json.dumps(value))

    def test_brute_requires_server_mfa_and_preserves_peak(self):
        token=self.demo('start')['demo_token']
        attack=self.demo('simulate',demo_token=token,kind='brute',context='familiar')
        self.assertEqual(attack['total'],20)
        self.assertEqual(attack['latest']['signals']['attempts_2m'],20)
        login=self.demo('attempt',demo_token=token,username='demo',password='VelaDemo!42',context='familiar')
        self.assertTrue(login['mfa_required'])
        self.assertFalse(login['allowed_access'])
        failed=self.demo('mfa',demo_token=token,code='000000')
        self.assertFalse(failed['allowed_access'])
        verified=self.demo('mfa',demo_token=token,code='123456')
        self.assertTrue(verified['allowed_access'])
        self.assertGreaterEqual(verified['latest']['peak_score'],login['latest']['peak_score'])
        self.assertEqual(verified['latest']['verification'],'mfa_verified')
        self.assertEqual(self.request('/api/demo/mfa',{'demo_token':token,'code':'123456'})[0],409)

    def test_unbound_expired_and_exhausted_mfa_cannot_grant_access(self):
        token=self.demo('start')['demo_token']
        self.assertEqual(self.request('/api/demo/mfa',{'demo_token':token,'code':'123456'})[0],409)
        self.demo('simulate',demo_token=token,kind='brute',context='familiar')
        self.demo('attempt',demo_token=token,username='demo',password='VelaDemo!42',context='familiar')
        for _ in range(5):
            self.assertFalse(self.demo('mfa',demo_token=token,code='000000')['allowed_access'])
        self.assertEqual(self.request('/api/demo/mfa',{'demo_token':token,'code':'123456'})[0],409)
        self.demo('attempt',demo_token=token,username='demo',password='VelaDemo!42',context='familiar')
        self.clock.value += 120
        self.assertEqual(self.request('/api/demo/mfa',{'demo_token':token,'code':'123456'})[0],409)

    def test_distributed_and_spray_have_distinct_source_account_counts(self):
        token=self.demo('start')['demo_token']
        result=self.demo('simulate',demo_token=token,kind='distributed',context='familiar')
        self.assertEqual(result['latest']['signals']['distinct_sources_2m'],12)
        self.assertEqual(result['latest']['action'],'review')
        token2=self.demo('start')['demo_token']
        result=self.demo('simulate',demo_token=token2,kind='spray',context='familiar')
        self.assertEqual(result['latest']['signals']['distinct_accounts_2m'],18)
        self.assertEqual(result['latest']['signals']['attempts_2m'],1)

    def test_password_weakness_is_not_an_unconditional_score_bonus(self):
        tokens=[self.demo('start')['demo_token'] for _ in range(2)]
        plain=self.demo('attempt',demo_token=tokens[0],username='demo',password='unit-invented-wrong',context='familiar')
        common=self.demo('attempt',demo_token=tokens[1],username='demo',password='password',context='familiar')
        self.assertEqual(plain['latest']['score'],common['latest']['score'])
        self.assertEqual(common['latest']['credential_risk']['match'],'exact')
        self.assertEqual(plain['latest']['action'],common['latest']['action'])

    def test_cold_start_is_unknown_and_does_not_grant_access(self):
        token=self.demo('start')['demo_token']
        result=self.demo('attempt',demo_token=token,username='demo',password='VelaDemo!42',context='cold_start')
        self.assertIsNone(result['latest']['score'])
        self.assertFalse(result['allowed_access'])
        self.assertEqual(result['latest']['data_quality']['level'],'insufficient')

    def test_ttl_reset_and_demo_isolation(self):
        token=self.demo('start')['demo_token']
        self.demo('attempt',demo_token=token,username='demo',password='wrong',context='familiar')
        other=self.demo('start')
        self.assertEqual(other['snapshot']['total'],0)
        self.demo('reset',demo_token=token)
        self.assertEqual(self.request('/api/demo/status',{'demo_token':token})[0],410)
        self.clock.value += 300
        self.runtime.cleanup()
        self.assertEqual(len(self.runtime.demos),0)
        self.assertEqual(self.request('/api/demo/status',{'demo_token':other['demo_token']})[0],410)

    def test_authenticated_ingestion_and_independent_feedback(self):
        event=self.event()
        body,headers=self.signed(event)
        status,value=self.request('/api/events',raw=body,headers=headers)
        self.assertEqual(status,200,value)
        self.assertEqual(value['enforcement'],'none')
        review={'event_id':event['event_id'],'label':'normal'}
        body,headers=self.signed(review,path='/api/review')
        self.assertEqual(self.request('/api/review',raw=body,headers=headers)[0],200)
        self.assertNotIn('acct_',json.dumps(self.runtime.trusted.snapshot()))
        self.assertNotRegex(json.dumps(self.runtime.trusted.snapshot()), r'(?:source|src)_[0-9a-f]{32}')

    def test_signature_tamper_replay_stale_and_operation_binding(self):
        body,headers=self.signed(self.event())
        self.assertEqual(self.request('/api/events',raw=body,headers=headers)[0],200)
        self.assertEqual(self.request('/api/events',raw=body,headers=headers)[0],409)
        body,headers=self.signed(self.event(),timestamp=int(self.clock())-31)
        self.assertEqual(self.request('/api/events',raw=body,headers=headers)[0],401)
        body,headers=self.signed(self.event())
        self.assertEqual(self.request('/api/events',raw=body+b' ',headers=headers)[0],401)
        body,headers=self.signed({'event_id':str(uuid.uuid4()),'label':'normal'})
        self.assertEqual(self.request('/api/review',raw=body,headers=headers)[0],401)
        self.assertEqual(self.request('/api/events',data=self.event())[0],401)

    def test_sensitive_or_extra_event_fields_rejected_without_echo(self):
        event=self.event(password='unit-sensitive',username='unit-private',is_suspicious=1)
        body,headers=self.signed(event)
        status,value=self.request('/api/events',raw=body,headers=headers)
        self.assertEqual(status,400)
        self.assertNotIn('unit-',json.dumps(value))

    def test_csrf_host_origin_media_and_body_boundaries(self):
        for headers in ({'Origin':'https://evil.example'}, {'Host':'evil.example'},
                        {'X-Sentinel-Demo':'0'},{'Sec-Fetch-Site':'cross-site'}):
            self.assertEqual(self.request('/api/demo/start',headers=headers)[0],403)
        self.assertEqual(self.request('/api/demo/start',headers={'Content-Type':'text/plain'})[0],400)
        self.assertEqual(self.request('/api/demo/start',raw=b'x'*16385)[0],413)
        self.assertEqual(self.request('/api/demo/start?password=unit-private')[0],400)
        self.assertEqual(self.request('/api/demo/start',raw=b'{"a":1,"a":2}')[0],400)
        self.assertEqual(self.request('/api/demo/start',raw=b'{"x":NaN}')[0],400)
        body,headers=self.signed(self.event())
        headers['Origin']='http://127.0.0.1:'+str(self.server.server_port)
        self.assertEqual(self.request('/api/events',raw=body,headers=headers)[0],403)

    def test_no_access_body_or_error_telemetry(self):
        output=io.StringIO()
        with contextlib.redirect_stderr(output),contextlib.redirect_stdout(output):
            self.request('/api/demo/attempt',data={'password':'unit-sensitive'})
            self.request('/api/events',raw=b'unit-sensitive')
        self.assertEqual(output.getvalue(),'')

    def test_process_capacity_includes_other_demo_and_trusted_events(self):
        with patch('src.runtime.service.MAX_TOTAL_EVENTS',2):
            token=self.demo('start')['demo_token']
            self.demo('attempt',demo_token=token,username='demo',password='wrong',context='familiar')
            body,headers=self.signed(self.event())
            self.assertEqual(self.request('/api/events',raw=body,headers=headers)[0],200)
            other=self.demo('start')['demo_token']
            self.assertEqual(self.request('/api/demo/attempt',{'demo_token':other,'username':'demo','password':'wrong','context':'familiar'})[0],429)
            body,headers=self.signed(self.event())
            self.assertEqual(self.request('/api/events',raw=body,headers=headers)[0],429)
            self.assertEqual(self.demo('status',demo_token=other)['total'],0)

    def test_reset_is_idempotent_after_expiry_or_previous_reset(self):
        token=self.demo('start')['demo_token']
        self.demo('reset',demo_token=token)
        self.assertEqual(self.demo('reset',demo_token=token),{})
        token=self.demo('start')['demo_token']
        self.clock.value+=300
        self.assertEqual(self.demo('reset',demo_token=token),{})

    def test_mfa_deadline_is_bound_to_the_original_session(self):
        token=self.demo('start')['demo_token']
        self.demo('attempt',demo_token=token,username='demo',password='wrong',context='familiar')
        self.clock.value+=110
        self.demo('attempt',demo_token=token,username='demo',password='VelaDemo!42',context='familiar')
        self.clock.value+=10
        self.assertEqual(self.request('/api/demo/mfa',{'demo_token':token,'code':'123456'})[0],409)

    def test_rejected_requests_cannot_rewrite_pending_mfa_context(self):
        token=self.demo('start')['demo_token']
        login=self.demo('attempt',demo_token=token,username='demo',password='VelaDemo!42',context='unfamiliar')
        self.assertTrue(login['mfa_required'])
        self.assertEqual(self.request('/api/demo/attempt',{'demo_token':token,'username':'invalid','password':'wrong','context':'familiar'})[0],400)
        self.assertEqual(self.request('/api/demo/simulate',{'demo_token':token,'kind':'invalid','context':'familiar'})[0],400)
        verified=self.demo('mfa',demo_token=token,code='123456')
        self.assertTrue(verified['allowed_access'])
        self.assertTrue(verified['latest']['signals']['new_unfamiliar_context'])

    def test_active_source_does_not_split_at_session_rotation(self):
        token=self.demo('start')['demo_token']
        self.demo('attempt',demo_token=token,username='demo',password='wrong',context='familiar')
        self.clock.value+=119
        self.demo('attempt',demo_token=token,username='demo',password='wrong',context='familiar')
        self.clock.value+=2  # Second incorrect password has a two-second delay.
        result=self.demo('attempt',demo_token=token,username='demo',password='wrong',context='familiar')
        self.assertEqual(result['latest']['signals']['distinct_sources_2m'],1)
        self.assertEqual(result['latest']['signals']['attempts_2m'],2)

    def test_policy_binding_rejects_changed_resealed_model(self):
        model=json.loads((ROOT/'models/demo_model.json').read_text())
        model['coefficients'][0]+=.01
        encoded=json.dumps({k:v for k,v in model.items() if k!='artifact_integrity'},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        model['artifact_integrity']['digest']=hashlib.sha256(encoded).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'model.json'
            path.write_text(json.dumps(model))
            runtime=RuntimeService(model_path=path)
            self.assertTrue(runtime.readiness()['model_ready'])
            self.assertFalse(runtime.readiness()['policy_ready'])

    def test_missing_artifacts_and_disabled_ingestion_fail_closed(self):
        missing=ROOT/'not-an-artifact.json'
        for kwargs in ({'model_path':missing},{'policy_path':missing},{'reference_path':missing}):
            runtime=RuntimeService(now=self.clock,**kwargs)
            start=runtime.demo_request('start',{})
            result=runtime.demo_request('attempt',{'demo_token':start['demo_token'],'username':'demo','password':'VelaDemo!42','context':'familiar'})
            self.assertFalse(result['allowed_access'])
        runtime=RuntimeService(now=self.clock)
        with self.assertRaises(APIError) as error:
            runtime.trusted_request('events',b'{}',{})
        self.assertEqual(error.exception.status,503)


if __name__ == '__main__': unittest.main()

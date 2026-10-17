"""Security boundaries for the datathon; public fixtures only."""
import copy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from src.security.demo_auth import verify_demo_password, SCRYPT_N, SCRYPT_R, SCRYPT_P
from src.security.receipts import DecisionReceipt
from src.runtime.context_guard import GuardedRiskEngine, REASON
from src.runtime.service import RuntimeService, APIError
from test_runtime_risk import Clock, features, event
import test_runtime_risk as fixtures

ROOT = Path(__file__).resolve().parents[1]


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.receipt = DecisionReceipt()
        self.result = {'score':42,'action':'review','model_version':'fixture'}

    def test_authentic_altered_cross_scope_and_stale_receipts(self):
        self.receipt.issue(self.result)
        original = self.receipt.current()
        self.assertTrue(self.receipt.verify(original))
        altered = copy.deepcopy(original); altered['payload']['score']=1
        self.assertFalse(self.receipt.verify(altered))
        other = DecisionReceipt(); other.issue(self.result)
        self.assertFalse(other.verify(original))
        self.receipt.issue(self.result)
        self.assertFalse(self.receipt.verify(original))

    def test_clear_revokes_key_and_proof_never_changes_current_receipt(self):
        self.receipt.issue(self.result); original = self.receipt.current()
        self.assertEqual(self.receipt.tamper_check()['altered_verified'],False)
        self.assertEqual(self.receipt.current(),original)
        self.receipt.clear()
        self.assertIsNone(self.receipt._key)
        self.assertFalse(self.receipt.verify(original))
        with self.assertRaises(ValueError): self.receipt.issue(self.result)

    def test_receipt_allowlist_has_no_identity_password_or_input_metadata(self):
        self.receipt.issue(dict(self.result, account_token='should-not-be-included',password='public-test-only'))
        payload=self.receipt.current()['payload']
        self.assertEqual(set(payload),{'version','counter','score','action','model_version','window_seconds'})
        self.assertEqual(self.receipt.inspect()['counter'],1)


class PasswordVerifierTests(unittest.TestCase):
    def test_memory_hard_public_fixture_verifier_and_rejected_inputs(self):
        self.assertEqual((SCRYPT_N,SCRYPT_R,SCRYPT_P),(32768,8,3))
        self.assertTrue(verify_demo_password('VelaDemo!42'))
        for value in ('wrong-example','',None,'x'*257,'\ud800'):
            self.assertFalse(verify_demo_password(value))


class ContextGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RuntimeRiskTests.setUpClass()

    def setUp(self):
        self.clock=Clock()
        self.engine=GuardedRiskEngine(fixtures.RuntimeRiskTests.model,fixtures.RuntimeRiskTests.test_policy,now=self.clock)

    def test_suspicious_success_requires_no_previous_failures_and_preserves_score(self):
        source=event(self.clock,features=features(device_new=1,network_familiarity='unfamiliar',hour_deviation=7))
        from src.runtime.risk import RiskEngine
        baseline=RiskEngine(fixtures.RuntimeRiskTests.model,fixtures.RuntimeRiskTests.test_policy,now=self.clock).ingest(source)
        result=self.engine.ingest(source)
        self.assertTrue(result['context_guard']['triggered'])
        self.assertEqual(result['score'],baseline['score'])
        self.assertEqual(result['signals']['account_failures_2m'],0)
        self.assertIn(result['action'],('mfa','review'))
        self.assertIn(REASON,result['reasons'])

    def test_single_context_signals_failures_and_passkey_do_not_trigger(self):
        for changes in ({'device_new':1},{'network_familiarity':'unfamiliar'},
                        {'hour_deviation':8},{'geo_velocity_kmh':1800,'asn_category':'vpn'},
                        {'device_new':1,'network_familiarity':'unfamiliar','hour_deviation':None}):
            self.engine.reset()
            self.assertFalse(self.engine.ingest(event(self.clock,features=features(**changes)))['context_guard']['triggered'])
        for kind,method in [('login_failure','password'),('login_success','passkey')]:
            self.engine.reset()
            result=self.engine.ingest(event(self.clock,event_type=kind,auth_method=method,
                password_in_blocklist=None,password_near_blocklist=None,
                features=features(device_new=1,network_familiarity='unfamiliar',hour_deviation=8)))
            self.assertFalse(result['context_guard']['triggered'])

    def test_guard_carries_only_within_same_session_and_two_minute_window(self):
        source=event(self.clock,features=features(device_new=1,network_familiarity='unfamiliar',hour_deviation=7))
        self.engine.ingest(source); self.clock.advance(1)
        result=self.engine.ingest(event(self.clock,source['session_token'],event_type='mfa_success',auth_method='totp',password_in_blocklist=None,password_near_blocklist=None))
        self.assertTrue(result['context_guard']['carried'])
        other=self.engine.ingest(event(self.clock))
        self.assertFalse(other['context_guard']['carried'])
        self.clock.advance(120)
        later=self.engine.ingest(event(self.clock,source['session_token']))
        self.assertFalse(later['context_guard']['carried'])


class DemoAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock()
        self.service=RuntimeService(now=self.clock,rate_now=self.clock)
        self.token=self.service.demo_request('start',{})['demo_token']

    def request(self, operation, **fields):
        return self.service.demo_request(operation,dict(demo_token=self.token,**fields))

    def login(self):
        return self.request('attempt',username='demo',password='VelaDemo!42',context='familiar')

    def authorize(self):
        result=self.login()
        return self.request('mfa',code='123456',challenge_id=result['mfa_challenge_id'])

    def test_resource_denied_before_verification_then_role_and_expiry_enforced(self):
        with self.assertRaises(APIError) as denial: self.request('resource',resource='workspace')
        self.assertEqual(denial.exception.status,403)
        pending=self.login()
        with self.assertRaises(APIError): self.request('resource',resource='workspace')
        self.request('mfa',code='123456',challenge_id=pending['mfa_challenge_id'])
        self.assertEqual(self.request('resource',resource='workspace')['resource']['classification'],'fictional_demo')
        with self.assertRaises(APIError): self.request('resource',resource='audit_console')
        with self.assertRaises(APIError): self.request('resource',resource='audit_console',role='administrator')
        self.clock.advance(120)
        with self.assertRaises(APIError): self.request('resource',resource='workspace')
        self.assertFalse(self.request('status')['allowed_access'])

    def test_failed_attempt_revokes_access_and_new_handle_cannot_borrow_it(self):
        self.authorize()
        other=self.service.demo_request('start',{})['demo_token']
        with self.assertRaises(APIError): self.service.demo_request('resource',{'demo_token':other,'resource':'workspace'})
        self.request('attempt',username='demo',password='wrong-example',context='familiar')
        with self.assertRaises(APIError): self.request('resource',resource='workspace')

    def test_proof_is_read_only_and_reset_destroys_receipt_scope(self):
        self.login(); demo=self.service.demos[self.token]
        before=(len(demo['events']),demo['deadline'],demo['latest']['score'],demo['receipt'].current())
        response=self.request('proof')
        self.assertTrue(response['security_test']['original_verified'])
        self.assertFalse(response['security_test']['altered_verified'])
        self.assertEqual(before,(len(demo['events']),demo['deadline'],demo['latest']['score'],demo['receipt'].current()))
        receipt=demo['receipt']; original=receipt.current()
        self.request('reset')
        self.assertFalse(receipt.verify(original)); self.assertIsNone(receipt._key)

    def test_password_capacity_rejects_before_hashing_and_clears_inflight(self):
        for _ in range(4): self.service._password_slots.acquire()
        try:
            with patch('src.runtime.service.verify_demo_password') as verifier:
                with self.assertRaises(APIError) as failure: self.login()
                self.assertEqual(failure.exception.status,429)
                verifier.assert_not_called()
            self.assertIsNone(self.service.demos[self.token]['checking'])
            self.assertEqual(self.request('status')['total'],0)
        finally:
            for _ in range(4): self.service._password_slots.release()

    def test_idle_expiry_removes_receipt_key(self):
        self.login(); receipt=self.service.demos[self.token]['receipt']; original=receipt.current()
        self.clock.advance(300); self.service.cleanup()
        self.assertFalse(receipt.verify(original)); self.assertIsNone(receipt._key)

    def test_experimental_guard_is_not_enabled_for_trusted_ingestion(self):
        self.assertNotIsInstance(self.service.trusted,GuardedRiskEngine)
        self.assertIsInstance(self.service.demos[self.token]['engine'],GuardedRiskEngine)


@unittest.skipUnless(shutil.which('openssl'),'OpenSSL is needed for the temporary local TLS fixture')
class TLSTests(unittest.TestCase):
    def test_tls13_serves_validated_certificate_and_same_origin_demo(self):
        spec=importlib.util.spec_from_file_location('datathon_tls_server',ROOT/'app/serve.py')
        serve=importlib.util.module_from_spec(spec); spec.loader.exec_module(serve)
        with tempfile.TemporaryDirectory() as folder:
            cert,key=Path(folder)/'cert.pem',Path(folder)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),
                '-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],
                check=True,capture_output=True,timeout=15)
            context=serve.create_tls_context(cert,key)
            self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_3)
            server=serve.DemoServer(('127.0.0.1',0),serve.DemoHandler,tls_context=context,
                                   runtime=RuntimeService(secret='a'*64,review_secret='b'*64))
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            try:
                client_context=ssl.create_default_context(cafile=str(cert))
                for origin,status in [(f'https://127.0.0.1:{server.server_port}',200),(f'http://127.0.0.1:{server.server_port}',403)]:
                    client=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=client_context,timeout=5)
                    try:
                        client.request('POST','/api/demo/start',body='{}',headers={'Origin':origin,'Content-Type':'application/json','X-Sentinel-Demo':'1'})
                        response=client.getresponse(); body=response.read(); self.assertEqual(response.status,status)
                        if status==200:
                            self.assertEqual(json.loads(body)['snapshot']['assurance']['transport'],'tls13_loopback')
                    finally: client.close()
                legacy=ssl.create_default_context(cafile=str(cert)); legacy.maximum_version=ssl.TLSVersion.TLSv1_2
                client=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=legacy,timeout=5)
                try:
                    with self.assertRaises(ssl.SSLError): client.request('GET','/company.html')
                finally: client.close()
                result=subprocess.run([sys.executable,'-m','src.runtime.adapter','--metrics','--port',str(server.server_port),
                    '--tls-ca',str(cert)],capture_output=True,text=True,timeout=8,cwd=ROOT,
                    env=dict(os.environ,SENTINEL_REVIEW_SECRET='b'*64))
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(result.stdout)['mode'],'shadow_only')
                self.assertNotIn('b'*64,result.stdout+result.stderr)
                failed=subprocess.run([sys.executable,'-m','src.runtime.adapter','--metrics','--port',str(server.server_port),
                    '--tls-ca',str(cert.parent/'missing.pem')],capture_output=True,text=True,timeout=8,cwd=ROOT,
                    env=dict(os.environ,SENTINEL_REVIEW_SECRET='b'*64))
                self.assertEqual(failed.returncode,1)
                self.assertNotIn('b'*64,failed.stdout+failed.stderr)
            finally:
                server.shutdown();server.server_close();thread.join()


if __name__=='__main__': unittest.main()

"""Company controller and API client against the real local HTTP implementation.

LinkeDOM validates behavior and wire contracts, not visual browser rendering.
"""
import importlib.util
import os
import json
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which('node') or '/usr/lib/chatgpt/resources/cua_node/bin/node'
spec = importlib.util.spec_from_file_location('sentinel_company_http', ROOT/'app/serve.py')
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


class CompanyHTTPTests(unittest.TestCase):
    def test_generic_adapter_transports_signed_event_without_echoing_secret(self):
        from src.runtime.service import RuntimeService, CONTEXTS
        secret=secrets.token_hex(32)
        runtime=RuntimeService(secret=secret)
        server=serve.DemoServer(('127.0.0.1',0),serve.DemoHandler,runtime=runtime)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            event={'event_id':str(uuid.uuid4()),'event_ts_utc':datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),
                   'account_token':'acct_'+'a'*32,'session_token':str(uuid.uuid4()),'source_token':'source_'+'b'*32,
                   'event_type':'login_success','auth_method':'password',
                   'features':dict(CONTEXTS['familiar'],attempts_2m=1,attempts_1h=1,distinct_accounts_2m=1,failed_ratio_24h=.1),
                   'password_in_blocklist':0,'password_near_blocklist':0}
            result=subprocess.run([sys.executable,'-m','src.runtime.adapter','--port',str(server.server_port)],
                                  input=json.dumps(event),capture_output=True,text=True,cwd=ROOT,timeout=10,
                                  env=dict(os.environ,SENTINEL_INGEST_SECRET=secret))
            self.assertEqual(result.returncode,0,result.stderr)
            response=json.loads(result.stdout)
            self.assertEqual(response['mode'],'shadow_only')
            self.assertEqual(response['enforcement'],'none')
            self.assertNotIn(secret,result.stdout+result.stderr)
            self.assertNotIn(event['account_token'],result.stdout+result.stderr)
        finally:
            server.shutdown();server.server_close();thread.join()

    @unittest.skipUnless(Path(NODE).is_file() and (ROOT/'app/node_modules/linkedom').exists(), 'Node and LinkeDOM are required')
    def test_company_flow_through_actual_http_service(self):
        self.run_company_flow(False)

    @unittest.skipUnless(Path(NODE).is_file() and (ROOT/'app/node_modules/linkedom').exists(), 'Node and LinkeDOM are required')
    def test_experimental_candidate_company_flow_through_actual_http_service(self):
        self.run_company_flow(True)

    def run_company_flow(self, tuned):
        from src.runtime.service import RuntimeService
        runtime = RuntimeService()
        if tuned:
            # Explicit test-only injection exercises wire compatibility. This
            # is not release qualification; the real CLI rejects this candidate.
            from src.models.tuned_runtime import validate
            runtime.demo_candidate = validate(json.loads((ROOT/'experiments/tuning_v2/models/tuned_sequence.json').read_text()))
        server = serve.DemoServer(('127.0.0.1',0),serve.DemoHandler,runtime=runtime)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = dict(os.environ, SENTINEL_TEST_URL=f'http://127.0.0.1:{server.server_port}')
            result = subprocess.run([NODE, str(ROOT/'app/tests/company-http.test.mjs'), *(['--tuned'] if tuned else [])], cwd=ROOT,
                                    capture_output=True,text=True,timeout=45,env=env)
            self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
            self.assertIn('HTTP',result.stdout)
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__': unittest.main()

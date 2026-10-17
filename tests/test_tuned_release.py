"""Qualified-demo selection and fail-closed release loading; no customer data."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from src.models.core import sha256_file
from src.models.tuned_runtime import seal
from src.runtime.service import RuntimeService
from test_model_tuning import candidate


class TunedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def write_release(self, model=None, **changes):
        model = model or candidate()
        path = self.folder/'tuned_model.json'; path.write_text(json.dumps(model))
        release = {'schema_version':'els-tuned-demo-release-v1','scope':'synthetic_demo_only',
            'eligible_for_demo_promotion':True,'model_sha256':sha256_file(path),
            'post_evaluation_mvp_check':'passed','attack_breakdown_sha256':'e'*64,
            'model_version':model['model_version'],'protocol_digest':model['protocol_digest']}
        release.update(changes)
        (self.folder/'tuned_release.json').write_text(json.dumps(release))

    def test_missing_or_unqualified_release_cannot_fall_back(self):
        with self.assertRaisesRegex(ValueError,'tuned demo release'):
            RuntimeService(tuned_demo=True,tuned_model_dir=self.folder)
        for changes in ({'eligible_for_demo_promotion':False},{'scope':'production'},
                        {'post_evaluation_mvp_check':'blocked'},{'post_evaluation_mvp_check':None},
                        {'attack_breakdown_sha256':None},{'attack_breakdown_sha256':'invalid'},
                        {'protocol_digest':'c'*64},{'model_version':'wrong'},{'model_sha256':'d'*64}):
            self.write_release(**changes)
            with self.assertRaises(ValueError): RuntimeService(tuned_demo=True,tuned_model_dir=self.folder)

    def test_qualified_candidate_is_demo_only_and_baseline_stays_default(self):
        self.write_release()
        service = RuntimeService(tuned_demo=True,tuned_model_dir=self.folder)
        self.assertIsNone(service.trusted.candidate)
        started = service.demo_request('start',{})
        token = started['demo_token']
        result = service.demo_request('attempt',{'demo_token':token,'username':'demo','password':'VelaDemo!42','context':'familiar'})
        self.assertEqual(result['latest']['model_version'],'unit-candidate')
        self.assertEqual(result['latest']['score'],50)
        self.assertTrue(result['allowed_access'])
        self.assertFalse(result['mfa_required'])
        self.assertIsNone(RuntimeService().demo_candidate)

    def test_corrupt_model_or_missing_threshold_rejects_startup(self):
        model = candidate(); model['thresholds']['mfa'] = None; seal(model)
        self.write_release(model)
        with self.assertRaises(ValueError): RuntimeService(tuned_demo=True,tuned_model_dir=self.folder)
        self.write_release()
        with (self.folder/'tuned_model.json').open('a') as stream: stream.write('broken')
        with self.assertRaises(ValueError): RuntimeService(tuned_demo=True,tuned_model_dir=self.folder)

    def test_tuned_demo_keeps_expiry_backoff_and_unknown_context(self):
        self.write_release(); now = [1800000000.]
        service = RuntimeService(tuned_demo=True,tuned_model_dir=self.folder,now=lambda:now[0],rate_now=lambda:now[0])
        token = service.demo_request('start',{})['demo_token']
        result = service.demo_request('attempt',{'demo_token':token,'username':'demo','password':'wrong-example','context':'familiar'})
        self.assertEqual(result['login_retry_after_ms'],1000)
        self.assertFalse(result['allowed_access'])
        now[0] += 1
        result = service.demo_request('attempt',{'demo_token':token,'username':'demo','password':'VelaDemo!42','context':'cold_start'})
        self.assertIsNone(result['latest']['score']); self.assertFalse(result['allowed_access'])
        now[0] += 300
        service.cleanup(); self.assertEqual(service.demos,{})


if __name__=='__main__': unittest.main()

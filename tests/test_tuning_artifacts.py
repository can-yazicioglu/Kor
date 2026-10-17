"""Audit persisted experiment evidence without refitting or selecting on tests."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from src.models.core import sha256_file
from src.models.promote_tuned import mvp_coverage_failures, promote
from src.models.tuned_runtime import digest, validate
from src.runtime.service import RuntimeService

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT/'experiments/tuning_v2'


class TuningArtifactTests(unittest.TestCase):
    def test_frozen_artifacts_source_snapshots_and_original_baseline_intact(self):
        protocol = json.loads((RUN/'protocol.json').read_text())
        frozen = json.loads((RUN/'frozen.json').read_text())
        self.assertEqual(digest(protocol),(RUN/'protocol.sha256').read_text().strip())
        self.assertEqual(digest(frozen),(RUN/'frozen.sha256').read_text().strip())
        for path,expected in protocol['baseline_sha256'].items():
            self.assertEqual(sha256_file(ROOT/path),expected,path)
        for path,expected in protocol['source_sha256'].items():
            self.assertEqual(sha256_file(RUN/'source_snapshot'/path),expected,path)
        for path,expected in frozen['files'].items():
            self.assertEqual(sha256_file(RUN/path),expected,path)

    def test_aggregate_success_cannot_hide_missing_required_scenario(self):
        report = json.loads((RUN/'reports/final_evaluation.json').read_text())
        audit = json.loads((RUN/'reports/attack_breakdown.json').read_text())
        self.assertTrue(report['promotion']['eligible_for_demo_promotion'])
        self.assertEqual(audit['final_report_sha256'],sha256_file(RUN/'reports/final_evaluation.json'))
        failures = mvp_coverage_failures(audit)
        self.assertEqual(len(failures),2)
        self.assertTrue(all('suspicious_success' in reason for reason in failures))
        self.assertFalse(report['holdout_used_for_selection'])

    def test_promotion_rejects_actual_candidate_without_writing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError,'MVP coverage blocks promotion'):
                promote(RUN,Path(directory))
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_blocked_release_is_preserved_for_audit_and_cannot_be_enabled(self):
        model = validate(json.loads((ROOT/'models/tuned_model.json').read_text()))
        release = json.loads((ROOT/'models/tuned_release.json').read_text())
        self.assertEqual(release['model_sha256'],sha256_file(ROOT/'models/tuned_model.json'))
        self.assertEqual(model['model_version'],release['model_version'])
        self.assertFalse(release['eligible_for_demo_promotion'])
        with self.assertRaisesRegex(ValueError,'tuned demo release'): RuntimeService(tuned_demo=True)
        self.assertIsNone(RuntimeService().demo_candidate)

    def test_superseded_aggregate_only_receipt_cannot_reenable_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            shutil.copyfile(ROOT/'models/tuned_model.json',folder/'tuned_model.json')
            shutil.copyfile(RUN/'reports/aggregate_qualification_superseded.json',folder/'tuned_release.json')
            with self.assertRaisesRegex(ValueError,'tuned demo release'):
                RuntimeService(tuned_demo=True,tuned_model_dir=folder)


if __name__=='__main__': unittest.main()

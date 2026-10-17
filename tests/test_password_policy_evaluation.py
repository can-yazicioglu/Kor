"""Independent tests of the existing-holdout password-policy evaluation."""
from argparse import Namespace
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import numpy as np
import pandas as pd

from src.models.evaluate_password_policy import adjusted_score, compare_policy, load_inputs

ROOT = Path(__file__).resolve().parents[1]


class PasswordPolicyEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.args = Namespace(data=ROOT / "data/mvp_synthetic_logins.csv",
            manifest=ROOT / "data/mvp_synthetic_logins.manifest.json",
            v2_data=ROOT / "data/mvp_synthetic_logins_v2.csv",
            v2_manifest=ROOT / "data/mvp_synthetic_logins_v2.manifest.json",
            reference=ROOT / "data/password_reference.json", model=ROOT / "models/demo_model.json",
            predictions=ROOT / "outputs/holdout_predictions.csv")
        cls.frame, cls.base, cls.adjusted, cls.hashes, cls.model = load_inputs(cls.args)

    def test_unknown_and_contradictory_evidence_abstains(self):
        for base, exact, near in [(None, 1, 0), (float("nan"), 0, 0), (20, None, 0),
                                  (20, 0, None), (20, 1, 1), (20, "1", 0), (20, True, 0),
                                  (-1, 0, 0), (101, 0, 0), (10.5, 0, 0)]:
            self.assertIsNone(adjusted_score(base, exact, near))

    def test_policy_points_and_cap(self):
        self.assertEqual(adjusted_score(20, 1, 0), 45)
        self.assertEqual(adjusted_score(20, 0, 1), 30)
        self.assertEqual(adjusted_score(20, 0, 0), 20)
        self.assertEqual(adjusted_score(94, 1, 0), 100)
        self.assertEqual(adjusted_score(94, 0, 1), 100)

    def test_holdout_binding_and_original_metrics_are_preserved(self):
        self.assertEqual(set(self.frame._split), {"test"})
        self.assertEqual(len(self.frame), 2000)
        result = compare_policy(self.frame, self.base, self.adjusted)
        original = json.loads((ROOT / "outputs/evaluation.json").read_text())["models"]["logistic_regression"]
        for unit, original_section in (("event", "demo_policy"), ("session", "session_policy")):
            for threshold, old_key in ((30, "mfa_or_review_score_ge_30"), (70, "review_score_ge_70")):
                new = result[unit]["base"][f"score_ge_{threshold}"]
                old = original[original_section][old_key]
                for key in ("precision", "recall", "false_positive_rate", "confusion_matrix"):
                    self.assertEqual(new[key], old[key])
        self.assertEqual(result["score_changes"]["decreased_events"], 0)
        self.assertEqual(result["event"]["base"]["abstentions"], result["event"]["password_policy"]["abstentions"])

    def test_one_unknown_event_abstains_whole_session(self):
        reset = self.frame.reset_index(drop=True)
        target = next(group.index[0] for _, group in reset.groupby("session_token")
                      if len(group) > 1 and np.isfinite(self.base[group.index]).all())
        changed = self.adjusted.copy()
        changed[target] = np.nan
        original = compare_policy(reset, self.base, self.adjusted)
        result = compare_policy(reset, self.base, changed)
        self.assertEqual(result["event"]["password_policy"]["abstentions"], original["event"]["password_policy"]["abstentions"] + 1)
        self.assertEqual(result["session"]["password_policy"]["abstentions"], original["session"]["password_policy"]["abstentions"] + 1)
        self.assertEqual(result["session"]["base"], original["session"]["base"])

    def test_nonfinite_saved_probability_is_rejected(self):
        predictions = pd.read_csv(self.args.predictions)
        index = predictions.index[(predictions.model == "logistic_regression") & (predictions.status == "scored")][0]
        predictions.loc[index, "probability"] = float("nan")
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "corrupt_predictions.csv"
            predictions.to_csv(changed, index=False)
            arguments = Namespace(**vars(self.args))
            arguments.predictions = changed
            with self.assertRaisesRegex(ValueError, "Saved scores do not match"):
                load_inputs(arguments)

    def test_browser_policy_matches_every_existing_holdout_event(self):
        node = shutil.which("node")
        if node is None:
            bundled = Path("/usr/lib/chatgpt/resources/cua_node/bin/node")
            if bundled.is_file():
                node = str(bundled)
        if node is None:
            self.skipTest("Node is required for browser policy parity.")
        rows = [{"score": None if not np.isfinite(base) else int(base),
                 "exact": int(exact), "near": int(near)} for base, exact, near in
                zip(self.base, self.frame.password_in_blocklist, self.frame.password_near_blocklist)]
        script = """
            import { readFileSync } from 'node:fs';
            import { applyPasswordRisk, assessmentFromFlags } from './app/password-risk.js';
            const rows=JSON.parse(readFileSync(0,'utf8'));
            const scores=rows.map(row => {
              const base=row.score===null?null:{risk_score:row.score,reasons:['Existing model prediction'],model_version:'parity-test'};
              return applyPasswordRisk(base,assessmentFromFlags(row.exact,row.near))?.risk_score ?? null;
            });
            process.stdout.write(JSON.stringify(scores));
        """
        completed = subprocess.run([node, "--input-type=module", "-e", script], cwd=ROOT,
            input=json.dumps(rows), capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        actual = json.loads(completed.stdout)
        expected = [None if not np.isfinite(value) else int(value) for value in self.adjusted]
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()

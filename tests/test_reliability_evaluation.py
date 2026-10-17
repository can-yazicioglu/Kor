"""Reliability-policy boundary tests without retraining the baseline model."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import numpy as np

from src.models.core import load_dataset
from src.models.calibrate_reliability import (CONSTRAINTS, EPSILON, apply_calibration,
    calibration_quality, infer_probabilities, load_policy, partition_validation,
    policy_action, reference_histograms, seal_policy, select_score_threshold,
    session_values, validate_policy)

ROOT = Path(__file__).resolve().parents[1]


class ReliabilityEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frame, _, _ = load_dataset(ROOT / "data/mvp_synthetic_logins.csv",
            ROOT / "data/mvp_synthetic_logins.manifest.json")
        cls.model = json.loads((ROOT / "models/demo_model.json").read_text())
        cls.policy = load_policy(ROOT / "models/reliability_policy.json", ROOT / "models/demo_model.json")
        cls.report = json.loads((ROOT / "outputs/reliability_evaluation.json").read_text())

    def test_runtime_helpers_require_standard_library_only(self):
        code = """
import json,sys
from src.models.calibrate_reliability import load_policy,apply_calibration,policy_action
policy=load_policy('models/reliability_policy.json','models/demo_model.json')
result=apply_calibration(policy,.5)
assert result is not None
assert 'numpy' not in sys.modules and 'sklearn' not in sys.modules and 'pandas' not in sys.modules
print('stdlib runtime verified')
"""
        result = subprocess.run([sys.executable, "-S", "-c", code], cwd=ROOT, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_validation_account_partition_is_deterministic_and_label_independent(self):
        validation = self.frame[self.frame._split == "validation"]
        fit, selection, audit = partition_validation(validation)
        self.assertFalse(set(fit.account_token) & set(selection.account_token))
        self.assertFalse(set(fit.session_token) & set(selection.session_token))
        self.assertEqual(set(fit.event_id) | set(selection.event_id), set(validation.event_id))
        changed = validation.iloc[::-1].copy()
        changed["is_suspicious"] = 1 - changed.is_suspicious
        changed["attack_type"] = "metadata-does-not-select-partitions"
        other_fit, other_selection, _ = partition_validation(changed)
        self.assertEqual(set(fit.account_token), set(other_fit.account_token))
        self.assertEqual(set(selection.account_token), set(other_selection.account_token))
        self.assertEqual(audit, self.policy["selection"]["partition"])
        self.assertEqual(set(fit._split) | set(selection._split), {"validation"})

    def test_saved_thresholds_use_only_selection_accounts_and_fixed_constraints(self):
        validation = self.frame[self.frame._split == "validation"]
        _, selection, _ = partition_validation(validation)
        raw = infer_probabilities(selection, self.model)
        probabilities = np.array([apply_calibration(self.policy, float(value))["probability"]
            if np.isfinite(value) else np.nan for value in raw])
        sessions = session_values(selection, probabilities).dropna()
        mfa = select_score_threshold(sessions.label, sessions.score, CONSTRAINTS["mfa"])
        review = select_score_threshold(sessions.label, sessions.score, CONSTRAINTS["review"], mfa["score_threshold"] or 0)
        self.assertEqual(mfa, self.policy["selection"]["mfa"])
        self.assertEqual(review, self.policy["selection"]["review"])
        self.assertEqual(self.policy["selection"]["constraints_declared_before_evaluation"], CONSTRAINTS)

    def test_infeasible_thresholds_are_explicit(self):
        selection = select_score_threshold([0, 1], [90, 10], {"max_fpr": 0., "min_recall": .5})
        self.assertFalse(selection["feasible"])
        self.assertIsNone(selection["score_threshold"])
        one_class = select_score_threshold([0, 0], [20, 30], CONSTRAINTS["mfa"])
        self.assertEqual(one_class["reason"], "selection_classes_or_scores_missing")

    def test_unavailable_thresholds_preserve_valid_score_and_require_review(self):
        policy = copy.deepcopy(self.policy)
        for action in ("mfa", "review"):
            policy["thresholds"][action] = None
            policy["selection"][action].update(feasible=False, score_threshold=None)
        seal_policy(policy)
        result = apply_calibration(policy, .5)
        self.assertIsNotNone(result)
        self.assertIsInstance(result["risk_score"], int)
        self.assertEqual(policy_action(policy, result["risk_score"]), "review")
        self.assertEqual(policy_action(policy, None), "review_unscored")

    def test_nested_threshold_action_boundaries(self):
        policy = copy.deepcopy(self.policy)
        for action, value in (("mfa", 20), ("review", 60)):
            policy["thresholds"][action] = value
            policy["selection"][action].update(feasible=True, score_threshold=value)
        seal_policy(policy)
        self.assertEqual(policy_action(policy, 19), "monitor")
        self.assertEqual(policy_action(policy, 20), "mfa")
        self.assertEqual(policy_action(policy, 59), "mfa")
        self.assertEqual(policy_action(policy, 60), "review")
        policy["thresholds"]["review"] = 10
        policy["selection"]["review"]["score_threshold"] = 10
        seal_policy(policy)
        with self.assertRaises(ValueError):
            validate_policy(policy)

    def test_invalid_input_or_corrupt_policy_abstains(self):
        for value in (None, float("nan"), float("inf"), -0.1, 1.1, "0.5", True):
            self.assertIsNone(apply_calibration(self.policy, value))
        for policy in (None, {}, {**self.policy, "model_version": "changed"}):
            self.assertIsNone(apply_calibration(policy, .5))
        changed = copy.deepcopy(self.policy)
        changed["calibration"]["intercept"] += .1
        self.assertIsNone(apply_calibration(changed, .5))
        self.assertEqual(policy_action(changed, 50), "review_unscored")

    def test_model_version_data_and_byte_bindings_fail_closed(self):
        for key in ("model_version", "training_data_sha256"):
            changed = {**self.model, key: "different"}
            with self.assertRaises(ValueError):
                validate_policy(self.policy, changed)
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "model.json"
            changed.write_text(json.dumps(self.model) + "\n")
            with self.assertRaisesRegex(ValueError, "checksum"):
                load_policy(ROOT / "models/reliability_policy.json", changed)

    def test_calibration_is_finite_and_monotone_at_probability_endpoints(self):
        values = [apply_calibration(self.policy, probability) for probability in (0., EPSILON, .2, .5, .8, 1-EPSILON, 1.)]
        probabilities = [item["probability"] for item in values]
        self.assertTrue(all(0 <= value <= 1 for value in probabilities))
        self.assertEqual(probabilities, sorted(probabilities))
        self.assertTrue(all(0 <= item["risk_score"] <= 100 for item in values))

    def test_brier_and_bin_counts_include_only_scorable_events(self):
        quality = calibration_quality([0, 1, 1], [0., 1., np.nan])
        self.assertEqual(quality["brier_score"], 0.)
        self.assertEqual(quality["scored_events"], 2)
        self.assertEqual(sum(value["count"] for value in quality["bins"]), 2)
        self.assertEqual(quality["bins"][-1]["count"], 1)
        comparison = self.report["regression_test"]
        self.assertEqual(sum(value["count"] for value in comparison["calibration_event_level"]["after"]["bins"]), 1631)
        self.assertEqual(comparison["session_decisions"]["after"]["mfa"]["abstentions"], 274)
        self.assertTrue(self.report["test_previously_inspected"])
        self.assertFalse(self.report["thresholds_tuned_on_test"])

    def test_drift_reference_comes_only_from_validation(self):
        validation = self.frame[self.frame._split == "validation"]
        reference = self.policy["reference_histograms"]
        self.assertEqual(reference, reference_histograms(validation))
        self.assertEqual(reference["rows"], len(validation))
        for feature in reference["features"].values():
            self.assertEqual(sum(feature["counts"]) + feature["missing"], len(validation))
            if feature["kind"] == "numeric":
                self.assertEqual(len(feature["counts"]), len(feature["edges"]) + 1)


if __name__ == "__main__":
    unittest.main()

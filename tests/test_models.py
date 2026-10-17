"""Regression tests on the delivered synthetic CSV and actual trained artifacts.

No training or replacement data generation occurs in these tests.
"""
import copy
import json
from pathlib import Path
import unittest

import joblib
import numpy as np
import pandas as pd

from src.models.core import (CATEGORIES, FEATURES, FORBIDDEN, NUMERIC, audit_splits,
    invalid_features, load_dataset, predict_portable, select_features, select_threshold,
    validate_artifact)
from src.models.evaluate import metrics, session_policy_metrics

ROOT = Path(__file__).resolve().parents[1]


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frame, cls.manifest, cls.audit = load_dataset(ROOT / "data/mvp_synthetic_logins.csv",
            ROOT / "data/mvp_synthetic_logins.manifest.json")
        cls.model = json.loads((ROOT / "models/demo_model.json").read_text())
        cls.bundle = joblib.load(ROOT / "models/comparison_models.joblib")
        cls.test = cls.frame[(cls.frame._split == "test") & cls.frame._eligible]
        cls.row = {key: cls.test.iloc[0][key] for key in FEATURES}

    def test_exact_feature_allowlist(self):
        self.assertEqual(list(select_features(self.frame).columns), FEATURES)
        self.assertEqual(len(FEATURES), 11)
        self.assertFalse(set(FEATURES) & FORBIDDEN)
        for name in self.model["transformed_feature_order"]:
            self.assertIn(name.split("=")[0], FEATURES)

    def test_all_metadata_changes_leave_features_and_prediction_unchanged(self):
        changed = self.frame.copy()
        for name in FORBIDDEN:
            changed[name] = "metadata-must-not-be-input"
        pd.testing.assert_frame_equal(select_features(self.frame), select_features(changed))
        row = self.row.copy()
        for name in FORBIDDEN:
            row[name] = "never-input"
        self.assertIsNone(predict_portable(self.model, row))
        selected = {key: row[key] for key in FEATURES}
        self.assertEqual(predict_portable(self.model, self.row), predict_portable(self.model, selected))

    def test_missing_and_unknown_features_abstain(self):
        for feature in FEATURES:
            for value in (None, float("nan")):
                row = {**self.row, feature: value}
                self.assertIsNone(predict_portable(self.model, row), feature)
        self.assertIsNone(predict_portable(self.model, {**self.row, "asn_category": "unseen"}))
        self.assertIsNone(predict_portable(None, self.row))

    def test_invalid_domains_abstain(self):
        invalid = {"attempts_2m": -1, "attempts_1h": 2.5, "distinct_accounts_2m": 0,
                   "failed_ratio_24h": 1.1, "hour_deviation": 13, "typical_weekday": 2,
                   "geo_velocity_kmh": float("inf"), "device_new": True, "device_managed": "1"}
        for name, value in invalid.items():
            self.assertIsNone(predict_portable(self.model, {**self.row, name: value}), name)
        self.assertIsNone(predict_portable(self.model, {**self.row, "attempts_2m": 99, "attempts_1h": 1}))
        self.assertIsNone(predict_portable(self.model, {**self.row, "geo_velocity_kmh": 1e100}))

    def test_bad_model_abstains(self):
        for field, value in [("feature_columns", ["account_token"]), ("coefficients", [0.]),
                             ("missing_policy", "zero")]:
            bad = {**self.model, field: value}
            self.assertIsNone(predict_portable(bad, self.row))
        bad = copy.deepcopy(self.model)
        bad["preprocessing"]["numeric"][0]["scale"] = 0
        self.assertIsNone(predict_portable(bad, self.row))

    def test_checksum_and_required_version_fail_closed(self):
        bad = copy.deepcopy(self.model)
        bad["intercept"] += .1
        self.assertIsNone(predict_portable(bad, self.row))
        with self.assertRaisesRegex(ValueError, "integrity"):
            validate_artifact(bad)
        for key in ("model_version", "artifact_integrity", "threshold_policy", "synthetic_only"):
            bad = copy.deepcopy(self.model)
            del bad[key]
            self.assertIsNone(predict_portable(bad, self.row))

    def test_all_identity_episode_source_disjoint(self):
        self.assertTrue(all(value == 0 for value in self.audit["overlap_counts"].values()))
        self.assertTrue(all(value >= 120 for value in self.audit["time_gaps_seconds"].values()))

    def test_identity_leakage_rejected(self):
        for name in ("account_token", "session_token", "_episode", "_source"):
            changed = self.frame.copy()
            fit_index = changed.index[changed._split == "fit"][0]
            test_index = changed.index[changed._split == "test"][0]
            changed.loc[test_index, name] = changed.loc[fit_index, name]
            with self.assertRaisesRegex(ValueError, "Split leakage"):
                audit_splits(changed)

    def test_time_gap_boundary_rejected(self):
        changed = self.frame.copy()
        last_fit = changed.loc[changed._split == "fit", "_time"].max()
        index = changed.index[changed._split == "validation"][0]
        changed.loc[index, "_time"] = last_fit + pd.Timedelta(seconds=119)
        with self.assertRaisesRegex(ValueError, "120 seconds"):
            audit_splits(changed)
        changed.loc[index, "_time"] = last_fit + pd.Timedelta(seconds=120)
        audit_splits(changed)

    def test_missing_split_timestamps_rejected(self):
        changed = self.frame.copy()
        changed.loc[changed._split == "test", "_time"] = pd.NaT
        with self.assertRaisesRegex(ValueError, "timestamps must not be missing"):
            audit_splits(changed)

    def test_preprocessing_fit_only_statistics(self):
        fit = self.frame[(self.frame._split == "fit") & self.frame._eligible]
        for field in self.model["preprocessing"]["numeric"]:
            self.assertAlmostEqual(field["mean"], float(fit[field["name"]].mean()), places=11)
            self.assertAlmostEqual(field["median"], float(fit[field["name"]].median()), places=11)
        scale = self.bundle["models"]["logistic_regression"].named_steps["preprocessor"].named_transformers_["numeric"]
        self.assertEqual(int(scale.n_samples_seen_), len(fit))

    def test_threshold_constraints_explicit_when_infeasible(self):
        result = select_threshold([0, 1], [.8, .2], max_fpr=0, min_recall=.5)
        self.assertFalse(result["feasible"])
        self.assertIsNone(result["threshold"])
        missing_class = select_threshold([0, 0], [.1, .2])
        self.assertEqual(missing_class["reason"], "validation_classes_missing")

    def test_threshold_no_alarm_option_is_explicit(self):
        result = select_threshold([0, 1], [1., 1.], max_fpr=0., min_recall=0.)
        self.assertTrue(result["feasible"])
        self.assertGreater(result["threshold"], 1.)
        self.assertEqual(result["validation_recall"], 0.)

    def test_threshold_invalid_inputs_rejected(self):
        for labels, probabilities in [([0, 1], [.2]), ([0, 2], [.2, .4]), ([0, 1], [.2, float("nan")]),
                                      ([0, 1], [-.1, .9]), ([0, 1], [.1, 1.1]), ([0, 1], [[.1], [.9]])]:
            with self.assertRaises(ValueError):
                select_threshold(labels, probabilities)
        self.assertFalse(select_threshold([], [])["feasible"])

    def test_saved_thresholds_recomputed_from_validation_only(self):
        validation = self.frame[(self.frame._split == "validation") & self.frame._eligible]
        for name, model in self.bundle["models"].items():
            saved = self.bundle["thresholds"][name]
            expected = select_threshold(validation.is_suspicious,
                model.predict_proba(select_features(validation))[:, 1], saved["max_fpr"], saved["min_recall"])
            self.assertEqual(saved, expected)

    def test_all_holdout_portable_probabilities_match_sklearn(self):
        expected = self.bundle["models"]["logistic_regression"].predict_proba(select_features(self.test))[:, 1]
        actual = [predict_portable(self.model, {key: row[key] for key in FEATURES})["probability"]
                  for _, row in self.test.iterrows()]
        np.testing.assert_allclose(actual, expected, rtol=0, atol=1e-12)

    def test_scores_and_explanations_are_actual_model_contributions(self):
        for _, row in self.test.head(40).iterrows():
            result = predict_portable(self.model, {key: row[key] for key in FEATURES})
            self.assertIsInstance(result["risk_score"], int)
            self.assertGreaterEqual(result["risk_score"], 0)
            self.assertLessEqual(result["risk_score"], 100)
            logit = self.model["intercept"] + sum(result["contributions"].values())
            self.assertAlmostEqual(1 / (1 + np.exp(-logit)), result["probability"], places=12)
            self.assertTrue(result["reasons"])

    def test_feature_change_can_change_prediction(self):
        original = predict_portable(self.model, self.row)
        changed = {**self.row, "attempts_2m": 100, "attempts_1h": 120,
                   "distinct_accounts_2m": 100, "failed_ratio_24h": .99}
        self.assertNotAlmostEqual(original["probability"], predict_portable(self.model, changed)["probability"])

    def test_actual_csv_parity_fixtures(self):
        fixtures = json.loads((ROOT / "outputs/parity_cases.json").read_text())
        self.assertEqual(fixtures["model_version"], self.model["model_version"])
        self.assertTrue(any(case["expected"] is None for case in fixtures["cases"]))
        for case in fixtures["cases"]:
            self.assertEqual(predict_portable(self.model, case["features"]), case["expected"])

    def test_no_feasible_threshold_metrics_are_not_fabricated(self):
        values = metrics([0, 1], [.8, .2], None)
        self.assertIsNone(values["precision"])
        self.assertIsNone(values["confusion_matrix"])
        self.assertIsNotNone(values["roc_auc"])

    def test_abstention_coverage_and_subgroup_support_in_report(self):
        report = json.loads((ROOT / "outputs/evaluation.json").read_text())
        expected = self.frame[self.frame._split == "test"]
        for model in report["models"].values():
            self.assertEqual(model["total_rows"], len(expected))
            self.assertEqual(model["abstentions"], int((~expected._eligible).sum()))
            self.assertGreater(model["abstentions"], 0)
            for scenario in ("user_error", "vpn_new_device", "travel_new_device", "brute_force", "password_spraying", "suspicious_success"):
                self.assertGreater(model["subgroups"][scenario]["total_rows"], 0)

    def test_session_policy_matches_max_integer_and_all_or_abstain(self):
        test = self.frame[self.frame._split == "test"].copy().reset_index(drop=True)
        probabilities = np.full(len(test), np.nan)
        probabilities[test._eligible] = self.bundle["models"]["logistic_regression"].predict_proba(
            select_features(test.loc[test._eligible]))[:, 1]
        result = session_policy_metrics(test, probabilities)
        reference = []
        for _, group in test.groupby("session_token"):
            if group._eligible.all():
                score = max(int(np.floor(probabilities[i] * 100 + .5)) for i in group.index)
                reference.append((int(group.is_suspicious.max()), score))
        self.assertEqual(result["total_sessions"], test.session_token.nunique())
        self.assertEqual(result["scored_sessions"], len(reference))
        self.assertGreater(result["abstained_sessions"], 0)
        for limit, key in [(30, "mfa_or_review_score_ge_30"), (70, "review_score_ge_70")]:
            matrix = [[0, 0], [0, 0]]
            for label, score in reference:
                matrix[label][int(score >= limit)] += 1
            self.assertEqual(result[key]["confusion_matrix"], matrix)


if __name__ == "__main__":
    unittest.main()

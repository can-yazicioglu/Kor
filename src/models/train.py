"""Train reproducible comparisons only on the delivered, audited synthetic CSV.

Run from repository root: python -m src.models.train
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .core import (CATEGORIES, FEATURES, LABELS, NUMERIC, baseline_probabilities,
                   load_dataset, predict_portable, select_features, select_threshold,
                   sha256_file, validate_artifact)


def make_pipeline(estimator):
    transform = ColumnTransformer([
        ("numeric", StandardScaler(), NUMERIC),
        ("categorical", OneHotEncoder(categories=list(CATEGORIES.values()),
            handle_unknown="error", sparse_output=False), list(CATEGORIES)),
    ], remainder="drop", verbose_feature_names_out=False)
    return Pipeline([("preprocessor", transform), ("classifier", estimator)])


def export_logistic(pipeline, fit_features, data_hash, threshold, seed):
    preprocess = pipeline.named_steps["preprocessor"]
    scaler = preprocess.named_transformers_["numeric"]
    classifier = pipeline.named_steps["classifier"]
    names = NUMERIC + [f"{name}={category}" for name, categories in CATEGORIES.items()
                       for category in categories]
    artifact = {
        "schema_version": "els-logistic-v1",
        "model_version": f"els-lr-{data_hash[:12]}-s{seed}",
        "synthetic_only": True,
        "feature_columns": FEATURES,
        "feature_labels": LABELS,
        "missing_policy": "abstain",
        "unknown_category_policy": "abstain",
        "preprocessing": {
            "numeric": [{"name": name, "median": float(fit_features[name].median()),
                "mean": float(scaler.mean_[i]), "scale": float(scaler.scale_[i])}
                for i, name in enumerate(NUMERIC)],
            "categorical": [{"name": name, "categories": categories}
                for name, categories in CATEGORIES.items()],
        },
        "transformed_feature_order": names,
        "coefficients": classifier.coef_[0].tolist(),
        "intercept": float(classifier.intercept_[0]),
        "threshold_policy": {"mfa_score": 30, "review_score": 70},
        "benchmark_threshold": threshold,
        "score_semantics": "uncalibrated_synthetic_probability",
        "score_rounding": "floor(probability * 100 + 0.5)",
        "explanation_semantics": "additive_log_odds_contribution_not_causality",
        "training_data_sha256": data_hash,
        "seed": seed,
        "sklearn_version": sklearn.__version__,
        "deployment_selection": "Logistic regression chosen for transparent browser-only deployment, not best holdout score.",
    }
    # This detects accidental edits; it is not a signature or authenticity proof.
    encoded = json.dumps(artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    artifact["artifact_integrity"] = {
        "algorithm": "sha256", "canonicalization": "python_json_sort_keys_utf8_excluding_artifact_integrity",
        "digest": hashlib.sha256(encoded).hexdigest(), "purpose": "accidental_corruption_not_authenticity",
    }
    validate_artifact(artifact)
    return artifact


def train(args):
    frame, manifest, audit = load_dataset(args.data, args.manifest)
    fit = frame[(frame._split == "fit") & frame._eligible]
    validation = frame[(frame._split == "validation") & frame._eligible]
    for part in (fit, validation):
        if set(part.is_suspicious) != {0, 1}:
            raise ValueError("Fit and validation splits must contain scorable observations from both classes.")
    xfit, yfit = select_features(fit), fit.is_suspicious.astype(int)
    xvalidation = select_features(validation)
    estimators = {
        "logistic_regression": LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000,
                                                   random_state=args.seed),
        "random_forest": RandomForestClassifier(n_estimators=160, max_depth=8, min_samples_leaf=8,
                         class_weight="balanced", random_state=args.seed, n_jobs=1),
    }
    unavailable = {}
    try:
        from xgboost import XGBClassifier
        estimators["xgboost"] = XGBClassifier(n_estimators=150, max_depth=3, learning_rate=.05,
            subsample=.85, colsample_bytree=1., scale_pos_weight=float((yfit == 0).sum() / (yfit == 1).sum()),
            eval_metric="logloss", random_state=args.seed, n_jobs=1, tree_method="hist")
    except ImportError:
        unavailable["xgboost"] = "not_installed"
    fitted, thresholds = {}, {}
    thresholds["rule_baseline"] = select_threshold(validation.is_suspicious,
        baseline_probabilities(xvalidation), args.max_fpr, args.min_recall)
    for name, estimator in estimators.items():
        pipeline = make_pipeline(estimator)
        pipeline.fit(xfit, yfit)
        fitted[name] = pipeline
        thresholds[name] = select_threshold(validation.is_suspicious,
            pipeline.predict_proba(xvalidation)[:, 1], args.max_fpr, args.min_recall)
    data_hash = sha256_file(args.data)
    artifact = export_logistic(fitted["logistic_regression"], xfit, data_hash,
                               thresholds["logistic_regression"], args.seed)
    # Check portable implementation against fitted sklearn on ALL eligible heldout rows.
    test = frame[(frame._split == "test") & frame._eligible]
    if test.empty:
        raise ValueError("No scorable test observations are available.")
    expected = fitted["logistic_regression"].predict_proba(select_features(test))[:, 1]
    actual = np.array([predict_portable(artifact, {key: row[key] for key in FEATURES})["probability"]
                       for _, row in test.iterrows()])
    parity_error = float(np.max(np.abs(actual - expected)))
    if parity_error > 1e-12:
        raise AssertionError("The portable Python model does not match sklearn.")
    args.model_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.model_dir / "demo_model.json").write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n")
    bundle = {"format": "els-training-bundle-v1", "models": fitted, "thresholds": thresholds,
              "seed": args.seed, "data_sha256": data_hash, "manifest_sha256": sha256_file(args.manifest),
              "split_audit": audit, "unavailable_models": unavailable, "feature_columns": FEATURES,
              "portable_parity_max_probability_error": parity_error,
              "versions": {"numpy": np.__version__, "sklearn": sklearn.__version__}}
    joblib.dump(bundle, args.model_dir / "comparison_models.joblib", compress=3)
    # Parity fixtures are feature-only selections from the actual delivered CSV, not generated data.
    selected = test.groupby("_scenario", sort=True).head(2)
    cases = []
    for _, row in selected.iterrows():
        features = {key: row[key] for key in FEATURES}
        cases.append({"features": features, "expected": predict_portable(artifact, features)})
    missing = frame[(frame._split == "test") & ~frame._eligible].head(2)
    for _, row in missing.iterrows():
        features = {key: (None if pd.isna(row[key]) else row[key]) for key in FEATURES}
        cases.append({"features": features, "expected": None})
    (args.output_dir / "parity_cases.json").write_text(json.dumps({"model_version": artifact["model_version"],
        "origin": "feature-only selections from the delivered synthetic holdout CSV", "cases": cases},
        indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    print(json.dumps({"status": "trained_on_delivered_synthetic_csv", "fit_eligible": len(fit),
        "validation_eligible": len(validation), "models": list(fitted), "unavailable": unavailable,
        "portable_parity_max_error": parity_error}, ensure_ascii=False))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/mvp_synthetic_logins.csv"))
    parser.add_argument("--manifest", type=Path, default=Path("data/mvp_synthetic_logins.manifest.json"))
    parser.add_argument("--model-dir", type=Path, default=Path("models"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-fpr", type=float, default=.05)
    parser.add_argument("--min-recall", type=float, default=.5)
    args = parser.parse_args()
    if not 0 <= args.max_fpr <= 1 or not 0 <= args.min_recall <= 1:
        parser.error("FPR and recall targets must be in [0,1].")
    return args


if __name__ == "__main__":
    train(parse_args())

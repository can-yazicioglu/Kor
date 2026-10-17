"""Shared feature boundary, split audit and portable logistic inference.

Identifiers, timestamps, labels and scenario metadata are NEVER model features.
Missing context is an abstention, not a low-risk observation.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

FEATURES = [
    "attempts_2m", "attempts_1h", "distinct_accounts_2m", "failed_ratio_24h",
    "hour_deviation", "typical_weekday", "geo_velocity_kmh", "network_familiarity",
    "asn_category", "device_managed", "device_new",
]
COLUMNS = ["event_id", "event_ts_utc", "session_token", "account_token", *FEATURES,
           "is_suspicious", "attack_type"]
CATEGORIES = {"network_familiarity": ["familiar", "unfamiliar"],
              "asn_category": ["residential", "business", "cloud", "vpn", "unknown"]}
NUMERIC = [name for name in FEATURES if name not in CATEGORIES]
FORBIDDEN = set(COLUMNS) - set(FEATURES)
LABELS = {
    "attempts_2m": "Login attempts in 2 minutes",
    "attempts_1h": "Login attempts in 1 hour",
    "distinct_accounts_2m": "Distinct accounts in 2 minutes",
    "failed_ratio_24h": "Failure ratio over 24 hours",
    "hour_deviation": "Deviation from usual login hour",
    "typical_weekday": "Usual weekday context",
    "geo_velocity_kmh": "Location change speed",
    "network_familiarity": "Network familiarity",
    "asn_category": "Network category",
    "device_managed": "Managed device status",
    "device_new": "New device context",
}
SPLITS = ("fit", "validation", "test")


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def select_features(frame):
    """Exact allowlist: changing metadata cannot alter model inputs."""
    return frame.loc[:, FEATURES].copy()


def invalid_features(row):
    """Return names only: never include potentially sensitive input values."""
    invalid = []
    for name in FEATURES:
        value = row.get(name)
        if name in CATEGORIES:
            if not isinstance(value, str) or value not in CATEGORIES[name]:
                invalid.append(name)
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            # numpy scalar types are accepted through float(), but strings are not.
            if isinstance(value, str) or value is None or isinstance(value, bool):
                invalid.append(name)
                continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            invalid.append(name)
            continue
        if not math.isfinite(number) or number < 0 or number > 9007199254740991:
            invalid.append(name)
        elif name in ("attempts_2m", "attempts_1h", "distinct_accounts_2m") and (
            number < 1 or not number.is_integer()
        ):
            invalid.append(name)
        elif name in ("typical_weekday", "device_managed", "device_new") and number not in (0, 1):
            invalid.append(name)
        elif name == "failed_ratio_24h" and number > 1:
            invalid.append(name)
        elif name == "hour_deviation" and number > 12:
            invalid.append(name)
    if not invalid and row["attempts_2m"] > row["attempts_1h"]:
        invalid.extend(["attempts_2m", "attempts_1h"])
    return invalid


def complete_mask(frame):
    return frame.apply(lambda row: not invalid_features(row), axis=1)


def load_dataset(csv_path, manifest_path):
    """Fail before training on absent, modified or non-synthetic input."""
    import pandas as pd

    csv_path, manifest_path = Path(csv_path), Path(manifest_path)
    if not csv_path.is_file() or not manifest_path.is_file():
        raise ValueError("The delivered CSV and audit manifest are required; training has not started.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("synthetic") is not True:
        raise ValueError("This command accepts only data explicitly marked as synthetic.")
    if manifest.get("csv_sha256") != sha256_file(csv_path):
        raise ValueError("The CSV checksum does not match the manifest.")
    frame = pd.read_csv(csv_path)
    if list(frame.columns) != COLUMNS:
        raise ValueError("The CSV must contain exactly the 17 shared columns in the specified order.")
    if frame.empty or frame["event_id"].isna().any() or frame["event_id"].duplicated().any():
        raise ValueError("Event identifiers are missing or duplicated; data rejected.")
    if not frame["is_suspicious"].isin([0, 1]).all():
        raise ValueError("Target labels must be 0 or 1.")
    events = manifest.get("events", {})
    if set(events) != set(frame["event_id"]):
        raise ValueError("Manifest events do not match the CSV exactly.")
    frame["_split"] = frame["event_id"].map(lambda event: events[event]["split"])
    frame["_episode"] = frame["event_id"].map(lambda event: events[event]["episode_id"])
    frame["_source"] = frame["event_id"].map(lambda event: events[event]["source_token"])
    frame["_scenario"] = frame["event_id"].map(lambda event: events[event]["scenario"])
    if not frame["event_ts_utc"].astype("string").str.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", na=False
    ).all():
        raise ValueError("Each event timestamp must be present and use UTC ISO-8601 Z format.")
    frame["_time"] = pd.to_datetime(frame["event_ts_utc"], utc=True, errors="raise")
    audit = audit_splits(frame)
    frame["_eligible"] = complete_mask(frame)
    return frame, manifest, audit


def audit_splits(frame):
    """Audit identities, episodes, sources and chronology before preprocessing."""
    if set(frame["_split"]) != set(SPLITS):
        raise ValueError("Complete fit/validation/test splits are required.")
    if frame["_time"].isna().any():
        raise ValueError("Split timestamps must not be missing.")
    report = {"overlap_counts": {}, "time_gaps_seconds": {}, "splits": {}}
    for split in SPLITS:
        part = frame[frame["_split"] == split]
        for key in ("account_token", "session_token", "_episode", "_source"):
            if part[key].isna().any() or part[key].eq("").any():
                raise ValueError("Split identifier metadata is missing.")
        report["splits"][split] = {"rows": len(part), "accounts": part.account_token.nunique(),
            "episodes": part._episode.nunique(), "sources": part._source.nunique(),
            "start_utc": part._time.min().isoformat(), "end_utc": part._time.max().isoformat()}
    for i, left in enumerate(SPLITS):
        for right in SPLITS[i + 1:]:
            a, b = frame[frame._split == left], frame[frame._split == right]
            for column in ("account_token", "session_token", "_episode", "_source"):
                count = len(set(a[column]) & set(b[column]))
                report["overlap_counts"][f"{left}/{right}:{column}"] = count
                if count:
                    raise ValueError(f"Split leakage: {left}/{right}, {column}.")
            gap = (b._time.min() - a._time.max()).total_seconds()
            report["time_gaps_seconds"][f"{left}/{right}"] = gap
            if not math.isfinite(gap) or gap < 120:
                raise ValueError("Splits must be chronological and separated by at least 120 seconds.")
    return report


def validate_artifact(model):
    if not isinstance(model, dict):
        raise ValueError("A model object is required.")
    if model.get("schema_version") != "els-logistic-v1" or model.get("feature_columns") != FEATURES:
        raise ValueError("Unsupported model contract.")
    if not isinstance(model.get("model_version"), str) or not model["model_version"].strip():
        raise ValueError("A model version is required.")
    if model.get("synthetic_only") is not True or model.get("threshold_policy") != {"mfa_score": 30, "review_score": 70}:
        raise ValueError("A synthetic model and the 30/70 demo policy are required.")
    prep = model["preprocessing"]
    if [field["name"] for field in prep["numeric"]] != NUMERIC:
        raise ValueError("Invalid numeric feature boundary.")
    if [field["name"] for field in prep["categorical"]] != list(CATEGORIES):
        raise ValueError("Invalid categorical feature boundary.")
    names = NUMERIC.copy()
    for field in prep["numeric"]:
        if not all(isinstance(field[key], (int, float)) and not isinstance(field[key], bool)
                   and math.isfinite(field[key]) for key in ("median", "mean", "scale")) or field["scale"] <= 0:
            raise ValueError("Invalid scaling parameter.")
    for field in prep["categorical"]:
        if field["categories"] != CATEGORIES[field["name"]]:
            raise ValueError("Unexpected category vocabulary.")
        names += [f"{field['name']}={category}" for category in field["categories"]]
    if model["transformed_feature_order"] != names or len(model["coefficients"]) != len(names):
        raise ValueError("Coefficient and feature dimensions do not match.")
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
               for v in [*model["coefficients"], model["intercept"]]):
        raise ValueError("Model coefficients must be finite.")
    if model.get("missing_policy") != "abstain" or model.get("unknown_category_policy") != "abstain":
        raise ValueError("Missing features must trigger abstention.")
    integrity = model.get("artifact_integrity", {})
    if integrity.get("algorithm") != "sha256" or integrity.get("canonicalization") != "python_json_sort_keys_utf8_excluding_artifact_integrity":
        raise ValueError("A model integrity checksum is required.")
    payload = {key: value for key, value in model.items() if key != "artifact_integrity"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if hashlib.sha256(encoded).hexdigest() != integrity.get("digest"):
        raise ValueError("The model integrity checksum does not match.")
    return model


def predict_portable(model, row):
    """Pure-Python browser-parity inference; returns None on unsupported input."""
    if model is None:
        return None
    if not isinstance(row, dict) or set(row) != set(FEATURES):
        return None
    try:
        validate_artifact(model)
    except (KeyError, TypeError, ValueError):
        return None
    if invalid_features(row):
        return None
    values, owners = [], []
    for field in model["preprocessing"]["numeric"]:
        values.append((float(row[field["name"]]) - field["mean"]) / field["scale"])
        owners.append(field["name"])
    for field in model["preprocessing"]["categorical"]:
        for category in field["categories"]:
            values.append(float(row[field["name"]] == category))
            owners.append(field["name"])
    contributions = {name: 0.0 for name in FEATURES}
    linear = float(model["intercept"])
    for value, coefficient, owner in zip(values, model["coefficients"], owners):
        contribution = value * coefficient
        if not math.isfinite(contribution):
            return None
        contributions[owner] += contribution
        linear += contribution
    if not math.isfinite(linear):
        return None
    probability = (1 / (1 + math.exp(-linear))) if linear >= 0 else (
        math.exp(linear) / (1 + math.exp(linear)))
    positive = sorted((name for name in FEATURES if contributions[name] > 0),
                      key=lambda name: (-contributions[name], FEATURES.index(name)))[:3]
    reasons = [f"{LABELS[name]}: positive model contribution (+{contributions[name]:.2f})"
               for name in positive]
    return {"risk_score": int(math.floor(probability * 100 + 0.5)), "probability": probability,
            "reasons": reasons or ["Combined feature assessment"],
            "model_version": model["model_version"], "contributions": contributions}


def baseline_probabilities(frame):
    """Documented fixed rules; thresholds are not learned from holdout labels."""
    import numpy as np
    brute = (frame.attempts_2m >= 8) & (frame.failed_ratio_24h >= .5)
    spray = frame.distinct_accounts_2m >= 8
    context = ((frame.device_new == 1) & (frame.network_familiarity == "unfamiliar") &
               (frame.hour_deviation >= 4) & (frame.geo_velocity_kmh >= 600))
    return np.maximum.reduce([np.full(len(frame), .05), np.where(brute, .85, .05),
                              np.where(spray, .8, .05), np.where(context, .75, .05)])


def select_threshold(labels, probabilities, max_fpr=.05, min_recall=.5):
    """Validation only. No feasible threshold is explicit, never a silent 0.5."""
    import numpy as np
    labels, probabilities = np.asarray(labels), np.asarray(probabilities, dtype=float)
    if labels.ndim != 1 or probabilities.ndim != 1 or len(labels) != len(probabilities):
        raise ValueError("Label and probability dimensions must match for threshold selection.")
    if not np.isin(labels, [0, 1]).all() or not np.isfinite(probabilities).all() or (
        probabilities.size and ((probabilities < 0).any() or (probabilities > 1).any())
    ) or not 0 <= max_fpr <= 1 or not 0 <= min_recall <= 1:
        raise ValueError("Threshold selection requires finite probabilities in [0,1] and binary labels.")
    positive, negative = labels == 1, labels == 0
    if not positive.any() or not negative.any() or not len(probabilities):
        return {"feasible": False, "threshold": None, "reason": "validation_classes_missing",
                "max_fpr": max_fpr, "min_recall": min_recall}
    # 1+epsilon represents the deliberate no-alarm option; recall constraints still apply.
    candidates = np.unique(np.r_[0., probabilities, 1., np.nextafter(1., 2.)])
    feasible = []
    for threshold in candidates:
        predicted = probabilities >= threshold
        fpr = float(predicted[negative].mean())
        recall = float(predicted[positive].mean())
        precision = float(labels[predicted].mean()) if predicted.any() else 0.0
        if fpr <= max_fpr and recall >= min_recall:
            feasible.append((recall, -fpr, precision, float(threshold)))
    if not feasible:
        return {"feasible": False, "threshold": None, "reason": "fpr_recall_constraints_infeasible",
                "max_fpr": max_fpr, "min_recall": min_recall}
    recall, minus_fpr, precision, threshold = max(feasible)
    return {"feasible": True, "threshold": threshold, "validation_recall": recall,
            "validation_fpr": -minus_fpr, "validation_precision": precision,
            "max_fpr": max_fpr, "min_recall": min_recall}

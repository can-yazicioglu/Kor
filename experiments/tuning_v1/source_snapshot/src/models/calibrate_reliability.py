"""Validation-only sigmoid calibration and session-policy selection.

Runtime helpers use only the standard library. Offline fitting imports sklearn
locally. The previously inspected test split is a regression comparison, not
an untouched pilot or evidence of real-world effectiveness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

SCHEMA = "els-reliability-policy-v1"
EPSILON = 1e-12
CONSTRAINTS = {"mfa": {"max_fpr": .05, "min_recall": .50},
               "review": {"max_fpr": .01, "min_recall": .25}}
PARTITION_SALT = "els-reliability-validation-partition-v1:"


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def policy_digest(policy):
    payload = {key: value for key, value in policy.items() if key != "artifact_integrity"}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def seal_policy(policy):
    policy["artifact_integrity"] = {"algorithm": "sha256",
        "canonicalization": "python_json_sort_keys_utf8_excluding_artifact_integrity",
        "purpose": "accidental_corruption_not_authenticity", "digest": policy_digest(policy)}
    return policy


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def validate_policy(policy, model=None):
    """Validate checksum and semantic/data binding; this is not authentication."""
    try:
        if not isinstance(policy, dict) or policy.get("schema_version") != SCHEMA:
            raise ValueError
        for name in ("policy_version", "model_version"):
            if not isinstance(policy.get(name), str) or not policy[name].strip() or len(policy[name]) > 120:
                raise ValueError
        for name in ("base_model_sha256", "training_data_sha256", "base_manifest_sha256"):
            value = policy.get(name)
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError
        calibration = policy["calibration"]
        if (calibration.get("method") != "sigmoid_logit" or calibration.get("epsilon") != EPSILON or
            not finite(calibration.get("slope")) or calibration["slope"] <= 0 or
            not finite(calibration.get("intercept"))):
            raise ValueError
        thresholds = policy["thresholds"]
        if set(thresholds) != {"mfa", "review"}:
            raise ValueError
        for name, threshold in thresholds.items():
            if threshold is not None and (type(threshold) is not int or not 0 <= threshold <= 100):
                raise ValueError
            selection = policy["selection"][name]
            if type(selection.get("feasible")) is not bool or selection["feasible"] != (threshold is not None):
                raise ValueError
            if selection.get("score_threshold") != threshold:
                raise ValueError
        if thresholds["mfa"] is not None and thresholds["review"] is not None and thresholds["review"] < thresholds["mfa"]:
            raise ValueError
        if (policy.get("missing_policy") != "abstain" or
            policy.get("unavailable_threshold_policy") != "missing_mfa_requires_review" or
            policy.get("score_semantics") != "calibrated_on_synthetic_validation_only" or
            policy["selection"].get("unit") != "session_max_integer"):
            raise ValueError
        integrity = policy.get("artifact_integrity", {})
        if (integrity.get("algorithm") != "sha256" or
            integrity.get("canonicalization") != "python_json_sort_keys_utf8_excluding_artifact_integrity" or
            integrity.get("purpose") != "accidental_corruption_not_authenticity" or
            integrity.get("digest") != policy_digest(policy)):
            raise ValueError
        if model is not None and (policy["model_version"] != model.get("model_version") or
            policy["training_data_sha256"] != model.get("training_data_sha256")):
            raise ValueError
    except (TypeError, KeyError, ValueError, OverflowError, AttributeError):
        raise ValueError("Reliability policy is missing, invalid, corrupted or bound to a different model.") from None
    return policy


def load_policy(path, model_path):
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    validate_policy(policy, model)
    if policy["base_model_sha256"] != file_digest(model_path):
        raise ValueError("Reliability policy does not match the baseline model file checksum.")
    return policy


def _calibrated_probability(calibration, raw_probability):
    probability = min(1 - calibration["epsilon"], max(calibration["epsilon"], float(raw_probability)))
    raw_logit = math.log(probability / (1 - probability))
    linear = calibration["slope"] * raw_logit + calibration["intercept"]
    if not math.isfinite(linear):
        return None
    return 1 / (1 + math.exp(-linear)) if linear >= 0 else math.exp(linear) / (1 + math.exp(linear))


def apply_calibration(policy, raw_probability):
    """Return a calibrated probability/integer score, or None; never a fallback."""
    try:
        validate_policy(policy)
    except ValueError:
        return None
    if not finite(raw_probability) or not 0 <= raw_probability <= 1:
        return None
    probability = _calibrated_probability(policy["calibration"], raw_probability)
    if probability is None:
        return None
    return {"probability": probability, "risk_score": int(math.floor(100 * probability + .5))}


def policy_action(policy, score):
    """Missing MFA selection cannot silently become a low-risk decision."""
    try:
        validate_policy(policy)
    except ValueError:
        return "review_unscored"
    if type(score) is not int or not 0 <= score <= 100:
        return "review_unscored"
    mfa, review = policy["thresholds"]["mfa"], policy["thresholds"]["review"]
    if review is not None and score >= review:
        return "review"
    if mfa is None:
        return "review"
    return "mfa" if score >= mfa else "monitor"


def partition_validation(validation):
    """Hash validation accounts into deterministic disjoint halves, without labels.

    Account/session separation is guaranteed. Episode/source overlap is measured
    and disclosed: the supplied validation set cannot provide two useful
    episode-independent calibration/selection cohorts without new data.
    """
    accounts = sorted(validation.account_token.unique(), key=lambda account:
        hashlib.sha256((PARTITION_SALT + account).encode()).hexdigest())
    if len(accounts) < 2:
        raise ValueError("At least two independent validation accounts are required.")
    calibration_accounts = set(accounts[:len(accounts) // 2])
    mask = validation.account_token.isin(calibration_accounts)
    calibration, selection = validation[mask].copy(), validation[~mask].copy()
    audit = {"method": "sha256 account tokens; first half calibration-fit, second half threshold selection",
        "salt": PARTITION_SALT, "labels_used_for_partition": False,
        "shared_time_period": "both subsets are within the original validation interval",
        "episode_independence": "not guaranteed within validation; overlaps are disclosed below",
        "overlap_counts": {}}
    for name, part in (("calibration_fit", calibration), ("threshold_selection", selection)):
        audit[name] = {"rows": len(part), "accounts": part.account_token.nunique(),
            "scorable_rows": int(part._eligible.sum()), "positives_scorable": int(part.loc[part._eligible, "is_suspicious"].sum()),
            "account_set_sha256": hashlib.sha256("|".join(sorted(part.account_token.unique())).encode()).hexdigest()}
    for column in ("account_token", "session_token", "_episode", "_source"):
        audit["overlap_counts"][column] = len(set(calibration[column]) & set(selection[column]))
        if column in ("account_token", "session_token") and audit["overlap_counts"][column]:
            raise AssertionError("Calibration and threshold-selection accounts/sessions overlap.")
    return calibration, selection, audit


def infer_probabilities(frame, model):
    import numpy as np
    from .core import FEATURES, predict_portable
    probabilities = []
    for _, row in frame.iterrows():
        result = predict_portable(model, {name: row[name] for name in FEATURES})
        probabilities.append(np.nan if result is None else result["probability"])
    return np.asarray(probabilities)


def reference_histograms(validation):
    """Reference distribution summaries from validation only, without identifiers."""
    import numpy as np
    from .core import CATEGORIES, FEATURES
    features = {}
    for name in FEATURES:
        values = validation[name]
        missing = int(values.isna().sum())
        if name in CATEGORIES:
            categories = CATEGORIES[name]
            features[name] = {"kind": "categorical", "categories": categories,
                "counts": [int(values.eq(category).sum()) for category in categories], "missing": missing}
        else:
            numeric = values.dropna().to_numpy(dtype=float)
            edges = np.unique(np.quantile(numeric, [0, .25, .5, .75, 1])).tolist() if len(numeric) else []
            counts = np.bincount(np.searchsorted(edges, numeric, side="right"), minlength=len(edges) + 1).tolist()
            features[name] = {"kind": "numeric", "edges": edges, "counts": counts, "missing": missing,
                "binning": "bisect_right(edges, value); includes underflow and overflow buckets"}
    return {"source": "original_validation_only", "rows": len(validation), "features": features,
            "purpose": "reference distributions for drift monitoring; no validated alert threshold"}


def session_values(frame, probabilities):
    import numpy as np
    work = frame[["session_token", "is_suspicious"]].copy()
    work["_probability"] = probabilities
    grouped = work.groupby("session_token", sort=True).agg(label=("is_suspicious", "max"),
        probability=("_probability", lambda values: values.max() if values.notna().all() else np.nan))
    grouped["score"] = np.floor(grouped.probability * 100 + .5)
    return grouped


def select_score_threshold(labels, scores, constraint, minimum=0):
    import numpy as np
    labels, scores = np.asarray(labels), np.asarray(scores, dtype=float)
    positive, negative = labels == 1, labels == 0
    result = {"feasible": False, "score_threshold": None, "constraints": constraint,
              "scorable_sessions": len(labels), "positive_sessions": int(positive.sum()),
              "negative_sessions": int(negative.sum()), "minimum_score_threshold": minimum}
    if not positive.any() or not negative.any() or not np.isfinite(scores).all():
        return {**result, "reason": "selection_classes_or_scores_missing"}
    candidates = []
    for threshold in range(minimum, 101):
        predicted = scores >= threshold
        fpr, recall = float(predicted[negative].mean()), float(predicted[positive].mean())
        if fpr <= constraint["max_fpr"] and recall >= constraint["min_recall"]:
            candidates.append((recall, -fpr, threshold))
    if not candidates:
        return {**result, "reason": "predeclared_fpr_recall_constraints_infeasible"}
    recall, negative_fpr, threshold = max(candidates)
    return {**result, "feasible": True, "score_threshold": threshold,
            "selection_recall": recall, "selection_fpr": -negative_fpr}


def calibration_quality(labels, probabilities):
    import numpy as np
    labels, probabilities = np.asarray(labels, dtype=int), np.asarray(probabilities, dtype=float)
    valid = np.isfinite(probabilities)
    labels, probabilities = labels[valid], probabilities[valid]
    bins, ece = [], 0.
    for index in range(10):
        lower, upper = index / 10, (index + 1) / 10
        selected = (probabilities >= lower) & (probabilities <= upper if index == 9 else probabilities < upper)
        count = int(selected.sum())
        mean = float(probabilities[selected].mean()) if count else None
        rate = float(labels[selected].mean()) if count else None
        bins.append({"lower": lower, "upper": upper, "upper_inclusive": index == 9,
                     "count": count, "mean_probability": mean, "observed_positive_rate": rate})
        if count:
            ece += count / len(labels) * abs(mean - rate)
    return {"scored_events": len(labels), "brier_score": float(np.mean((probabilities - labels) ** 2)) if len(labels) else None,
            "ece_10_equal_width_bins": float(ece) if len(labels) else None, "bins": bins}


def decision_metrics(labels, scores, threshold):
    import numpy as np
    from .evaluate import metrics
    labels, scores = np.asarray(labels), np.asarray(scores, dtype=float)
    valid = np.isfinite(scores)
    values = metrics(labels[valid], scores[valid] / 100, None if threshold is None else threshold / 100)
    values.pop("pr_auc_average_precision")
    values.pop("roc_auc")
    values.pop("threshold")
    return {"total": len(scores), "scored": int(valid.sum()), "abstentions": int((~valid).sum()),
            "coverage": float(valid.mean()) if len(valid) else None, "score_threshold": threshold, **values}


def evaluate_regression(frame, raw, calibrated, policy):
    import numpy as np
    result = {"calibration_event_level": {"before": calibration_quality(frame.is_suspicious, raw),
                                          "after": calibration_quality(frame.is_suspicious, calibrated)},
              "event_decisions": {}, "session_decisions": {}, "event_subgroups": {}}
    for name, probabilities, thresholds in (("before", raw, {"mfa": 30, "review": 70}),
                                             ("after", calibrated, policy["thresholds"])):
        scores = np.floor(probabilities * 100 + .5)
        result["event_decisions"][name] = {action: decision_metrics(frame.is_suspicious, scores, threshold)
                                            for action, threshold in thresholds.items()}
        sessions = session_values(frame, probabilities)
        result["session_decisions"][name] = {action: decision_metrics(sessions.label, sessions.score, threshold)
                                              for action, threshold in thresholds.items()}
        if name == "after":
            action_counts = {action: 0 for action in ("monitor", "mfa", "review", "review_unscored")}
            for score in sessions.score:
                action = policy_action(policy, int(score) if np.isfinite(score) else None)
                action_counts[action] += 1
            result["after_session_actions"] = action_counts
        for scenario in sorted(frame._scenario.unique()):
            mask = (frame._scenario == scenario).to_numpy()
            result["event_subgroups"].setdefault(scenario, {})[name] = {
                action: decision_metrics(frame.loc[mask, "is_suspicious"], scores[mask], threshold)
                for action, threshold in thresholds.items()}
    return result


def run(args):
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from .core import load_dataset, validate_artifact

    frame, _, original_audit = load_dataset(args.data, args.manifest)
    model = json.loads(args.model.read_text())
    validate_artifact(model)
    if model["training_data_sha256"] != file_digest(args.data):
        raise ValueError("The baseline model and dataset must match.")
    validation = frame[frame._split == "validation"]
    fit, selection, partition = partition_validation(validation)
    raw_fit = infer_probabilities(fit, model)
    eligible = np.isfinite(raw_fit)
    labels = fit.loc[eligible, "is_suspicious"].to_numpy()
    if set(labels) != {0, 1}:
        raise ValueError("Both classes are required in the scorable calibration-fit partition.")
    clipped = np.clip(raw_fit[eligible], EPSILON, 1 - EPSILON)
    raw_logits = np.log(clipped / (1 - clipped)).reshape(-1, 1)
    calibrator = LogisticRegression(C=1., class_weight=None, max_iter=1000, solver="lbfgs", random_state=42)
    calibrator.fit(raw_logits, labels)
    calibration = {"method": "sigmoid_logit", "slope": float(calibrator.coef_[0, 0]),
                   "intercept": float(calibrator.intercept_[0]), "epsilon": EPSILON}
    if calibration["slope"] <= 0:
        raise ValueError("Validation does not support a positive monotonic calibration slope; policy unavailable.")
    raw_selection = infer_probabilities(selection, model)
    calibrated_selection = np.array([_calibrated_probability(calibration, value) if np.isfinite(value) else np.nan
                                     for value in raw_selection])
    selection_sessions = session_values(selection, calibrated_selection)
    selected = selection_sessions[selection_sessions.probability.notna()]
    mfa = select_score_threshold(selected.label, selected.score, CONSTRAINTS["mfa"])
    review = select_score_threshold(selected.label, selected.score, CONSTRAINTS["review"], mfa["score_threshold"] or 0)
    policy = seal_policy({"schema_version": SCHEMA, "policy_version": "els-reliability-v1-validation-only",
        "model_version": model["model_version"], "base_model_sha256": file_digest(args.model),
        "training_data_sha256": file_digest(args.data), "base_manifest_sha256": file_digest(args.manifest),
        "calibration": calibration, "thresholds": {"mfa": mfa["score_threshold"], "review": review["score_threshold"]},
        "missing_policy": "abstain", "unavailable_threshold_policy": "missing_mfa_requires_review",
        "score_semantics": "calibrated_on_synthetic_validation_only",
        "reference_histograms": reference_histograms(validation),
        "selection": {"unit": "session_max_integer", "constraints_declared_before_evaluation": CONSTRAINTS,
            "calibration_fit": "unweighted logistic regression on raw logits; C=1; no class balancing",
            "partition": partition, "mfa": mfa, "review": review,
            "total_selection_sessions": len(selection_sessions), "abstained_selection_sessions": int(selection_sessions.probability.isna().sum())}})
    validate_policy(policy, model)
    args.policy.parent.mkdir(parents=True, exist_ok=True)
    args.policy.write_text(json.dumps(policy, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    # No test labels or test scores have been used above this point. Policy is now frozen.
    test = frame[frame._split == "test"].copy()
    raw_test = infer_probabilities(test, model)
    calibrated_test = np.array([_calibrated_probability(calibration, value) if np.isfinite(value) else np.nan for value in raw_test])
    report = {"scope": "previously_inspected_synthetic_test_regression_comparison_not_untouched_pilot",
        "test_previously_inspected": True, "test_comparison_repeated_after_validation_partition_correction": True, "training_performed": "calibrator only on validation calibration-fit accounts",
        "baseline_model_retrained": False, "thresholds_tuned_on_test": False,
        "policy_artifact_sha256": file_digest(args.policy), "policy": policy,
        "original_split_audit": original_audit,
        "calibration_fit_quality": {"before": calibration_quality(fit.is_suspicious, raw_fit),
            "after": calibration_quality(fit.is_suspicious, np.array([
                _calibrated_probability(calibration, value) if np.isfinite(value) else np.nan for value in raw_fit]))},
        "threshold_selection_quality": {"before": calibration_quality(selection.is_suspicious, raw_selection),
                                         "after": calibration_quality(selection.is_suspicious, calibrated_selection)},
        "regression_test": evaluate_regression(test, raw_test, calibrated_test, policy)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    write_report(report, args.report)
    print(json.dumps({"status": "validation_only_calibration_and_threshold_selection_complete",
        "thresholds": policy["thresholds"], "calibration": calibration,
        "regression_test_rows": len(test), "test_used_for_selection": False}))
    return report


def write_report(report, path):
    from .evaluate import number
    policy, regression = report["policy"], report["regression_test"]
    partition = policy["selection"]["partition"]
    lines = ["# Reliability calibration and decision-policy evaluation", "",
        "This change fits a separate sigmoid calibrator and selects session thresholds using **validation data only**. "
        "The original model, its 11 inputs, baseline dataset and password-risk policy were not modified. "
        "The existing test labels/results had already been inspected in earlier work: results here are a regression comparison, "
        "not an untouched pilot, a novel-scenario validation or proven real-world performance. A future untouched, authorized pilot remains necessary.", "",
        "```bash", ".venv/bin/python -m src.models.calibrate_reliability", "```", "",
        "## Calibration and selection protocol", "",
        "Validation account tokens are deterministically "
        "hashed into two equal-sized account partitions (rounded down/up). Labels and predictions do not influence that partition. Calibration fitting "
        "and threshold selection share no accounts or sessions. Episode/source overlap within validation is disclosed below; the original fit/validation/test boundaries remain disjoint. Both subsets remain within the original validation time interval.", "",
        "| Partition | Rows | Scorable events | Scorable positives | Accounts |", "|---|---:|---:|---:|---:|"]
    for name in ("calibration_fit", "threshold_selection"):
        part = partition[name]
        lines.append(f"| {name} | {part['rows']} | {part['scorable_rows']} | {part['positives_scorable']} | {part['accounts']} |")
    calibration = policy["calibration"]
    lines += ["", f"Within-validation overlaps: accounts {partition['overlap_counts']['account_token']}, sessions {partition['overlap_counts']['session_token']}, episodes {partition['overlap_counts']['_episode']}, sources {partition['overlap_counts']['_source']}. "
        "This is account-disjoint validation, not fully episode-independent validation. A stricter connected-component split left no positive examples in the threshold partition because one connected component contains most accounts. New independent validation cohorts are required to remove this limitation.", "", "The calibrator is unweighted Logistic Regression on the original probability's logit (C=1, no class balancing). "
        "Probabilities are clipped to [1e-12, 1−1e-12] before conversion. "
        f"The fitted mapping is `sigmoid({calibration['slope']:.8f} × logit(p) + ({calibration['intercept']:.8f}))`. "
        "The integer score remains `floor(100*p + 0.5)`. Calibration describes these synthetic distributions; it does not make the score a proven real-world attack probability.", "",
        "Before inspecting this regression comparison, the selection constraints were fixed as MFA FPR ≤5% and recall ≥50%; "
        "review FPR ≤1% and recall ≥25%. Integer thresholds 0–100 are selected only on complete threshold-selection sessions, "
        "maximizing recall, then preferring lower FPR. Review must be at least the selected MFA threshold. "
        "If no candidate satisfies a constraint, its threshold is explicitly null. No 30/70 fallback is used.", "",
        "| Action | Selected score threshold | Feasible | Selection FPR | Selection recall |", "|---|---:|---|---:|---:|"]
    for action in ("mfa", "review"):
        value = policy["selection"][action]
        lines.append(f"| {action} | {value['score_threshold'] if value['score_threshold'] is not None else 'unavailable'} | {value['feasible']} | {number(value.get('selection_fpr'))} | {number(value.get('selection_recall'))} |")
    lines += ["", "Missing calibration or behaviour context produces no score. If MFA selection is unavailable, scores below any available "
        "review threshold require manual review; a valid calibrated numeric score is retained and threshold availability is reported separately. "
        "If both thresholds are unavailable every decision requires review. `review_unscored` is reserved for missing model/policy/context rather than missing decision thresholds. "
        "If only review selection is unavailable, the feasible MFA threshold can still recommend MFA. These actions never lock an account automatically.", "",
        "## Event-level probability reliability", "",
        "Brier score is the mean squared probability error (lower is better). ECE uses 10 predeclared equal-width probability bins; "
        "it depends on binning and finite support. Both exclude unscorable events. The JSON report records counts, mean probability and "
        "observed positive rate for every bin. The calibration-fit row is an in-sample diagnostic, not a generalization result.", "",
        "| Data | Scorable | Brier before | Brier after | ECE before | ECE after |", "|---|---:|---:|---:|---:|---:|"]
    for label, quality in (("Calibration fit (in-sample)", report["calibration_fit_quality"]),
                           ("Threshold selection", report["threshold_selection_quality"]),
                           ("Previously inspected test", regression["calibration_event_level"])):
        before, after = quality["before"], quality["after"]
        lines.append(f"| {label} | {after['scored_events']} | {number(before['brier_score'])} | {number(after['brier_score'])} | {number(before['ece_10_equal_width_bins'])} | {number(after['ece_10_equal_width_bins'])} |")
    lines += ["", "## Existing test regression comparison", "",
        "Before uses the original uncalibrated 30/70 behaviour policy. After uses the validation-fitted calibrator and its "
        "validation-selected thresholds. This comparison changes both calibration and decision policy; it must not attribute all "
        "decision changes to calibration alone. The password bonus is excluded here and remains a separately evaluated heuristic. "
        "Sessions use the maximum event probability/rounded score and abstain if any event is unscorable. A maximum of event probabilities "
        "is a risk aggregate, not a calibrated probability that at least one event is malicious. Threshold metrics exclude abstentions.", "",
        "| Unit | Policy | Action | Threshold | Scored / total | Abstained | Precision | Recall | FPR | TN / FP / FN / TP |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---|"]
    for unit in ("event", "session"):
        for timing in ("before", "after"):
            for action, values in regression[f"{unit}_decisions"][timing].items():
                matrix = values["confusion_matrix"]
                cells = " / ".join(str(n) for row in matrix for n in row) if matrix else "—"
                threshold = values["score_threshold"] if values["score_threshold"] is not None else "unavailable"
                lines.append(f"| {unit} | {timing} | {action} | {threshold} | {values['scored']} / {values['total']} | {values['abstentions']} | {number(values['precision'])} | {number(values['recall'])} | {number(values['false_positive_rate'])} | {cells} |")
    lines += ["", "After-policy session action counts: " + ", ".join(f"{name}={count}" for name, count in regression["after_session_actions"].items()) + ".", "",
        "## Limits and runtime binding", "",
        "A lower false-alarm rate can come with lower recall. Small subgroup and session counts limit precision of estimates. "
        "The positive sigmoid mapping preserves the original probability ranking; it cannot create new separation between attacks and normal contexts. "
        "Calibration and threshold feasibility on validation do not guarantee the same FPR/recall on this test split, new scenarios or customer traffic. "
        "This work does not establish independence from the generator's scenario templates. Novel-scenario challenge tests and an untouched pilot "
        "are separate requirements, not satisfied by reusing these test labels.", "",
        "`models/reliability_policy.json` contains only the calibration parameters, selected thresholds, aggregate selection evidence and "
        "model/data bindings. Runtime helpers use the standard library, verify the integrity checksum and reject missing/mismatched policy files. "
        "The checksum detects accidental corruption, not authenticity. The baseline model version is unchanged and the policy has its own version. "
        "The artifact also contains numeric/categorical reference histograms computed only from the original validation rows. "
        "They support distribution monitoring but do not define a validated drift-alert threshold. "
        "`outputs/reliability_evaluation.json` preserves full reliability bins, subgroup metrics, support and abstention counts.", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/mvp_synthetic_logins.csv"))
    parser.add_argument("--manifest", type=Path, default=Path("data/mvp_synthetic_logins.manifest.json"))
    parser.add_argument("--model", type=Path, default=Path("models/demo_model.json"))
    parser.add_argument("--policy", type=Path, default=Path("models/reliability_policy.json"))
    parser.add_argument("--output", type=Path, default=Path("outputs/reliability_evaluation.json"))
    parser.add_argument("--report", type=Path, default=Path("docs/reliability_results.md"))
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())

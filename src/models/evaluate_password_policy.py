"""Evaluate the password-policy overlay on the existing synthetic holdout.

No training, threshold tuning, password lookup or new data generation occurs.
Run: python -m src.models.evaluate_password_policy
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

from .core import COLUMNS, FEATURES, load_dataset, predict_portable, sha256_file, validate_artifact
from .evaluate import metrics, number

FLAGS = ["password_in_blocklist", "password_near_blocklist"]
V2_COLUMNS = [*COLUMNS, *FLAGS]
POLICY = {"version": "password-policy-v1", "exact_bonus": 25, "near_bonus": 10, "cap": 100}


def adjusted_score(base, exact, near):
    """Independent policy calculation; unknown/contradictory evidence abstains."""
    valid_numeric = lambda value: isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if not valid_numeric(base) or not float(base).is_integer() or not 0 <= base <= 100:
        return None
    if not all(valid_numeric(value) and value in (0, 1) for value in (exact, near)) or exact + near > 1:
        return None
    return min(100, int(base) + (25 if exact else 10 if near else 0))


def score_metrics(labels, scores):
    """Use displayed integer scores for thresholds; unknowns stay outside metrics."""
    labels, scores = np.asarray(labels, dtype=int), np.asarray(scores, dtype=float)
    valid = np.isfinite(scores)
    result = {"total": len(scores), "scored": int(valid.sum()), "abstentions": int((~valid).sum()),
              "coverage": float(valid.mean()) if len(valid) else None}
    for threshold in (30, 70):
        item = metrics(labels[valid], scores[valid] / 100, threshold / 100)
        # These are policy scores, not probabilities; avoid relabelling them as probability AUC.
        item.pop("pr_auc_average_precision")
        item.pop("roc_auc")
        item["score_threshold"] = threshold
        item.pop("threshold")
        result[f"score_ge_{threshold}"] = item
    return result


def compare_policy(frame, base_scores, policy_scores):
    base_scores, policy_scores = np.asarray(base_scores, dtype=float), np.asarray(policy_scores, dtype=float)
    labels = frame.is_suspicious.to_numpy()
    result = {"event": {"base": score_metrics(labels, base_scores),
                        "password_policy": score_metrics(labels, policy_scores)}}
    grouped = frame[["session_token", "is_suspicious"]].copy()
    grouped["base"] = base_scores
    grouped["policy"] = policy_scores
    sessions = grouped.groupby("session_token", sort=True).agg(
        label=("is_suspicious", "max"), base=("base", lambda values: values.max() if values.notna().all() else np.nan),
        policy=("policy", lambda values: values.max() if values.notna().all() else np.nan))
    result["session"] = {"base": score_metrics(sessions.label, sessions.base),
                         "password_policy": score_metrics(sessions.label, sessions.policy)}
    valid = np.isfinite(base_scores) & np.isfinite(policy_scores)
    delta = policy_scores[valid] - base_scores[valid]
    result["score_changes"] = {"paired_scorable_events": int(valid.sum()), "increased_events": int((delta > 0).sum()),
        "unchanged_events": int((delta == 0).sum()), "decreased_events": int((delta < 0).sum()),
        "capped_at_100_events": int((policy_scores[valid] == 100).sum()),
        "mean_increase_points": float(delta.mean()) if len(delta) else None}
    result["event_subgroups"] = {}
    for scenario in sorted(frame._scenario.unique()):
        mask = (frame._scenario == scenario).to_numpy()
        result["event_subgroups"][scenario] = {
            "base": score_metrics(labels[mask], base_scores[mask]),
            "password_policy": score_metrics(labels[mask], policy_scores[mask])}
    return result


def load_inputs(args):
    baseline, manifest, audit = load_dataset(args.data, args.manifest)
    v2_manifest = json.loads(args.v2_manifest.read_text())
    if v2_manifest.get("synthetic") is not True or v2_manifest.get("schema_version") != "els-synthetic-password-flags-v2":
        raise ValueError("A delivered synthetic v2 manifest is required.")
    expected_hashes = {"csv_sha256": sha256_file(args.v2_data), "base_csv_sha256": sha256_file(args.data),
        "base_manifest_sha256": sha256_file(args.manifest), "reference_sha256": sha256_file(args.reference)}
    if any(v2_manifest.get(key) != value for key, value in expected_hashes.items()):
        raise ValueError("The v2 data, baseline or password-reference checksum does not match its manifest.")
    if v2_manifest.get("events") != manifest.get("events"):
        raise ValueError("The v2 event metadata must preserve the audited baseline split exactly.")
    base_text = pd.read_csv(args.data, dtype=str, keep_default_na=False)
    v2_text = pd.read_csv(args.v2_data, dtype=str, keep_default_na=False)
    if list(v2_text.columns) != V2_COLUMNS or not v2_text[COLUMNS].equals(base_text):
        raise ValueError("V2 must preserve every original column and row, adding only the two password flags.")
    model = json.loads(args.model.read_text())
    validate_artifact(model)
    if model["training_data_sha256"] != expected_hashes["base_csv_sha256"]:
        raise ValueError("The saved model is not bound to the baseline dataset.")
    saved = pd.read_csv(args.predictions)
    saved = saved[(saved.model == "logistic_regression") & (saved.split == "test")]
    test = baseline[baseline._split == "test"].copy()
    if saved.event_id.duplicated().any() or set(saved.event_id) != set(test.event_id):
        raise ValueError("Saved logistic predictions do not exactly cover the existing holdout.")
    saved = saved.set_index("event_id")
    for index, row in test.iterrows():
        expected = predict_portable(model, {name: row[name] for name in FEATURES})
        actual = saved.loc[row.event_id]
        if expected is None:
            if actual.status != "abstain" or not pd.isna(actual.risk_score):
                raise ValueError("Saved abstention does not match the unchanged model.")
        elif (actual.status != "scored" or actual.risk_score != expected["risk_score"] or
              not math.isfinite(float(actual.probability)) or abs(actual.probability - expected["probability"]) > 1e-12):
            raise ValueError("Saved scores do not match the unchanged model.")
    for name in FLAGS:
        values = v2_text.loc[test.index, name]
        if not values.isin(["", "0", "1"]).all():
            raise ValueError("Password flags must be 0, 1 or empty for unknown.")
        test[name] = values.map({"": None, "0": 0, "1": 1})
    base_scores = test.event_id.map(saved.risk_score).to_numpy(dtype=float)
    adjusted = np.array([adjusted_score(base, exact, near) for base, exact, near in
        zip(base_scores, test.password_in_blocklist, test.password_near_blocklist)], dtype=float)
    return test, base_scores, adjusted, expected_hashes, model


def evaluate(args):
    test, base_scores, policy_scores, hashes, model = load_inputs(args)
    report = {"scope": "existing_synthetic_holdout_policy_comparison_not_real_world_validation",
        "policy": POLICY, "model_version": model["model_version"], "data_hashes": hashes,
        "model_artifact_sha256": sha256_file(args.model), "prediction_file_sha256": sha256_file(args.predictions),
        "split": "unchanged audited test split; no training, model selection or threshold tuning",
        "semantics": {"score": "integer behaviour score plus policy bonus, capped at 100; not a calibrated probability",
                      "abstention": "unknown base or password result abstains; any unscored event abstains its entire session",
                      "session_target": "maximum event target for evaluation only"},
        "flag_support": {"exact": int((test.password_in_blocklist == 1).sum()),
                         "near": int((test.password_near_blocklist == 1).sum()),
                         "neither": int(((test.password_in_blocklist == 0) & (test.password_near_blocklist == 0)).sum()),
                         "unknown_or_invalid": int(test[FLAGS].isna().any(axis=1).sum() + ((test.password_in_blocklist + test.password_near_blocklist) > 1).sum())},
        **compare_policy(test, base_scores, policy_scores)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    write_report(report, args.report)
    print(json.dumps({"status": "evaluated_existing_synthetic_holdout_password_policy", "rows": len(test),
        "report": str(args.report), "training_performed": False}))
    return report


def write_report(report, path):
    lines = ["# Password-risk policy evaluation", "",
        "> Historical experiment: the current server demo separates credential weakness and uses no fixed +25/+10 bonus. This report preserves the earlier CSV policy for reproducibility. See [reliability results](reliability_results.md) and [architecture](architecture.md).", "",
        "The password flags are a **separate heuristic policy**, not learned features or calibrated attack probabilities. "
        "The original 11-feature Logistic Regression model, coefficients and audited test split are unchanged. "
        "No retraining, threshold selection, new password lookup or data generation occurred during this evaluation. "
        "This is a comparison on synthetic data, not evidence of improved real-world detection.", "",
        "```bash", ".venv/bin/python -m src.models.evaluate_password_policy", "```", "",
        "The evaluator verifies the v2 CSV/manifest, baseline and reference checksums, exact preservation of the original 17 columns, "
        "unchanged event split metadata and agreement between saved LR predictions and portable inference. "
        "It evaluates only the existing test split. No submitted password or event-password hash is read or exported.", "",
        f"Model version: `{report['model_version']}`. V2 CSV SHA-256: `{report['data_hashes']['csv_sha256']}`.", "",
        "## Policy and support", "",
        "An exact common-password reference match adds 25 points; a close variant adds 10; neither adds zero. "
        "Exact and near are mutually exclusive. The integer result is capped at 100. Missing base risk or unknown/contradictory "
        "password flags produce abstention rather than zero. Session risk is the maximum event score only if every event is scorable. "
        "A no-match result does not prove password safety. Reference membership does not prove account compromise.", "",
        f"Test flag support: exact {report['flag_support']['exact']}, near {report['flag_support']['near']}, "
        f"neither {report['flag_support']['neither']}, unknown/invalid {report['flag_support']['unknown_or_invalid']}.", "",
        "The delivered fixture contains checked flags; unknown handling is tested separately. Synthetic password profiles were assigned "
        "independently of target/scenario, so normal logins can receive bonus points and suspicious logins can have no reference match.", "",
        "## Existing holdout comparison", "",
        "Precision, recall and FPR below exclude abstentions. Confusion matrices are TN / FP / FN / TP. "
        "Targets are event labels or, for sessions, the maximum event label used only for evaluation.", "",
        "| Unit | Policy | Scored / total | Abstained | Threshold | Precision | Recall | FPR | TN / FP / FN / TP |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|"]
    for unit in ("event", "session"):
        for policy, label in (("base", "Behaviour only"), ("password_policy", "Behaviour + password policy")):
            value = report[unit][policy]
            for threshold in (30, 70):
                item = value[f"score_ge_{threshold}"]
                cells = " / ".join(str(n) for row in item["confusion_matrix"] for n in row) if item["confusion_matrix"] else "—"
                lines.append(f"| {unit} | {label} | {value['scored']} / {value['total']} | {value['abstentions']} | ≥{threshold} | {number(item['precision'])} | {number(item['recall'])} | {number(item['false_positive_rate'])} | {cells} |")
    changes = report["score_changes"]
    lines += ["", f"Of {changes['paired_scorable_events']} events scorable under both policies, {changes['increased_events']} increased, "
        f"{changes['unchanged_events']} were unchanged and {changes['decreased_events']} decreased. "
        f"The adjusted score reached 100 for {changes['capped_at_100_events']} events. "
        f"Mean increase: {number(changes['mean_increase_points'])} points.", "",
        "## False alarms and limitations", "",
        "Adding only non-negative points can raise both recall and false alarms at the same fixed thresholds. "
        "That trade-off must not be reported as an unconditional improvement. The model already produces unnecessary alarms for some "
        "normal travel/new-device contexts; the overlay does not solve that limitation. No policy points or thresholds were tuned against "
        "these holdout results. MFA and review are recommendations, with no automatic locking.", "",
        "| Normal subgroup | Scored / total | Base ≥30 FPR | Adjusted ≥30 FPR | Base ≥70 FPR | Adjusted ≥70 FPR |",
        "|---|---:|---:|---:|---:|---:|"]
    for name, value in report["event_subgroups"].items():
        base, adjusted = value["base"], value["password_policy"]
        if base["score_ge_30"]["negatives"] == 0:
            continue
        lines.append(f"| {name} | {adjusted['scored']} / {adjusted['total']} | {number(base['score_ge_30']['false_positive_rate'])} | {number(adjusted['score_ge_30']['false_positive_rate'])} | {number(base['score_ge_70']['false_positive_rate'])} | {number(adjusted['score_ge_70']['false_positive_rate'])} |")
    lines += ["", "Full support, abstention and subgroup metrics are in `outputs/password_policy_evaluation.json`. "
        "The original model comparison remains in `docs/model_results.md` and `outputs/evaluation.json`; neither is replaced by this policy evaluation.", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/mvp_synthetic_logins.csv"))
    parser.add_argument("--manifest", type=Path, default=Path("data/mvp_synthetic_logins.manifest.json"))
    parser.add_argument("--v2-data", type=Path, default=Path("data/mvp_synthetic_logins_v2.csv"))
    parser.add_argument("--v2-manifest", type=Path, default=Path("data/mvp_synthetic_logins_v2.manifest.json"))
    parser.add_argument("--reference", type=Path, default=Path("data/password_reference.json"))
    parser.add_argument("--model", type=Path, default=Path("models/demo_model.json"))
    parser.add_argument("--predictions", type=Path, default=Path("outputs/holdout_predictions.csv"))
    parser.add_argument("--output", type=Path, default=Path("outputs/password_policy_evaluation.json"))
    parser.add_argument("--report", type=Path, default=Path("docs/password_policy_results.md"))
    return parser.parse_args()


if __name__ == "__main__":
    evaluate(parse_args())

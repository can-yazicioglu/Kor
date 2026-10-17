"""Evaluate the saved comparison bundle without retraining; synthetic only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score)

from .core import (FEATURES, baseline_probabilities, load_dataset, select_features, sha256_file)


def metrics(labels, probability, threshold):
    labels, probability = np.asarray(labels, dtype=int), np.asarray(probability, dtype=float)
    both = len(np.unique(labels)) == 2
    result = {"eligible_rows": len(labels), "positives": int((labels == 1).sum()),
              "negatives": int((labels == 0).sum()),
              "pr_auc_average_precision": float(average_precision_score(labels, probability)) if both else None,
              "roc_auc": float(roc_auc_score(labels, probability)) if both else None,
              "threshold": threshold}
    if threshold is None or not len(labels):
        result.update(precision=None, recall=None, false_positive_rate=None, confusion_matrix=None)
        return result
    predictions = probability >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    result.update(precision=float(precision_score(labels, predictions, zero_division=0)),
                  recall=float(recall_score(labels, predictions, zero_division=0)) if result["positives"] else None,
                  false_positive_rate=float(fp / (tn + fp)) if tn + fp else None,
                  confusion_matrix=[[int(tn), int(fp)], [int(fn), int(tp)]])
    return result


def subset_metrics(frame, probabilities, mask, threshold):
    part = frame[mask]
    valid = part._eligible.to_numpy(dtype=bool)
    selected = probabilities[mask.to_numpy()][valid]
    result = metrics(part.loc[part._eligible, "is_suspicious"], selected, threshold)
    result["total_rows"] = len(part)
    result["abstentions"] = int((~part._eligible).sum())
    result["coverage"] = float(part._eligible.mean()) if len(part) else None
    return result


def session_policy_metrics(frame, probabilities):
    """Mirror the demo: max rounded event risk; any abstention defers the session.

    Session label = maximum event label for evaluation only, never inference.
    Unknown sessions remain outside score-based metrics with explicit coverage.
    """
    work = frame[["session_token", "is_suspicious", "_eligible"]].copy()
    work["_score"] = np.floor(np.asarray(probabilities) * 100 + .5)
    grouped = work.groupby("session_token", sort=True).agg(
        label=("is_suspicious", "max"), eligible=("_eligible", "all"),
        score=("_score", "max"), events=("_eligible", "size"))
    valid = grouped[grouped.eligible]
    return {"aggregation": "max_integer_event_score; any_unscored_event_abstains_entire_session",
        "evaluation_label": "max event target label; never an inference input",
        "total_sessions": len(grouped), "scored_sessions": len(valid),
        "abstained_sessions": int((~grouped.eligible).sum()),
        "coverage": float(grouped.eligible.mean()) if len(grouped) else None,
        "multievent_sessions": int((grouped.events > 1).sum()),
        "mfa_or_review_score_ge_30": metrics(valid.label, valid.score / 100, .3),
        "review_score_ge_70": metrics(valid.label, valid.score / 100, .7)}


def evaluate(args):
    frame, manifest, audit = load_dataset(args.data, args.manifest)
    # Only load the repository's own locally generated bundle. Joblib/pickle is not an upload format.
    bundle = joblib.load(args.model_dir / "comparison_models.joblib")
    if bundle.get("data_sha256") != sha256_file(args.data) or bundle.get("manifest_sha256") != sha256_file(args.manifest):
        raise ValueError("The model data/manifest checksum has changed; explicitly retrain before evaluation.")
    if bundle.get("feature_columns") != FEATURES or bundle.get("split_audit") != audit:
        raise ValueError("The model feature or split contract has changed.")
    test = frame[frame._split == "test"].copy().reset_index(drop=True)
    eligible = test._eligible.to_numpy(dtype=bool)
    x = select_features(test.loc[test._eligible])
    report = {"scope": "synthetic_generator_holdout_only_not_real_world_performance",
        "data_sha256": bundle["data_sha256"], "manifest_sha256": bundle["manifest_sha256"],
        "feature_columns": FEATURES, "split_audit": audit,
        "coverage_by_split": {split: {"total_rows": len(part), "eligible_rows": int(part._eligible.sum()),
            "abstentions": int((~part._eligible).sum())} for split, part in frame.groupby("_split")},
        "threshold_selection": "validation only: maximize recall subject to per-model saved max_fpr/min_recall constraints; infeasibility explicit",
        "unavailable_models": bundle["unavailable_models"],
        "portable_parity_max_probability_error": bundle["portable_parity_max_probability_error"],
        "models": {}, "versions": bundle["versions"], "seed": bundle["seed"]}
    predictions = []
    arrays = {}
    for name in ["rule_baseline", *bundle["models"]]:
        probabilities = np.full(len(test), np.nan)
        probabilities[eligible] = (baseline_probabilities(x) if name == "rule_baseline" else
                                   bundle["models"][name].predict_proba(x)[:, 1])
        arrays[name] = probabilities
        selection = bundle["thresholds"][name]
        threshold = selection["threshold"]
        scored = subset_metrics(test, probabilities, pd.Series(True, index=test.index), threshold)
        scored["validation_threshold_selection"] = selection
        masks = {scenario: test._scenario == scenario for scenario in sorted(test._scenario.unique())}
        masks.update({"normal_with_vpn": (test.is_suspicious == 0) & (test.asn_category == "vpn"),
            "normal_new_device": (test.is_suspicious == 0) & (test.device_new == 1),
            "normal_unfamiliar_network": (test.is_suspicious == 0) & (test.network_familiarity == "unfamiliar")})
        scored["subgroups"] = {group: subset_metrics(test, probabilities, mask, threshold)
                               for group, mask in masks.items()}
        for group, mask in masks.items():
            scored["subgroups"][group]["demo_mfa_fpr"] = subset_metrics(test, probabilities, mask, .295)["false_positive_rate"]
            scored["subgroups"][group]["demo_review_fpr"] = subset_metrics(test, probabilities, mask, .695)["false_positive_rate"]
        # Score policy uses the displayed integer score: 30 starts at probability 0.295.
        scored["demo_policy"] = {"mfa_or_review_score_ge_30": subset_metrics(test, probabilities,
            pd.Series(True, index=test.index), .295), "review_score_ge_70": subset_metrics(test, probabilities,
            pd.Series(True, index=test.index), .695)}
        scored["session_policy"] = session_policy_metrics(test, probabilities)
        report["models"][name] = scored
        for index, row in test.iterrows():
            p = probabilities[index]
            predictions.append({"event_id": row.event_id, "split": "test", "model": name,
                "probability": None if np.isnan(p) else float(p),
                "risk_score": None if np.isnan(p) else int(np.floor(p * 100 + .5)),
                "status": "abstain" if np.isnan(p) else "scored"})
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "evaluation.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    prediction_frame = pd.DataFrame(predictions)
    prediction_frame["risk_score"] = prediction_frame["risk_score"].astype("Int64")
    prediction_frame.to_csv(args.output_dir / "holdout_predictions.csv", index=False)
    plot_comparison(test, arrays, args.output_dir / "precision_recall.png")
    write_report(report, args.report)
    print(json.dumps({"status": "evaluated_synthetic_holdout", "test_rows": len(test),
                      "abstentions_per_model": int((~eligible).sum()), "report": str(args.report)}))
    return report


def plot_comparison(test, arrays, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    valid = test._eligible.to_numpy(dtype=bool)
    labels = test.loc[test._eligible, "is_suspicious"].to_numpy()
    fig, ax = plt.subplots(figsize=(8, 5))
    for name, probabilities in arrays.items():
        precision, recall, _ = precision_recall_curve(labels, probabilities[valid])
        ax.plot(recall, precision, label=name.replace("_", " "))
    ax.axhline(labels.mean(), color="gray", linestyle="--", label="eligible synthetic prevalence")
    ax.set(xlabel="Recall", ylabel="Precision", title="Synthetic holdout only — not real-world validation", xlim=(0, 1), ylim=(0, 1.03))
    ax.legend(loc="lower left", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def number(value):
    return "—" if value is None else f"{value:.4f}"


def write_report(report, path):
    lines = ["# AI 3 — Modelling and synthetic evaluation", "",
        "These results describe **only the held-out test split of the delivered synthetic generator**. "
        "They are not real customer performance, calibrated attack probabilities or proven real-world effectiveness. "
        "Generator templates appear in every split, so generalization beyond those templates has not been validated. "
        "This report evaluates the original 11-feature behaviour model; any additional password-risk policy is a separate application layer, not a trained input or part of these metrics.", "",
        "## Reproduce", "", "```bash", ".venv/bin/python -m src.models.train", ".venv/bin/python -m src.models.evaluate",
        ".venv/bin/python -m unittest discover -s tests -p 'test_models.py' -v", "```", "",
        "Training stops before fitting if the delivered CSV or its checksum-matched synthetic manifest is missing. "
        "Evaluation uses the saved local model without retraining. `comparison_models.joblib` is a trusted artifact created by this project; "
        "do not load external pickle/joblib files. The browser uses only `models/demo_model.json`; customer CSV files are never uploaded. "
        "Python inference and the demo server check the model JSON checksum. This detects accidental corruption, not authenticity or a signature.", "",
        f"CSV SHA-256: `{report['data_sha256']}`.", "",
        "## Feature and split boundaries", "",
        "Inputs use an exact 11-feature allowlist. `event_id`, `event_ts_utc`, `session_token`, `account_token`, "
        "`is_suspicious`, `attack_type` and all manifest metadata are excluded. Identifiers are used only for split audits; "
        "the target is used only for supervised fitting and evaluation. Scaling is fitted only on `fit`; category vocabularies "
        "are fixed by the data contract. A row with any missing history or unsupported feature abstains. It is not assigned zero risk "
        "and no missing values are imputed. Exported medians are fit summaries only and are not used during inference.", "",
        "| Split | Total rows | Scorable | Abstentions | Accounts | Episodes |", "|---|---:|---:|---:|---:|---:|"]
    for split in ("fit", "validation", "test"):
        cov, audit = report["coverage_by_split"][split], report["split_audit"]["splits"][split]
        lines.append(f"| {split} | {cov['total_rows']} | {cov['eligible_rows']} | {cov['abstentions']} | {audit['accounts']} | {audit['episodes']} |")
    lines += ["", "Account, session, episode and synthetic source overlap is **zero** for every pair of splits. "
        "Chronology and a gap of at least 120 seconds are checked before fitting. The 30-day history is simulated only in the synthetic manifest; "
        "no real user history is assumed.", "",
        "## Model comparison and thresholds", "",
        "Rule baseline: at least 8 account attempts in 2 minutes and failure ratio at least 0.5 → 0.85; "
        "at least 8 distinct accounts in 2 minutes → 0.80; new device + unfamiliar network + at least 4 hours of deviation "
        "+ location-change speed of at least 600 km/h → 0.75; otherwise → 0.05. The largest applicable score is used. "
        "A VPN or a new device alone does not trigger the rule baseline.", "",
        "LR: C=1, balanced class weights, up to 2,000 iterations. RF: 160 trees, maximum depth 8, minimum leaf size 8, "
        "balanced class weights. Installed XGBoost: 150 trees, depth 3, learning rate 0.05; class weighting comes only from fit data. "
        f"Seed {report['seed']}; neither models nor hyperparameters are selected using holdout results.", "",
        "Decision thresholds are selected on validation only, maximizing recall subject to each saved `max_fpr` / `min_recall` constraint "
        "and preferring lower FPR on ties. If no threshold is feasible, `feasible=false` and `threshold=null`; there is no silent 50-point fallback. "
        "Validation constraints are not guaranteed on the test split. PR-AUC here means `average_precision_score` (Average Precision), "
        "not trapezoidal area. Threshold metrics use only scorable rows in their denominators.", "",
        "| Model | PR-AUC/AP | ROC-AUC | Precision | Recall | FPR | Threshold | TN / FP / FN / TP |", "|---|---:|---:|---:|---:|---:|---:|---|"]
    for name, result in report["models"].items():
        matrix = result["confusion_matrix"]
        cells = "—" if matrix is None else " / ".join(str(n) for row in matrix for n in row)
        lines.append(f"| {name} | {number(result['pr_auc_average_precision'])} | {number(result['roc_auc'])} | {number(result['precision'])} | {number(result['recall'])} | {number(result['false_positive_rate'])} | {number(result['threshold'])} | {cells} |")
    constraints = report["models"]["logistic_regression"]["validation_threshold_selection"]
    lines.append(f"\nValidation targets for this run: FPR ≤{constraints['max_fpr']:.2%}, recall ≥{constraints['min_recall']:.2%}.")
    baseline_policy = report["models"]["rule_baseline"]["demo_policy"]
    baseline_mfa = baseline_policy["mfa_or_review_score_ge_30"]
    baseline_review = baseline_policy["review_score_ge_70"]
    if baseline_mfa["confusion_matrix"] == baseline_review["confusion_matrix"]:
        cells = " / ".join(str(n) for row in baseline_mfa["confusion_matrix"] for n in row)
        lines.append("\nThe rule baseline makes the same decisions under the existing 30/70 demo policies: "
            f"precision **{number(baseline_mfa['precision'])}**, recall **{number(baseline_mfa['recall'])}**, "
            f"FPR **{number(baseline_mfa['false_positive_rate'])}**, TN / FP / FN / TP **{cells}**. "
            "These are predefined demo-policy metrics, not a selected validation threshold or a silent fallback after infeasibility. "
            "The comparison table retains missing threshold metrics because the validation constraints were infeasible.")
    for name, reason in report["unavailable_models"].items():
        lines.append(f"\n{name} was not run: {reason}.")
    lr = report["models"]["logistic_regression"]
    lines += ["", "## Demo model and explanations", "",
        "**Logistic Regression** is selected for the demo because it runs locally in the browser using a small, inspectable JSON artifact. "
        "This deployment choice is not based on the best holdout metric. The 0–100 score is the class-weighted LR sigmoid output rounded "
        "with `floor(p*100+0.5)`; it must not be interpreted as the true probability of an attack. Explanations list the three largest "
        "positive feature contributions in log-odds units. They are neither SHAP values nor causal explanations.", "",
        "Base behaviour-score policy: 0–29 monitor, 30–69 recommend MFA, 70–100 recommend MFA and review; there is no automatic account lock. "
        "This product policy is separate from the validation-selected benchmark threshold. Unscorable events require review rather than a low-risk assumption. "
        "On scorable test events, the FPR is " + number(lr["demo_policy"]["mfa_or_review_score_ge_30"]["false_positive_rate"]) +
        " at score ≥30 and " + number(lr["demo_policy"]["review_score_ge_70"]["false_positive_rate"]) + " at score ≥70.", "",
        f"Maximum held-out probability difference between portable Python inference and sklearn: `{report['portable_parity_max_probability_error']:.3g}`. "
        "`outputs/parity_cases.json` checks JavaScript parity using feature-only selections from the actual delivered synthetic CSV and their expected results.", "",
        "## Session-level demo audit", "",
        "The metrics above are at **event** level. The demo session score is the maximum rounded event score. If any event is unscorable, "
        "the entire session abstains and requires review. For this independent evaluation only, the session target is the maximum event target. "
        "Abstaining sessions are excluded from the score-threshold denominator and are not counted as true negatives or missed attacks.", "",
        f"LR test sessions: {lr['session_policy']['total_sessions']} total, {lr['session_policy']['scored_sessions']} scored, "
        f"{lr['session_policy']['abstained_sessions']} abstained; {lr['session_policy']['multievent_sessions']} contain multiple events.", "",
        "| Session policy | FPR | Recall | TN / FP / FN / TP |", "|---|---:|---:|---|"]
    for key, label in [("mfa_or_review_score_ge_30", "Score ≥30: MFA/review"), ("review_score_ge_70", "Score ≥70: review")]:
        item = lr["session_policy"][key]
        cells = " / ".join(str(n) for row in item["confusion_matrix"] for n in row) if item["confusion_matrix"] else "—"
        lines.append(f"| {label} | {number(item['false_positive_rate'])} | {number(item['recall'])} | {cells} |")
    lines += ["", "## Challenging normal contexts and attack subgroups", "",
        "The LR benchmark results below use the validation-selected threshold. Metrics without class support are shown as `—`. "
        "Abstentions are excluded from metrics and counted separately; they must not be counted as successful detections or true negatives. "
        "The ≥30/≥70 columns show event-level FPR under the base behaviour-score UI policy.", "",
        "| Subgroup | Total | Scored | Abstentions | Benchmark FPR | Recall | ≥30 FPR | ≥70 FPR |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, subgroup in lr["subgroups"].items():
        lines.append(f"| {name} | {subgroup['total_rows']} | {subgroup['eligible_rows']} | {subgroup['abstentions']} | {number(subgroup['false_positive_rate'])} | {number(subgroup['recall'])} | {number(subgroup['demo_mfa_fpr'])} | {number(subgroup['demo_review_fpr'])} |")
    lines += ["", "## Remaining limitations and artifacts", "",
        "The CSV cannot independently establish a successful real IdP login; manifest `auth_success` is synthetic audit metadata only. "
        "Borderline attacks overlap with normal VPN and travel contexts. False alarms and missed examples remain. This prototype is not a "
        "production security control and has not been validated on real customer data. Probability calibration and drift monitoring are not implemented.", "",
        "`outputs/evaluation.json` contains support, abstentions, subgroup metrics, confusion matrices and policy metrics for all compared models. "
        "`outputs/holdout_predictions.csv` contains only synthetic event correlation IDs, scores and status; it excludes accounts, sessions, timestamps, "
        "target labels and attack metadata. `models/comparison_models.joblib` supports local reevaluation. `models/demo_model.json` contains portable "
        "parameters without customer/event records. Synthetic development artifacts may remain in the repository; customer notebook/CSV/prediction "
        "exports are outside this workflow. Evaluation stops if the data or manifest checksum changes.", "",
        "![Synthetic precision-recall comparison](../outputs/precision_recall.png)", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/mvp_synthetic_logins.csv"))
    parser.add_argument("--manifest", type=Path, default=Path("data/mvp_synthetic_logins.manifest.json"))
    parser.add_argument("--model-dir", type=Path, default=Path("models"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--report", type=Path, default=Path("docs/model_results.md"))
    return parser.parse_args()


if __name__ == "__main__":
    evaluate(parse_args())

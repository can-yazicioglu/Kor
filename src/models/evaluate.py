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
        raise ValueError("Modelin veri/manifest özeti değişmiş; önce açıkça yeniden eğitim yapın.")
    if bundle.get("feature_columns") != FEATURES or bundle.get("split_audit") != audit:
        raise ValueError("Model özellik veya bölme sözleşmesi değişmiş.")
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
    lines = ["# AI 3 — Modelleme ve sentetik değerlendirme", "",
        "Bu sonuçlar **yalnızca teslim edilen sentetik üreticinin ayrılmış test bölümüne** aittir. "
        "Gerçek müşteri performansı, kalibre saldırı olasılığı veya gerçek dünyada kanıtlanmış başarı değildir. "
        "Aynı üreticinin şablonları tüm bölmelerde bulunduğu için şablondan bağımsız genelleme doğrulanmamıştır.", "",
        "## Tekrar çalıştırma", "", "```bash", ".venv/bin/python -m src.models.train", ".venv/bin/python -m src.models.evaluate",
        ".venv/bin/python -m unittest discover -s tests -p 'test_models.py' -v", "```", "",
        "İlk komut teslim edilmiş CSV ve SHA-256 eşleşen sentetik manifest yoksa eğitimden önce durur. "
        "İkinci komut yeniden eğitim yapmadan yerelde oluşturulmuş modeli değerlendirir. "
        "`comparison_models.joblib` yalnızca bu projede üretilmiş güvenilen dosyadır; dışarıdan gelen pickle/joblib yüklemeyin. "
        "Tarayıcı yalnızca `models/demo_model.json` kullanır; müşteri CSV'si sunucuya yüklenmez. "
        "Model JSON bütünlük özeti Python çıkarımında ve demo sunucusunda doğrulanır; SHA-256 özeti "
        "kazara değişikliği yakalar, imza veya kaynak doğrulaması değildir.", "",
        f"CSV SHA-256: `{report['data_sha256']}`.", "",
        "## Özellik ve bölme sınırı", "",
        "Girdi yalnızca sabit 11 özellik allowlist'idir. `event_id`, `event_ts_utc`, `session_token`, "
        "`account_token`, `is_suspicious`, `attack_type` ve tüm manifest metaverisi girdiden dışlanır. "
        "Kimlikler yalnızca ayrım denetiminde, etiket yalnızca hedef/değerlendirmede kullanılır. "
        "Ölçekleme sadece `fit` üzerinde öğrenilir; kategoriler veri sözleşmesinde önceden sabittir. "
        "Eksik geçmişi olan veya desteklenmeyen herhangi bir özelliği olan satır puanlanmaz; 0 risk sayılmaz, imputasyon yapılmaz. "
        "JSON'daki median yalnızca fit özeti olarak taşınır ve çıkarımda kullanılmaz.", "",
        "| Bölme | Tüm satırlar | Puanlanabilir | Çekimser | Hesap | Episode |", "|---|---:|---:|---:|---:|---:|"]
    for split in ("fit", "validation", "test"):
        cov, audit = report["coverage_by_split"][split], report["split_audit"]["splits"][split]
        lines.append(f"| {split} | {cov['total_rows']} | {cov['eligible_rows']} | {cov['abstentions']} | {audit['accounts']} | {audit['episodes']} |")
    lines += ["", "Bütün bölme çiftlerinde ortak hesap, oturum, episode ve sentetik kaynak sayısı **0**. "
        "Zaman sırası ve en az 120 saniyelik boşluk eğitim başlamadan doğrulanır. "
        "30 günlük geçmiş yalnızca sentetik manifestte simüle edilir; gerçek kullanıcı geçmişi varsayılmaz.", "",
        "## Karşılaştırma ve eşikler", "",
        "Kural referansı: 2 dakikada ≥8 hesap denemesi ve başarısızlık oranı ≥0,5 → 0,85; "
        "2 dakikada ≥8 farklı hesap → 0,80; yeni cihaz + yabancı ağ + ≥4 saat sapma + ≥600 km/saat → 0,75; "
        "aksi → 0,05. Birden çok kuralın maksimumu alınır. VPN veya yeni cihaz tek başına kural alarmı oluşturmaz.", "",
        "LR: C=1, dengeli sınıf ağırlığı, en çok 2000 iterasyon. RF: 160 ağaç, derinlik 8, yaprak en az 8, "
        "dengeli sınıf ağırlığı. Kurulu XGBoost: 150 ağaç, derinlik 3, öğrenme 0,05; sınıf ağırlığı yalnız fit'ten. "
        f"Seed {report['seed']}; model/hyperparametreler test sonuçlarına göre seçilmez.", "",
        "Karar eşiği yalnız validation üzerinde her modelin JSON sonuçlarında kaydedilen `max_fpr` / `min_recall` "
        "koşulları altında en yüksek recall "
        "(eşitlikte daha düşük FPR) için seçilir. Uygun eşik yoksa `feasible=false`, `threshold=null`; "
        "sessiz 50 puan varsayımı yoktur. Bu koşul test kümesinde garanti değildir. PR-AUC burada "
        "`average_precision_score` (Average Precision), trapezoid alanı değildir. Eşik metriklerinin paydası yalnız puanlanabilir satırlardır.", "",
        "| Model | PR-AUC/AP | ROC-AUC | Precision | Recall | FPR | Eşik | TN / FP / FN / TP |", "|---|---:|---:|---:|---:|---:|---:|---|"]
    for name, result in report["models"].items():
        matrix = result["confusion_matrix"]
        cells = "—" if matrix is None else " / ".join(str(n) for row in matrix for n in row)
        lines.append(f"| {name} | {number(result['pr_auc_average_precision'])} | {number(result['roc_auc'])} | {number(result['precision'])} | {number(result['recall'])} | {number(result['false_positive_rate'])} | {number(result['threshold'])} | {cells} |")
    constraints = report["models"]["logistic_regression"]["validation_threshold_selection"]
    lines.append(f"\nBu çalıştırmanın validation hedefleri: FPR ≤{constraints['max_fpr']:.2%}, recall ≥{constraints['min_recall']:.2%}.")
    baseline_policy = report["models"]["rule_baseline"]["demo_policy"]
    baseline_mfa = baseline_policy["mfa_or_review_score_ge_30"]
    baseline_review = baseline_policy["review_score_ge_70"]
    if baseline_mfa["confusion_matrix"] == baseline_review["confusion_matrix"]:
        cells = " / ".join(str(n) for row in baseline_mfa["confusion_matrix"] for n in row)
        lines.append("\nKural referansının mevcut 30/70 demo politikaları aynı kararları verir: "
            f"precision **{number(baseline_mfa['precision'])}**, recall **{number(baseline_mfa['recall'])}**, "
            f"FPR **{number(baseline_mfa['false_positive_rate'])}**, TN / FP / FN / TP **{cells}**. "
            "Bunlar önceden tanımlanmış demo politikası metrikleridir; seçilmiş validation eşiği veya "
            "uygun eşik bulunamadığında kullanılan sessiz bir varsayılan değildir. Validation kısıtlarının "
            "sağlanamaması karşılaştırma tablosunda hâlâ boş eşik/metrik olarak gösterilir.")
    for name, reason in report["unavailable_models"].items():
        lines.append(f"\n{name} çalıştırılmadı: {reason}.")
    lr = report["models"]["logistic_regression"]
    lines += ["", "## Demo modeli ve açıklamalar", "",
        "**Logistic Regression** tarayıcıda küçük, denetlenebilir bir JSON ile yerel çalışabildiği için demo modeli olarak seçildi. "
        "Bu seçim en iyi test metriğine dayanmıyor. 0–100 puan, sınıf ağırlıklı LR sigmoid çıktısının "
        "`floor(p*100+0.5)` ile yuvarlanmasıdır; saldırının gerçek olasılığı olarak yorumlanmamalıdır. "
        "Üç en büyük pozitif özellik katkısı log-odds cinsinden gerekçedir; SHAP veya nedensellik iddiası yoktur.", "",
        "UI politikası: 0–29 izleme, 30–69 MFA önerisi, 70–100 MFA + inceleme önerisi; otomatik hesap kilidi yok. "
        "Bu ürün politikası validation'da seçilen benchmark eşiğinden ayrıdır. Puanlanamayan olay inceleme gerektirir; "
        "düşük risk varsayılmaz. Testte puan ≥30 MFA/inceleme için FPR " + number(lr["demo_policy"]["mfa_or_review_score_ge_30"]["false_positive_rate"]) +
        ", puan ≥70 inceleme için FPR " + number(lr["demo_policy"]["review_score_ge_70"]["false_positive_rate"]) + ".", "",
        f"Taşınabilir Python çıkarımı ile sklearn arasındaki test maksimum olasılık farkı: `{report['portable_parity_max_probability_error']:.3g}`. "
        "`outputs/parity_cases.json` gerçek sentetik CSV'den seçilmiş özellikler ve beklenen sonuçlarla JavaScript eşliğini sınar.", "",
        "## Oturum düzeyinde demo doğrulaması", "",
        "Üstteki metrikler **olay** düzeyindedir. Demo oturum puanını puanlanabilir olayların yuvarlanmış "
        "puanlarının maksimumu olarak gösterir; herhangi bir olay puanlanamıyorsa tüm oturum puan bekler/inceleme önerir. "
        "Aşağıdaki bağımsız denetimde oturum hedefi, yalnız değerlendirme için olay hedeflerinin maksimumudur. "
        "Çekimser oturumlar aşağıdaki puan eşiklerinin paydasında yoktur; doğru negatif veya kaçırılan saldırı sayılmaz.", "",
        f"LR test oturumları: {lr['session_policy']['total_sessions']} toplam, {lr['session_policy']['scored_sessions']} puanlanan, "
        f"{lr['session_policy']['abstained_sessions']} çekimser; {lr['session_policy']['multievent_sessions']} birden çok olay içeriyor.", "",
        "| Oturum politikası | FPR | Recall | TN / FP / FN / TP |", "|---|---:|---:|---|"]
    for key, label in [("mfa_or_review_score_ge_30", "Puan ≥30 MFA/inceleme"), ("review_score_ge_70", "Puan ≥70 inceleme")]:
        item = lr["session_policy"][key]
        cells = " / ".join(str(n) for row in item["confusion_matrix"] for n in row) if item["confusion_matrix"] else "—"
        lines.append(f"| {label} | {number(item['false_positive_rate'])} | {number(item['recall'])} | {cells} |")
    lines += ["", "## Normal zor durumlar ve saldırı alt grupları", "",
        "Aşağıdaki LR sonuçları validation'da seçilen benchmark eşiğindedir. Desteği olmayan sınıf metriği `—` gösterilir. "
        "Çekimser satırlar metrik dışında kalır ve ayrıca sayılır; bunları başarılı tespit veya doğru negatif saymak hatalıdır.", "",
        "MFA/inceleme FPR sütunları gerçek UI'nın 30/70 puan politikasındaki olay yanlış alarm oranlarını gösterir.", "",
        "| Alt grup | Toplam | Puanlanan | Çekimser | Benchmark FPR | Recall | ≥30 FPR | ≥70 FPR |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, subgroup in lr["subgroups"].items():
        lines.append(f"| {name} | {subgroup['total_rows']} | {subgroup['eligible_rows']} | {subgroup['abstentions']} | {number(subgroup['false_positive_rate'])} | {number(subgroup['recall'])} | {number(subgroup['demo_mfa_fpr'])} | {number(subgroup['demo_review_fpr'])} |")
    lines += ["", "## Kalan sınırlar ve dosyalar", "",
        "Özellikle şüpheli başarılı girişin gerçek IdP başarı kaydı CSV'den bağımsız doğrulanamaz; sentetik manifestteki "
        "auth_success yalnız test denetimidir. Yakın/sınır saldırılar ve normal VPN/seyahat bağlamları çakışabilir. "
        "Yanlış alarmlar ve kaçırılan örnekler var; bu prototip üretim güvenlik kontrolü değildir. "
        "Model gerçek müşteri verisiyle doğrulanmamıştır, kalibrasyon ve drift izleme yapılmamıştır.", "",
        "`outputs/evaluation.json` tüm modellerin destek, çekimserlik, alt grup, confusion matrix ve politika metriklerini içerir. "
        "`outputs/holdout_predictions.csv` sadece sentetik event_id korelasyonu ve puan/status taşır; hesap/oturum, "
        "timestamp, hedef etiketi ve saldırı metaverisi yazılmaz. `models/comparison_models.joblib` yerel yeniden "
        "değerlendirme içindir. `models/demo_model.json` müşteri/olay kayıtları içermeyen taşınabilir parametrelerdir. "
        "Bu sentetik geliştirme dosyaları depoda kalabilir; müşteri verisiyle notebook, CSV veya tahmin export'u "
        "bu çalışma akışının kapsamı değildir. Manifest/CSV özeti değişirse değerlendirme durur.", "",
        "![Sentetik PR karşılaştırması](../outputs/precision_recall.png)", ""]
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

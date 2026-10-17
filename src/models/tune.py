"""Reproducible, gated synthetic tuning; never overwrites the deployed baseline.

Stages: prepare -> fit -> evaluate. The final cohorts do not exist until models,
calibration and thresholds are frozen. A run cannot consume its holdout twice.
Repeated experiments on these seeds are reproductions, not new blind tests.
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from datetime import datetime
import gzip
import io
import itertools
import json
import math
from pathlib import Path
import uuid

import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.preprocessing import StandardScaler

from src.data.generate_synthetic import generate_dataset, write_dataset
from src.models.core import COLUMNS, FEATURES, invalid_features, sha256_file
from src.models.calibrate_reliability import CONSTRAINTS, calibration_quality, session_values
from src.models.tuned_runtime import digest, predict, seal, sigmoid, validate
from src.models.tuning_features import PRIOR_FEATURES, VARIANTS, columns, prior_features, vector, vector_names

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUN = ROOT/'experiments/tuning_v1'
SOURCES = ['src/data/generate_synthetic.py', 'src/models/tuning_features.py',
           'src/models/tuned_runtime.py', 'src/runtime/risk.py']
BASELINE = ['models/demo_model.json', 'models/reliability_policy.json',
            'data/mvp_synthetic_logins.csv', 'data/mvp_synthetic_logins.manifest.json']
COHORTS = [
    ('fit', 101, 18000, '2025-03-01'),
    ('tune_a', 211, 6000, '2025-04-01'), ('tune_b', 307, 6000, '2025-05-01'),
    ('calibration', 401, 8000, '2025-06-01'), ('selection', 503, 12000, '2025-07-01'),
    ('holdout_a', 601, 12000, '2025-08-01'), ('holdout_b', 709, 12000, '2025-09-01'),
]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False)+'\n')


def read_json(path):
    return json.loads(path.read_text())


def make_protocol():
    return {'version': 'els-tuning-v1', 'synthetic_only': True,
        'cohorts': [dict(name=n, seed=s, rows=r, start=d+'T00:00:00Z', attack_rate=.08) for n,s,r,d in COHORTS],
        'variants': list(VARIANTS), 'C': [.01, .1, 1., 10.], 'class_weights': ['none', 'balanced', 'positive_3'],
        'selection_objective': 'lexicographic: worst tuning-cohort session recall at FPR<=5%, mean recall, mean session AP; then stable candidate ID',
        'calibration': 'positive-slope sigmoid on a separate cohort; unweighted C=1',
        'threshold_selection': 'integer session maxima; Wilson 95% upper FPR and lower recall satisfy targets; no fallback threshold',
        'constraints': CONSTRAINTS,
        'promotion': {'both_final_cohorts_required': True, 'min_session_ap_gain_vs_current': .02,
            'max_brier_regression': .002, 'minimum_scored_negative_sessions': 500, 'minimum_scored_positive_sessions': 50,
            'model_and_full_runtime_must_meet_targets': True,
            'benign_subgroup_max_fpr': {'mfa': .05, 'review': .01},
            'minimum_benign_subgroup_sessions': 30,
            'unknown_sessions': 'retain review fallback; report total workload separately; never count abstentions as correct'},
        'scope': 'New independent random cohorts from the SAME authored generator; not independent real-world validation. Current labels and auth outcomes never enter candidate vectors.',
        'baseline_sha256': {p: sha256_file(ROOT/p) for p in BASELINE},
        'source_sha256': {p: sha256_file(ROOT/p) for p in SOURCES},
        'versions': {'sklearn': sklearn.__version__, 'numpy': np.__version__, 'pandas': pd.__version__}}


def verify_protocol(run):
    protocol = read_json(run/'protocol.json')
    if digest(protocol) != (run/'protocol.sha256').read_text().strip():
        raise ValueError('Experiment protocol was modified.')
    for group in ('baseline_sha256', 'source_sha256'):
        for name, expected in protocol[group].items():
            if sha256_file(ROOT/name) != expected:
                raise ValueError('A bound baseline or feature/runtime source changed; use a separately declared experiment.')
    return protocol


def create_cohort(run, spec):
    csv_path = run/'data'/f"{spec['name']}.csv"
    if csv_path.with_suffix('.csv.gz').exists():
        raise ValueError('Cohort already exists; never replace an experiment cohort.')
    rows, manifest = generate_dataset(row_count=spec['rows'], attack_rate=spec['attack_rate'], seed=spec['seed'],
        start=datetime.fromisoformat(spec['start'].replace('Z', '+00:00')))
    # Generator event numbers are file-local. Namespace them before hashing or
    # merging so cross-cohort event uniqueness is auditable as well.
    events = manifest['events']
    prefix = (spec.get('namespace','')+'_' if spec.get('namespace') else '')+spec['name']+'_'
    for row in rows:
        old = row['event_id']; row['event_id'] = prefix+old
    manifest['events'] = {prefix+key: value for key, value in events.items()}
    manifest['experiment_phase'] = spec['name']
    manifest['phase_semantics'] = 'Entire cohort belongs to this experiment phase; internal generator splits are not reused as experiment phases.'
    csv_path, manifest_path = write_dataset(rows, manifest, csv_path)
    for path in (csv_path, manifest_path):
        payload = path.read_bytes()
        path.with_suffix(path.suffix+'.gz').write_bytes(gzip.compress(payload, mtime=0))
        path.unlink()  # Keep lossless, deterministic compressed synthetic fixtures.


def load_cohort(run, name):
    csv_payload = gzip.decompress((run/'data'/f'{name}.csv.gz').read_bytes())
    manifest = json.loads(gzip.decompress((run/'data'/f'{name}.manifest.json.gz').read_bytes()))
    import hashlib
    if manifest.get('synthetic') is not True or manifest.get('experiment_phase') != name or hashlib.sha256(csv_payload).hexdigest() != manifest['csv_sha256']:
        raise ValueError('Synthetic cohort provenance or checksum mismatch.')
    frame = pd.read_csv(io.BytesIO(csv_payload))
    if list(frame.columns) != COLUMNS or frame.event_id.duplicated().any() or set(frame.event_id) != set(manifest['events']):
        raise ValueError('Cohort does not match the fixed CSV contract.')
    if not frame.is_suspicious.isin([0,1]).all():
        raise ValueError('Invalid labels.')
    metadata = manifest['events']
    frame['_source'] = frame.event_id.map(lambda key: metadata[key]['source_token'])
    frame['_episode'] = frame.event_id.map(lambda key: metadata[key]['episode_id'])
    frame['_scenario'] = frame.event_id.map(lambda key: metadata[key]['scenario'])
    frame['_auth_success'] = frame.event_id.map(lambda key: metadata[key]['auth_success'])
    if not all(type(metadata[key]['auth_success']) is bool for key in frame.event_id):
        raise ValueError('Synthetic outcomes must be explicit booleans.')
    frame['_time'] = pd.to_datetime(frame.event_ts_utc, utc=True)
    if not frame._time.is_monotonic_increasing:
        raise ValueError('Events must retain causal ingestion order.')
    frame['_eligible'] = [not invalid_features(row) for row in frame[FEATURES].to_dict('records')]
    return frame, manifest


def add_prior_features(frame):
    account, source = defaultdict(deque), defaultdict(deque)
    result = []
    for row in frame.to_dict('records'):
        ts = row['_time'].timestamp(); a, s = row['account_token'], row['_source']
        for queue in (account[a], source[s]):
            while queue and queue[0]['_ts'] <= ts-120:
                queue.popleft()
        result.append(prior_features(account[a], source[s], ts))
        event = {'_ts':ts, 'account_token':a, 'source_token':s,
                 'event_type':'login_success' if row['_auth_success'] else 'login_failure'}
        account[a].append(event); source[s].append(event)
    return pd.concat([frame.reset_index(drop=True), pd.DataFrame(result)], axis=1)


def audit_cohorts(cohorts, baseline_frame=None):
    report = {'overlaps': {}, 'time_gaps_seconds': {}, 'cohorts': {}}
    named = list(cohorts.items())
    if baseline_frame is not None:
        named = [('original_previously_inspected', baseline_frame), *named]
    for name, frame in named:
        report['cohorts'][name] = {'events':len(frame), 'scored_events':int(frame._eligible.sum()),
            'positive_events':int(frame.is_suspicious.sum()), 'accounts':frame.account_token.nunique(),
            'sessions':frame.session_token.nunique(), 'episodes':frame._episode.nunique()}
    for (a, left), (b, right) in itertools.combinations(named, 2):
        for key in ('event_id', 'account_token', 'session_token', '_source', '_episode'):
            overlap = len(set(left[key]) & set(right[key]))
            report['overlaps'][f'{a}:{b}:{key}'] = overlap
            if overlap:
                raise ValueError('Experiment identity/source/episode leakage.')
        gap = (right._time.min()-left._time.max()).total_seconds()
        report['time_gaps_seconds'][f'{a}:{b}'] = gap
        if gap < 120:
            raise ValueError('Experiment phase chronology overlaps.')
    return report


def baseline_frame():
    from src.models.core import load_dataset
    return load_dataset(ROOT/'data/mvp_synthetic_logins.csv', ROOT/'data/mvp_synthetic_logins.manifest.json')[0]


def audit_reference(protocol):
    frames = [baseline_frame()]
    for previous in protocol.get('previous_experiments',[]):
        path = ROOT/previous
        for spec in read_json(path/'protocol.json')['cohorts']:
            frames.append(load_cohort(path,spec['name'])[0])
    return pd.concat(frames,ignore_index=True)


def matrix(frame, variant):
    values = [vector(row, variant) for row in frame[columns(variant)].to_dict('records')]
    valid = np.array([value is not None for value in values])
    return np.array([value for value in values if value is not None], dtype=float), valid


def wilson(successes, total):
    if not total:
        return [None, None]
    z = 1.959963984540054
    p = successes/total; denominator = 1+z*z/total
    center = (p+z*z/(2*total))/denominator
    half = z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/denominator
    return [max(0., center-half), min(1., center+half)]


def binary_metrics(labels, predicted):
    labels, predicted = np.asarray(labels), np.asarray(predicted, dtype=bool)
    tn = int(((labels == 0) & ~predicted).sum()); fp = int(((labels == 0) & predicted).sum())
    fn = int(((labels == 1) & ~predicted).sum()); tp = int(((labels == 1) & predicted).sum())
    return {'confusion_matrix':[[tn,fp],[fn,tp]], 'negative_sessions':tn+fp, 'positive_sessions':tp+fn,
            'false_positive_rate': fp/(tn+fp) if tn+fp else None, 'recall':tp/(tp+fn) if tp+fn else None,
            'precision':tp/(tp+fp) if tp+fp else None,
            'fpr_wilson95':wilson(fp,tn+fp), 'recall_wilson95':wilson(tp,tp+fn)}


def meets_targets(metrics, constraint, confidence=True):
    fpr = metrics['fpr_wilson95'][1] if confidence else metrics['false_positive_rate']
    recall = metrics['recall_wilson95'][0] if confidence else metrics['recall']
    return fpr is not None and recall is not None and fpr <= constraint['max_fpr'] and recall >= constraint['min_recall']


def select_thresholds(sessions):
    valid = sessions[sessions.score.notna()]
    chosen, details = {}, {}
    for name, constraint in CONSTRAINTS.items():
        options = []
        minimum = chosen.get('mfa') or 0
        for threshold in range(minimum, 101):
            stats = binary_metrics(valid.label, valid.score >= threshold)
            if meets_targets(stats, constraint):
                options.append((stats['recall'], -stats['false_positive_rate'], threshold, stats))
        if options:
            _, _, threshold, stats = max(options, key=lambda value:value[:3])
            chosen[name] = threshold; details[name] = stats
        else:
            chosen[name] = None; details[name] = {'reason':'predeclared_constraints_infeasible'}
    return chosen, details


def ranking(frame, probabilities):
    sessions = session_values(frame, probabilities).dropna()
    labels, p = sessions.label.to_numpy(), sessions.probability.to_numpy()
    # Ranking is on tuning data only. Calibration and final thresholds use
    # later independent cohorts. This does not select holdout thresholds.
    candidates = np.unique(np.r_[0., p, 1.0000001])
    recalls = [float((p[labels==1] >= cut).mean()) for cut in candidates if (p[labels==0] >= cut).mean() <= .05]
    return {'recall_at_fpr_5pct':max(recalls, default=0.),
            'session_average_precision':float(average_precision_score(labels, p)),
            'scored_sessions':len(sessions)}


def candidate_probabilities(model, frame):
    values = [predict(model, row) for row in frame[columns(model['variant'])].to_dict('records')]
    return np.array([value['calibrated_probability'] if value else np.nan for value in values])


def fit_one(frame, variant, c, weight, protocol_hash, training_hash, identifier):
    x, valid = matrix(frame, variant)
    scaler = StandardScaler().fit(x)
    class_weight = None if weight == 'none' else 'balanced' if weight == 'balanced' else {0:1,1:3}
    estimator = LogisticRegression(C=c, class_weight=class_weight, max_iter=2000, random_state=42)
    estimator.fit(scaler.transform(x), frame.loc[valid, 'is_suspicious'].to_numpy())
    if int(estimator.n_iter_.max()) >= 2000:
        raise ValueError('Candidate failed to converge; do not silently rank it.')
    model = seal({'schema_version':'els-tuned-logistic-v1', 'synthetic_only':True, 'missing_policy':'abstain',
        'model_version':'els-tuned-v1-'+identifier, 'variant':variant, 'feature_columns':columns(variant),
        'vector_names':vector_names(variant), 'means':scaler.mean_.tolist(), 'scales':scaler.scale_.tolist(),
        'coefficients':estimator.coef_[0].tolist(), 'intercept':float(estimator.intercept_[0]),
        'calibration':{'slope':1.,'intercept':0.}, 'thresholds':{'mfa':None,'review':None},
        'training_digest':training_hash, 'protocol_digest':protocol_hash, 'C':c, 'class_weight':weight,
        'fit_events':int(valid.sum()), 'iterations':int(estimator.n_iter_.max())})
    validate(model)
    expected = estimator.predict_proba(scaler.transform(x))[:,1]
    actual = candidate_probabilities(model, frame)[valid]
    if np.max(np.abs(actual-expected)) > 1e-12:
        raise AssertionError('Portable candidate differs from sklearn.')
    return model


def calibrate(model, frame):
    results = [predict(model,row) for row in frame[columns(model['variant'])].to_dict('records')]
    valid = np.array([result is not None for result in results])
    logits = np.array([result['raw_margin'] for result in results if result is not None])
    calibration = LogisticRegression(C=1., max_iter=2000, random_state=42)
    calibration.fit(logits.reshape(-1,1), frame.loc[valid, 'is_suspicious'])
    slope = float(calibration.coef_[0,0])
    if slope <= 0 or int(calibration.n_iter_.max()) >= 2000:
        raise ValueError('Calibration cannot preserve a valid ranking.')
    model['calibration'] = {'slope':slope, 'intercept':float(calibration.intercept_[0])}
    return seal(model)


def prepare(run):
    if run.exists():
        raise ValueError('Experiment directory already exists; do not overwrite its evidence.')
    run.mkdir(parents=True)
    protocol = make_protocol(); write_json(run/'protocol.json', protocol)
    (run/'protocol.sha256').write_text(digest(protocol)+'\n')
    for spec in protocol['cohorts']:
        if not spec['name'].startswith('holdout'):
            create_cohort(run, spec)
    print('Prepared development cohorts; final holdouts have not been generated.', flush=True)


def fit(run):
    protocol = verify_protocol(run)
    if (run/'frozen.json').exists() or (run/'evaluation_started.json').exists():
        raise ValueError('This experiment is frozen or already consumed.')
    frames, manifests = {}, {}
    for spec in protocol['cohorts']:
        if not spec['name'].startswith('holdout'):
            frame, manifest = load_cohort(run, spec['name'])
            frames[spec['name']] = add_prior_features(frame); manifests[spec['name']] = manifest
    audit = audit_cohorts(frames, baseline_frame())
    candidates, scores = {}, []
    for variant, c, weight in itertools.product(protocol['variants'], protocol['C'], protocol['class_weights']):
        identifier = f'{variant}-c{c:g}-{weight}'
        model = fit_one(frames['fit'], variant, c, weight, digest(protocol), manifests['fit']['csv_sha256'], identifier)
        folds = [ranking(frames[name], candidate_probabilities(model, frames[name])) for name in ('tune_a','tune_b')]
        key = [min(f['recall_at_fpr_5pct'] for f in folds),
               sum(f['recall_at_fpr_5pct'] for f in folds)/2,
               sum(f['session_average_precision'] for f in folds)/2]
        scores.append({'id':identifier, 'variant':variant, 'C':c, 'class_weight':weight, 'rank':key, 'folds':folds})
        candidates[identifier] = model
        print('Fitted '+identifier, flush=True)
    ordered = sorted(scores, key=lambda item:(*[-v for v in item['rank']], item['id']))
    base = next(item for item in ordered if item['variant'] != 'sequence_log')
    sequence = next(item for item in ordered if item['variant'] == 'sequence_log')
    selected = {'tuned_base':base['id'], 'tuned_sequence':sequence['id']}
    winner = 'tuned_sequence' if ordered[0]['variant'] == 'sequence_log' else 'tuned_base'
    threshold_results = {}
    for name, identifier in selected.items():
        model = calibrate(candidates[identifier], frames['calibration'])
        sessions = session_values(frames['selection'], candidate_probabilities(model, frames['selection']))
        model['thresholds'], details = select_thresholds(sessions)
        seal(model); validate(model)
        write_json(run/'models'/f'{name}.json', model)
        threshold_results[name] = {'thresholds':model['thresholds'], 'selection_metrics':details,
                                   'sessions':len(sessions), 'unscored_sessions':int(sessions.score.isna().sum())}
    write_json(run/'reports/development.json', {'candidates':scores, 'selected':selected, 'winner':winner,
        'threshold_selection':threshold_results, 'split_audit':audit, 'selection_uses_holdout':False})
    files = sorted(p for folder in ('data','models','reports') for p in (run/folder).glob('*') if p.is_file())
    freeze = {'protocol_digest':digest(protocol), 'winner':winner, 'selected':selected,
        'files':{str(path.relative_to(run)):sha256_file(path) for path in files},
        'holdouts_generated':False, 'source_sha256':protocol['source_sha256']}
    write_json(run/'frozen.json', freeze)
    (run/'frozen.sha256').write_text(digest(freeze)+'\n')
    print(json.dumps({'winner':winner, 'thresholds':threshold_results}), flush=True)


def replay_runtime(frame, model, policy=None, candidate=None):
    """Exercise the actual runtime; labels are never passed to its event API."""
    from src.runtime.risk import RiskEngine
    now = [frame._time.iloc[0].timestamp()]
    engine = RiskEngine(model, policy, now=lambda:now[0], candidate=candidate)
    results = []
    for row in frame.to_dict('records'):
        now[0] = row['_time'].timestamp()
        fields = {key:None if pd.isna(row[key]) else row[key] for key in FEATURES}
        result = engine.ingest({'event_id':str(uuid.uuid5(uuid.NAMESPACE_URL, row['event_id'])),
            'event_ts_utc':row['event_ts_utc'], 'session_token':str(uuid.uuid5(uuid.NAMESPACE_URL,row['session_token'])),
            'account_token':row['account_token'], 'source_token':row['_source'],
            'event_type':'login_success' if row['_auth_success'] else 'login_failure', 'auth_method':'password',
            'features':fields, 'password_in_blocklist':None, 'password_near_blocklist':None})
        results.append(result)
    return results


def evaluate_model(frame, probabilities, thresholds, runtime_results):
    sessions = session_values(frame, probabilities)
    valid = sessions.score.notna()
    ranks = ranking(frame, probabilities)
    runtime = frame[['session_token','is_suspicious']].copy()
    runtime['action'] = [{'monitor':0,'mfa':1,'review':2}[result['action']] for result in runtime_results]
    runtime['scored'] = [result['score'] is not None for result in runtime_results]
    grouped = runtime.groupby('session_token', sort=True).agg(action=('action','max'),scored=('scored','all'),label=('is_suspicious','max'))
    if not np.array_equal(valid.to_numpy(), grouped.scored.to_numpy()):
        raise AssertionError('Offline and runtime score coverage disagree.')
    expected_scores = np.floor(probabilities*100+.5)
    actual_scores = np.array([result['score'] if result['score'] is not None else np.nan for result in runtime_results])
    if not np.allclose(expected_scores, actual_scores, equal_nan=True, atol=0, rtol=0):
        raise AssertionError('Offline and runtime feature/inference scores disagree.')
    result = {'session_ranking':ranks, 'event_calibration':calibration_quality(frame.is_suspicious, probabilities),
        'total_sessions':len(sessions), 'scored_sessions':int(valid.sum()), 'unscored_sessions':int((~valid).sum()),
        'coverage':float(valid.mean()), 'thresholds':thresholds, 'model_decisions':{}, 'runtime_scored_decisions':{},
        'runtime_all_sessions':{}, 'benign_subgroups':{}, 'offline_runtime_integer_score_parity':True}
    for name, level in (('mfa',1),('review',2)):
        threshold = thresholds[name]
        result['model_decisions'][name] = binary_metrics(sessions.loc[valid,'label'],
            np.ones(int(valid.sum()),dtype=bool) if threshold is None else sessions.loc[valid,'score'] >= threshold)
        result['runtime_scored_decisions'][name] = binary_metrics(grouped.loc[valid,'label'],grouped.loc[valid,'action'] >= level)
        result['runtime_all_sessions'][name] = binary_metrics(grouped.label,grouped.action >= level)
    for scenario in ('normal','user_error','vpn_new_device','travel_new_device','night_shift','cold_start'):
        ids = set(frame.loc[(frame._scenario==scenario) & (frame.is_suspicious==0),'session_token'])
        subset = grouped[grouped.index.isin(ids) & grouped.scored]
        result['benign_subgroups'][scenario] = {'scored_sessions':len(subset),
            **{name:binary_metrics(subset.label,subset.action>=level) for name,level in (('mfa',1),('review',2))}}
    return result


def promotion_gate(report, protocol):
    failures = []
    winner = report['winner']; targets = protocol['promotion']
    for name, cohort in report['holdouts'].items():
        model, baseline = cohort[winner], cohort['current_deployed']
        if any(value is None for value in model['thresholds'].values()):
            failures.append(name+': required threshold unavailable')
        if model['session_ranking']['session_average_precision'] < baseline['session_ranking']['session_average_precision'] + targets['min_session_ap_gain_vs_current']:
            failures.append(name+': session ranking gain below declared minimum')
        if model['event_calibration']['brier_score'] > baseline['event_calibration']['brier_score'] + targets['max_brier_regression']:
            failures.append(name+': calibration regression')
        if model['coverage'] < baseline['coverage']:
            failures.append(name+': score coverage regressed')
        for family in ('model_decisions','runtime_scored_decisions'):
            for action, constraint in protocol['constraints'].items():
                metrics = model[family][action]
                if metrics['negative_sessions'] < targets['minimum_scored_negative_sessions'] or metrics['positive_sessions'] < targets['minimum_scored_positive_sessions']:
                    failures.append(f'{name}: insufficient {family}/{action} support')
                if not meets_targets(metrics,constraint):
                    failures.append(f'{name}: {family}/{action} missed uncertainty-aware targets')
        for group, stats in model['benign_subgroups'].items():
            if group == 'cold_start':
                continue  # Explicitly unscored, included in total review workload.
            if stats['scored_sessions'] < targets['minimum_benign_subgroup_sessions']:
                failures.append(f'{name}: insufficient {group} support')
            for action, limit in targets['benign_subgroup_max_fpr'].items():
                fpr = stats[action]['false_positive_rate']
                if fpr is None or fpr > limit:
                    failures.append(f'{name}: {group}/{action} false-positive limit exceeded')
    if set(report['holdouts']) != {'holdout_a','holdout_b'}:
        failures.append('Both final cohorts are required.')
    return {'eligible_for_demo_promotion':not failures, 'failures':failures,
            'automatic_production_deployment':False,
            'uncertainty_scope':'Wilson intervals treat sessions as binomial trials; residual within-cohort correlations and common generator bias are not eliminated. Not production assurance.'}


def evaluate(run):
    protocol = verify_protocol(run); freeze = read_json(run/'frozen.json')
    if digest(freeze) != (run/'frozen.sha256').read_text().strip() or freeze['protocol_digest'] != digest(protocol):
        raise ValueError('Frozen experiment binding changed.')
    for path, expected in freeze['files'].items():
        if sha256_file(run/path) != expected:
            raise ValueError('Frozen training data, model or selection results changed.')
    if (run/'evaluation_started.json').exists():
        raise ValueError('Holdout already consumed. Do not retune on it; use a separately declared future study.')
    write_json(run/'evaluation_started.json', {'freeze_digest':digest(freeze),'holdout_use':'single_final_evaluation'})
    frames = {spec['name']:load_cohort(run,spec['name'])[0] for spec in protocol['cohorts'] if not spec['name'].startswith('holdout')}
    models = {name:validate(read_json(run/'models'/f'{name}.json')) for name in freeze['selected']}
    baseline = read_json(ROOT/'models/demo_model.json'); policy = read_json(ROOT/'models/reliability_policy.json')
    report = {'scope':'same_generator_synthetic_only', 'winner':freeze['winner'], 'freeze_digest':digest(freeze),
        'protocol_digest':digest(protocol), 'holdout_used_for_selection':False, 'holdouts':{}}
    for spec in protocol['cohorts']:
        name = spec['name']
        if not name.startswith('holdout'):
            continue
        create_cohort(run,spec); frame, _ = load_cohort(run,name); frames[name] = frame
        audit_cohorts(frames, audit_reference(protocol))
        augmented = add_prior_features(frame)
        cohort = {}
        base_results = replay_runtime(frame,baseline,policy)
        from src.models.core import predict_portable
        from src.models.calibrate_reliability import apply_calibration
        probabilities = []
        for row in frame[FEATURES].to_dict('records'):
            raw = predict_portable(baseline,row)
            probabilities.append(apply_calibration(policy,raw['probability'])['probability'] if raw else np.nan)
        cohort['current_deployed'] = evaluate_model(frame,np.array(probabilities),policy['thresholds'],base_results)
        for model_name, model in models.items():
            probabilities = candidate_probabilities(model,augmented)
            results = replay_runtime(frame,baseline,policy,candidate=model)
            cohort[model_name] = evaluate_model(frame,probabilities,model['thresholds'],results)
        report['holdouts'][name] = cohort
        print('Evaluated frozen models on '+name, flush=True)
    report['split_audit'] = audit_cohorts(frames,audit_reference(protocol))
    report['promotion'] = promotion_gate(report,protocol)
    report['artifact_sha256'] = {str(p.relative_to(run)):sha256_file(p) for p in (run/'models').glob('*.json')}
    write_json(run/'reports/final_evaluation.json',report)
    write_report(run,report)
    print(json.dumps(report['promotion']),flush=True)


def write_report(run, report):
    lines = ['# Model tuning experiment', '',
        '**Synthetic-only evaluation.** All new cohorts use the existing authored generator; independence of random draws does not establish generalization to customer traffic.', '',
        f"Frozen winner: `{report['winner']}`. Holdout labels were not used to choose it.",
        f"Demo promotion eligible: **{report['promotion']['eligible_for_demo_promotion']}**.", '',
        '| Final cohort | Model | Scored sessions / total | Session AP | Event Brier | MFA FPR / recall | Review FPR / recall |',
        '|---|---|---:|---:|---:|---:|---:|']
    def number(value):
        return 'unknown' if value is None else f'{value:.4f}'
    for cohort, models in report['holdouts'].items():
        for name, result in models.items():
            mfa, review = result['runtime_scored_decisions']['mfa'], result['runtime_scored_decisions']['review']
            lines.append(f"| {cohort} | {name} | {result['scored_sessions']} / {result['total_sessions']} | {number(result['session_ranking']['session_average_precision'])} | {number(result['event_calibration']['brier_score'])} | {number(mfa['false_positive_rate'])} / {number(mfa['recall'])} | {number(review['false_positive_rate'])} / {number(review['recall'])} |")
    lines += ['', 'FPR/recall above include the actual contextual runtime policy on fully scored sessions. Unknown sessions still require review; total-session workload, subgroup denominators, model-only metrics and Wilson intervals are reported in `reports/final_evaluation.json`.', '',
        '## Promotion checks', '']
    lines += ['- '+failure for failure in report['promotion']['failures']] or ['- All predeclared synthetic gates passed. Production approval is not implied.']
    lines += ['', 'The two final cohorts are now consumed. Repeating these seeds is reproduction, not a new blind evaluation. Do not use their results to select a runner-up or retune thresholds.', '',
        'Models, source hashes, phase assignments and targets were fixed in `protocol.json` and `frozen.json` before final cohort generation. The original CSV, baseline model, calibration policy and historical viewer were preserved.', '',
        'The new sequence variant uses ten causal prior-login features. It never reads the current outcome, target, scenario or identifier as an ML input. Shared feature extraction is exercised in offline preparation and the real runtime, with exact displayed-score parity required.', '',
        'These checks do not cover real identity-provider behavior, unrepresented attack types, production latency, missing-history resolution or independently collected customer outcomes. Wilson intervals are descriptive under a binomial-session assumption; common generator bias and residual correlations remain.', '']
    (run/'README.md').write_text('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=('prepare','fit','evaluate'))
    parser.add_argument('--run-dir',type=Path,default=DEFAULT_RUN)
    args = parser.parse_args()
    {'prepare':prepare,'fit':fit,'evaluate':evaluate}[args.stage](args.run_dir.resolve())


if __name__ == '__main__':
    main()

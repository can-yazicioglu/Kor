"""Second predeclared study after v1 failure; entirely new final cohorts.

Nonlinear candidates, subgroup-aware selection and a corroborated recovery
rule are hypotheses motivated by the now-consumed v1 experiment. Nothing from
v1 is presented as a fresh final test. Baseline production behavior is intact.
"""
from __future__ import annotations

import argparse
import itertools
import math
from pathlib import Path
import shutil

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

from . import tune as study
from .tuned_runtime import digest, seal, validate
from .tuning_features import columns, vector_names

DEFAULT_RUN = study.ROOT/'experiments/tuning_v2'


def protocol():
    p = study.make_protocol()
    p['version'] = 'els-tuning-v2'
    specs = [('fit',1001,24000,'2026-01-01'),('tune_a',1211,6000,'2026-02-01'),
             ('tune_b',1307,6000,'2026-03-01'),('calibration',1401,8000,'2026-04-01'),
             ('selection',1503,18000,'2026-05-01'),('holdout_a',1601,16000,'2026-06-01'),
             ('holdout_b',1709,16000,'2026-07-01')]
    p['cohorts'] = [dict(name=n,seed=s,rows=r,start=d+'T00:00:00Z',attack_rate=.08,namespace='v2') for n,s,r,d in specs]
    p['previous_experiments'] = ['experiments/tuning_v1']
    p['previous_evidence_use'] = 'V1 final failure motivated this new study; v1 cohorts are consumed and not final validation for v2.'
    p['variants'] = ['base_raw','sequence_log']
    p['C'] = [10.]; p['class_weights'] = ['none']
    p['boosting'] = {'n_estimators':100,'max_depth':[2,3],'min_samples_leaf':[30,100],'learning_rate':[.05,.1]}
    p['selection_objective'] = 'Worst then mean tuning-cohort session recall at <=5% overall and per-benign-subgroup FPR; then mean session AP and stable ID.'
    p['threshold_selection'] = 'Frozen integer thresholds must pass model AND runtime Wilson targets, plus tighter selection subgroup FPR margins; no fallback.'
    p['selection_subgroup_margins'] = {'mfa':.03,'review':.005}
    p['sequence_policy'] = 'corroborated_context_v3'
    p['sequence_change'] = 'Success after >=3 failures requires BOTH new/unfamiliar context AND unusual hour/velocity to recommend MFA. Other floors unchanged.'
    extra = ['src/models/tune.py','src/models/tune_followup.py','src/models/core.py',
             'src/models/calibrate_reliability.py','src/models/evaluate.py','src/runtime/insights.py']
    p['source_sha256'].update({name:study.sha256_file(study.ROOT/name) for name in extra})
    return p


def prepare(run):
    if run.exists(): raise ValueError('Do not overwrite an experiment.')
    run.mkdir(parents=True); p = protocol()
    study.write_json(run/'protocol.json',p); (run/'protocol.sha256').write_text(digest(p)+'\n')
    for name in p['source_sha256']:
        target = run/'source_snapshot'/name; target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(study.ROOT/name,target)
    for spec in p['cohorts']:
        if not spec['name'].startswith('holdout'): study.create_cohort(run,spec)
    print('Prepared v2 development cohorts. V2 final cohorts do not yet exist.',flush=True)


def fit_boosted(frame, variant, parameters, protocol_hash, training_hash, identifier):
    x, valid = study.matrix(frame,variant)
    scaler = StandardScaler().fit(x); transformed = scaler.transform(x)
    estimator = GradientBoostingClassifier(**parameters,random_state=42)
    estimator.fit(transformed,frame.loc[valid,'is_suspicious'])
    trees = []
    for fitted in estimator.estimators_[:,0]:
        tree = fitted.tree_
        trees.append({'left':tree.children_left.tolist(),'right':tree.children_right.tolist(),
            'feature':tree.feature.tolist(),'threshold':tree.threshold.tolist(),'value':tree.value[:,0,0].tolist()})
    prior = float(estimator.init_.class_prior_[1])
    model = seal({'schema_version':'els-tuned-boosted-v1','model_version':'els-tuned-v2-'+identifier,
        'synthetic_only':True,'missing_policy':'abstain','variant':variant,'feature_columns':columns(variant),
        'vector_names':vector_names(variant),'means':scaler.mean_.tolist(),'scales':scaler.scale_.tolist(),
        'intercept':math.log(prior/(1-prior)),'learning_rate':parameters['learning_rate'],'trees':trees,
        'calibration':{'slope':1.,'intercept':0.},'thresholds':{'mfa':None,'review':None},
        'training_digest':training_hash,'protocol_digest':protocol_hash,'parameters':parameters,
        'fit_events':int(valid.sum()),'sequence_policy':'corroborated_context_v3'})
    validate(model)
    error = np.max(np.abs(study.candidate_probabilities(model,frame)[valid]-estimator.predict_proba(transformed)[:,1]))
    if error > 1e-12: raise AssertionError('Portable boosted trees differ from sklearn.')
    model['portable_parity_max_probability_error'] = float(error)
    return seal(model)


def groups(frame, sessions):
    return {scenario:sessions.index.isin(set(frame.loc[(frame._scenario==scenario)&(frame.is_suspicious==0),'session_token']))
            for scenario in ('normal','user_error','vpn_new_device','travel_new_device','night_shift')}


def rank_candidate(frame, probabilities):
    sessions = study.session_values(frame,probabilities).dropna()
    masks = groups(frame,sessions)
    labels,p = sessions.label.to_numpy(),sessions.probability.to_numpy()
    best = 0.
    for cut in np.unique(np.r_[0.,p,1.0000001]):
        predictions = p >= cut
        if predictions[labels==0].mean() > .05: continue
        if any(not mask.any() or predictions[mask].mean() > .05 for mask in masks.values()): continue
        best = max(best,float(predictions[labels==1].mean()))
    return {'recall_at_fpr_5pct':best,
            'session_average_precision':float(study.average_precision_score(labels,p)), 'scored_sessions':len(sessions)}


def select_thresholds(model, frame, p):
    probabilities = study.candidate_probabilities(model,frame)
    sessions = study.session_values(frame,probabilities).dropna()
    # Replay real rules once; use floors, not the unavailable-threshold fallback.
    result = study.replay_runtime(frame,None,candidate=model)
    work = frame[['session_token']].copy()
    work['floor'] = [{'monitor':0,'mfa':1,'review':2}[r['signals']['sequence_action_floor']] for r in result]
    floor = work.groupby('session_token',sort=True)['floor'].max().reindex(sessions.index).to_numpy()
    masks = groups(frame,sessions)
    chosen,details = {},{}
    for name,level in (('mfa',1),('review',2)):
        options = []
        for threshold in range(chosen.get('mfa') or 0,101):
            predictions = sessions.score.to_numpy() >= threshold
            actual = predictions | (floor >= level)
            raw = study.binary_metrics(sessions.label,predictions); combined = study.binary_metrics(sessions.label,actual)
            if not study.meets_targets(raw,p['constraints'][name]) or not study.meets_targets(combined,p['constraints'][name]): continue
            if any(not mask.any() or actual[mask].mean() > p['selection_subgroup_margins'][name] for mask in masks.values()): continue
            options.append((raw['recall'],-combined['false_positive_rate'],threshold,raw,combined))
        if options:
            _,_,threshold,raw,combined = max(options,key=lambda value:value[:3])
            chosen[name] = threshold; details[name] = {'model':raw,'runtime':combined}
        else:
            chosen[name] = None; details[name] = {'reason':'full_policy_or_subgroup_constraints_infeasible'}
    return chosen,details


def fit(run):
    p = study.verify_protocol(run)
    if (run/'frozen.json').exists() or (run/'evaluation_started.json').exists(): raise ValueError('Experiment is frozen.')
    frames,manifests = {},{}
    for spec in p['cohorts']:
        if not spec['name'].startswith('holdout'):
            frame,manifest = study.load_cohort(run,spec['name'])
            frames[spec['name']] = study.add_prior_features(frame); manifests[spec['name']] = manifest
    audit = study.audit_cohorts(frames,study.audit_reference(p))
    models,scores = {},[]
    specifications = []
    for variant in p['variants']:
        specifications.append((variant,'logistic',{}))
        for depth,leaf,rate in itertools.product(p['boosting']['max_depth'],p['boosting']['min_samples_leaf'],p['boosting']['learning_rate']):
            specifications.append((variant,'boosted',dict(n_estimators=100,max_depth=depth,min_samples_leaf=leaf,learning_rate=rate)))
    for variant,algorithm,parameters in specifications:
        identifier = f'{variant}-{algorithm}'+('' if not parameters else f"-d{parameters['max_depth']}-l{parameters['min_samples_leaf']}-r{parameters['learning_rate']}")
        args = (frames['fit'],variant)
        if algorithm=='boosted':
            model = fit_boosted(*args,parameters,digest(p),manifests['fit']['csv_sha256'],identifier)
        else:
            model = study.fit_one(*args,10.,'none',digest(p),manifests['fit']['csv_sha256'],identifier)
            model['model_version'] = 'els-tuned-v2-'+identifier
            model['sequence_policy'] = p['sequence_policy']; seal(model)
        folds = [rank_candidate(frames[name],study.candidate_probabilities(model,frames[name])) for name in ('tune_a','tune_b')]
        rank = [min(f['recall_at_fpr_5pct'] for f in folds),sum(f['recall_at_fpr_5pct'] for f in folds)/2,
                sum(f['session_average_precision'] for f in folds)/2]
        scores.append({'id':identifier,'variant':variant,'algorithm':algorithm,'parameters':parameters,'rank':rank,'folds':folds})
        models[identifier] = model
        print('Fitted '+identifier,flush=True)
    ordered = sorted(scores,key=lambda item:(*[-v for v in item['rank']],item['id']))
    selected = {name:next(row['id'] for row in ordered if (row['variant']=='sequence_log')==sequence)
                for name,sequence in (('tuned_base',False),('tuned_sequence',True))}
    winner = 'tuned_sequence' if ordered[0]['variant']=='sequence_log' else 'tuned_base'
    details = {}
    for name,identifier in selected.items():
        model = study.calibrate(models[identifier],frames['calibration'])
        model['thresholds'],selection = select_thresholds(model,frames['selection'],p)
        seal(model); validate(model); study.write_json(run/'models'/f'{name}.json',model)
        details[name] = {'thresholds':model['thresholds'],'selection_metrics':selection}
    study.write_json(run/'reports/development.json',{'candidates':scores,'selected':selected,'winner':winner,
        'threshold_selection':details,'split_audit':audit,'selection_uses_holdout':False})
    files = sorted(path for folder in ('data','models','reports','source_snapshot') for path in (run/folder).rglob('*') if path.is_file())
    freeze = {'protocol_digest':digest(p),'winner':winner,'selected':selected,
              'files':{str(path.relative_to(run)):study.sha256_file(path) for path in files},'holdouts_generated':False}
    study.write_json(run/'frozen.json',freeze); (run/'frozen.sha256').write_text(digest(freeze)+'\n')
    print(study.json.dumps({'winner':winner,'thresholds':details}),flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=('prepare','fit','evaluate'))
    parser.add_argument('--run-dir',type=Path,default=DEFAULT_RUN)
    args = parser.parse_args()
    {'prepare':prepare,'fit':fit,'evaluate':study.evaluate}[args.stage](args.run_dir.resolve())


if __name__=='__main__': main()

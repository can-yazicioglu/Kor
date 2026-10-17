"""Feature causality and evaluation guards; no project artifacts are retrained.

A tiny in-memory tree fixture checks the sklearn-to-portable export boundary.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from src.models.core import FEATURES, predict_portable, sha256_file
from src.models.tune import (add_prior_features, audit_cohorts, binary_metrics, evaluate,
    make_protocol, matrix, promotion_gate, select_thresholds, verify_protocol, wilson, write_json)
from src.models.tuned_runtime import digest, predict, seal, validate
from src.models.tuning_features import columns, prior_features, vector, vector_names
from src.runtime.risk import RiskEngine
from test_runtime_risk import Clock, event, features

ROOT = Path(__file__).resolve().parents[1]


def candidate(variant='sequence_log'):
    size = len(vector_names(variant))
    return seal({'schema_version':'els-tuned-logistic-v1', 'model_version':'unit-candidate',
        'synthetic_only':True, 'missing_policy':'abstain', 'variant':variant,
        'feature_columns':columns(variant), 'vector_names':vector_names(variant),
        'means':[0.]*size, 'scales':[1.]*size, 'coefficients':[0.]*size, 'intercept':0.,
        'calibration':{'slope':1.,'intercept':0.}, 'thresholds':{'mfa':60,'review':90},
        'training_digest':'a'*64,'protocol_digest':'b'*64})


def frame():
    rows = []
    for i in range(4):
        rows.append({**features(attempts_2m=i+1, distinct_accounts_2m=1), 'event_id':f'e{i}',
            'account_token':'a', 'session_token':'s', '_source':'source', '_episode':'ep', '_scenario':'normal',
            '_time':pd.Timestamp('2025-03-01',tz='UTC')+pd.Timedelta(seconds=i*10),
            'is_suspicious':int(i==3), '_auth_success':i==3, '_eligible':True})
    return pd.DataFrame(rows)


class TuningFeaturesTests(unittest.TestCase):
    def test_bounded_boosted_tree_inference_and_bad_graph_rejection(self):
        model = candidate('base_raw')
        model['schema_version'] = 'els-tuned-boosted-v1'
        del model['coefficients']
        model['learning_rate'] = 1.
        model['trees'] = [{'left':[1,-1,-1],'right':[2,-1,-1],
            'feature':[0,-2,-2],'threshold':[1.5,-2.,-2.],'value':[0.,-1.,1.]}]
        seal(model); validate(model)
        self.assertEqual(predict(model,features(attempts_2m=1,distinct_accounts_2m=1))['score'],27)
        self.assertEqual(predict(model,features(attempts_2m=2,distinct_accounts_2m=1))['score'],73)
        for field,index,value in [('left',0,0),('right',0,999),('feature',0,999),('feature',1,0)]:
            bad = copy.deepcopy(model); bad['trees'][0][field][index] = value; seal(bad)
            with self.assertRaises(ValueError): validate(bad)

    def test_followup_recovery_rule_requires_both_context_signals(self):
        for variant,context,expected in (
            ('baseline_v2',features(hour_deviation=8),'mfa'),
            ('corroborated_context_v3',features(hour_deviation=8),'monitor'),
            ('corroborated_context_v3',features(hour_deviation=8,device_new=1,network_familiarity='unfamiliar'),'mfa'),
        ):
            clock = Clock(); model = candidate(); model['sequence_policy'] = variant; seal(model)
            engine = RiskEngine(now=clock,candidate=model)
            for _ in range(4):
                engine.ingest(event(clock,event_type='login_failure',features=context)); clock.advance(1)
            result = engine.ingest(event(clock,features=context))
            self.assertEqual(result['signals']['sequence_action_floor'],expected)
            self.assertEqual(result['score'],50)

    def test_boosted_export_matches_sklearn_on_training_vectors(self):
        from src.models.tune_followup import fit_boosted
        model = fit_boosted(add_prior_features(frame()),'sequence_log',
            {'n_estimators':3,'max_depth':1,'min_samples_leaf':1,'learning_rate':.1},'a'*64,'b'*64,'unit')
        self.assertLessEqual(model['portable_parity_max_probability_error'],1e-12)
        self.assertEqual(model['sequence_policy'],'corroborated_context_v3')

    def test_targets_scenarios_and_identifier_values_are_not_inputs(self):
        original = frame(); changed = original.copy()
        changed['is_suspicious'] = 1-changed.is_suspicious; changed['_scenario'] = 'different-label'
        for key in ('event_id','account_token','session_token','_source','_episode'):
            changed[key] = changed[key].map(lambda value:'renamed-'+value)
        a, _ = matrix(add_prior_features(original),'sequence_log')
        b, _ = matrix(add_prior_features(changed),'sequence_log')
        np.testing.assert_array_equal(a,b)
        self.assertFalse(set(columns('sequence_log')) & {'event_id','account_token','session_token','_source','_episode','is_suspicious','attack_type','_auth_success'})

    def test_current_outcome_and_future_events_cannot_change_current_vector(self):
        original = add_prior_features(frame())
        changed = frame(); changed.loc[1,'_auth_success'] = True
        altered = add_prior_features(changed)
        names = columns('sequence_log')
        self.assertEqual(original.loc[1,names].tolist(),altered.loc[1,names].tolist())
        self.assertNotEqual(original.loc[2,names].tolist(),altered.loc[2,names].tolist())
        prefix = add_prior_features(frame().iloc[:2])
        pd.testing.assert_frame_equal(original.iloc[:2][names],prefix[names])

    def test_window_boundary_mfa_exclusion_and_explicit_empty_support(self):
        rows = [{'_ts':t, 'event_type':kind, 'source_token':'s','account_token':'a'}
                for t,kind in ((0,'login_failure'),(1,'login_failure'),(119,'mfa_failure'),(120,'login_success'),(121,'login_failure'))]
        values = prior_features(rows,rows,120)
        self.assertEqual(values['prior_account_attempts_2m'],2)
        self.assertEqual(values['prior_account_failures_2m'],1)
        self.assertEqual(values['prior_gap_support'],1)
        self.assertEqual(values['prior_median_gap_seconds'],0)
        empty = prior_features([],[],120)
        self.assertEqual(empty['prior_account_attempts_2m'],0)
        self.assertEqual(empty['prior_source_failure_ratio_2m'],0)

    def test_candidate_allowlist_and_unknown_context_abstain(self):
        row = {**features(attempts_2m=1, distinct_accounts_2m=1),**prior_features([],[],0)}
        self.assertIsNotNone(vector(row,'sequence_log'))
        self.assertIsNone(vector({**row,'is_suspicious':1},'sequence_log'))
        self.assertIsNone(vector({**row,'hour_deviation':None},'sequence_log'))
        self.assertIsNone(vector({**row,'prior_source_failure_ratio_2m':1.1},'sequence_log'))
        self.assertIsNone(vector({**row,'prior_account_attempts_2m':float('inf')},'sequence_log'))
        self.assertIsNone(vector({**row,'prior_account_failures_2m':1},'sequence_log'))

    def test_corrupted_or_invalid_candidates_rejected_even_when_resealed(self):
        validate(candidate())
        mutations = [lambda m:m['coefficients'].append(1), lambda m:m['scales'].__setitem__(0,0),
                     lambda m:m['feature_columns'].append('account_token'),
                     lambda m:m['thresholds'].__setitem__('review',2),
                     lambda m:m['calibration'].__setitem__('slope',-1),
                     lambda m:m.__setitem__('synthetic_only',False)]
        for mutate in mutations:
            model = candidate(); mutate(model); seal(model)
            with self.assertRaises(ValueError): validate(model)
        model = candidate(); model['intercept'] = 2
        with self.assertRaises(ValueError): validate(model)

    def test_runtime_and_offline_share_prior_features_and_do_not_store_extra_history(self):
        model = candidate()
        model['coefficients'][vector_names('sequence_log').index('prior_account_failures_2m')] = 1
        seal(model)
        clock = Clock(); engine = RiskEngine(now=clock,candidate=model)
        first = event(clock,event_type='login_failure')
        result = engine.ingest(first)
        self.assertEqual(result['score'],50)
        clock.advance(1)
        second = event(clock,event_type='login_success')
        result = engine.ingest(second)
        self.assertEqual(result['score'],67)  # sigmoid(log1p(1)) = 2/3.
        self.assertEqual(result['model_version'],'unit-candidate')
        self.assertEqual(len(engine._records),2)
        self.assertEqual(set(engine._records[-1]['event']['features']),set(FEATURES))
        self.assertIsNone(engine.ingest(event(clock,features=features(hour_deviation=None)))['score'])

    def test_explicit_invalid_candidate_never_silently_uses_baseline(self):
        model = json.loads((ROOT/'models/demo_model.json').read_text())
        policy = json.loads((ROOT/'models/reliability_policy.json').read_text())
        clock = Clock(); engine = RiskEngine(model,policy,now=clock,candidate={'invalid':True})
        self.assertFalse(engine.model_ready)
        self.assertIsNone(engine.ingest(event(clock))['score'])

    def test_baseline_default_predictions_remain_unchanged(self):
        model = json.loads((ROOT/'models/demo_model.json').read_text())
        row = {k:v for k,v in features(attempts_2m=1,distinct_accounts_2m=1).items()}
        self.assertIsNotNone(predict_portable(model,row))
        self.assertEqual(len(model['feature_columns']),11)


class TuningProtocolTests(unittest.TestCase):
    def test_zero_observed_false_positives_does_not_mean_zero_uncertainty(self):
        self.assertGreater(wilson(0,100)[1],0.03)
        self.assertLess(wilson(100,100)[0],.97)
        self.assertEqual(wilson(0,0),[None,None])

    def test_thresholds_have_no_silent_fallback(self):
        sessions = pd.DataFrame({'label':[0,1],'score':[50,50]})
        thresholds,_ = select_thresholds(sessions)
        self.assertEqual(thresholds,{'mfa':None,'review':None})
        sessions = pd.DataFrame({'label':[0]*1000+[1]*200,'score':[10]*1000+[90]*200})
        thresholds,_ = select_thresholds(sessions)
        self.assertTrue(all(v is not None for v in thresholds.values()))
        self.assertGreaterEqual(thresholds['review'],thresholds['mfa'])

    def test_group_and_time_leakage_fail_before_fitting(self):
        a = frame(); b = a.copy()
        b['_time'] += pd.Timedelta(days=1)
        with self.assertRaisesRegex(ValueError,'leakage'): audit_cohorts({'a':a,'b':b})
        for name in ('event_id','account_token','session_token','_source','_episode'): b[name] = 'new-'+b[name]
        audit_cohorts({'a':a,'b':b})
        b['_time'] = a['_time']+pd.Timedelta(seconds=119)
        with self.assertRaisesRegex(ValueError,'chronology'): audit_cohorts({'a':a,'b':b})

    def test_protocol_and_holdout_consumption_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory); protocol = make_protocol()
            write_json(run/'protocol.json',protocol); (run/'protocol.sha256').write_text(digest(protocol))
            verify_protocol(run)
            frozen = {'protocol_digest':digest(protocol),'files':{}}
            write_json(run/'frozen.json',frozen); (run/'frozen.sha256').write_text(digest(frozen))
            write_json(run/'evaluation_started.json',{})
            with patch('src.models.tune.create_cohort') as create:
                with self.assertRaisesRegex(ValueError,'consumed'): evaluate(run)
                create.assert_not_called()
            protocol['C'] = [999]
            write_json(run/'protocol.json',protocol)
            with self.assertRaisesRegex(ValueError,'modified'): verify_protocol(run)

    def test_promotion_requires_both_cohorts_and_full_runtime_not_just_model(self):
        protocol = make_protocol()
        good = binary_metrics([0]*2000+[1]*200,[False]*2000+[True]*200)
        candidate_result = {'thresholds':{'mfa':60,'review':90},'coverage':.8,
            'session_ranking':{'session_average_precision':.8},'event_calibration':{'brier_score':.04},
            'model_decisions':{'mfa':copy.deepcopy(good),'review':copy.deepcopy(good)},
            'runtime_scored_decisions':{'mfa':copy.deepcopy(good),'review':copy.deepcopy(good)},
            'benign_subgroups':{name:{'scored_sessions':100,'mfa':{'false_positive_rate':0},'review':{'false_positive_rate':0}}
                               for name in ('normal','user_error','vpn_new_device','travel_new_device','night_shift')}}
        baseline = {'coverage':.8,'session_ranking':{'session_average_precision':.7},'event_calibration':{'brier_score':.05}}
        report = {'winner':'tuned_sequence','holdouts':{name:{'tuned_sequence':copy.deepcopy(candidate_result),'current_deployed':baseline}
                    for name in ('holdout_a','holdout_b')}}
        self.assertTrue(promotion_gate(report,protocol)['eligible_for_demo_promotion'])
        report['holdouts']['holdout_b']['tuned_sequence']['runtime_scored_decisions']['mfa']['fpr_wilson95'][1] = .06
        self.assertFalse(promotion_gate(report,protocol)['eligible_for_demo_promotion'])
        del report['holdouts']['holdout_b']
        self.assertFalse(promotion_gate(report,protocol)['eligible_for_demo_promotion'])


if __name__ == '__main__': unittest.main()

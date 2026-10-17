"""Descriptive rule regression on CONSUMED synthetic cohorts; no fitting.

Reports the new context rule separately from baseline review fallback. Do not
count its matches as proven attacks or advertise this as independent testing.
"""
import json
from pathlib import Path
import uuid

import pandas as pd

from .core import FEATURES, sha256_file
from .tune import load_cohort
from src.runtime.context_guard import GuardedRiskEngine, GUARD_VERSION

ROOT=Path(__file__).resolve().parents[2]


def evaluate():
    model=json.loads((ROOT/'models/demo_model.json').read_text())
    policy=json.loads((ROOT/'models/reliability_policy.json').read_text())
    report={'scope':'posthoc_consumed_synthetic_cohorts_rule_only_not_new_validation',
            'model_retrained':False,'numeric_scores_changed':False,'guard_version':GUARD_VERSION,
            'source_sha256':sha256_file(ROOT/'src/runtime/context_guard.py'),
            'limitations':['Shared authored generator and previously inspected final cohorts.',
                          'Rule alerts can include legitimate combined context changes.',
                          'Baseline fallback still recommends review; these are rule matches, not full-policy FPR.',
                          'The blocked tuned candidate is not enabled by this evaluation.'], 'cohorts':{}}
    for name in ('holdout_a','holdout_b'):
        frame,_=load_cohort(ROOT/'experiments/tuning_v2',name)
        clock=[frame._time.iloc[0].timestamp()]
        engine=GuardedRiskEngine(model,policy,now=lambda:clock[0])
        sessions={}
        for row in frame.to_dict('records'):
            clock[0]=row['_time'].timestamp()
            result=engine.ingest({'event_id':str(uuid.uuid5(uuid.NAMESPACE_URL,row['event_id'])),
                'event_ts_utc':row['event_ts_utc'],'session_token':str(uuid.uuid5(uuid.NAMESPACE_URL,row['session_token'])),
                'account_token':row['account_token'],'source_token':row['_source'],
                'event_type':'login_success' if row['_auth_success'] else 'login_failure','auth_method':'password',
                'features':{key:None if pd.isna(row[key]) else row[key] for key in FEATURES},
                'password_in_blocklist':None,'password_near_blocklist':None})
            session=sessions.setdefault(row['session_token'],{'scenario':row['_scenario'],'scored':True,'triggered':False})
            session['scored'] &= result['score'] is not None
            session['triggered'] |= result['context_guard']['triggered'] or result['context_guard']['carried']
        grouped={}
        for scenario in sorted({value['scenario'] for value in sessions.values()}):
            values=[value for value in sessions.values() if value['scenario']==scenario]
            scored=[value for value in values if value['scored']]
            triggered=sum(value['triggered'] for value in scored)
            grouped[scenario]={'all_sessions':len(values),'scored_sessions':len(scored),
                'scored_rule_matches':triggered,'scored_rule_match_rate':triggered/len(scored) if scored else None,
                'all_rule_matches':sum(value['triggered'] for value in values)}
        report['cohorts'][name]=grouped
    return report


if __name__=='__main__':
    report=evaluate()
    path=ROOT/'outputs/context_guard_regression.json'
    path.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({name:{group:values[group] for group in ('suspicious_success','vpn_new_device','travel_new_device')}
                      for name,values in report['cohorts'].items()},indent=2))

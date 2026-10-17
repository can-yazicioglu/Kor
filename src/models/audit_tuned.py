"""Descriptive attack breakdown of already-consumed final cohorts.

Never selects models/thresholds, retrains, changes a gate or calls this a new
blind test. Produces an audit supplement and a figure from the frozen release.
"""
import argparse
from pathlib import Path

import numpy as np

from . import tune as study


def audit(run):
    report = study.read_json(run/'reports/final_evaluation.json')
    frozen = study.read_json(run/'frozen.json')
    if report['winner'] != frozen['winner'] or report['freeze_digest'] != study.digest(frozen):
        raise ValueError('Final evaluation binding differs.')
    model_path = run/'models'/f"{report['winner']}.json"
    if study.sha256_file(model_path) != report['artifact_sha256'][str(model_path.relative_to(run))]:
        raise ValueError('Frozen candidate differs.')
    model = study.validate(study.read_json(model_path))
    output = {'scope':'post_evaluation_descriptive_stratification_not_new_validation',
              'model_version':model['model_version'],'thresholds':model['thresholds'],
              'candidate_sha256':study.sha256_file(model_path),
              'final_report_sha256':study.sha256_file(run/'reports/final_evaluation.json'),
              'freeze_digest':study.digest(frozen),'cohorts':{}}
    for name in report['holdouts']:
        frame,_ = study.load_cohort(run,name)
        results = study.replay_runtime(frame,None,candidate=model)
        work = frame[['session_token','is_suspicious','_scenario']].copy()
        work['action'] = [{'monitor':0,'mfa':1,'review':2}[r['action']] for r in results]
        work['scored'] = [r['score'] is not None for r in results]
        sessions = work.groupby('session_token',sort=True).agg(label=('is_suspicious','max'),
            scenario=('_scenario','first'),action=('action','max'),scored=('scored','all'))
        output['cohorts'][name] = {}
        for scenario in ('brute_force','password_spraying','suspicious_success'):
            subset = sessions[sessions.scenario==scenario]; valid = subset[subset.scored]
            output['cohorts'][name][scenario] = {'total_sessions':len(subset),'scored_sessions':len(valid),
                'unscored_sessions':len(subset)-len(valid),
                **{action:study.binary_metrics(valid.label,valid.action>=level) for action,level in (('mfa',1),('review',2))}}
    study.write_json(run/'reports/attack_breakdown.json',output)
    plot(report,run/'reports/comparison.png')
    print(study.json.dumps(output),flush=True)


def plot(report,path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes = plt.subplots(1,2,figsize=(11,4.5),layout='constrained')
    names = ['current_deployed','tuned_base','tuned_sequence']
    labels = ['Original logistic','Tuned · 11 inputs','Tuned · 21 inputs']
    colors = ['#8396a5','#4a7fa6','#226149']
    for ax,(cohort,models) in zip(axes,report['holdouts'].items()):
        values = [models[name]['session_ranking']['session_average_precision'] for name in names]
        bars = ax.bar(labels,values,color=colors,width=.62)
        ax.bar_label(bars,labels=[f'{v:.3f}' for v in values],padding=4)
        ax.set_ylim(0,1.05); ax.set_ylabel('Session average precision (AP)'); ax.set_title(cohort.replace('_',' ').title())
        ax.grid(axis='y',alpha=.2); ax.set_axisbelow(True); ax.tick_params(axis='x',labelsize=9)
    fig.suptitle('Frozen synthetic holdouts · ranking quality on fully scored sessions\nSame generator; not real-world validation',fontsize=12)
    fig.savefig(path,dpi=150); plt.close(fig)


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir',type=Path,default=study.ROOT/'experiments/tuning_v2')
    audit(parser.parse_args().run_dir.resolve())

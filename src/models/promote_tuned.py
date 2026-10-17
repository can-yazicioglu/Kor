"""Qualify a frozen synthetic candidate for an explicitly enabled local demo.

Does not replace baseline artifacts or activate trusted/customer inference.
Run only on this repository's own locally produced experiment files.
"""
from __future__ import annotations
import argparse
import math
from pathlib import Path

from .tune import ROOT, promotion_gate, read_json, sha256_file, verify_protocol, write_json
from .tuned_runtime import digest, validate


def mvp_coverage_failures(audit):
    """Post-evaluation safety safeguard, separate from predeclared statistics.

Passing aggregate targets cannot qualify a model that misses a whole required
attack scenario. This guard never chooses or retunes thresholds.
"""
    failures = []
    if set(audit.get('cohorts',{})) != {'holdout_a','holdout_b'}:
        failures.append('Both final attack breakdowns are required.')
    for cohort,groups in audit.get('cohorts',{}).items():
        for scenario in ('brute_force','password_spraying','suspicious_success'):
            stats = groups.get(scenario,{})
            recall = stats.get('mfa',{}).get('recall')
            if (type(stats.get('scored_sessions')) is not int or stats['scored_sessions'] <= 0 or
                type(recall) not in (int,float) or not math.isfinite(recall) or not 0 < recall <= 1):
                failures.append(f'{cohort}: no detected scored sessions for required scenario {scenario}')
    return failures


def promote(run, destination):
    protocol = verify_protocol(run)
    frozen = read_json(run/'frozen.json')
    report = read_json(run/'reports/final_evaluation.json')
    if (digest(frozen) != (run/'frozen.sha256').read_text().strip() or
        frozen['protocol_digest'] != digest(protocol) or report['protocol_digest'] != digest(protocol) or
        report['freeze_digest'] != digest(frozen) or report['winner'] != frozen['winner'] or
        report.get('holdout_used_for_selection') is not False):
        raise ValueError('Final report is not bound to the frozen experiment.')
    for name, expected in frozen['files'].items():
        if sha256_file(run/name) != expected:
            raise ValueError('Frozen experiment files have changed.')
    verdict = promotion_gate(report,protocol)
    if verdict != report['promotion'] or not verdict['eligible_for_demo_promotion']:
        raise ValueError('Candidate did not pass every predeclared promotion gate.')
    model_file = run/'models'/f"{frozen['winner']}.json"
    model = validate(read_json(model_file))
    if (model['protocol_digest'] != digest(protocol) or
        sha256_file(model_file) != report['artifact_sha256'][str(model_file.relative_to(run))] or
        any(value is None for value in model['thresholds'].values())):
        raise ValueError('Candidate or thresholds are not bound to the final result.')
    audit = read_json(run/'reports/attack_breakdown.json')
    if (audit.get('candidate_sha256') != sha256_file(model_file) or
        audit.get('final_report_sha256') != sha256_file(run/'reports/final_evaluation.json') or
        audit.get('freeze_digest') != digest(frozen) or audit.get('model_version') != model['model_version']):
        raise ValueError('Required scenario audit is not bound to the frozen result.')
    failures = mvp_coverage_failures(audit)
    if failures:
        raise ValueError('MVP coverage blocks promotion: '+'; '.join(failures))
    if any((destination/name).exists() for name in ('tuned_model.json','tuned_release.json')):
        raise ValueError('A tuned release already exists; do not silently replace it.')
    destination.mkdir(parents=True,exist_ok=True)
    (destination/'tuned_model.json').write_bytes(model_file.read_bytes())
    write_json(destination/'tuned_release.json',{
        'schema_version':'els-tuned-demo-release-v1','scope':'synthetic_demo_only',
        'eligible_for_demo_promotion':True,'model_version':model['model_version'],
        'model_sha256':sha256_file(model_file),'protocol_digest':digest(protocol),
        'final_report_sha256':sha256_file(run/'reports/final_evaluation.json'),
        'post_evaluation_mvp_check':'passed',
        'attack_breakdown_sha256':sha256_file(run/'reports/attack_breakdown.json'),
        'experiment':str(run.relative_to(ROOT)) if run.is_relative_to(ROOT) else run.name,
        'constraints':protocol['constraints'],
        'notice':'Checksums detect accidental edits, not authenticity. Real-world effectiveness remains unvalidated.'})
    return model['model_version']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir',type=Path,default=ROOT/'experiments/tuning_v2')
    parser.add_argument('--destination',type=Path,default=ROOT/'models')
    args = parser.parse_args()
    print('Qualified local demo release: '+promote(args.run_dir.resolve(),args.destination.resolve()))


if __name__=='__main__': main()

"""Read-only explanations over the existing, expiring event store.

Shorter windows replay three volume rules, never the two-minute ML model.
No extra history, identifiers, inferred labels or accuracy estimates are emitted.
"""
from __future__ import annotations

WINDOWS = (30, 60, 120)
VOLUME_REASONS = {
    'account_failures': 'Repeated account failures in two minutes require review.',
    'distributed_failures': 'At least five failures across three or more failing transient sources target the same account.',
    'source_spraying': 'One transient source failed against at least eight accounts, with failures comprising at least 80% of its observed login attempts.',
}


def volume_rules(failures, failed_sources, failed_accounts, source_failure_ratio, complete):
    """Shared with live policy so the lab cannot silently diverge from its rules."""
    conditions = (failures >= 8, failures >= 5 and failed_sources >= 3,
                  failed_accounts >= 8 and source_failure_ratio is not None
                  and source_failure_ratio >= .8 and complete)
    return [name for name, applies in zip(VOLUME_REASONS, conditions) if applies]


def history_sensitivity(records, started_at, event_mode, now, retention_seconds):
    if not records:
        return None
    latest = records[-1]['event']
    ts = latest['_ts']
    rows = []
    for window in WINDOWS:
        events = [r['event'] for r in records if ts-window < r['event']['_ts'] <= ts
                  and r['event']['event_type'].startswith('login_')]
        account = [e for e in events if e['account_token'] == latest['account_token']]
        source = [e for e in events if e['source_token'] == latest['source_token']]
        failed_account = [e for e in account if e['event_type'] == 'login_failure']
        failed_source = [e for e in source if e['event_type'] == 'login_failure']
        observed = event_mode == 'synthetic_demo' or ts-started_at >= window
        # An old decision may outlive part of its supporting window. Never
        # present already-evicted history as a complete replay on refresh.
        retained = max(started_at, ts-window) >= now-retention_seconds
        complete = observed and retained
        ratio = len(failed_source)/len(source) if source else None
        failed_sources = len({e['source_token'] for e in failed_account})
        failed_accounts = len({e['account_token'] for e in failed_source})
        rows.append({'window_seconds': window, 'account_attempts': len(account),
                     'account_failures': len(failed_account), 'failed_sources': failed_sources,
                     'source_failed_accounts': failed_accounts, 'source_failure_ratio': ratio,
                     'observation_complete': complete,
                     'rules': volume_rules(len(failed_account), failed_sources, failed_accounts, ratio, complete)})
    baseline = set(rows[-1]['rules'])
    for row in rows:
        row['lost_rules'] = [name for name in VOLUME_REASONS if name in baseline and name not in row['rules']]
        row['gained_rules'] = [name for name in VOLUME_REASONS if name not in baseline and name in row['rules']]
    matching = [r['window_seconds'] for r in rows if r['observation_complete'] and set(r['rules']) == baseline]
    return {'anchor': 'latest_event', 'rows': rows,
            'smallest_matching_window_seconds': min(matching) if baseline and rows[-1]['observation_complete'] and matching else None}


def _decision_values(record):
    result = record['result']
    signals = result['signals']
    return {**{name: signals[name] for name in ('attempts_2m', 'account_failures_2m',
                'distinct_failed_sources_2m', 'source_failed_accounts_2m', 'mfa_failures_2m')},
            'missing_features': len(result['data_quality']['missing_features']),
            'sequence_action_floor': signals['sequence_action_floor'],
            'verification': result['verification'],
            'credential_evidence': result['credential_risk']['evidence'],
            'outcome': record['event']['event_type']}


def decision_delta(records):
    if not records:
        return None
    latest = records[-1]
    event, result = latest['event'], latest['result']
    previous = next((r for r in reversed(records[:-1]) if
                     r['event']['account_token'] == event['account_token'] and
                     r['event']['session_token'] == event['session_token']), None)
    before = _decision_values(previous) if previous else {}
    changes = [{'field': name, 'before': before[name], 'after': value}
               for name, value in _decision_values(latest).items()
               if previous and before[name] != value]
    old = previous['result'] if previous else None
    score_delta = result['score']-old['score'] if old and old['score'] is not None and result['score'] is not None else None
    return {'has_previous': previous is not None, 'previous_score': old['score'] if old else None,
            'current_score': result['score'], 'score_delta': score_delta,
            'previous_action': old['action'] if old else None, 'current_action': result['action'],
            'basis': 'unscored_review' if result['score'] is None else
                     'threshold_unavailable_review' if not result['data_quality']['action_threshold_available'] else
                     'model_and_sequence',
            'changes': changes}


def inspect_records(records, started_at, event_mode, now, retention_seconds):
    """Aggregate view only. The caller supplies already-retained records."""
    return {'history_sensitivity': history_sensitivity(records, started_at, event_mode, now, retention_seconds),
            'decision_delta': decision_delta(records),
            'latest_event_age_seconds': max(0, now-records[-1]['event']['_ts']) if records else None,
            'inventory': {'events': len(records),
                          'review_labels': sum(r['human_label'] is not None for r in records)}}

"""Versioned candidate features; base CSV and historical model stay unchanged.

Sequence inputs use only previous observed login outcomes in (t-120,t].
Neither the current outcome, attack labels, identifiers nor future rows enter
the vector. Zero ratios mean zero observed attempts and have explicit counts.
"""
from __future__ import annotations

import math
from statistics import median

from .core import CATEGORIES, FEATURES, invalid_features

PRIOR_FEATURES = [
    'prior_account_attempts_2m', 'prior_account_failures_2m',
    'prior_account_failure_ratio_2m', 'prior_failing_sources_2m',
    'prior_source_attempts_2m', 'prior_source_failed_accounts_2m',
    'prior_source_failure_ratio_2m', 'prior_median_gap_seconds',
    'prior_burst_ratio', 'prior_gap_support',
]
VARIANTS = ('base_raw', 'base_log', 'sequence_log')
LOG_FEATURES = {'attempts_2m', 'attempts_1h', 'distinct_accounts_2m', 'geo_velocity_kmh',
                'prior_account_attempts_2m', 'prior_account_failures_2m',
                'prior_failing_sources_2m', 'prior_source_attempts_2m',
                'prior_source_failed_accounts_2m', 'prior_median_gap_seconds', 'prior_gap_support'}


def prior_features(account_events, source_events, ts):
    """Events are already ingested dictionaries; current event is not supplied."""
    account = [e for e in account_events if ts-120 < e['_ts'] <= ts and e['event_type'].startswith('login_')]
    source = [e for e in source_events if ts-120 < e['_ts'] <= ts and e['event_type'].startswith('login_')]
    failed = [e for e in account if e['event_type'] == 'login_failure']
    source_failed = [e for e in source if e['event_type'] == 'login_failure']
    gaps = [b['_ts']-a['_ts'] for a, b in zip(account, account[1:])]
    if any(gap < 0 for gap in gaps):
        raise ValueError('Prior evidence must be ordered.')
    return dict(zip(PRIOR_FEATURES, (
        len(account), len(failed), len(failed)/len(account) if account else 0.,
        len({e['source_token'] for e in failed}), len(source),
        len({e['account_token'] for e in source_failed}), len(source_failed)/len(source) if source else 0.,
        median(gaps) if len(gaps) >= 2 else 0.,
        sum(gap <= 5 for gap in gaps)/len(gaps) if len(gaps) >= 2 else 0., len(gaps))))


def columns(variant):
    if variant not in VARIANTS:
        raise ValueError('Unsupported candidate feature variant.')
    return FEATURES + (PRIOR_FEATURES if variant == 'sequence_log' else [])


def vector_names(variant):
    return [name for name in columns(variant) if name not in CATEGORIES] + [
        f'{name}={category}' for name, values in CATEGORIES.items() for category in values]


def vector(row, variant):
    if set(row) != set(columns(variant)) or invalid_features(row):
        return None
    numeric = []
    for name in columns(variant):
        if name in CATEGORIES:
            continue
        value = row[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            return None
        if name in PRIOR_FEATURES:
            if value > (1 if 'ratio' in name else 120 if name == 'prior_median_gap_seconds' else 5000):
                return None
            if name not in ('prior_account_failure_ratio_2m', 'prior_source_failure_ratio_2m',
                            'prior_median_gap_seconds', 'prior_burst_ratio') and int(value) != value:
                return None
        numeric.append(math.log1p(value) if variant != 'base_raw' and name in LOG_FEATURES else float(value))
    if variant == 'sequence_log':
        if row['prior_account_failures_2m'] > row['prior_account_attempts_2m'] or row['prior_failing_sources_2m'] > row['prior_account_failures_2m'] or row['prior_source_failed_accounts_2m'] > row['prior_source_attempts_2m']:
            return None
    return numeric + [float(row[name] == category) for name, values in CATEGORIES.items() for category in values]

"""Standard-library-only, bounded shadow risk engine.

Authentication outcomes must come from a trusted server/IdP adapter, never from
an unauthenticated browser claim. This module does not verify credentials.
"""
from __future__ import annotations

import copy
import math
import re
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from statistics import median

from src.models.core import CATEGORIES, FEATURES, predict_portable, validate_artifact
from src.runtime.insights import VOLUME_REASONS, inspect_records, volume_rules

EVENT_FIELDS = frozenset(('event_id', 'event_ts_utc', 'account_token', 'session_token',
                          'source_token', 'event_type', 'auth_method', 'features',
                          'password_in_blocklist', 'password_near_blocklist'))
EVENT_TYPES = frozenset(('login_success', 'login_failure', 'mfa_success', 'mfa_failure'))
AUTH_METHODS = frozenset(('password', 'passkey', 'totp', 'none'))
WINDOW_SECONDS = 120
RETENTION_SECONDS = 300
MAX_EVENTS = 5000
RUNTIME_POLICY_VERSION = 'els-contextual-shadow-v2'
TOKEN_PATTERNS = {'account_token': re.compile(r'^acct_[0-9a-f]{32}$'),
                  'source_token': re.compile(r'^(?:source|src)_[0-9a-f]{32}$')}
TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$')
ACTION_LABELS = {'monitor': 'Monitor in shadow mode', 'mfa': 'Recommend additional verification',
                 'review': 'Recommend human review'}
SUBGROUPS = ('vpn', 'new_device', 'unfamiliar_network', 'high_velocity', 'unusual_hour', 'missing_context')
SEQUENCE_CONTEXTS = ('shared_source_success_dominant', 'concentrated_account_failures',
                     'multisource_recovery', 'distributed_account_failures', 'failure_dominant_source')


class EventValidationError(ValueError):
    """A controlled rejection; messages contain field names, never submitted data."""


class CapacityError(EventValidationError):
    """The bounded store is full; callers should throttle rather than lose history."""


def _timestamp(value):
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise EventValidationError('event_ts_utc must be an ISO-8601 UTC timestamp ending in Z.')
    try:
        return datetime.fromisoformat(value[:-1]+'+00:00').timestamp()
    except (ValueError, OverflowError):
        raise EventValidationError('event_ts_utc must be a valid calendar time.') from None


def _uuid(value, field):
    try:
        if not isinstance(value, str) or len(value) != 36:
            raise ValueError
        parsed = uuid.UUID(value)
        if parsed.int == 0 or str(parsed) != value.lower():
            raise ValueError
        return str(parsed)
    except (ValueError, TypeError, AttributeError):
        raise EventValidationError(f'{field} must be a canonical, nonzero UUID.') from None


def _validate_features(features):
    if not isinstance(features, dict) or set(features) != set(FEATURES):
        raise EventValidationError('features must contain exactly the 11 baseline feature names.')
    result = {}
    for name in FEATURES:
        value = features[name]
        if value is None:
            result[name] = None
            continue
        if name in CATEGORIES:
            if not isinstance(value, str) or value not in CATEGORIES[name]:
                raise EventValidationError(f'{name} contains an unsupported category.')
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 9007199254740991:
                raise EventValidationError(f'{name} must be a finite, nonnegative number or null.')
            if name in ('attempts_2m', 'attempts_1h', 'distinct_accounts_2m') and int(value) != value:
                raise EventValidationError(f'{name} must be an integer or null.')
            if name in ('typical_weekday', 'device_managed', 'device_new') and value not in (0, 1):
                raise EventValidationError(f'{name} must be 0, 1 or null.')
            if name == 'failed_ratio_24h' and value > 1 or name == 'hour_deviation' and value > 12:
                raise EventValidationError(f'{name} exceeds its defined range.')
        result[name] = value
    return result


def _validate_event(event):
    if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
        raise EventValidationError('Event fields do not match the trusted event contract.')
    result = copy.deepcopy(event)
    result['event_id'] = _uuid(event['event_id'], 'event_id')
    result['session_token'] = _uuid(event['session_token'], 'session_token')
    for field, pattern in TOKEN_PATTERNS.items():
        if not isinstance(event[field], str) or not pattern.fullmatch(event[field]):
            raise EventValidationError(f'{field} must be a server-generated opaque token.')
    result['_ts'] = _timestamp(event['event_ts_utc'])
    if (not isinstance(event['event_type'],str) or not isinstance(event['auth_method'],str) or
            event['event_type'] not in EVENT_TYPES or event['auth_method'] not in AUTH_METHODS):
        raise EventValidationError('Unsupported event_type or auth_method.')
    if event['event_type'].startswith('mfa_') and event['auth_method'] not in ('totp', 'passkey'):
        raise EventValidationError('MFA events require a verified TOTP or passkey adapter.')
    if event['event_type'].startswith('login_') and event['auth_method'] not in ('password', 'passkey', 'none'):
        raise EventValidationError('Login events require password, passkey or failed unauthenticated context.')
    if event['event_type']=='login_success' and event['auth_method']=='none':
        raise EventValidationError('A successful login requires an authentication method.')
    flags = (event['password_in_blocklist'], event['password_near_blocklist'])
    if any(value is not None and (isinstance(value, bool) or not isinstance(value, int) or value not in (0,1)) for value in flags):
        raise EventValidationError('Password flags must be 0, 1 or null.')
    if flags == (1,1) or ((flags[0] is None) != (flags[1] is None)):
        raise EventValidationError('Password flags must be mutually exclusive or both unknown.')
    if event['auth_method'] != 'password' and flags != (None,None):
        raise EventValidationError('Non-password authentication must not claim password-reference results.')
    result['features'] = _validate_features(event['features'])
    return result


def validate_event(event):
    """Validate the public schema before transport; return an independent copy.

    Temporal ordering, retention, session binding and replay checks need the
    receiving engine's state and clock, so ingestion still validates them.
    """
    validated = _validate_event(event)
    del validated['_ts']
    return validated


def _subgroups(features):
    conditions = {'vpn':features['asn_category']=='vpn', 'new_device':features['device_new']==1,
        'unfamiliar_network':features['network_familiarity']=='unfamiliar',
        'high_velocity':(features['geo_velocity_kmh'] or 0)>=900,
        'unusual_hour':(features['hour_deviation'] or 0)>=4,
        'missing_context':any(value is None for value in features.values())}
    return [name for name, applies in conditions.items() if applies]


def _ratio(numerator, denominator):
    return numerator/denominator if denominator else None


def _sequence_contexts(signals):
    """Descriptive, overlapping contexts; neither outcomes nor target labels."""
    conditions = {
        'shared_source_success_dominant': signals['source_successful_accounts_2m'] >= 8
            and signals['source_failure_ratio_2m'] < 0.5,
        'concentrated_account_failures': signals['account_failures_2m'] >= 5
            and signals['distinct_failed_sources_2m'] == 1,
        'multisource_recovery': signals['success_after_failures']
            and signals['distinct_sources_2m'] >= 3 and signals['distinct_failed_sources_2m'] < 3,
        'distributed_account_failures': signals['account_failures_2m'] >= 5
            and signals['distinct_failed_sources_2m'] >= 3,
        'failure_dominant_source': signals['source_failed_accounts_2m'] >= 8
            and signals['source_failure_ratio_2m'] >= 0.8 and signals['derived_window_complete'],
    }
    return [name for name, applies in conditions.items() if applies]


class RiskEngine:
    """One configured tenant per instance; never accept tenant selectors in events."""
    def __init__(self, model=None, policy=None, now=time.time, *, event_mode='synthetic_demo', candidate=None):
        if event_mode not in ('synthetic_demo','trusted_idp'):
            raise ValueError('event_mode must be synthetic_demo or trusted_idp.')
        self.now = now
        self.event_mode = event_mode
        self.model = copy.deepcopy(model)
        self.policy = copy.deepcopy(policy)
        self.model_ready = False
        self._calibrate = None
        self._policy_action = None
        self.candidate = None
        try:
            from src.models.calibrate_reliability import apply_calibration, policy_action, validate_policy
            validate_artifact(self.model)
            validate_policy(self.policy, self.model)
            self._calibrate = apply_calibration
            self._policy_action = policy_action
            self.model_ready = True
        except (ImportError, ValueError, TypeError, KeyError, AttributeError):
            pass
        if candidate is not None:
            # Explicit candidate selection must fail closed, never silently fall
            # back to a different model. The default remains the baseline.
            from src.models.tuned_runtime import validate
            self.model_ready = False
            try:
                self.candidate = copy.deepcopy(validate(candidate))
                self.model_ready = True
            except (ValueError, TypeError):
                pass
        self.reset()

    @property
    def policy_ready(self):
        """Valid model/calibration artifacts; selected thresholds may still be absent."""
        return self.model_ready

    def _threshold_available(self, score):
        if score is None or not self.model_ready:
            return False
        thresholds = (self.candidate or self.policy)['thresholds']
        return thresholds['mfa'] is not None or (thresholds['review'] is not None and score >= thresholds['review'])

    def reset(self):
        self._records = []
        self._last_event_ts = None
        self._observation_started_at = float(self.now())

    def _retained(self, now):
        return [record for record in self._records if record['event']['_ts'] > now-RETENTION_SECONDS]

    def ingest(self, event):
        event = _validate_event(event)
        now = float(self.now())
        if not math.isfinite(now):
            raise EventValidationError('The server clock is unavailable.')
        ts = event['_ts']
        if ts <= now-RETENTION_SECONDS:
            raise EventValidationError('Event is outside the five-minute retention horizon.')
        if ts > now:
            raise EventValidationError('Future events are rejected; retry when the server clock reaches event_ts_utc.')
        if self._last_event_ts is not None and ts < self._last_event_ts:
            raise EventValidationError('Late events are rejected; ingestion timestamps must be nondecreasing.')
        records = self._retained(now)
        if any(record['event']['event_id']==event['event_id'] for record in records):
            raise EventValidationError('Duplicate event_id within the retained replay window.')
        if len(records) >= MAX_EVENTS:
            raise CapacityError('The five-minute event capacity is full; retry after expiry.')
        account, session, source = event['account_token'], event['session_token'], event['source_token']
        if any(record['event']['session_token']==session and record['event']['account_token']!=account for record in records):
            raise EventValidationError('session_token is already bound to another account within retention.')
        observed_seconds = max(0.0, min(now,ts)-self._observation_started_at)
        window_complete = self.event_mode=='synthetic_demo' or observed_seconds >= WINDOW_SECONDS
        same_session = [record for record in records if record['event']['account_token']==account and record['event']['session_token']==session]
        if event['event_type'].startswith('mfa_') and not any(record['event']['event_type']=='login_success' for record in same_session):
            raise EventValidationError('MFA evidence requires a prior successful login in the same account and session.')
        recent = [record['event'] for record in records if ts-WINDOW_SECONDS < record['event']['_ts'] <= ts]
        is_login = event['event_type'].startswith('login_')
        logins = [previous for previous in recent if previous['event_type'].startswith('login_')]
        account_prior = [previous for previous in logins if previous['account_token']==account]
        source_prior = [previous for previous in logins if previous['source_token']==source]
        account_events = account_prior + ([event] if is_login else [])
        source_events = source_prior + ([event] if is_login else [])
        prior_consecutive = 0
        for previous in reversed(account_prior):
            if previous['event_type'] != 'login_failure':
                break
            prior_consecutive += 1
        consecutive = prior_consecutive+1 if event['event_type']=='login_failure' else 0 if event['event_type']=='login_success' else prior_consecutive
        success_after = prior_consecutive if event['event_type']=='login_success' else 0
        known_hour_count = sum(record['event']['event_type'].startswith('login_') and record['event']['account_token']==account
                               and ts-3600 < record['event']['_ts'] <= ts for record in records) + int(is_login)
        features = event['features'].copy()
        features['attempts_2m'] = len(account_events) or None
        features['distinct_accounts_2m'] = len({previous['account_token'] for previous in source_events}) or None
        if features['attempts_1h'] is not None and features['attempts_1h'] < known_hour_count:
            raise EventValidationError('attempts_1h is smaller than the observed account attempt count.')
        # Trusted aggregate history is not fabricated from an incomplete five-minute stream.
        event['features'] = features
        missing = [name for name in FEATURES if features[name] is None]
        context_new = features['device_new']==1 and features['network_familiarity']=='unfamiliar'
        context_unusual = (features['hour_deviation'] or 0)>=4 or (features['geo_velocity_kmh'] or 0)>=900
        account_failed = [previous for previous in account_events if previous['event_type']=='login_failure']
        source_failed = [previous for previous in source_events if previous['event_type']=='login_failure']
        failed_sources = Counter(previous['source_token'] for previous in account_failed)
        failures = len(account_failed)
        sources = len({previous['source_token'] for previous in account_events})
        source_failures = len(source_failed)
        attempt_gaps = [current['_ts']-previous['_ts'] for previous,current in zip(account_events,account_events[1:])]
        gap_support = len(attempt_gaps)
        mfa_failures = sum(record['event']['event_type']=='mfa_failure' and ts-WINDOW_SECONDS < record['event']['_ts'] <= ts for record in same_session) + int(event['event_type']=='mfa_failure')
        signals = {'attempts_2m':len(account_events), 'distinct_accounts_2m':len({previous['account_token'] for previous in source_events}),
            'distinct_sources_2m':sources,'account_failures_2m':failures,'source_failures_2m':source_failures,
            'account_failure_ratio_2m':_ratio(failures,len(account_events)),
            'source_failure_ratio_2m':_ratio(source_failures,len(source_events)),
            'source_failed_accounts_2m':len({previous['account_token'] for previous in source_failed}),
            'source_successful_accounts_2m':len({previous['account_token'] for previous in source_events if previous['event_type']=='login_success'}),
            'distinct_failed_sources_2m':len(failed_sources),
            'account_max_failures_per_source_2m':max(failed_sources.values(),default=0),
            'median_attempt_gap_seconds':median(attempt_gaps) if gap_support>=2 else None,
            'burst_ratio':_ratio(sum(gap<=5 for gap in attempt_gaps),gap_support) if gap_support>=2 else None,
            'attempt_gap_support':gap_support,'derived_window_complete':window_complete,
            'consecutive_failures':consecutive,'success_after_failures':success_after>0,
            'prior_failures_before_success':success_after,'mfa_failures_2m':mfa_failures,
            'new_unfamiliar_context':context_new,'unusual_context':context_unusual,
            'known_attempts_1h_lower_bound':known_hour_count,'window_seconds':WINDOW_SECONDS,
            'counts_are_lower_bounds':not window_complete}
        verification = same_session[-1]['result']['verification'] if same_session else 'not_verified'
        if event['event_type']=='login_success':
            if event['auth_method']=='passkey':
                verification = 'passkey_verified'
            elif verification not in ('mfa_verified','passkey_verified'):
                verification = 'password_verified'
        elif event['event_type']=='mfa_success':
            verification = 'passkey_verified' if event['auth_method']=='passkey' else 'mfa_verified'
        base = None
        calibrated = None
        if self.model_ready and not missing and window_complete:
            try:
                if self.candidate:
                    from src.models.tuning_features import prior_features
                    from src.models.tuned_runtime import predict
                    extra = prior_features(account_prior, source_prior, ts) if self.candidate['variant'] == 'sequence_log' else {}
                    base = predict(self.candidate, {**features, **extra})
                    calibrated = {'risk_score': base['score']} if base else None
                else:
                    base = predict_portable(self.model, features)
                    calibrated = self._calibrate(self.policy, base['probability']) if base else None
            except (ValueError, TypeError, KeyError, OverflowError):
                base = calibrated = None
        score = calibrated['risk_score'] if calibrated else None
        action = 'review'
        reasons = []
        if score is not None:
            if self.candidate:
                from src.models.tuned_runtime import action as candidate_action
                selected = candidate_action(self.candidate, score)
            else:
                selected = self._policy_action(self.policy, score)
            if selected in ACTION_LABELS:
                action = selected
            if not self._threshold_available(score):
                reasons.append('No validated action threshold is available for this score; human review is required.')
            reasons.extend(base.get('reasons', []))
        else:
            if not window_complete:
                reasons.append('The trusted stream has not completed its two-minute startup observation window; rolling counts are lower bounds and risk remains unscored.')
            else:
                reasons.append('Risk is unscored because trusted context, a valid model, or calibration is unavailable; unknown is not low risk.')
        floors = [('review', VOLUME_REASONS[name]) for name in volume_rules(
            failures, len(failed_sources), signals['source_failed_accounts_2m'],
            signals['source_failure_ratio_2m'], window_complete)]
        if mfa_failures >= 3:
            floors.append(('review','Repeated step-up verification failures require review.'))
        if success_after >= 3 and (context_new or context_unusual):
            floors.append(('mfa','A successful login follows repeated failures and an unusual context.'))
        flags = (event['password_in_blocklist'],event['password_near_blocklist'])
        credential_match = 'unknown' if flags==(None,None) else 'exact' if flags[0] else 'near' if flags[1] else 'none'
        credential_evidence = ('not_password_authentication' if event['auth_method']!='password' else
                               'verified_password_weakness' if event['event_type']=='login_success' and credential_match in ('exact','near') else
                               'attempted_value_only' if event['event_type']=='login_failure' else 'no_weakness_established')
        if event['event_type']=='login_success' and credential_match in ('exact','near') and context_new and success_after >= 2:
            floors.append(('review','A verified weak-reference password follows failures from a new unfamiliar context.'))
        if event['event_type']=='login_failure' and credential_match in ('exact','near'):
            reasons.append('A weak-reference value was submitted unsuccessfully; this does not identify the account password.')
        originating_floors = list(floors) if is_login or event['event_type']=='mfa_failure' else []
        for record in same_session:
            if ts-WINDOW_SECONDS < record['event']['_ts'] <= ts:
                floors.extend(record.get('originating_floors', []))
        floors = list(dict.fromkeys(floors))
        rank = {'monitor':0,'mfa':1,'review':2}
        signals['sequence_action_floor'] = max((floor for floor,_ in floors),key=rank.get,default='monitor')
        for floor, reason in floors:
            if rank[floor] > rank[action]:
                action = floor
            reasons.append(reason)
        if verification in ('mfa_verified','passkey_verified'):
            reasons.append('Strong verification is recorded separately; existing sequence evidence and peak risk are retained.')
        previous_peaks = [record['result']['peak_score'] for record in same_session if record['result']['peak_score'] is not None]
        peak = max(previous_peaks + ([score] if score is not None else []), default=None)
        result = {'event_id':event['event_id'],'score':score,'peak_score':peak,'base_score':base['risk_score'] if base else None,
            'reasons':reasons,'action':action,'action_label':ACTION_LABELS[action],
            'data_quality':{'level':'insufficient' if score is None else 'sufficient' if self._threshold_available(score) else 'limited',
                'missing_features':missing,'feature_coverage':(len(FEATURES)-len(missing))/len(FEATURES),
                'history':{'attempts_1h':'unknown' if features['attempts_1h'] is None else 'trusted_adapter_aggregate',
                           'failed_ratio_24h':'unknown' if features['failed_ratio_24h'] is None else 'trusted_adapter_aggregate',
                           'profile':'unknown' if features['hour_deviation'] is None or features['typical_weekday'] is None else 'trusted_adapter_context',
                           'observed_retention_seconds':RETENTION_SECONDS,'complete_24h_history_observed':False,
                           'rolling_window':'complete' if window_complete else 'startup_lower_bound'},
                'observation_window_seconds':min(float(WINDOW_SECONDS),observed_seconds),
                'window_complete':window_complete,
                'window_basis':'synthetic_stream_starts_empty' if self.event_mode=='synthetic_demo' else 'ordered_trusted_stream_since_engine_reset',
                'provenance':'server_verified_contract','environment':self.event_mode,
                'model_calibration_available':self.model_ready,'action_threshold_available':self._threshold_available(score)},
            'signals':signals,
            'credential_risk':{'status':'unknown' if credential_match=='unknown' else 'checked',
                'match':credential_match,'evidence':credential_evidence,'numeric_bonus':0,
                'contextual_escalation':any('verified weak-reference' in reason for _,reason in floors),
                'scope':'Limited public-reference similarity; no account breach assertion and no safety guarantee.'},
            'verification':verification,'policy_version':self.candidate['model_version'] if self.candidate else self.policy.get('policy_version',self.policy.get('schema_version')) if self.model_ready else RUNTIME_POLICY_VERSION,
            'sequence_policy_version':RUNTIME_POLICY_VERSION,'model_version':self.candidate['model_version'] if self.candidate else self.model['model_version'] if self.model_ready else 'unavailable',
            'shadow_mode':True,'enforced':False}
        # Commit only after every validation and calculation succeeds.
        self._records = records + [{'event':event,'result':copy.deepcopy(result),'human_label':None,
            'subgroups':_subgroups(features),'sequence_contexts':_sequence_contexts(signals),
            'originating_floors':originating_floors}]
        self._last_event_ts = ts
        return result

    def inspect_latest(self):
        """Read-only, identifier-free diagnostics; never an authentication decision."""
        now = float(self.now())
        return inspect_records(self._retained(now), self._observation_started_at, self.event_mode, now, RETENTION_SECONDS)

    def feedback(self, event_id, label):
        event_id = _uuid(event_id,'event_id')
        if label not in ('normal','suspicious'):
            raise EventValidationError('Feedback label must be independently reviewed normal or suspicious.')
        records = self._retained(float(self.now()))
        matching = [record for record in records if record['event']['event_id']==event_id]
        if not matching:
            raise EventValidationError('Feedback target is missing or expired.')
        matching[0]['human_label'] = label
        self._records = records
        return self._feedback_summary(records)

    @staticmethod
    def _feedback_summary(records):
        labelled = [record for record in records if record['human_label'] is not None]
        tn=fp=fn=tp=0
        for record in labelled:
            positive = record['result']['action'] in ('mfa','review')
            suspicious = record['human_label']=='suspicious'
            tp += int(positive and suspicious);fp += int(positive and not suspicious)
            fn += int(not positive and suspicious);tn += int(not positive and not suspicious)
        return {'label_source':'independent_human_review_only','reviewed_events':len(labelled),
            'normal':tn+fp,'suspicious':tp+fn,'action_confusion_matrix':[[tn,fp],[fn,tp]],
            'false_positive_rate':_ratio(fp,tn+fp),'recall':_ratio(tp,tp+fn),'precision':_ratio(tp,tp+fp),
            'unscored_reviewed_events':sum(record['result']['score'] is None for record in labelled),
            'scope':'Retained, human-labelled events; MFA/login outcomes never become labels automatically.'}

    def snapshot(self):
        self._records = self._retained(float(self.now()))
        records = self._records
        actions = Counter(record['result']['action'] for record in records)
        outcomes = Counter(record['event']['event_type'] for record in records)
        bins = Counter()
        for record in records:
            score = record['result']['score']
            bins['unknown' if score is None else '80-100' if score>=80 else f'{score//20*20}-{score//20*20+19}'] += 1
        subgroup_stats = {}
        for name in SUBGROUPS:
            subset = [record for record in records if name in record['subgroups']]
            subgroup_stats[name] = {'events':len(subset),'alerts':sum(record['result']['action']!='monitor' for record in subset),
                'unscored':sum(record['result']['score'] is None for record in subset),
                'human_feedback':self._feedback_summary(subset)}
        sequence_stats = {}
        for name in SEQUENCE_CONTEXTS:
            subset = [record for record in records if name in record['sequence_contexts']]
            sequence_stats[name] = {'events':len(subset),
                'alerts':sum(record['result']['action']!='monitor' for record in subset),
                'sequence_alerts':sum(record['result']['signals']['sequence_action_floor']!='monitor' for record in subset),
                'unscored':sum(record['result']['score'] is None for record in subset),
                'human_feedback':self._feedback_summary(subset)}
        midpoint = len(records)//2
        halves = (records[:midpoint],records[midpoint:])
        rates = [{'events':len(part),'missing_context_rate':_ratio(sum(bool(record['result']['data_quality']['missing_features']) for record in part),len(part)),
                  'login_failure_rate':_ratio(sum(record['event']['event_type']=='login_failure' for record in part),len(part))} for part in halves]
        scored = sum(record['result']['score'] is not None for record in records)
        return {'shadow_mode':True,'enforced':False,'environment':self.event_mode,
            'retention_seconds':RETENTION_SECONDS,'capacity_events':MAX_EVENTS,'retained_events':len(records),
            'scored_events':scored,'unscored_events':len(records)-scored,'score_coverage':_ratio(scored,len(records)),
            'actions':{name:actions[name] for name in ACTION_LABELS},'alert_frequency':_ratio(actions['mfa']+actions['review'],len(records)),
            'outcomes':{name:outcomes[name] for name in sorted(EVENT_TYPES)},
            'score_bins':{name:bins[name] for name in ('0-19','20-39','40-59','60-79','80-100','unknown')},
            'subgroups':subgroup_stats,'sequence_contexts':sequence_stats,'human_feedback':self._feedback_summary(records),
            'window_comparison':{'earlier':rates[0],'later':rates[1],
                'scope':'Descriptive retained-window changes, not a validated drift detector or performance estimate.'}}

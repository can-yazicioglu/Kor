"""Fresh adversarial scenario tests; never training data or empirical accuracy claims."""
import copy
import json
import unittest
import uuid
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch

from src.models.calibrate_reliability import seal_policy
from src.runtime.risk import (CapacityError, EventValidationError, MAX_EVENTS, RiskEngine, validate_event)

ROOT=Path(__file__).resolve().parents[1]
ACCOUNT='acct_'+'a'*32
SOURCE='source_'+'b'*32


class Clock:
    def __init__(self): self.value=1780000000.
    def __call__(self): return self.value
    def advance(self,seconds): self.value+=seconds


def features(**changes):
    values={'attempts_2m':999,'attempts_1h':100,'distinct_accounts_2m':999,
            'failed_ratio_24h':0.1,'hour_deviation':0,'typical_weekday':1,
            'geo_velocity_kmh':10,'network_familiarity':'familiar','asn_category':'business',
            'device_managed':1,'device_new':0}
    values.update(changes)
    return values


def event(clock,session=None,**changes):
    values={'event_id':str(uuid.uuid4()),'event_ts_utc':datetime.fromtimestamp(clock(),timezone.utc).isoformat().replace('+00:00','Z'),
            'account_token':ACCOUNT,'session_token':session or str(uuid.uuid4()),'source_token':SOURCE,
            'event_type':'login_success','auth_method':'password','features':features(),
            'password_in_blocklist':0,'password_near_blocklist':0}
    values.update(changes)
    return values


class RuntimeRiskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model=json.loads((ROOT/'models/demo_model.json').read_text())
        cls.actual_policy=json.loads((ROOT/'models/reliability_policy.json').read_text())
        # Deliberately artificial test-only thresholds isolate sequence logic.
        # These are never exported, deployed, trained or described as validated.
        cls.test_policy=copy.deepcopy(cls.actual_policy)
        cls.test_policy['thresholds']={'mfa':99,'review':100}
        for name,threshold in cls.test_policy['thresholds'].items():
            cls.test_policy['selection'][name]['feasible']=True
            cls.test_policy['selection'][name]['score_threshold']=threshold
        seal_policy(cls.test_policy)

    def setUp(self):
        self.clock=Clock()
        self.engine=RiskEngine(self.model,self.test_policy,now=self.clock)
        self.session=str(uuid.uuid4())

    def test_normal_vpn_travel_new_device_have_no_sequence_escalation(self):
        cases=(features(asn_category='vpn',geo_velocity_kmh=4500),
               features(device_new=1,network_familiarity='unfamiliar',geo_velocity_kmh=2500,hour_deviation=8),
               features(device_new=1))
        for index,context in enumerate(cases):
            result=self.engine.ingest(event(self.clock,features=context,account_token='acct_'+f'{index+1:032x}'))
            self.assertEqual(result['signals']['sequence_action_floor'],'monitor')
            self.assertIsInstance(result['score'],int)
            self.assertTrue(result['shadow_mode']);self.assertFalse(result['enforced'])
            self.clock.advance(1)

    def test_three_wrong_passwords_do_not_make_password_claim_or_sequence_alarm(self):
        for _ in range(3):
            result=self.engine.ingest(event(self.clock,self.session,event_type='login_failure',password_in_blocklist=1))
            self.assertEqual(result['signals']['sequence_action_floor'],'monitor')
            self.assertEqual(result['credential_risk']['evidence'],'attempted_value_only')
            self.assertEqual(result['credential_risk']['numeric_bonus'],0)
            self.clock.advance(1)
        self.assertEqual(result['signals']['consecutive_failures'],3)

    def test_cold_start_stays_unknown_and_reviews(self):
        result=self.engine.ingest(event(self.clock,features=features(attempts_1h=None,failed_ratio_24h=None,hour_deviation=None,typical_weekday=None)))
        self.assertIsNone(result['score'])
        self.assertEqual(result['action'],'review')
        self.assertIn('failed_ratio_24h',result['data_quality']['missing_features'])
        self.assertEqual(result['data_quality']['history']['failed_ratio_24h'],'unknown')
        self.assertFalse(result['data_quality']['history']['complete_24h_history_observed'])

    def test_recomputed_counts_ignore_supplied_two_minute_values(self):
        first=self.engine.ingest(event(self.clock,self.session))
        self.assertEqual(first['signals']['attempts_2m'],1)
        self.assertEqual(first['signals']['distinct_accounts_2m'],1)
        self.clock.advance(1)
        second=self.engine.ingest(event(self.clock,self.session))
        self.assertEqual(second['signals']['attempts_2m'],2)
        self.assertEqual(second['signals']['distinct_accounts_2m'],1)

    def test_distributed_failures_correlate_across_cookies_and_sources(self):
        for index in range(5):
            result=self.engine.ingest(event(self.clock,event_type='login_failure',source_token='source_'+f'{index+1:032x}'))
            self.clock.advance(1)
        self.assertEqual(result['signals']['distinct_sources_2m'],5)
        self.assertEqual(result['signals']['distinct_failed_sources_2m'],5)
        self.assertEqual(result['signals']['sequence_action_floor'],'review')
        self.assertEqual(result['action'],'review')

    def test_password_spray_counts_accounts_from_shared_source(self):
        for index in range(8):
            result=self.engine.ingest(event(self.clock,event_type='login_failure',account_token='acct_'+f'{index+1:032x}'))
            self.clock.advance(1)
        self.assertEqual(result['signals']['distinct_accounts_2m'],8)
        self.assertEqual(result['signals']['attempts_2m'],1)
        self.assertEqual(result['signals']['source_failed_accounts_2m'],8)
        self.assertEqual(result['signals']['source_failure_ratio_2m'],1)
        self.assertEqual(result['signals']['sequence_action_floor'],'review')

    def test_busy_shared_office_source_does_not_turn_one_users_errors_into_spray(self):
        for index in range(20):
            self.engine.ingest(event(self.clock,account_token='acct_'+f'{index+1:032x}'))
            self.clock.advance(1)
        for _ in range(6):
            result=self.engine.ingest(event(self.clock,self.session,event_type='login_failure'))
            self.clock.advance(1)
        self.assertEqual(result['signals']['distinct_accounts_2m'],21)
        self.assertEqual(result['signals']['source_failed_accounts_2m'],1)
        self.assertEqual(result['signals']['source_successful_accounts_2m'],20)
        self.assertAlmostEqual(result['signals']['source_failure_ratio_2m'],6/26)
        self.assertEqual(result['signals']['account_max_failures_per_source_2m'],6)
        self.assertEqual(result['signals']['sequence_action_floor'],'monitor')
        contexts=self.engine.snapshot()['sequence_contexts']
        self.assertGreater(contexts['shared_source_success_dominant']['events'],0)
        self.assertEqual(contexts['shared_source_success_dominant']['sequence_alerts'],0)
        self.assertEqual(contexts['concentrated_account_failures']['events'],2)
        # Shared-source successes never whitelist repeated failures against one account.
        for _ in range(2):
            result=self.engine.ingest(event(self.clock,self.session,event_type='login_failure'))
            self.clock.advance(1)
        self.assertEqual(result['signals']['sequence_action_floor'],'review')
        self.assertTrue(any('Repeated account failures' in reason for reason in result['reasons']))
        self.assertFalse(any('eight accounts' in reason for reason in result['reasons']))

    def test_spray_requires_failed_account_breadth_and_failure_dominance(self):
        for successes,expected in ((3,'monitor'),(2,'review')):
            with self.subTest(successes=successes):
                engine=RiskEngine(self.model,self.test_policy,now=self.clock)
                for index in range(successes):
                    engine.ingest(event(self.clock,account_token='acct_'+f'{index+101:032x}'))
                for index in range(8):
                    result=engine.ingest(event(self.clock,event_type='login_failure',account_token='acct_'+f'{index+1:032x}'))
                self.assertEqual(result['signals']['source_failed_accounts_2m'],8)
                self.assertAlmostEqual(result['signals']['source_failure_ratio_2m'],8/(8+successes))
                self.assertEqual(result['signals']['sequence_action_floor'],expected)
        for index in range(7):
            self.engine.ingest(event(self.clock,event_type='login_failure',account_token='acct_'+f'{index+1:032x}'))
        repeated=self.engine.ingest(event(self.clock,event_type='login_failure',account_token='acct_'+f'{1:032x}'))
        self.assertEqual(repeated['signals']['source_failures_2m'],8)
        self.assertEqual(repeated['signals']['source_failed_accounts_2m'],7)
        self.assertEqual(repeated['signals']['sequence_action_floor'],'monitor')

    def test_successful_sources_do_not_inflate_distributed_failure_evidence(self):
        for index in range(2):
            self.engine.ingest(event(self.clock,source_token='source_'+f'{index+1:032x}'))
            self.clock.advance(1)
        for _ in range(5):
            result=self.engine.ingest(event(self.clock,self.session,event_type='login_failure'))
            self.clock.advance(1)
        self.assertEqual(result['signals']['distinct_sources_2m'],3)
        self.assertEqual(result['signals']['distinct_failed_sources_2m'],1)
        self.assertEqual(result['signals']['account_max_failures_per_source_2m'],5)
        self.assertEqual(result['signals']['sequence_action_floor'],'monitor')
        recovery=self.engine.ingest(event(self.clock,self.session,source_token='source_'+f'{3:032x}'))
        self.assertTrue(recovery['signals']['success_after_failures'])
        self.assertAlmostEqual(recovery['signals']['account_failure_ratio_2m'],5/8)
        self.assertEqual(recovery['signals']['sequence_action_floor'],'monitor')
        contexts=self.engine.snapshot()['sequence_contexts']
        self.assertEqual(contexts['multisource_recovery']['events'],1)
        self.assertEqual(contexts['distributed_account_failures']['events'],0)
        self.assertEqual(contexts['multisource_recovery']['human_feedback']['reviewed_events'],0)
        self.engine.feedback(recovery['event_id'],'normal')
        self.assertEqual(self.engine.snapshot()['sequence_contexts']['multisource_recovery']['human_feedback']['normal'],1)

    def test_source_successes_do_not_erase_distributed_failures(self):
        for index in range(12):
            self.engine.ingest(event(self.clock,account_token='acct_'+f'{index+1:032x}',
                                     source_token='source_'+f'{index%3+1:032x}'))
        for index in range(5):
            result=self.engine.ingest(event(self.clock,event_type='login_failure',source_token='source_'+f'{index%3+1:032x}'))
        self.assertLess(result['signals']['source_failure_ratio_2m'],0.8)
        self.assertEqual(result['signals']['distinct_failed_sources_2m'],3)
        self.assertEqual(result['signals']['account_failures_2m'],5)
        self.assertEqual(result['signals']['sequence_action_floor'],'review')
        self.assertEqual(self.engine.snapshot()['sequence_contexts']['distributed_account_failures']['events'],1)

    def test_gap_statistics_require_support_and_use_only_account_login_events(self):
        first=self.engine.ingest(event(self.clock,self.session,event_type='login_failure'))
        self.assertEqual(first['signals']['attempt_gap_support'],0)
        self.assertIsNone(first['signals']['median_attempt_gap_seconds'])
        self.assertIsNone(first['signals']['burst_ratio'])
        self.clock.advance(5)
        second=self.engine.ingest(event(self.clock,self.session))
        self.assertEqual(second['signals']['attempt_gap_support'],1)
        self.assertIsNone(second['signals']['median_attempt_gap_seconds'])
        self.clock.advance(10)
        third=self.engine.ingest(event(self.clock,self.session))
        self.assertEqual(third['signals']['attempt_gap_support'],2)
        self.assertEqual(third['signals']['median_attempt_gap_seconds'],7.5)
        self.assertEqual(third['signals']['burst_ratio'],0.5)
        self.assertAlmostEqual(third['signals']['account_failure_ratio_2m'],1/3)
        mfa=self.engine.ingest(event(self.clock,self.session,event_type='mfa_success',auth_method='totp',
                                   password_in_blocklist=None,password_near_blocklist=None))
        self.assertEqual(mfa['signals']['attempt_gap_support'],2)
        self.assertEqual(mfa['signals']['median_attempt_gap_seconds'],7.5)
        self.clock.advance(105)
        boundary=self.engine.ingest(event(self.clock,self.session))
        self.assertEqual(boundary['signals']['attempts_2m'],3)
        self.assertEqual(boundary['signals']['account_failure_ratio_2m'],0)
        self.assertEqual(boundary['signals']['median_attempt_gap_seconds'],57.5)
        self.assertEqual(boundary['signals']['burst_ratio'],0)

    def test_derived_ratios_are_unknown_with_no_recent_login_denominator(self):
        self.engine.ingest(event(self.clock,self.session))
        self.clock.advance(121)
        result=self.engine.ingest(event(self.clock,self.session,event_type='mfa_success',auth_method='totp',
                                      password_in_blocklist=None,password_near_blocklist=None))
        self.assertEqual(result['signals']['attempts_2m'],0)
        self.assertEqual(result['signals']['source_failed_accounts_2m'],0)
        self.assertIsNone(result['signals']['account_failure_ratio_2m'])
        self.assertIsNone(result['signals']['source_failure_ratio_2m'])
        self.assertIsNone(result['signals']['median_attempt_gap_seconds'])
        self.assertIsNone(result['signals']['burst_ratio'])

    def test_incomplete_trusted_window_does_not_use_observed_ratio_as_complete(self):
        engine=RiskEngine(self.model,self.test_policy,now=self.clock,event_mode='trusted_idp')
        for index in range(8):
            result=engine.ingest(event(self.clock,event_type='login_failure',account_token='acct_'+f'{index+1:032x}'))
        self.assertEqual(result['signals']['source_failure_ratio_2m'],1)
        self.assertFalse(result['signals']['derived_window_complete'])
        self.assertEqual(result['signals']['sequence_action_floor'],'monitor')
        self.assertIsNone(result['score'])
        self.assertEqual(result['action'],'review')

    def test_mfa_records_evidence_without_erasing_peak_or_context_review(self):
        context=features(device_new=1,network_familiarity='unfamiliar',hour_deviation=6)
        for _ in range(2):
            self.engine.ingest(event(self.clock,self.session,event_type='login_failure',features=context))
            self.clock.advance(1)
        before=self.engine.ingest(event(self.clock,self.session,features=context,password_in_blocklist=1))
        self.assertIs(before['signals']['success_after_failures'],True)
        self.assertEqual(before['signals']['prior_failures_before_success'],2)
        self.assertTrue(before['credential_risk']['contextual_escalation'])
        self.assertEqual(before['signals']['sequence_action_floor'],'review')
        self.clock.advance(1)
        after=self.engine.ingest(event(self.clock,self.session,event_type='mfa_success',auth_method='totp',features=context,
                                      password_in_blocklist=None,password_near_blocklist=None))
        self.assertEqual(after['verification'],'mfa_verified')
        self.assertGreaterEqual(after['peak_score'],before['peak_score'])
        self.assertEqual(after['signals']['sequence_action_floor'],'review')
        self.assertEqual(after['action'],'review')
        self.assertEqual(self.engine.snapshot()['human_feedback']['reviewed_events'],0)

    def test_unbound_mfa_and_cross_account_mfa_do_not_grant_verification(self):
        invalid=event(self.clock,self.session,event_type='mfa_success',auth_method='totp',password_in_blocklist=None,password_near_blocklist=None)
        with self.assertRaises(EventValidationError):self.engine.ingest(invalid)
        self.engine.ingest(event(self.clock,self.session))
        invalid['account_token']='acct_'+'c'*32
        with self.assertRaises(EventValidationError):self.engine.ingest(invalid)
        self.assertEqual(self.engine.snapshot()['retained_events'],1)

    def test_passkey_and_unrelated_failure_preserve_verification_isolation(self):
        verified=self.engine.ingest(event(self.clock,self.session,auth_method='passkey',password_in_blocklist=None,password_near_blocklist=None))
        self.assertEqual(verified['verification'],'passkey_verified')
        self.clock.advance(1)
        other=self.engine.ingest(event(self.clock,event_type='login_failure',account_token='acct_'+'d'*32))
        self.assertEqual(other['verification'],'not_verified')
        self.clock.advance(1)
        again=self.engine.ingest(event(self.clock,self.session))
        self.assertEqual(again['verification'],'passkey_verified')

    def test_session_cannot_be_reused_by_another_account_within_retention(self):
        self.engine.ingest(event(self.clock,self.session))
        before=self.engine.snapshot()
        for outcome in ('login_success','login_failure'):
            with self.assertRaisesRegex(EventValidationError,'already bound'):
                self.engine.ingest(event(self.clock,self.session,event_type=outcome,account_token='acct_'+'d'*32))
            self.assertEqual(self.engine.snapshot(),before)
        self.clock.advance(300)
        expired=self.engine.ingest(event(self.clock,self.session,event_type='login_failure',account_token='acct_'+'d'*32))
        self.assertEqual(expired['verification'],'not_verified')

    def test_public_validation_preserves_schema_and_does_not_share_mutable_inputs(self):
        original=event(self.clock,self.session)
        original['session_token']=original['session_token'].upper()
        checked=validate_event(original)
        self.assertEqual(set(checked),set(original))
        self.assertNotIn('_ts',checked)
        self.assertEqual(checked['session_token'],self.session)
        checked['features']['attempts_1h']=None
        self.assertEqual(original['features']['attempts_1h'],100)
        for name in ('password','username','ip','is_suspicious'):
            invalid=copy.deepcopy(original);invalid[name]='forbidden'
            with self.assertRaises(EventValidationError):validate_event(invalid)

    def test_120_second_left_boundary_is_excluded(self):
        self.engine.ingest(event(self.clock,self.session,event_type='login_failure'))
        self.clock.advance(119)
        inside=self.engine.ingest(event(self.clock,self.session,event_type='login_failure'))
        self.assertEqual(inside['signals']['attempts_2m'],2)
        self.clock.advance(1)
        boundary=self.engine.ingest(event(self.clock,self.session,event_type='login_failure'))
        self.assertEqual(boundary['signals']['attempts_2m'],2)
        self.assertEqual(boundary['signals']['consecutive_failures'],2)

    def test_replay_late_future_and_schema_rejections_do_not_mutate(self):
        original=event(self.clock,self.session);self.engine.ingest(original)
        snapshot=self.engine.snapshot()
        malformed=[copy.deepcopy(original)]
        late=event(self.clock);late['event_ts_utc']=datetime.fromtimestamp(self.clock()-1,timezone.utc).isoformat().replace('+00:00','Z');malformed.append(late)
        future=event(self.clock);future['event_ts_utc']=datetime.fromtimestamp(self.clock()+31,timezone.utc).isoformat().replace('+00:00','Z');malformed.append(future)
        extra=event(self.clock);extra['is_suspicious']=1;malformed.append(extra)
        leak=event(self.clock);leak['account_token']='real-user@example.invalid';malformed.append(leak)
        wrong=event(self.clock,features=features(attempts_1h=0));malformed.append(wrong)
        for item in malformed:
            with self.assertRaises(EventValidationError):self.engine.ingest(item)
            self.assertEqual(self.engine.snapshot(),snapshot)

    def test_expiry_removes_state_and_feedback_target(self):
        original=event(self.clock,self.session);self.engine.ingest(original)
        self.clock.advance(300)
        self.assertEqual(self.engine.snapshot()['retained_events'],0)
        with self.assertRaises(EventValidationError):self.engine.feedback(original['event_id'],'normal')
        with self.assertRaises(EventValidationError):self.engine.ingest(original)
        result=self.engine.ingest(event(self.clock,self.session))
        self.assertEqual(result['signals']['attempts_2m'],1)

    def test_bounded_capacity_rejects_without_silent_counter_loss(self):
        self.assertEqual(MAX_EVENTS,5000)
        with patch('src.runtime.risk.MAX_EVENTS',3):
            for _ in range(3):self.engine.ingest(event(self.clock,self.session))
            before=self.engine.snapshot()
            with self.assertRaises(CapacityError):self.engine.ingest(event(self.clock,self.session))
            self.assertEqual(self.engine.snapshot(),before)

    def test_feedback_only_human_labels_and_private_aggregate_snapshot(self):
        first=event(self.clock,self.session);self.engine.ingest(first)
        summary=self.engine.snapshot()
        self.assertEqual(summary['human_feedback']['reviewed_events'],0)
        with self.assertRaises(EventValidationError):self.engine.feedback(first['event_id'],'mfa_success')
        reviewed=self.engine.feedback(first['event_id'],'normal')
        self.assertEqual(reviewed['reviewed_events'],1)
        corrected=self.engine.feedback(first['event_id'],'suspicious')
        self.assertEqual(corrected['reviewed_events'],1)
        self.assertEqual(corrected['normal'],0)
        self.assertEqual(corrected['suspicious'],1)
        text=json.dumps(self.engine.snapshot())
        for value in (first['event_id'],first['session_token'],ACCOUNT,SOURCE):self.assertNotIn(value,text)
        self.assertIn('window_comparison',summary)
        self.assertIn('human_feedback',summary['subgroups']['vpn'])
        self.engine.reset();self.assertEqual(self.engine.snapshot()['retained_events'],0)

    def test_current_score_and_peak_are_separate_and_credentials_do_not_add_points(self):
        one=event(self.clock,self.session)
        normal=self.engine.ingest(one)
        matched_engine=RiskEngine(self.model,self.test_policy,now=self.clock)
        matched=copy.deepcopy(one);matched['password_in_blocklist']=1
        weak=matched_engine.ingest(matched)
        self.assertEqual(normal['score'],weak['score'])
        self.assertEqual(normal['base_score'],weak['base_score'])
        self.assertEqual(weak['credential_risk']['numeric_bonus'],0)
        self.assertFalse(weak['credential_risk']['contextual_escalation'])
        self.clock.advance(121)
        second=self.engine.ingest(event(self.clock,self.session,features=features(attempts_1h=100,failed_ratio_24h=None)))
        self.assertIsNone(second['score'])
        self.assertEqual(second['peak_score'],normal['peak_score'])
        self.assertEqual(second['action'],'review')

    def test_actual_infeasible_thresholds_and_corrupt_calibration_fail_closed(self):
        actual=RiskEngine(self.model,self.actual_policy,now=self.clock)
        result=actual.ingest(event(self.clock))
        self.assertTrue(actual.policy_ready)
        self.assertIsInstance(result['score'],int)
        self.assertEqual(result['action'],'review')
        self.assertEqual(result['data_quality']['level'],'limited')
        self.assertFalse(result['data_quality']['action_threshold_available'])
        broken=copy.deepcopy(self.actual_policy);broken['calibration']['slope']+=1
        corrupt=RiskEngine(self.model,broken,now=self.clock)
        self.assertFalse(corrupt.policy_ready)
        result=corrupt.ingest(event(self.clock))
        self.assertIsNone(result['score']);self.assertEqual(result['action'],'review')
        self.assertEqual(result['data_quality']['level'],'insufficient')
        self.assertEqual(result['model_version'],'unavailable')

    def test_trusted_stream_waits_full_120_seconds_before_scoring(self):
        trusted=RiskEngine(self.model,self.test_policy,now=self.clock,event_mode='trusted_idp')
        first=trusted.ingest(event(self.clock,self.session))
        self.assertIsNone(first['score'])
        self.assertEqual(first['data_quality']['level'],'insufficient')
        self.assertEqual(first['data_quality']['observation_window_seconds'],0)
        self.assertFalse(first['data_quality']['window_complete'])
        self.assertTrue(first['signals']['counts_are_lower_bounds'])
        self.assertTrue(any('startup observation window' in reason for reason in first['reasons']))
        self.clock.advance(119)
        second=trusted.ingest(event(self.clock,self.session))
        self.assertIsNone(second['score'])
        self.assertEqual(second['data_quality']['observation_window_seconds'],119)
        self.clock.advance(1)
        ready=trusted.ingest(event(self.clock,self.session))
        self.assertIsInstance(ready['score'],int)
        self.assertTrue(ready['data_quality']['window_complete'])
        self.assertEqual(ready['data_quality']['observation_window_seconds'],120)
        self.assertFalse(ready['signals']['counts_are_lower_bounds'])
        self.assertEqual(ready['signals']['attempts_2m'],2)

    def test_trusted_warmup_cannot_be_bypassed_by_future_or_backfilled_time(self):
        trusted=RiskEngine(self.model,self.test_policy,now=self.clock,event_mode='trusted_idp')
        self.clock.advance(90)
        future=event(self.clock)
        future['event_ts_utc']=datetime.fromtimestamp(self.clock()+30,timezone.utc).isoformat().replace('+00:00','Z')
        before=trusted.snapshot()
        with self.assertRaisesRegex(EventValidationError,'Future events'):
            trusted.ingest(future)
        self.assertEqual(trusted.snapshot(),before)
        result=trusted.ingest(event(self.clock))
        self.assertIsNone(result['score'])
        self.assertEqual(result['data_quality']['observation_window_seconds'],90)
        self.assertFalse(result['data_quality']['window_complete'])
        # An idle engine accepts an old but retained event without pretending it
        # observed the period before startup. Current wall time alone is insufficient.
        idle=RiskEngine(self.model,self.test_policy,now=self.clock,event_mode='trusted_idp')
        start=self.clock()
        self.clock.advance(120)
        backfilled=event(self.clock)
        backfilled['event_ts_utc']=datetime.fromtimestamp(start+119,timezone.utc).isoformat().replace('+00:00','Z')
        result=idle.ingest(backfilled)
        self.assertIsNone(result['score'])
        self.assertFalse(result['data_quality']['window_complete'])
        self.assertEqual(result['data_quality']['observation_window_seconds'],119)

    def test_tiny_future_timestamp_cannot_poison_global_ordering(self):
        original=event(self.clock,self.session)
        original['event_ts_utc']=datetime.fromtimestamp(self.clock()+0.001,timezone.utc).isoformat().replace('+00:00','Z')
        with self.assertRaisesRegex(EventValidationError,'Future events'):self.engine.ingest(original)
        present=self.engine.ingest(event(self.clock,account_token='acct_'+'c'*32))
        self.assertEqual(present['signals']['attempts_2m'],1)
        self.clock.advance(0.001)
        accepted=self.engine.ingest(original)
        self.assertEqual(accepted['event_id'],original['event_id'])
        self.assertEqual(self.engine.snapshot()['retained_events'],2)

    def test_trusted_idle_expiry_does_not_reset_warmup_but_reset_does(self):
        trusted=RiskEngine(self.model,self.test_policy,now=self.clock,event_mode='trusted_idp')
        trusted.ingest(event(self.clock,self.session))
        self.clock.advance(301)
        self.assertEqual(trusted.snapshot()['retained_events'],0)
        result=trusted.ingest(event(self.clock,self.session))
        self.assertIsInstance(result['score'],int)
        self.assertTrue(result['data_quality']['window_complete'])
        self.assertEqual(result['signals']['attempts_2m'],1)
        self.clock.advance(1)
        missing=trusted.ingest(event(self.clock,self.session,features=features(failed_ratio_24h=None,attempts_1h=None)))
        self.assertTrue(missing['data_quality']['window_complete'])
        self.assertIsNone(missing['score'])
        self.assertIn('failed_ratio_24h',missing['data_quality']['missing_features'])
        trusted.reset()
        reset=trusted.ingest(event(self.clock,self.session))
        self.assertFalse(reset['data_quality']['window_complete'])
        self.assertIsNone(reset['score'])

    def test_synthetic_stream_start_is_an_explicit_empty_history_assumption(self):
        result=self.engine.ingest(event(self.clock))
        self.assertTrue(result['data_quality']['window_complete'])
        self.assertEqual(result['data_quality']['window_basis'],'synthetic_stream_starts_empty')
        self.assertEqual(result['data_quality']['observation_window_seconds'],0)
        self.assertIsInstance(result['score'],int)


if __name__=='__main__':unittest.main()

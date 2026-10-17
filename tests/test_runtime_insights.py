"""Read-only diagnostic correctness, isolation and retention; no accuracy claims."""
import copy
import json
from pathlib import Path
import unittest
import uuid

from src.runtime.risk import RiskEngine
from src.runtime.service import APIError, RuntimeService
from test_runtime_risk import Clock, event, features

ROOT = Path(__file__).resolve().parents[1]


class RuntimeInsightTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.engine = RiskEngine(json.loads((ROOT/'models/demo_model.json').read_text()),
                                 json.loads((ROOT/'models/reliability_policy.json').read_text()), now=self.clock)
        self.session = str(uuid.uuid4())

    def add(self, **changes):
        return self.engine.ingest(event(self.clock, self.session, **changes))

    def test_half_open_window_boundaries_and_mfa_exclusion(self):
        # At t=120, exact left edges t=0/60/90 are excluded from 120/60/30.
        for advance in (0, 60, 30, 30):
            self.clock.advance(advance)
            self.add()
        self.add(event_type='mfa_success', auth_method='totp',
                 password_in_blocklist=None, password_near_blocklist=None)
        rows = self.engine.inspect_latest()['history_sensitivity']['rows']
        self.assertEqual([r['account_attempts'] for r in rows], [1, 2, 3])
        self.assertEqual(self.engine._records[-1]['result']['signals']['attempts_2m'], 3)

    def test_shorter_window_loses_old_failure_evidence(self):
        for _ in range(8):
            self.add(event_type='login_failure')
        self.clock.advance(61)
        self.add()
        history = self.engine.inspect_latest()['history_sensitivity']
        self.assertEqual(history['smallest_matching_window_seconds'], 120)
        self.assertEqual(history['rows'][0]['lost_rules'], ['account_failures'])
        self.assertEqual(history['rows'][2]['rules'], ['account_failures'])

    def test_shorter_window_can_add_spray_rule_when_successes_expire(self):
        for i in range(8):
            self.engine.ingest(event(self.clock, account_token='acct_'+f'{i+1:032x}'))
        self.clock.advance(61)
        for i in range(8):
            self.engine.ingest(event(self.clock, account_token='acct_'+f'{i+1:032x}', event_type='login_failure'))
        history = self.engine.inspect_latest()['history_sensitivity']
        self.assertEqual(history['rows'][0]['gained_rules'], ['source_spraying'])
        self.assertEqual(history['rows'][2]['source_failure_ratio'], .5)
        self.assertEqual(history['rows'][2]['rules'], [])
        self.assertIsNone(history['smallest_matching_window_seconds'])

    def test_live_volume_rules_equal_120_second_replay(self):
        for i in range(8):
            result = self.add(event_type='login_failure', source_token='source_'+f'{i+1:032x}')
        history = self.engine.inspect_latest()['history_sensitivity']
        self.assertEqual(history['rows'][2]['rules'], ['account_failures', 'distributed_failures'])
        self.assertEqual(result['signals']['sequence_action_floor'], 'review')
        self.assertEqual(history['smallest_matching_window_seconds'], 30)

    def test_trusted_startup_completeness_anchored_to_event_not_refresh(self):
        self.engine = RiskEngine(now=self.clock, event_mode='trusted_idp')
        self.clock.advance(30)
        self.add()
        self.clock.advance(120)
        history = self.engine.inspect_latest()['history_sensitivity']
        self.assertEqual([r['observation_complete'] for r in history['rows']], [True, False, False])
        self.assertIsNone(history['smallest_matching_window_seconds'])

    def test_delta_uses_same_account_session_only(self):
        self.add(event_type='login_failure')
        other = event(self.clock, account_token='acct_'+'c'*32)
        self.engine.ingest(other)
        self.assertFalse(self.engine.inspect_latest()['decision_delta']['has_previous'])
        current = self.add()
        delta = self.engine.inspect_latest()['decision_delta']
        self.assertTrue(delta['has_previous'])
        self.assertEqual(delta['current_score'], current['score'])
        outcome = next(c for c in delta['changes'] if c['field'] == 'outcome')
        self.assertEqual(outcome, {'field':'outcome', 'before':'login_failure', 'after':'login_success'})
        self.engine.ingest(event(self.clock))  # Same account, rotated session.
        self.assertFalse(self.engine.inspect_latest()['decision_delta']['has_previous'])

    def test_aged_decision_does_not_hide_evicted_supporting_history(self):
        self.engine = RiskEngine(now=self.clock, event_mode='trusted_idp')
        self.add()
        self.clock.advance(120)
        for _ in range(8):
            self.add(event_type='login_failure')
        self.clock.advance(250)
        history = self.engine.inspect_latest()['history_sensitivity']
        self.assertEqual([r['observation_complete'] for r in history['rows']], [True, False, False])
        self.assertIsNone(history['smallest_matching_window_seconds'])

    def test_unknown_delta_never_treats_missing_as_zero(self):
        self.add(features=features(hour_deviation=None))
        self.add()
        delta = self.engine.inspect_latest()['decision_delta']
        self.assertIsNone(delta['previous_score'])
        self.assertIsNone(delta['score_delta'])
        self.assertEqual(delta['basis'], 'threshold_unavailable_review')
        self.add(features=features(hour_deviation=None))
        self.assertEqual(self.engine.inspect_latest()['decision_delta']['basis'], 'unscored_review')

    def test_inspection_is_read_only_and_identifier_free(self):
        self.add()
        before = copy.deepcopy(self.engine._records)
        first = self.engine.inspect_latest()
        self.assertEqual(first, self.engine.inspect_latest())
        self.assertEqual(before, self.engine._records)
        serialized = json.dumps(first)
        for name in ('event_id', 'session_token', 'account_token', 'source_token'):
            self.assertNotIn(name, serialized)
            self.assertNotIn(before[0]['event'][name], serialized)
        first['decision_delta']['changes'].append({'fake': True})
        self.assertEqual(before, self.engine._records)

    def test_empty_expired_and_reset_state_has_no_old_evidence(self):
        self.assertIsNone(self.engine.inspect_latest()['history_sensitivity'])
        self.add()
        self.clock.advance(300)
        insight = self.engine.inspect_latest()
        self.assertEqual(insight['inventory']['events'], 0)
        self.assertIsNone(insight['decision_delta'])
        self.engine.reset()
        self.assertIsNone(self.engine.inspect_latest()['latest_event_age_seconds'])


class DemoInsightTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.service = RuntimeService(now=self.clock, rate_now=self.clock)
        self.token = self.service.demo_request('start', {})['demo_token']

    def call(self, op, **body):
        return self.service.demo_request(op, {'demo_token': self.token, **body})

    def test_inventory_refresh_does_not_extend_ttl_or_create_events(self):
        initial = self.call('status')['insights']
        self.assertEqual(initial['lifecycle']['events'], 0)
        attempt = self.call('attempt', username='demo', password='VelaDemo!42', context='familiar')
        self.assertTrue(attempt['insights']['lifecycle']['pending_mfa'])
        before = copy.deepcopy(self.service.demos[self.token]['engine']._records)
        self.clock.advance(31)
        status = self.call('status')
        self.assertEqual(status['insights']['lifecycle']['expires_in_ms'], 269000)
        self.assertEqual(status['insights']['lifecycle']['events'], 1)
        self.assertEqual(status['insights']['lifecycle']['account_mappings'], 1)
        self.assertEqual(status['insights']['latest_event_age_seconds'], 31)
        self.assertEqual(before, self.service.demos[self.token]['engine']._records)
        self.assertEqual(attempt['insights']['decision_delta'], status['insights']['decision_delta'])

    def test_feedback_inventory_mfa_expiry_and_reset(self):
        attempt = self.call('attempt', username='demo', password='VelaDemo!42', context='familiar')
        result = self.call('feedback', event_id=attempt['latest']['event_id'], label='normal')
        self.assertEqual(result['insights']['lifecycle']['review_labels'], 1)
        self.clock.advance(120)
        result = self.call('status')
        self.assertFalse(result['insights']['lifecycle']['pending_mfa'])
        self.assertIsNone(result['insights']['lifecycle']['mfa_expires_in_ms'])
        self.call('reset')
        self.assertNotIn(self.token, self.service.demos)
        with self.assertRaises(APIError) as rejected:
            self.call('status')
        self.assertEqual(rejected.exception.status, 410)

    def test_inventory_is_per_demo_and_disappears_at_deadline(self):
        self.call('simulate', kind='spray', context='familiar')
        other = self.service.demo_request('start', {})
        self.assertEqual(other['snapshot']['insights']['lifecycle']['events'], 0)
        self.assertEqual(self.call('status')['insights']['lifecycle']['events'], 18)
        self.clock.advance(300)
        with self.assertRaises(APIError):
            self.call('status')
        self.assertEqual(self.service.demos, {})
        self.assertNotIn('insights', self.service.status())


if __name__ == '__main__':
    unittest.main()

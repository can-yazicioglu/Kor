"""Independent behavioral checks for synthetic provenance and causal windows."""
import csv
import hashlib
import json
import re
import tempfile
import unittest
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.data.generate_synthetic import COLUMNS, generate_dataset, parse_utc, write_dataset


class SyntheticDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.manifest = generate_dataset(row_count=10000, attack_rate=0.08, seed=42,
                                                start=parse_utc('2025-01-01T00:00:00Z'))

    def test_fixed_schema_cardinality_and_class_counts(self):
        self.assertEqual(len(self.rows), 10000)
        self.assertEqual(sum(row['is_suspicious'] for row in self.rows), 800)
        self.assertTrue(all(list(row) == COLUMNS for row in self.rows))
        self.assertEqual(len({row['event_id'] for row in self.rows}), 10000)
        self.assertEqual(set(self.manifest['events']), {row['event_id'] for row in self.rows})

    def test_counters_recomputed_without_generator_rolling_logic(self):
        accounts = defaultdict(list)
        sources = defaultdict(list)
        for row in self.rows:
            ts = parse_utc(row['event_ts_utc'])
            account = row['account_token']
            source = self.manifest['events'][row['event_id']]['source_token']
            accounts[account].append(ts)
            sources[source].append((ts, account))
            expected_2m = sum(ts-timedelta(seconds=120) < value <= ts for value in accounts[account])
            expected_1h = sum(ts-timedelta(hours=1) < value <= ts for value in accounts[account])
            expected_accounts = {value for when, value in sources[source] if ts-timedelta(seconds=120) < when <= ts}
            self.assertEqual(row['attempts_2m'], expected_2m)
            self.assertEqual(row['attempts_1h'], expected_1h)
            self.assertEqual(row['distinct_accounts_2m'], len(expected_accounts))
            self.assertLessEqual(row['attempts_2m'], row['attempts_1h'])

    def test_failure_ratio_excludes_current_and_future_outcomes(self):
        outcomes = defaultdict(list)
        for event in self.manifest['warmup_events']:
            outcomes[event['account_token']].append((parse_utc(event['event_ts_utc']), event['auth_success']))
        for row in self.rows:
            ts = parse_utc(row['event_ts_utc'])
            account = row['account_token']
            prior = [success for when, success in outcomes[account] if ts-timedelta(hours=24) < when <= ts]
            expected = round(sum(not success for success in prior) / len(prior), 6) if prior else None
            self.assertEqual(row['failed_ratio_24h'], expected)
            outcomes[account].append((ts, self.manifest['events'][row['event_id']]['auth_success']))

    def test_splits_account_episode_source_session_disjoint_and_chronological(self):
        groups = {split: {name: set() for name in ('accounts', 'episodes', 'sources', 'sessions', 'times')}
                  for split in ('fit', 'validation', 'test')}
        for row in self.rows:
            event = self.manifest['events'][row['event_id']]
            split = groups[event['split']]
            for name, value in [('accounts', row['account_token']), ('sessions', row['session_token']),
                                ('episodes', event['episode_id']), ('sources', event['source_token']),
                                ('times', parse_utc(row['event_ts_utc']))]:
                split[name].add(value)
        order = ['fit', 'validation', 'test']
        for index, split in enumerate(order):
            for later in order[index+1:]:
                for name in ('accounts', 'episodes', 'sources', 'sessions'):
                    self.assertFalse(groups[split][name] & groups[later][name])
                self.assertLess(max(groups[split]['times']) + timedelta(seconds=120), min(groups[later]['times']))

    def test_multiple_events_per_session_and_ephemeral_source_lifetimes(self):
        session_events = defaultdict(list)
        source_events = defaultdict(list)
        session_accounts = defaultdict(set)
        for row in self.rows:
            session_events[row['session_token']].append(parse_utc(row['event_ts_utc']))
            source_events[self.manifest['events'][row['event_id']]['source_token']].append(parse_utc(row['event_ts_utc']))
            session_accounts[row['session_token']].add(row['account_token'])
        self.assertGreater(sum(len(events)>1 for events in session_events.values()), 1000)
        for events in list(session_events.values()) + list(source_events.values()):
            self.assertLess((max(events)-min(events)).total_seconds(), 120)
        self.assertTrue(all(len(accounts)==1 for accounts in session_accounts.values()))
        spray = [row for row in self.rows if row['attack_type']=='password_spraying']
        self.assertTrue(any(row['distinct_accounts_2m']>=8 for row in spray))

    def test_hard_benign_controls_and_positive_scenarios_exist_in_each_split(self):
        for split in ('fit', 'validation', 'test'):
            records = [row for row in self.rows if self.manifest['events'][row['event_id']]['split']==split]
            scenarios = {row['attack_type'] for row in records}
            self.assertEqual(scenarios, {'normal', 'user_error', 'vpn_new_device', 'travel_new_device', 'night_shift',
                                         'cold_start', 'brute_force', 'password_spraying', 'suspicious_success'})
            for scenario in ('normal','user_error','vpn_new_device','travel_new_device','night_shift',
                             'brute_force','password_spraying','suspicious_success'):
                complete = [row for row in records if row['attack_type']==scenario and all(row[name] is not None for name in COLUMNS[4:15])]
                self.assertGreater(len(complete), 5, (split,scenario))
            benign = [row for row in records if not row['is_suspicious']]
            self.assertTrue(any((row['geo_velocity_kmh'] or 0)>2000 for row in benign))
            self.assertTrue(any((row['hour_deviation'] or 0)>8 for row in benign))
            self.assertTrue(any(row['attack_type']=='cold_start' and row['hour_deviation'] is None for row in benign))

    def test_auth_success_ground_truth_and_feature_ranges(self):
        for row in self.rows:
            meta = self.manifest['events'][row['event_id']]
            if row['attack_type']=='suspicious_success':
                self.assertTrue(meta['auth_success'])
            self.assertNotIn('auth_success', row)
            self.assertNotIn('source_token', row)
            self.assertIn(row['network_familiarity'], ('familiar','unfamiliar',None))
            self.assertIn(row['asn_category'], ('residential','business','cloud','vpn','unknown'))
            self.assertTrue(row['hour_deviation'] is None or 0<=row['hour_deviation']<=12)
            self.assertTrue(row['failed_ratio_24h'] is None or 0<=row['failed_ratio_24h']<=1)
            for field in ('typical_weekday','device_managed','device_new'):
                self.assertIn(row[field], (0,1,None))

    def test_reproducible_different_seed_and_edge_sizes(self):
        options = dict(row_count=123, attack_rate=0.17, seed=20261017, start=parse_utc('2025-01-01T00:00:00Z'))
        first = generate_dataset(**options)
        self.assertEqual(first, generate_dataset(**options))
        self.assertNotEqual(first, generate_dataset(**{**options,'seed':1}))
        for count in (1,2,3,13):
            for rate in (0,0.08,1):
                rows, manifest = generate_dataset(row_count=count,attack_rate=rate,seed=1,start=options['start'])
                self.assertEqual(len(rows),count)
                self.assertEqual(sum(row['is_suspicious'] for row in rows),round(count*rate))

    def test_csv_roundtrip_digest_and_manifest_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            output, sidecar = write_dataset(self.rows,self.manifest.copy(),Path(directory)/'events.csv')
            manifest = json.loads(sidecar.read_text())
            self.assertEqual(manifest['csv_sha256'],hashlib.sha256(output.read_bytes()).hexdigest())
            with output.open(newline='') as handle:
                reader = csv.DictReader(handle)
                self.assertEqual(reader.fieldnames,COLUMNS)
                restored = list(reader)
            self.assertEqual(len(restored),10000)
            self.assertTrue(any(row['hour_deviation']=='' for row in restored))
            with self.assertRaises(ValueError):
                write_dataset(self.rows,self.manifest.copy(),output,output)

    def test_privacy_and_explicit_synthetic_provenance(self):
        self.assertTrue(self.manifest['synthetic'])
        for row in self.rows:
            self.assertRegex(row['event_id'],r'^evt_\d{8}$')
            self.assertRegex(row['session_token'],r'^ses_[0-9a-f]{32}$')
            self.assertRegex(row['account_token'],r'^acct_[0-9a-f]{32}$')
        forbidden_fields = {'ip','ip_address','password','username','email','fingerprint','mouse','keyboard'}
        self.assertFalse(set(COLUMNS) & forbidden_fields)
        self.assertTrue(all(profile['synthetic'] for profile in self.manifest['profiles'].values()))
        text=json.dumps(self.rows)
        self.assertIsNone(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text))
        self.assertIsNone(re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',text))

    def test_invalid_arguments_fail(self):
        for rows,rate in ((0,0.08),(-1,0.08),(20,-0.1),(20,1.1),(20,float('nan'))):
            with self.assertRaises(ValueError):
                generate_dataset(row_count=rows,attack_rate=rate,seed=42,start=parse_utc('2025-01-01T00:00:00Z'))
        with self.assertRaises(ValueError):
            generate_dataset(row_count=10,attack_rate=0.08,seed=42,start=datetime(2025,1,1))

    def test_non_midnight_start_never_reads_future_baseline_or_warmup(self):
        start=parse_utc('2025-01-01T13:45:00Z')
        rows, manifest=generate_dataset(row_count=1500,attack_rate=0.08,seed=42,start=start)
        first_by_account={}
        for row in rows:
            when=parse_utc(row['event_ts_utc'])
            account=row['account_token']
            first_by_account.setdefault(account,when)
            profile=manifest['profiles'][account]
            split_index=manifest['split_order'].index(profile['split'])
            self.assertGreaterEqual(when,start+timedelta(days=10*split_index))
            if profile['baseline_end_utc']:
                self.assertLess(parse_utc(profile['baseline_end_utc']),when)
        for event in manifest['warmup_events']:
            first=first_by_account.get(event['account_token'])
            if first:
                self.assertLess(parse_utc(event['event_ts_utc']),first-timedelta(hours=1))


if __name__=='__main__':
    unittest.main()

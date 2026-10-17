"""Offline checks for local reference matching and the versioned flag extension."""
import copy
import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.data.extend_password_flags import V2_COLUMNS, extend_dataset
from src.data.generate_synthetic import COLUMNS
from src.security.build_password_reference import build_reference, parse_public_entries
from src.security.password_check import (MAX_CANDIDATES, PasswordChecker, edit_candidates,
                                        normalize, seal_reference, validate_reference)

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'data/mvp_synthetic_logins.csv'
MANIFEST=ROOT/'data/mvp_synthetic_logins.manifest.json'
BASE_HASH='41383a34524cefb434a66608c74a6554bada4377968298c6d7b7a43e4168b625'
# Intentionally invented unit fixtures, never credentials or imported dictionary rows.
FIXTURES=['sentinelunit','novemberwidget','unitanchor','cobaltunit','abcd']
SOURCES=[{'name':'invented-unit-fixture','sha256':'0'*64,'entry_count':len(FIXTURES),
          'path':'synthetic-fixture','license':'test-only','url':'not-a-network-source'}]


class PasswordReferenceTests(unittest.TestCase):
    def setUp(self):
        self.artifact=build_reference(FIXTURES,SOURCES)
        self.checker=PasswordChecker(self.artifact)

    def test_exact_raw_utf8_has_priority_and_exclusive_flags(self):
        answer=self.checker.check(FIXTURES[0])
        self.assertEqual(answer,{'status':'checked','password_in_blocklist':1,
                                'password_near_blocklist':0,'match_type':'exact','bonus':25})

    def test_nfkc_case_and_leet_near_match(self):
        for value in ('ＳＥＮＴＩＮＥＬＵＮＩＴ','SENTINELUNIT','s3nt1n3lun1t'):
            result=self.checker.check(value)
            self.assertEqual(result['match_type'],'normalized')
            self.assertEqual(result['bonus'],10)
            self.assertEqual(result['password_in_blocklist'],0)
        self.assertEqual(normalize('4@01!|35$7+'),'aao iiiesstt'.replace(' ',''))

    def test_suffix_uses_raw_value_and_bounded_tail(self):
        self.assertEqual(self.checker.check('sentinelunit2026')['match_type'],'suffix')
        self.assertEqual(self.checker.check('unitanchor!23')['match_type'],'suffix')
        checker=PasswordChecker(build_reference(['ab'],SOURCES))
        self.assertEqual(checker.check('ab2026')['match_type'],'none')

    def test_single_edit_variants_are_checked(self):
        for value in ('sentineluni','sentinelunitz','sentinelunix','sentienlunit'):
            self.assertEqual(self.checker.check(value)['match_type'],'single_edit')

    def test_single_edit_boundaries_and_candidate_budget(self):
        self.assertEqual(list(edit_candidates('short')),[])
        self.assertEqual(list(edit_candidates('a'*33)),[])
        self.assertEqual(list(edit_candidates('emoji🙂unit')),[])
        values=list(edit_candidates('abcdefghijklmnopqrstuvwxyzabcdef'))
        self.assertLessEqual(len(values),MAX_CANDIDATES)
        self.assertEqual(len(values),len(set(values)))
        self.assertEqual(values,list(edit_candidates('abcdefghijklmnopqrstuvwxyzabcdef')))

    def test_non_match_is_limited_lookup_result_not_safety_status(self):
        value='els-test-'+('d41f'*12)
        answer=self.checker.check(value)
        self.assertEqual(answer['match_type'],'none')
        self.assertEqual(answer['bonus'],0)
        self.assertNotIn('safe',answer)

    def test_invalid_input_or_reference_remains_unknown(self):
        for value in ('',None,123,'x'*257,'\ud800'):
            self.assertEqual(self.checker.check(value)['status'],'unknown')
        answer=PasswordChecker(None).check(FIXTURES[0])
        self.assertIsNone(answer['password_in_blocklist'])
        self.assertIsNone(answer['password_near_blocklist'])
        self.assertIsNone(answer['bonus'])

    def test_integrity_and_algorithm_corruption_fail_closed(self):
        for mutate in (lambda a:a['exact_sha256'].pop(),lambda a:a.update(artifact_integrity=7),
                       lambda a:a['normalization'].update(max_candidates=99999),
                       lambda a:a.update(sources=[])):
            artifact=copy.deepcopy(self.artifact);mutate(artifact)
            self.assertFalse(PasswordChecker(artifact).ready)
            self.assertEqual(PasswordChecker(artifact).check(FIXTURES[0])['status'],'unknown')

    def test_reference_loader_rejects_missing_bad_or_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'reference.json'
            self.assertFalse(PasswordChecker.from_file(path).ready)
            path.write_text('{broken')
            self.assertFalse(PasswordChecker.from_file(path).ready)
            path.write_bytes(b' '*(4*1024*1024+1))
            self.assertFalse(PasswordChecker.from_file(path).ready)

    def test_public_parser_excludes_record_like_values(self):
        payload=b'inventedunit\nunit@example.invalid\nuser:secret\n127.0.0.1\ncontrol\tvalue\n\n'
        entries,excluded=parse_public_entries(payload)
        self.assertEqual(entries,['inventedunit'])
        self.assertEqual(excluded,5)

    def test_delivered_reference_integrity_and_provenance(self):
        path=ROOT/'data/password_reference.json'
        artifact=validate_reference(json.loads(path.read_text()))
        self.assertLess(path.stat().st_size,4*1024*1024)
        self.assertEqual(len(artifact['sources']),2)
        self.assertGreater(len(artifact['exact_sha256']),10000)
        provenance=json.loads((ROOT/'third_party/passwords/provenance.json').read_text())
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),provenance['reference_sha256'])
        self.assertFalse(provenance['raw_lists_retained'])
        self.assertTrue(all(source['license']=='MIT' for source in artifact['sources']))
        self.assertNotIn('passwords',artifact)

    def test_versioned_schema_preserves_baseline_and_labels(self):
        self.assertEqual(hashlib.sha256(BASE.read_bytes()).hexdigest(),BASE_HASH)
        with BASE.open(newline='') as handle:
            original=list(csv.DictReader(handle))
        with (ROOT/'data/mvp_synthetic_logins_v2.csv').open(newline='') as handle:
            reader=csv.DictReader(handle)
            self.assertEqual(reader.fieldnames,V2_COLUMNS)
            updated=list(reader)
        self.assertEqual(len(updated),len(original))
        for before,after in zip(original,updated):
            self.assertEqual(before,{name:after[name] for name in COLUMNS})
            flags=(int(after['password_in_blocklist']),int(after['password_near_blocklist']))
            self.assertIn(flags,((0,0),(1,0),(0,1)))
        for label in ('0','1'):
            flags={(row['password_in_blocklist'],row['password_near_blocklist'])
                   for row in updated if row['is_suspicious']==label}
            self.assertEqual(flags,{('0','0'),('1','0'),('0','1')})
        manifest=json.loads((ROOT/'data/mvp_synthetic_logins_v2.manifest.json').read_text())
        self.assertEqual(manifest['base_csv_sha256'],BASE_HASH)
        self.assertEqual(manifest['csv_sha256'],hashlib.sha256((ROOT/'data/mvp_synthetic_logins_v2.csv').read_bytes()).hexdigest())
        for row in updated:
            profile=manifest['password_profiles'][row['session_token']]
            for name in V2_COLUMNS[-2:]:
                self.assertEqual(int(row[name]),profile[name])
            self.assertEqual(set(profile),{'profile_type','match_type',*V2_COLUMNS[-2:]})

    def test_extension_uses_actual_checker_and_reproducible_profiles(self):
        calls=[]
        original_check=PasswordChecker.check
        def observed_check(checker,value):
            answer=original_check(checker,value)
            calls.append((answer['password_in_blocklist'],answer['password_near_blocklist']))
            return answer
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory)
            reference=directory/'reference.json';reference.write_text(json.dumps(self.artifact))
            output=directory/'v2.csv';manifest=directory/'v2.manifest.json'
            with patch('src.data.extend_password_flags.fetch_public_entries',return_value=(FIXTURES,SOURCES)),patch.object(PasswordChecker,'check',observed_check):
                first=extend_dataset(BASE,MANIFEST,reference,output,manifest,42)
                bytes_first=output.read_bytes()
                second=extend_dataset(BASE,MANIFEST,reference,output,manifest,42)
            self.assertEqual(first,second)
            self.assertEqual(output.read_bytes(),bytes_first)
            self.assertGreaterEqual(len(calls),2*len(first['password_profiles']))
            self.assertEqual(set(calls),{(1,0),(0,1),(0,0)})
            with self.assertRaises(ValueError):
                extend_dataset(BASE,MANIFEST,reference,BASE,manifest,42)
        self.assertEqual(hashlib.sha256(BASE.read_bytes()).hexdigest(),BASE_HASH)


if __name__=='__main__':
    unittest.main()

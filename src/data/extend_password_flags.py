"""Versioned synthetic-only password flag extension; preserve the 17-column baseline.

Re-fetches only pinned public password dictionaries, checks synthetic ephemeral
candidates locally, then writes flags and provenance. No event password or its
hash is persisted. The existing model is not trained or modified.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import random
from collections import Counter
from pathlib import Path

from src.data.generate_synthetic import COLUMNS
from src.security.build_password_reference import fetch_public_entries
from src.security.password_check import PasswordChecker, validate_reference

V2_COLUMNS = [*COLUMNS, 'password_in_blocklist', 'password_near_blocklist']


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extend_dataset(base: Path, base_manifest: Path, reference: Path, output: Path,
                   manifest_output: Path, seed: int = 42):
    inputs = {base.resolve(), base_manifest.resolve(), reference.resolve()}
    if output.resolve() in inputs or manifest_output.resolve() in inputs or output.resolve() == manifest_output.resolve():
        raise ValueError('Versioned outputs must not overwrite the baseline, reference or each other.')
    baseline_hash = sha256_file(base)
    baseline_manifest = json.loads(base_manifest.read_text(encoding='utf-8'))
    if baseline_manifest.get('synthetic') is not True or baseline_manifest.get('csv_sha256') != baseline_hash:
        raise ValueError('A verified synthetic baseline CSV and matching manifest are required.')
    artifact = validate_reference(json.loads(reference.read_text(encoding='utf-8')))
    checker = PasswordChecker(artifact)
    entries, _ = fetch_public_entries(artifact['sources'])
    near_bases = [entry for entry in entries if 4 <= len(entry) <= 252]
    if not near_bases:
        raise ValueError('The public reference has no supported synthetic near-match profiles.')
    with base.open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != COLUMNS:
            raise ValueError('Baseline must have the exact original 17-column schema.')
        rows = list(reader)
    if set(baseline_manifest.get('events', {})) != {row['event_id'] for row in rows}:
        raise ValueError('Baseline event provenance is incomplete.')
    rng = random.Random(seed)
    profiles = {}
    counts = Counter()
    by_label = {'0': Counter(), '1': Counter()}
    for row in rows:
        session = row['session_token']
        if session not in profiles:
            # Profile selection never reads attack_type, target, split or model.
            category = rng.choices(('public_exact', 'near_variant', 'unmatched_random'), (.20,.30,.50))[0]
            answer = None
            for _ in range(100):
                if category == 'public_exact':
                    candidate = rng.choice(entries)
                elif category == 'near_variant':
                    candidate = rng.choice(near_bases) + '2026'
                else:
                    candidate = 'els-demo-' + f'{rng.getrandbits(160):040x}'
                checked = checker.check(candidate)
                candidate = None
                desired = ((category == 'public_exact' and checked['match_type']=='exact') or
                           (category == 'near_variant' and checked['password_near_blocklist']==1) or
                           (category == 'unmatched_random' and checked['match_type']=='none'))
                if checked['status']=='checked' and desired:
                    answer = checked
                    break
            if answer is None:
                raise ValueError('Could not produce a checked synthetic profile within the attempt budget.')
            profiles[session] = {'profile_type': category, 'match_type': answer['match_type'],
                'password_in_blocklist': answer['password_in_blocklist'],
                'password_near_blocklist': answer['password_near_blocklist']}
        profile = profiles[session]
        row['password_in_blocklist'] = profile['password_in_blocklist']
        row['password_near_blocklist'] = profile['password_near_blocklist']
        counts[profile['profile_type']] += 1
        by_label[row['is_suspicious']][profile['profile_type']] += 1
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream,fieldnames=V2_COLUMNS,lineterminator='\n')
    writer.writeheader(); writer.writerows(rows)
    payload = stream.getvalue().encode('utf-8')
    manifest = {'schema_version':'els-synthetic-password-flags-v2','synthetic':True,
        'columns':V2_COLUMNS,'row_count':len(rows),'seed':seed,
        'csv_file':output.name,'csv_sha256':hashlib.sha256(payload).hexdigest(),
        'base_csv_file':base.name,'base_csv_sha256':baseline_hash,
        'base_manifest_file':base_manifest.name,'base_manifest_sha256':sha256_file(base_manifest),
        'reference_file':reference.name,'reference_sha256':sha256_file(reference),
        'reference_integrity_digest':artifact['artifact_integrity']['digest'],
        'events':baseline_manifest['events'],'password_profiles':profiles,
        'counts':dict(counts),'counts_by_target':{label:dict(values) for label,values in by_label.items()},
        'semantics':{
            'flags':'0/1 results from the actual local checker on ephemeral synthetic candidates; exact and near are mutually exclusive',
            'profile_scope':'one deterministic synthetic password profile per session',
            'profile_selection':'20% exact / 30% near / 50% unmatched profile sampling independent of all target labels and scenarios',
            'storage':'only flags and profile category are stored; no submitted password, normalized password or event-password hash',
            'model':'baseline 17 columns and existing 11-feature model unchanged; two flags are a separate unvalidated policy overlay',
            'bonus':'exact +25, near +10, neither +0; final risk capped at 100 only when base model score exists',
            'coverage':'limited public common-password references; no account breach proof; no match is not a safety guarantee',
            'source_fetch':'only pinned public password-only files are re-fetched in memory to construct actual checked synthetic profiles',
        }}
    output.parent.mkdir(parents=True,exist_ok=True)
    manifest_output.parent.mkdir(parents=True,exist_ok=True)
    output.write_bytes(payload)
    manifest_output.write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    if sha256_file(base) != baseline_hash:
        raise RuntimeError('Baseline changed while writing the extension.')
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',type=Path,default=Path('data/mvp_synthetic_logins.csv'))
    parser.add_argument('--base-manifest',type=Path,default=Path('data/mvp_synthetic_logins.manifest.json'))
    parser.add_argument('--reference',type=Path,default=Path('data/password_reference.json'))
    parser.add_argument('--output',type=Path,default=Path('data/mvp_synthetic_logins_v2.csv'))
    parser.add_argument('--manifest-output',type=Path,default=Path('data/mvp_synthetic_logins_v2.manifest.json'))
    parser.add_argument('--seed',type=int,default=42)
    args=parser.parse_args()
    manifest=extend_dataset(args.base,args.base_manifest,args.reference,args.output,args.manifest_output,args.seed)
    print(json.dumps({key:manifest[key] for key in ('row_count','csv_sha256','base_csv_sha256','counts','counts_by_target')}))


if __name__=='__main__':
    main()

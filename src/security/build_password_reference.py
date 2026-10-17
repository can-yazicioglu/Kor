"""Fetch only two pinned public password-only lists, then keep hashes and attribution."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from pathlib import Path

from .password_check import NORMALIZATION, SCHEMA_VERSION, MAX_REFERENCE_BYTES, normalize, seal_reference, sha256_text, validate_reference

REPOSITORY_COMMIT = '1cb6ade5539246c326986193d67954a2855581f6'
REPOSITORY = 'https://github.com/danielmiessler/SecLists'
SOURCE_PATHS = (
    'Passwords/Common-Credentials/10k-most-common.txt',
    'Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt',
)
RAW_ROOT = f'https://raw.githubusercontent.com/danielmiessler/SecLists/{REPOSITORY_COMMIT}'
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024


def download(path: str) -> bytes:
    if path not in (*SOURCE_PATHS, 'LICENSE'):
        raise ValueError('Only the pinned public dictionary and license paths are allowed.')
    request = urllib.request.Request(f'{RAW_ROOT}/{path}', headers={'User-Agent': 'Kor-reference-builder'})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.geturl() != request.full_url:
            raise ValueError('Unexpected source redirect.')
        data = response.read(MAX_DOWNLOAD_BYTES+1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError('Public reference download exceeds the size limit.')
    return data


def parse_public_entries(payload: bytes) -> tuple[list[str], int]:
    entries, excluded = [], 0
    # Password-only files can contain record-like strings. Exclude them instead
    # of treating an address, IP, or colon-separated record as a password sample.
    for value in payload.decode('utf-8', errors='strict').splitlines():
        if (not value or len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value) or
                ':' in value or re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value) or
                re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', value)):
            excluded += 1
        else:
            entries.append(value)
    return entries, excluded


def fetch_public_entries(expected_sources: list[dict] | None = None):
    entries, sources = [], []
    expected = {source['path']: source for source in expected_sources or []}
    for path in SOURCE_PATHS:
        payload = download(path)
        digest = hashlib.sha256(payload).hexdigest()
        if expected_sources and (path not in expected or expected[path]['sha256'] != digest):
            raise ValueError('Pinned public source does not match the reference provenance.')
        accepted, excluded = parse_public_entries(payload)
        sources.append({'name': Path(path).name, 'url': f'{RAW_ROOT}/{path}',
                        'repository': REPOSITORY, 'repository_commit': REPOSITORY_COMMIT,
                        'path': path, 'sha256': digest, 'license': 'MIT',
                        'license_url': f'{RAW_ROOT}/LICENSE', 'entry_count': len(accepted),
                        'excluded_record_like_or_invalid': excluded, 'bytes': len(payload)})
        entries.extend(accepted)
    return sorted(set(entries)), sources


def build_reference(entries: list[str], sources: list[dict]) -> dict:
    artifact = {'schema_version': SCHEMA_VERSION, 'reference_kind': 'limited_public_common_password_dictionary',
                'coverage_notice': 'A reference-list match does not establish that any particular account was breached; no match does not establish password safety.',
                'normalization': NORMALIZATION, 'sources': sources,
                'exact_sha256': sorted({sha256_text(value) for value in entries}),
                'normalized_sha256': sorted({sha256_text(normalize(value)) for value in entries}),
                'policy_bonus': {'exact': 25, 'near': 10, 'none': 0},
                'policy_semantics': 'Unvalidated demo heuristic, separate from the unchanged 11-feature model.'}
    return validate_reference(seal_reference(artifact))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('data/password_reference.json'))
    parser.add_argument('--attribution-dir', type=Path, default=Path('third_party/passwords'))
    args = parser.parse_args()
    entries, sources = fetch_public_entries()
    artifact = build_reference(entries, sources)
    payload = json.dumps(artifact, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8') + b'\n'
    if len(payload) > MAX_REFERENCE_BYTES:
        raise ValueError('Hashed public reference exceeds 4 MiB.')
    license_payload = download('LICENSE')
    if b'MIT License' not in license_payload:
        raise ValueError('Unexpected repository license; attribution requires review.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.attribution_dir.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    (args.attribution_dir/'SecLists-LICENSE.txt').write_bytes(license_payload)
    provenance = {'sources': sources, 'license_sha256': hashlib.sha256(license_payload).hexdigest(),
                  'reference_sha256': hashlib.sha256(payload).hexdigest(), 'reference_bytes': len(payload),
                  'unique_exact_entries': len(artifact['exact_sha256']),
                  'unique_normalized_entries': len(artifact['normalized_sha256']),
                  'raw_lists_retained': False,
                  'scope': 'Only public password-only dictionaries; no usernames, account records or email-password dumps.'}
    (args.attribution_dir/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key: provenance[key] for key in ('reference_sha256','reference_bytes','unique_exact_entries','unique_normalized_entries')}))


if __name__ == '__main__':
    main()

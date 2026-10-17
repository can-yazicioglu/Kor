"""Local password-only reference matching. Never log or persist submitted values."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import string
import sys
import unicodedata
from pathlib import Path

SCHEMA_VERSION = 'els-password-reference-v1'
MAX_REFERENCE_BYTES = 4 * 1024 * 1024
MAX_PASSWORD_CODEPOINTS = 256
MAX_CANDIDATES = 5000
ALPHABET = string.ascii_lowercase + string.digits
LEET_MAP = {'4': 'a', '@': 'a', '0': 'o', '1': 'i', '!': 'i', '|': 'i',
            '3': 'e', '5': 's', '$': 's', '7': 't', '+': 't'}
NORMALIZATION = {
    'unicode': 'NFKC', 'case': 'lower', 'leet_map': LEET_MAP,
    'suffix_pattern': r'[0-9!@#$%^&*?._-]{1,4}$', 'suffix_min_base_codepoints': 4,
    'edit_pattern': r'[a-z0-9]{6,32}', 'edit_alphabet': ALPHABET,
    'edit_order': ['delete', 'insert', 'substitute', 'adjacent_swap'],
    'max_candidates': MAX_CANDIDATES, 'max_password_codepoints': MAX_PASSWORD_CODEPOINTS,
}
HEX = re.compile(r'^[0-9a-f]{64}$')


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def normalize(value: str) -> str:
    return unicodedata.normalize('NFKC', value).lower().translate(str.maketrans(LEET_MAP))


def canonical_digest(artifact: dict) -> str:
    payload = {key: value for key, value in artifact.items() if key != 'artifact_integrity'}
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def seal_reference(artifact: dict) -> dict:
    artifact['artifact_integrity'] = {
        'algorithm': 'sha256', 'canonicalization': 'python_json_sort_keys_utf8_excluding_artifact_integrity',
        'digest': canonical_digest(artifact), 'purpose': 'accidental_corruption_not_authenticity',
    }
    return artifact


def validate_reference(artifact: dict) -> dict:
    try:
        if not isinstance(artifact, dict) or artifact.get('schema_version') != SCHEMA_VERSION:
            raise ValueError
        if artifact.get('normalization') != NORMALIZATION:
            raise ValueError
        integrity = artifact.get('artifact_integrity', {})
        if (not isinstance(integrity, dict) or integrity.get('algorithm') != 'sha256' or
                integrity.get('canonicalization') != 'python_json_sort_keys_utf8_excluding_artifact_integrity' or
                integrity.get('purpose') != 'accidental_corruption_not_authenticity' or
                integrity.get('digest') != canonical_digest(artifact)):
            raise ValueError
        for field in ('exact_sha256', 'normalized_sha256'):
            values = artifact.get(field)
            if (not isinstance(values, list) or not 1 <= len(values) <= 30000 or
                    any(not isinstance(value, str) or not HEX.fullmatch(value) for value in values) or
                    values != sorted(set(values))):
                raise ValueError
        if not isinstance(artifact.get('sources'), list) or not artifact['sources']:
            raise ValueError
        for source in artifact['sources']:
            if (not isinstance(source, dict) or not isinstance(source.get('name'), str) or
                    not isinstance(source.get('sha256'), str) or not HEX.fullmatch(source['sha256']) or
                    not isinstance(source.get('entry_count'), int) or source['entry_count'] < 1):
                raise ValueError
    except (TypeError, KeyError, ValueError, OverflowError):
        raise ValueError('Password reference is missing, invalid, or corrupted.') from None
    return artifact


def edit_candidates(value: str):
    """Deterministic bounded single ASCII edit set, never sent over a network."""
    if not re.fullmatch(NORMALIZATION['edit_pattern'], value):
        return
    seen = {value}
    produced = 0
    def variants():
        for index in range(len(value)):
            yield value[:index] + value[index+1:]
        for index in range(len(value)+1):
            for letter in ALPHABET:
                yield value[:index] + letter + value[index:]
        for index in range(len(value)):
            for letter in ALPHABET:
                if letter != value[index]:
                    yield value[:index] + letter + value[index+1:]
        for index in range(len(value)-1):
            if value[index] != value[index+1]:
                yield value[:index] + value[index+1] + value[index] + value[index+2:]
    for candidate in variants():
        if candidate in seen:
            continue
        seen.add(candidate)
        produced += 1
        if produced > MAX_CANDIDATES:
            return
        yield candidate


def result(match_type: str) -> dict:
    unknown = match_type == 'unknown'
    exact = match_type == 'exact'
    near = match_type in ('normalized', 'suffix', 'single_edit')
    return {'status': 'unknown' if unknown else 'checked',
            'password_in_blocklist': None if unknown else int(exact),
            'password_near_blocklist': None if unknown else int(near),
            'match_type': match_type, 'bonus': None if unknown else 25 if exact else 10 if near else 0}


class PasswordChecker:
    def __init__(self, artifact: dict | None):
        self.exact = frozenset()
        self.normalized = frozenset()
        self.ready = False
        try:
            validate_reference(artifact)
            self.exact = frozenset(artifact['exact_sha256'])
            self.normalized = frozenset(artifact['normalized_sha256'])
            self.ready = True
        except ValueError:
            pass

    @classmethod
    def from_file(cls, path: str | Path):
        try:
            path = Path(path)
            if path.stat().st_size > MAX_REFERENCE_BYTES:
                return cls(None)
            return cls(json.loads(path.read_text(encoding='utf-8')))
        except (OSError, ValueError, UnicodeError):
            return cls(None)

    def check(self, password: str) -> dict:
        if not self.ready or not isinstance(password, str) or not 1 <= len(password) <= MAX_PASSWORD_CODEPOINTS:
            return result('unknown')
        try:
            if sha256_text(password) in self.exact:
                return result('exact')
            normalized = normalize(password)
            if sha256_text(normalized) in self.normalized:
                return result('normalized')
            stripped = re.sub(NORMALIZATION['suffix_pattern'], '', password)
            if stripped != password and len(stripped) >= NORMALIZATION['suffix_min_base_codepoints']:
                if sha256_text(normalize(stripped)) in self.normalized:
                    return result('suffix')
            for candidate in edit_candidates(normalized):
                if sha256_text(candidate) in self.normalized:
                    return result('single_edit')
        except (UnicodeError, ValueError):
            return result('unknown')
        return result('none')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, default=Path('data/password_reference.json'))
    parser.add_argument('--stdin', action='store_true', help='read one value from standard input instead of a hidden prompt')
    args = parser.parse_args()
    checker = PasswordChecker.from_file(args.reference)
    if not checker.ready:
        print(json.dumps(result('unknown')))
        raise SystemExit(1)
    password = sys.stdin.readline(MAX_PASSWORD_CODEPOINTS*4+2).rstrip('\r\n') if args.stdin else getpass.getpass('Test password (local only): ')
    answer = checker.check(password)
    password = None
    print(json.dumps(answer))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Offline demo readiness and deterministic SHA-256 release comparison.

Checksums are NOT signatures. --write-manifest is a maintainer build action;
verification requires a separately trusted checkout/manifest.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
MANIFEST=ROOT/'outputs/release_manifest.json'


def files():
    selected=[p for p in (ROOT/'app').iterdir() if p.suffix in ('.html','.css','.js','.svg','.py')]
    selected+=list((ROOT/'src').rglob('*.py'))
    selected+=list((ROOT/'models').glob('*.json'))
    selected += [ROOT/name for name in ('data/password_reference.json','requirements.txt','requirements-optional.txt',
                                      'app/package.json','app/pnpm-lock.yaml','scripts/preflight.py')]
    return sorted(selected)


def manifest():
    return {'version':'els-release-manifest-v1','algorithm':'SHA-256',
            'purpose':'integrity_comparison_not_authenticity_or_attestation',
            'files':{str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in files()}}


def verify():
    if json.loads(MANIFEST.read_text()) != manifest():
        raise ValueError('Release files differ from the checked manifest. Review the changes before rebuilding it.')
    from src.runtime.service import RuntimeService
    service=RuntimeService()
    if not all(service.readiness().values()):
        raise ValueError('A required demo artifact is unavailable.')
    if service.demo_candidate is not None:
        raise ValueError('Unexpected tuned-candidate activation.')
    start=service.demo_request('start',{})
    service.demo_request('reset',{'demo_token':start['demo_token']})
    if service.demos:
        raise ValueError('Demo reset failed.')
    return {'release_files':len(files()),'runtime_artifacts':'ready','default_model':'baseline',
            'tuned_candidate':'blocked','customer_idp':'not_connected','ibm_z_execution':'not_verified',
            'scope':'offline_readiness_not_production_certification'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-manifest',action='store_true',help='Rebuild checksums after reviewed source changes')
    args=parser.parse_args()
    try:
        if args.write_manifest:
            MANIFEST.write_text(json.dumps(manifest(),indent=2,sort_keys=True)+'\n')
        print(json.dumps(verify(),indent=2))
    except (ValueError,OSError,TypeError,KeyError):
        parser.exit(1,'Preflight failed: required files, checksums or runtime readiness differ. No demo was published.\n')


if __name__=='__main__': main()

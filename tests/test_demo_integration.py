"""Real delivered CSV -> Python and browser scorer parity, plus DOM behavior.

No browser automation is available here. Linkedom tests interaction semantics,
not layout/rendering. Node and pnpm install --dir app are development dependencies.
"""
import csv
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which('node')
if NODE is None:
    bundled = Path('/usr/lib/chatgpt/resources/cua_node/bin/node')
    if bundled.is_file():
        NODE = str(bundled)


@unittest.skipUnless(NODE, 'Node.js is required for browser-code integration checks')
class DemoIntegrationTests(unittest.TestCase):
    def run_js(self, script):
        result = subprocess.run([NODE, str(ROOT / script)], cwd=ROOT, capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_schema_and_model_contracts_on_delivered_artifacts(self):
        self.assertIn('17 JavaScript', self.run_js('app/tests/contracts.test.mjs'))
        self.assertIn('10 JavaScript', self.run_js('app/tests/model-integration.test.mjs'))

    def test_all_actual_csv_events_have_python_javascript_score_and_reason_parity(self):
        spec = importlib.util.spec_from_file_location('kor_portable_core', ROOT / 'src/models/core.py')
        core = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(core)
        model = json.loads((ROOT / 'models/demo_model.json').read_text())
        expected = []
        with (ROOT / 'data/mvp_synthetic_logins.csv').open(newline='') as stream:
            for row in csv.DictReader(stream):
                features = {name: (row[name] or None) if name in core.CATEGORIES else
                            (float(row[name]) if row[name] else None) for name in core.FEATURES}
                prediction = core.predict_portable(model, features)
                expected.append(None if prediction is None else {
                    key: prediction[key] for key in ('risk_score', 'reasons', 'model_version')})
        script = """
            import { readFileSync } from 'node:fs';
            import { parseCSV, selectFeatures } from './app/schema.js';
            import { createPredictor } from './app/model-adapter.js';
            const model = JSON.parse(readFileSync('./models/demo_model.json', 'utf8'));
            const events = parseCSV(readFileSync('./data/mvp_synthetic_logins.csv', 'utf8'));
            const predict = createPredictor(model);
            process.stdout.write(JSON.stringify(events.map(row => predict(selectFeatures(row)))));
        """
        result = subprocess.run([NODE, '--input-type=module', '-e', script], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = json.loads(result.stdout)
        self.assertEqual(len(actual), 10000)
        self.assertEqual(len(actual), len(expected))
        for index, (left, right) in enumerate(zip(actual, expected)):
            self.assertEqual(left, right, f'Python/JS mismatch at CSV data row {index + 1}')

    def test_import_filter_search_pagination_reset_expiry_and_failure_dom_behavior(self):
        if not (ROOT / 'app/node_modules/linkedom').exists():
            self.skipTest('Install app dev dependencies with pnpm --dir app install --frozen-lockfile')
        self.assertIn('12 DOM', self.run_js('app/tests/ui.test.mjs'))


if __name__ == '__main__':
    unittest.main()

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'audit.py'


class AuditCliTests(unittest.TestCase):
    def test_default_json_and_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            migration = Path(directory) / 'migration.sql'
            migration.write_text('CREATE TABLE users (id int); UPDATE users SET id=2 WHERE id=1;', encoding='utf-8')
            default = subprocess.run([sys.executable, str(SCRIPT), str(migration)], capture_output=True, text=True)
            self.assertEqual(default.returncode, 0)
            self.assertEqual(json.loads(default.stdout)['high_risk'], 0)
            strict = subprocess.run([sys.executable, str(SCRIPT), str(migration), '--fail-on', 'medium', '--format', 'summary'], capture_output=True, text=True)
            self.assertEqual(strict.returncode, 2)
            self.assertIn('Medium: 1', strict.stdout)
            self.assertIn('Low: 1', strict.stdout)

    def test_none_does_not_fail_on_high_risk(self):
        with tempfile.TemporaryDirectory() as directory:
            migration = Path(directory) / 'migration.sql'
            migration.write_text('DROP TABLE users;', encoding='utf-8')
            result = subprocess.run([sys.executable, str(SCRIPT), str(migration), '--fail-on', 'none'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['high_risk'], 1)

    def test_missing_file_gives_a_readable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'missing.sql'
            result = subprocess.run([sys.executable, str(SCRIPT), str(missing)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('cannot read migration file', result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()

"""Protege o CLI do auditor contra arquivos SQL excessivamente grandes."""
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AuditSizeTests(unittest.TestCase):
    def test_reject_oversized_sql_before_parsing(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "large.sql"
            with source.open("wb") as stream:
                stream.seek(5 * 1024 * 1024)
                stream.write(b"X")
            run = subprocess.run(
                [sys.executable, str(ROOT / "audit.py"), str(source)],
                capture_output=True, text=True,
            )
        self.assertEqual(run.returncode, 2)
        self.assertIn("exceeds 5 MiB safety limit", run.stderr)
        self.assertEqual(run.stdout, "")


if __name__ == "__main__":
    unittest.main()

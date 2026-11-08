import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from migration_plan import Migration, audit_plan, load_migrations
from advanced_audit import main, render

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "advanced_audit.py"


class MigrationPlanTests(unittest.TestCase):
    def test_flyway_and_numeric_versions(self):
        self.assertEqual(Migration("V1__init.sql", "").version, (1,))
        self.assertEqual(Migration("V2_3__add_column.sql", "").version, (2, 3))
        self.assertEqual(Migration("12_update.sql", "").version, (12,))
        self.assertEqual(Migration("notes.sql", "").version, None)

    def test_invalid_migration_name_and_content(self):
        with self.assertRaises(ValueError):
            Migration("README.md", "SELECT 1")
        with self.assertRaises(TypeError):
            Migration("V1__init.sql", None)

    def test_duplicate_version_is_high_risk(self):
        files = [
            Migration("V1__users.sql", "CREATE TABLE users(id int)"),
            Migration("V1__orders.sql", "CREATE TABLE orders(id int)"),
        ]
        findings = audit_plan(files)
        self.assertIn("PLAN-DUPLICATE-VERSION", [f.rule_id for f in findings])

    def test_out_of_order_version_is_medium_risk(self):
        files = [
            Migration("V3__third.sql", "SELECT 1"),
            Migration("V2__second.sql", "SELECT 2"),
        ]
        findings = audit_plan(files)
        self.assertIn("PLAN-OUT-OF-ORDER", [f.rule_id for f in findings])
        self.assertNotIn("PLAN-OUT-OF-ORDER",
                         [f.rule_id for f in audit_plan(files, check_order=False)])

    def test_repeated_table_creation_is_flagged(self):
        files = [
            Migration("V1__first.sql", "CREATE TABLE customers(id int)"),
            Migration("V2__second.sql", "CREATE TABLE customers(id int)"),
        ]
        findings = audit_plan(files)
        self.assertIn("PLAN-DUPLICATE-TABLE", [f.rule_id for f in findings])

    def test_drop_then_recreate_is_not_duplicate(self):
        files = [
            Migration("V1__first.sql", "CREATE TABLE customers(id int)"),
            Migration("V2__second.sql", "DROP TABLE customers; CREATE TABLE customers(id int)"),
        ]
        findings = audit_plan(files)
        self.assertNotIn("PLAN-DUPLICATE-TABLE", [f.rule_id for f in findings])

    def test_quoted_schema_qualified_table_names(self):
        files = [
            Migration("V1__first.sql", 'CREATE TABLE "public"."Customers"(id int)'),
            Migration("V2__second.sql", 'CREATE TABLE "public"."Customers"(id int)'),
        ]
        findings = audit_plan(files)
        self.assertIn("PLAN-DUPLICATE-TABLE", [f.rule_id for f in findings])

    def test_duplicate_file_path_is_flagged(self):
        file = Migration("V1__init.sql", "SELECT 1")
        findings = audit_plan([file, file])
        self.assertIn("PLAN-DUPLICATE-FILE", [f.rule_id for f in findings])

    def test_lex_error_does_not_crash_plan_analysis(self):
        findings = audit_plan([Migration("V1__bad.sql", "SELECT 'broken")])
        self.assertEqual([f.rule_id for f in findings], ["LEX-ERROR"])

    def test_file_count_limit(self):
        with self.assertRaises(ValueError):
            audit_plan([Migration("V1__x.sql", "")] * 1001)

    def test_load_migrations_reads_utf8_and_checks_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "V1__data.sql"
            file.write_text("SELECT 'café';", encoding="utf-8")
            migrations = load_migrations([str(file)])
            self.assertEqual(len(migrations), 1)
            self.assertIn("café", migrations[0].sql)
            with self.assertRaises(ValueError):
                load_migrations([str(file)], max_bytes=5)
            with self.assertRaises(ValueError):
                load_migrations([])
            with self.assertRaises(ValueError):
                load_migrations([str(file)], max_bytes=0)

    def test_missing_file_is_readable_error(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            load_migrations(["nonexistent.sql"])

    def test_all_report_formats_render(self):
        findings = audit_plan([Migration("V1__users.sql", "DROP TABLE users")])
        for format_name in ("json", "sarif", "csv", "markdown", "summary"):
            with self.subTest(format=format_name):
                self.assertTrue(render(findings, format_name))
        with self.assertRaises(ValueError):
            render(findings, "unsupported")

    def test_cli_json_and_fail_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "V1__users.sql"
            file.write_text("DROP TABLE users;", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(file)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["counts"]["high"], 1)
            allowed = subprocess.run(
                [sys.executable, str(SCRIPT), str(file), "--fail-on", "none"],
                capture_output=True, text=True)
            self.assertEqual(allowed.returncode, 0)

    def test_cli_sarif_and_output_file(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "V1__users.sql"
            output = Path(directory) / "report.sarif"
            file.write_text("CREATE TABLE users(id int);", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(file), "--format", "sarif",
                 "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(json.loads(output.read_text())["version"], "2.1.0")

    def test_cli_multi_file_order_check(self):
        with tempfile.TemporaryDirectory() as directory:
            second = Path(directory) / "V2__second.sql"
            first = Path(directory) / "V1__first.sql"
            second.write_text("SELECT 1", encoding="utf-8")
            first.write_text("SELECT 2", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(second), str(first)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("PLAN-OUT-OF-ORDER", result.stdout)

    def test_cli_missing_file_returns_readable_error(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "missing.sql"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not found", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_rejects_output_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            sql = Path(directory) / "V1__x.sql"
            target = Path(directory) / "real.txt"
            link = Path(directory) / "link.txt"
            sql.write_text("SELECT 1", encoding="utf-8")
            target.write_text("original", encoding="utf-8")
            link.symlink_to(target)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(sql), "--output", str(link)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(target.read_text(), "original")


if __name__ == "__main__":
    unittest.main()

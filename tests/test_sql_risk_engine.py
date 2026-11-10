import csv
import io
import json
import unittest

from sql_lexer import split_statements
from sql_risk_engine import (
    Finding, RANK, RULES, audit_sql, classify, counts, should_fail, summary,
    to_csv, to_json, to_markdown, to_sarif,
)


class SqlRiskEngineTests(unittest.TestCase):
    def rule(self, sql):
        return classify(split_statements(sql)[0]).rule_id

    def test_destructive_ddl(self):
        cases = {
            "DROP TABLE users": "DDL-DROP",
            "DROP DATABASE app": "DDL-DROP",
            "DROP SCHEMA public": "DDL-DROP",
            "TRUNCATE TABLE users": "DDL-TRUNCATE",
            "ALTER TABLE users DROP COLUMN email": "DDL-DROP-COLUMN",
            "VACUUM FULL users": "DDL-VACUUM-FULL",
            "DROP INDEX idx_email": "DDL-INDEX-DROP",
        }
        for sql, expected in cases.items():
            with self.subTest(sql=sql):
                self.assertEqual(self.rule(sql), expected)

    def test_update_delete_without_where_are_high(self):
        cases = {
            "DELETE FROM users": "DML-DELETE-ALL",
            "DELETE FROM users WHERE TRUE": "DML-DELETE-ALL",
            "DELETE FROM users WHERE 1=1": "DML-DELETE-ALL",
            "UPDATE users SET name='x'": "DML-UPDATE-ALL",
            "UPDATE users SET name='x' WHERE TRUE": "DML-UPDATE-ALL",
            "UPDATE users SET name='x' WHERE 1=1": "DML-UPDATE-ALL",
        }
        for sql, expected in cases.items():
            with self.subTest(sql=sql):
                self.assertEqual(self.rule(sql), expected)

    def test_where_inside_literal_is_not_a_filter(self):
        self.assertEqual(self.rule("DELETE FROM users WHERELESS = 'WHERE'"),
                         "DML-DELETE-ALL")
        self.assertEqual(self.rule("UPDATE users SET text='WHERE'"),
                         "DML-UPDATE-ALL")

    def test_real_where_is_reviewable_not_high(self):
        self.assertEqual(self.rule("DELETE FROM users WHERE id=3"), "DML-WRITE")
        self.assertEqual(self.rule("UPDATE users SET active=0 WHERE id=1"), "DML-WRITE")

    def test_ddl_constraints_and_renames(self):
        cases = {
            "ALTER TABLE users ADD COLUMN age int NOT NULL": "DDL-NOT-NULL",
            "ALTER TABLE users ALTER COLUMN age SET NOT NULL": "DDL-NOT-NULL",
            "ALTER TABLE users ADD COLUMN age int NOT NULL DEFAULT 0": "DDL-ALTER",
            "ALTER TABLE users RENAME TO people": "DDL-RENAME",
            "ALTER TABLE users ADD COLUMN age int": "DDL-ALTER",
            "LOCK TABLE users": "DDL-LOCK",
        }
        for sql, expected in cases.items():
            with self.subTest(sql=sql):
                self.assertEqual(self.rule(sql), expected)

    def test_index_and_create_rules(self):
        cases = {
            "CREATE TABLE users(id int)": "DDL-CREATE",
            "CREATE SCHEMA analytics": "DDL-CREATE",
            "CREATE INDEX ix ON users(id)": "DDL-INDEX",
            "CREATE UNIQUE INDEX ix ON users(id)": "DDL-INDEX",
            "CREATE INDEX CONCURRENTLY ix ON users(id)": "DDL-CREATE",
            "CREATE EXTENSION pgcrypto": "DDL-EXTENSION",
            "CREATE FUNCTION f() RETURNS int AS $$SELECT 1$$ LANGUAGE sql": "DDL-GENERIC",
        }
        for sql, expected in cases.items():
            with self.subTest(sql=sql):
                self.assertEqual(self.rule(sql), expected)

    def test_permissions_and_dynamic_sql(self):
        cases = {
            "GRANT ALL ON users TO public": "SEC-GRANT-ALL",
            "REVOKE SELECT ON users FROM guest": "SEC-REVOKE",
            "EXECUTE 'DROP TABLE users'": "DYN-SQL",
            "DO $$ BEGIN EXECUTE 'DELETE FROM users'; END $$": "DYN-SQL",
            "MERGE INTO users USING source ON users.id=source.id WHEN MATCHED THEN DELETE": "DML-WRITE",
            "MERGE INTO users USING source WHEN MATCHED THEN DELETE": "DML-MERGE",
        }
        for sql, expected in cases.items():
            with self.subTest(sql=sql):
                self.assertEqual(self.rule(sql), expected)

    def test_read_only_and_unrecognized(self):
        for sql in ["SELECT 1", "BEGIN", "COMMIT", "ROLLBACK", "EXPLAIN SELECT 1"]:
            with self.subTest(sql=sql):
                self.assertEqual(self.rule(sql), "READ-ONLY")
        self.assertEqual(self.rule("CALL refresh_cache()"), "UNRECOGNIZED")

    def test_insert_is_medium(self):
        self.assertEqual(self.rule("INSERT INTO users VALUES (1)"), "DML-WRITE")
        self.assertEqual(self.rule("REPLACE INTO users VALUES (1)"), "DML-WRITE")

    def test_multiple_statements_have_distinct_locations(self):
        findings = audit_sql("-- comment\nCREATE TABLE x(id int);\nDROP TABLE x;", "V1.sql")
        self.assertEqual(len(findings), 2)
        self.assertEqual([f.line for f in findings], [2, 3])
        self.assertEqual([f.severity for f in findings], ["low", "high"])
        self.assertEqual([f.file for f in findings], ["V1.sql", "V1.sql"])

    def test_lexical_error_becomes_high_risk_finding(self):
        findings = audit_sql("SELECT 'unterminated", "bad.sql")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "LEX-ERROR")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].line, 1)

    def test_literals_are_not_exposed_in_reports(self):
        findings = audit_sql("UPDATE users SET password='super-secret' WHERE id=1", "safe.sql")
        outputs = [to_json(findings), to_markdown(findings), to_csv(findings),
                   json.dumps(to_sarif(findings))]
        for output in outputs:
            self.assertNotIn("super-secret", output)
        self.assertIn("?", findings[0].statement)

    def test_json_report_has_counts_and_source_locations(self):
        findings = audit_sql("CREATE TABLE x(id int);\nDROP TABLE x", "migration.sql")
        report = json.loads(to_json(findings))
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["total"], 2)
        self.assertEqual(report["counts"], {"high": 1, "medium": 0, "low": 1})
        self.assertEqual(report["findings"][1]["line"], 2)

    def test_sarif_is_schema_conformant_enough_for_ci(self):
        findings = audit_sql("DROP TABLE users; DROP TABLE orders;", "migrations/V1.sql")
        sarif = to_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], "migrations/V1.sql")
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]
                         ["region"]["startLine"], 1)

    def test_markdown_escapes_pipe_characters(self):
        finding = Finding("path|name.sql", 1, 1, "medium", "X",
                          "reason|pipe", "review", "SELECT 1")
        report = to_markdown([finding])
        self.assertIn("path\\|name.sql", report)
        self.assertIn("reason\\|pipe", report)
        self.assertIn("Statements: 1", report)

    def test_csv_is_machine_readable(self):
        findings = audit_sql("CREATE TABLE users(id int);", "V1.sql")
        rows = list(csv.DictReader(io.StringIO(to_csv(findings))))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["rule_id"], "DDL-CREATE")
        self.assertEqual(rows[0]["file"], "V1.sql")

    def test_csv_formula_injection_is_escaped(self):
        finding = Finding("=2+2.sql", 1, 1, "high", "X", "=SUM(1,2)", "review", "@cmd")
        row = list(csv.reader(io.StringIO(to_csv([finding]))))[1]
        self.assertTrue(row[0].startswith("'"))
        self.assertTrue(row[5].startswith("'"))
        self.assertTrue(row[7].startswith("'"))

    def test_summary_is_readable(self):
        findings = audit_sql("DROP TABLE users", "V1.sql")
        report = summary(findings)
        self.assertIn("Total: 1", report)
        self.assertIn("High: 1", report)
        self.assertIn("V1.sql:1:1", report)

    def test_counts_and_thresholds(self):
        findings = audit_sql("CREATE TABLE x(id int); UPDATE x SET id=1; DROP TABLE x")
        self.assertEqual(counts(findings), {"high": 2, "medium": 0, "low": 1})
        self.assertTrue(should_fail(findings, "high"))
        self.assertTrue(should_fail(findings, "medium"))
        self.assertTrue(should_fail(findings, "low"))
        self.assertFalse(should_fail(findings, "none"))
        self.assertFalse(should_fail(audit_sql("SELECT 1"), "high"))
        with self.assertRaises(ValueError):
            should_fail(findings, "critical")

    def test_rule_registry_has_valid_severities(self):
        self.assertTrue(RULES)
        for key, rule in RULES.items():
            self.assertEqual(key, rule.rule_id)
            self.assertIn(rule.severity, RANK)
            self.assertTrue(rule.recommendation)

    def test_invalid_finding_is_rejected(self):
        with self.assertRaises(ValueError):
            Finding("x.sql", 0, 1, "high", "X", "r", "fix", "")
        with self.assertRaises(ValueError):
            Finding("x.sql", 1, 1, "critical", "X", "r", "fix", "")

    def test_empty_audit_returns_empty_reports(self):
        findings = audit_sql("-- comment only")
        self.assertEqual(findings, [])
        self.assertEqual(json.loads(to_json(findings))["total"], 0)
        self.assertEqual(to_sarif(findings)["runs"][0]["results"], [])
        self.assertFalse(should_fail(findings))


if __name__ == "__main__":
    unittest.main()

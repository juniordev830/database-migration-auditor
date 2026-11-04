import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from audit import audit
from sql_lexer import split_sql


SCRIPT = Path(__file__).resolve().parents[1] / "audit.py"


class SqlLexerTests(unittest.TestCase):
    def test_preserves_semicolon_inside_quoted_value_and_doubled_quotes(self):
        sql = "INSERT INTO notes (txt) VALUES ('hello; it''s SQL'); CREATE TABLE t (id int);"
        output = split_sql(sql)
        self.assertEqual(len(output), 2)
        self.assertIn("'hello; it''s SQL'", output[0][0])
        self.assertEqual([f["severity"] for f in audit(sql)], ["medium", "low"])

    def test_where_inside_string_does_not_hide_unbounded_update(self):
        sql = "UPDATE accounts SET label='WHERE'; DELETE FROM logs WHERE reason='WHERE; --';"
        findings = audit(sql)
        self.assertEqual([f["severity"] for f in findings], ["high", "medium"])
        self.assertEqual(findings[0]["reason"], "update without WHERE")

    def test_removes_comments_without_joining_sql_tokens(self):
        sql = """
        DELETE/**/FROM logs; -- DROP TABLE ignored
        /* comment ; DROP TABLE fake */
        UPDATE users SET flag=1 /* WHERE id=1 */;
        INSERT INTO logs (message) VALUES ('-- not a comment; DROP TABLE');
        """
        findings = audit(sql)
        self.assertEqual([f["severity"] for f in findings], ["high", "high", "medium"])
        self.assertEqual(len(findings), 3)

    def test_supports_quoted_identifiers_and_semicolons(self):
        sql = 'CREATE TABLE "messages;archive" (id int); DROP TABLE "messages;archive";'
        findings = audit(sql)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[1]["reason"], "destructive drop")

    def test_rejects_unterminated_literals_and_comments(self):
        for sql in ("SELECT 'oops", 'SELECT "oops', "SELECT 1; /* unfinished"):
            with self.subTest(sql=sql):
                with self.assertRaises(ValueError):
                    audit(sql)

    def test_cli_reports_unterminated_sql_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.sql"
            path.write_text("UPDATE users SET title='oops;", encoding="utf-8")
            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 2)
            self.assertIn("invalid SQL input", run.stderr)
            self.assertNotIn("Traceback", run.stderr)


if __name__ == "__main__":
    unittest.main()

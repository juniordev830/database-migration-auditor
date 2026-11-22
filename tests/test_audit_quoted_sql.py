import unittest
from audit import audit


class QuotedSqlAuditTests(unittest.TestCase):
    def test_comment_marker_inside_string_does_not_hide_drop(self):
        items = audit("SELECT '-- ; DROP TABLE not_real'; DROP TABLE users;")
        self.assertEqual([item["severity"] for item in items], ["medium", "high"])

    def test_semicolon_inside_string_does_not_split_statements(self):
        items = audit("SELECT 'a;b;c'; UPDATE accounts SET enabled = 0;")
        self.assertEqual(len(items), 2)
        self.assertEqual(items[1]["reason"], "update without WHERE")

    def test_where_word_in_literal_is_not_treated_as_filter(self):
        findings = audit("DELETE FROM logs RETURNING 'WHERE';")
        self.assertEqual(findings[0]["reason"], "delete without WHERE")
        self.assertEqual(findings[0]["severity"], "high")

    def test_real_where_clause_still_demands_manual_review(self):
        findings = audit("DELETE FROM logs WHERE id = 2;")
        self.assertEqual(findings[0]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()

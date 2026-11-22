import unittest
from audit import audit, sarif_report


class SarifLocationTests(unittest.TestCase):
    def test_findings_have_their_real_statement_lines(self):
        sql = "CREATE TABLE x (id int);\n-- comment\n\nDROP TABLE x;"
        findings = audit(sql)
        self.assertEqual([finding["line"] for finding in findings], [1, 4])
        report = sarif_report(findings, "migration.sql")
        result_lines = [
            item["locations"][0]["physicalLocation"]["region"]["startLine"]
            for item in report["runs"][0]["results"]
        ]
        self.assertEqual(result_lines, [1, 4])


if __name__ == "__main__":
    unittest.main()

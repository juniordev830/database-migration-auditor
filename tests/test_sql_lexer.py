import unittest

from sql_lexer import (
    SqlLexError, identifier_after, keyword_positions, redact_literals,
    split_statements, tokenize,
)


class SqlLexerTests(unittest.TestCase):
    def test_simple_statement_and_positions(self):
        tokens = tokenize("CREATE TABLE users (id INT);")
        self.assertEqual(tokens[0].value, "CREATE")
        self.assertEqual(tokens[0].line, 1)
        self.assertEqual(tokens[0].column, 1)
        self.assertEqual(tokens[-1].kind, "SEMI")
        self.assertEqual(len(split_statements("CREATE TABLE users (id INT);")), 1)

    def test_comments_do_not_count_as_keywords(self):
        sql = "-- DROP TABLE secrets;\nCREATE TABLE users(id INT);"
        statements = split_statements(sql)
        self.assertEqual(len(statements), 1)
        self.assertEqual(statements[0].first, "CREATE")
        self.assertEqual(statements[0].line, 2)
        self.assertNotIn("DROP", statements[0].words)

    def test_block_comments_can_contain_semicolons(self):
        sql = "/* DROP TABLE secret; */ CREATE TABLE a(id int); /* ; */ SELECT 1;"
        statements = split_statements(sql)
        self.assertEqual([s.first for s in statements], ["CREATE", "SELECT"])

    def test_nested_block_comments_are_skipped(self):
        sql = "/* outer /* inner ; DROP */ still comment */ SELECT 1;"
        self.assertEqual(split_statements(sql)[0].words, ("SELECT",))

    def test_semicolon_inside_single_quote_is_not_separator(self):
        sql = "INSERT INTO logs VALUES ('a;b;c'); SELECT 2;"
        statements = split_statements(sql)
        self.assertEqual(len(statements), 2)
        self.assertEqual(statements[0].first, "INSERT")
        self.assertIn("'a;b;c'", statements[0].text)

    def test_doubled_single_quote_does_not_close_literal(self):
        sql = "SELECT 'it''s; still one literal'; SELECT 1;"
        self.assertEqual(len(split_statements(sql)), 2)

    def test_backslash_escaped_quote_does_not_split(self):
        sql = r"SELECT 'escaped \'; still string'; SELECT 1;"
        self.assertEqual(len(split_statements(sql)), 2)

    def test_double_quoted_identifier_is_not_keyword(self):
        tokens = tokenize('SELECT "DROP" FROM "my;table";')
        self.assertEqual([t.kind for t in tokens if t.value.startswith('"')],
                         ["IDENT", "IDENT"])
        self.assertNotIn("DROP", [t.upper for t in tokens])

    def test_backtick_identifier_is_not_keyword(self):
        sql = "SELECT " + chr(96) + "a;b" + chr(96) + " FROM data;"
        self.assertEqual(len(split_statements(sql)), 1)

    def test_bracket_identifier_handles_escaped_closing_bracket(self):
        tokens = tokenize("SELECT [a]]b] FROM [my;table];")
        identifiers = [t.identifier() for t in tokens if t.kind == "IDENT"]
        self.assertEqual(identifiers, ["a]b", "my;table"])

    def test_dollar_quoted_function_body_is_one_statement(self):
        sql = "CREATE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1; END; $$ LANGUAGE plpgsql;"
        statements = split_statements(sql)
        self.assertEqual(len(statements), 1)
        self.assertEqual(statements[0].first, "CREATE")

    def test_tagged_dollar_quotes(self):
        sql = "SELECT $body$ DROP TABLE x; $body$; SELECT 2;"
        statements = split_statements(sql)
        self.assertEqual(len(statements), 2)
        self.assertEqual(statements[0].first, "SELECT")

    def test_dollar_body_is_redacted(self):
        sql = "SELECT $tag$private data$tag$;"
        preview = redact_literals(split_statements(sql)[0])
        self.assertNotIn("private data", preview)
        self.assertIn("?", preview)

    def test_string_literals_are_redacted(self):
        statement = split_statements("UPDATE users SET email='private@example.com' WHERE id=2;")[0]
        preview = redact_literals(statement)
        self.assertNotIn("private@example.com", preview)
        self.assertIn("?", preview)
        self.assertIn("UPDATE", preview)

    def test_preview_length_is_bounded(self):
        statement = split_statements("SELECT " + ", ".join(["name"] * 100))[0]
        preview = redact_literals(statement, 50)
        self.assertLessEqual(len(preview), 50)
        self.assertTrue(preview.endswith("…"))
        with self.assertRaises(ValueError):
            redact_literals(statement, 5)

    def test_multiple_statements_have_correct_lines(self):
        sql = "\n\nSELECT 1;\n\nDROP TABLE x;\nSELECT 3;"
        statements = split_statements(sql)
        self.assertEqual([s.line for s in statements], [3, 5, 6])
        self.assertEqual([s.column for s in statements], [1, 1, 1])

    def test_comment_only_sql_has_no_statements(self):
        self.assertEqual(split_statements("-- comment\n/* block */"), [])
        self.assertEqual(split_statements(" ; ; "), [])
        self.assertEqual(tokenize(""), [])

    def test_missing_semicolon_is_valid_last_statement(self):
        statements = split_statements("SELECT 1; SELECT 2")
        self.assertEqual(len(statements), 2)
        self.assertEqual(statements[-1].text, "SELECT 2")

    def test_statement_limit_is_enforced(self):
        with self.assertRaises(ValueError):
            split_statements("SELECT 1; SELECT 2;", max_statements=1)
        with self.assertRaises(ValueError):
            split_statements("SELECT 1;", max_statements=0)

    def test_unterminated_single_quote_is_diagnostic(self):
        with self.assertRaises(SqlLexError) as caught:
            tokenize("SELECT\n'never closed")
        self.assertEqual(caught.exception.line, 2)
        self.assertEqual(caught.exception.column, 1)
        self.assertIn("unterminated", str(caught.exception))

    def test_unterminated_block_comment_is_diagnostic(self):
        with self.assertRaises(SqlLexError) as caught:
            tokenize("SELECT 1;\n/* incomplete")
        self.assertEqual(caught.exception.line, 2)
        self.assertIn("block comment", caught.exception.message)

    def test_unterminated_dollar_quote_is_diagnostic(self):
        with self.assertRaises(SqlLexError):
            tokenize("SELECT $tag$unfinished")

    def test_unterminated_bracket_identifier_is_diagnostic(self):
        with self.assertRaises(SqlLexError):
            tokenize("SELECT [unfinished")

    def test_unterminated_double_quote_is_diagnostic(self):
        with self.assertRaises(SqlLexError):
            tokenize('SELECT "unfinished')

    def test_nul_byte_is_rejected(self):
        with self.assertRaises(SqlLexError):
            tokenize("SELECT 1\x00")

    def test_input_size_is_bounded(self):
        with self.assertRaises(ValueError):
            tokenize("SELECT 1", max_chars=3)
        with self.assertRaises(ValueError):
            tokenize("", max_chars=0)
        with self.assertRaises(TypeError):
            tokenize(None)

    def test_identifiers_are_normalized_correctly(self):
        tokens = tokenize('table "a""b" [c]]d] ' + chr(96) + 'x' + chr(96))
        self.assertEqual(tokens[0].identifier(), "table")
        self.assertEqual(tokens[1].identifier(), 'a"b')
        self.assertEqual(tokens[2].identifier(), "c]d")
        self.assertEqual(tokens[3].identifier(), "x")

    def test_identifier_method_rejects_symbols(self):
        symbol = tokenize("+")[0]
        with self.assertRaises(ValueError):
            symbol.identifier()

    def test_keyword_positions_ignore_string_literals(self):
        statement = split_statements("SELECT 'WHERE' WHERE id = 1")[0]
        positions = keyword_positions(statement, "where")
        self.assertEqual(len(positions), 1)
        self.assertEqual(positions[0].upper, "WHERE")

    def test_identifier_after_keyword(self):
        statement = split_statements("CREATE TABLE customers (id INT)")[0]
        self.assertEqual(identifier_after(statement, "TABLE"), "customers")
        self.assertIsNone(identifier_after(statement, "MISSING"))

    def test_newlines_inside_literals_advance_line_number(self):
        sql = "SELECT 'first\nsecond';\nDROP TABLE users;"
        statements = split_statements(sql)
        self.assertEqual(statements[1].line, 3)

    def test_quoted_keyword_does_not_become_statement_first(self):
        statement = split_statements('"DROP" TABLE x;')[0]
        self.assertEqual(statement.first, "TABLE")
        self.assertNotIn("DROP", statement.words)

    def test_token_offsets_preserve_original_source(self):
        sql = " -- comment\n SELECT 'a;b' ;"
        for token in tokenize(sql):
            self.assertEqual(sql[token.offset:token.end], token.value)


if __name__ == "__main__":
    unittest.main()

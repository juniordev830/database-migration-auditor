"""Read-only SQL lexical analysis with precise source locations.

This lexer deliberately avoids executing SQL or connecting to databases.
It handles common PostgreSQL/MySQL/SQL Server quoting conventions, but is not
a complete SQL grammar or a replacement for a dialect-specific parser.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
_NUMBER = re.compile(r"\d+(?:\.\d+)?")
_DOLLAR = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")


class SqlLexError(ValueError):
    """Malformed lexical input, including unterminated quoted regions."""

    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"{message} at line {line}, column {column}")
        self.line = line
        self.column = column
        self.message = message


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    offset: int
    end: int
    line: int
    column: int

    @property
    def upper(self) -> str:
        return self.value.upper() if self.kind == "WORD" else ""

    @property
    def is_identifier(self) -> bool:
        return self.kind in ("WORD", "IDENT")

    def identifier(self) -> str:
        if self.kind == "WORD":
            return self.value
        if self.kind != "IDENT":
            raise ValueError("token is not an identifier")
        if self.value.startswith("["):
            return self.value[1:-1].replace("]]", "]")
        quote = self.value[0]
        return self.value[1:-1].replace(quote * 2, quote)


@dataclass(frozen=True)
class Statement:
    text: str
    tokens: tuple[Token, ...]
    line: int
    column: int
    end_line: int

    @property
    def words(self) -> tuple[str, ...]:
        return tuple(token.upper for token in self.tokens if token.kind == "WORD")

    @property
    def first(self) -> str:
        return self.words[0] if self.words else ""

    @property
    def significant(self) -> bool:
        return bool(self.tokens)


def tokenize(sql: str, max_chars: int = 2_000_000) -> list[Token]:
    """Tokenize without interpreting SQL literals as keywords."""
    if not isinstance(sql, str):
        raise TypeError("sql must be a string")
    if max_chars < 1 or len(sql) > max_chars:
        raise ValueError("SQL exceeds configured character limit")

    tokens: list[Token] = []
    i = 0
    line = 1
    column = 1
    size = len(sql)

    def advance(end: int) -> None:
        nonlocal i, line, column
        fragment = sql[i:end]
        newlines = fragment.count("\n")
        if newlines:
            line += newlines
            column = len(fragment.rsplit("\n", 1)[-1]) + 1
        else:
            column += len(fragment)
        i = end

    def add(kind: str, end: int) -> None:
        tokens.append(Token(kind, sql[i:end], i, end, line, column))
        advance(end)

    while i < size:
        char = sql[i]
        if char.isspace():
            advance(i + 1)
            continue

        if sql.startswith("--", i):
            end = sql.find("\n", i + 2)
            advance(size if end == -1 else end)
            continue

        if sql.startswith("/*", i):
            start_line, start_column = line, column
            cursor = i + 2
            depth = 1
            while cursor < size and depth:
                if sql.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif sql.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise SqlLexError("unterminated block comment", start_line, start_column)
            advance(cursor)
            continue

        if char in ("'", '"', chr(96)):
            start_line, start_column = line, column
            cursor = i + 1
            closed = False
            while cursor < size:
                if sql[cursor] == char:
                    if cursor + 1 < size and sql[cursor + 1] == char:
                        cursor += 2
                        continue
                    cursor += 1
                    closed = True
                    break
                if char == "'" and sql[cursor] == "\\" and cursor + 1 < size:
                    cursor += 2
                else:
                    cursor += 1
            if not closed:
                raise SqlLexError("unterminated quoted value", start_line, start_column)
            add("STRING" if char == "'" else "IDENT", cursor)
            continue

        if char == "[":
            start_line, start_column = line, column
            cursor = i + 1
            closed = False
            while cursor < size:
                if sql.startswith("]]", cursor):
                    cursor += 2
                    continue
                if sql[cursor] == "]":
                    cursor += 1
                    closed = True
                    break
                cursor += 1
            if not closed:
                raise SqlLexError("unterminated bracket identifier", start_line, start_column)
            add("IDENT", cursor)
            continue

        if char == "$":
            match = _DOLLAR.match(sql, i)
            if match:
                tag = match.group()
                start_line, start_column = line, column
                closing = sql.find(tag, match.end())
                if closing < 0:
                    raise SqlLexError("unterminated dollar-quoted body",
                                      start_line, start_column)
                add("STRING", closing + len(tag))
                continue

        match = _WORD.match(sql, i)
        if match:
            add("WORD", match.end())
            continue

        match = _NUMBER.match(sql, i)
        if match:
            add("NUMBER", match.end())
            continue

        if char == ";":
            add("SEMI", i + 1)
            continue

        if char == "\x00":
            raise SqlLexError("NUL byte is not valid SQL input", line, column)

        add("SYMBOL", i + 1)

    return tokens


def split_statements(sql: str, max_statements: int = 10_000) -> list[Statement]:
    """Split only at semicolons outside strings, identifiers and comments."""
    if max_statements < 1:
        raise ValueError("max_statements must be positive")
    tokens = tokenize(sql)
    statements: list[Statement] = []
    current: list[Token] = []
    begin = 0

    def flush(end: int) -> None:
        if not current:
            return
        first = current[0]
        last = current[-1]
        raw = sql[begin:end].strip()
        if not raw:
            return
        if len(statements) >= max_statements:
            raise ValueError("too many SQL statements")
        statements.append(Statement(
            text=raw,
            tokens=tuple(current),
            line=first.line,
            column=first.column,
            end_line=last.line + last.value.count("\n"),
        ))

    for token in tokens:
        if token.kind == "SEMI":
            flush(token.offset)
            current = []
            begin = token.end
        else:
            current.append(token)
    flush(len(sql))
    return statements


def redact_literals(statement: Statement, limit: int = 240) -> str:
    """Build a readable preview without leaking literal string values."""
    if limit < 16:
        raise ValueError("preview limit must be at least 16")
    output: list[str] = []
    for token in statement.tokens:
        output.append("?" if token.kind == "STRING" else token.value)
    preview = " ".join(" ".join(output).split())
    return preview if len(preview) <= limit else preview[:limit - 1] + "…"


def keyword_positions(statement: Statement, word: str) -> list[Token]:
    target = word.upper()
    return [token for token in statement.tokens
            if token.kind == "WORD" and token.upper == target]


def identifier_after(statement: Statement, keyword: str) -> str | None:
    tokens = statement.tokens
    for index, token in enumerate(tokens[:-1]):
        if token.upper == keyword.upper() and tokens[index + 1].is_identifier:
            return tokens[index + 1].identifier()
    return None

"""Minimal SQL statement scanner for static review, never executing SQL.

Understands SQL single-quoted values, double-quoted identifiers, doubled quotes,
-- line comments and /* block comments */. Not a dialect-specific SQL parser.
"""
from __future__ import annotations


def split_sql(sql: str) -> list[tuple[str, str]]:
    """Return (display statement, keyword-safe statement) pairs.

    Keyword-safe statements mask quoted values/identifiers and comments so that
    WHERE inside a value cannot suppress a high-risk UPDATE/DELETE finding.
    A semicolon only splits statements outside quoted values and comments.
    """
    if not isinstance(sql, str):
        raise TypeError("SQL must be text")

    found: list[tuple[str, str]] = []
    display: list[str] = []
    masked: list[str] = []
    state = "normal"
    index = 0

    def flush() -> None:
        original = " ".join("".join(display).split())
        safe = " ".join("".join(masked).split())
        if original:
            found.append((original, safe))
        display.clear()
        masked.clear()

    while index < len(sql):
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""

        if state == "normal":
            if char == "-" and next_char == "-":
                display.append(" ")
                masked.append(" ")
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                display.append(" ")
                masked.append(" ")
                state = "block_comment"
                index += 2
                continue
            if char in ("'", '"'):
                display.append(char)
                masked.append(" ")
                state = "single" if char == "'" else "double"
                index += 1
                continue
            if char == ";":
                flush()
                index += 1
                continue
            display.append(char)
            masked.append(char)
        elif state == "line_comment":
            if char == "\n":
                display.append("\n")
                masked.append("\n")
                state = "normal"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "normal"
                index += 2
                continue
        elif state in ("single", "double"):
            quote = "'" if state == "single" else '"'
            display.append(char)
            masked.append(" ")
            if char == quote:
                if next_char == quote:  # doubled quote is an escaped quote
                    display.append(next_char)
                    masked.append(" ")
                    index += 2
                    continue
                state = "normal"
        index += 1

    if state in ("single", "double", "block_comment"):
        raise ValueError("Unterminated SQL string, identifier or block comment")
    flush()
    return found

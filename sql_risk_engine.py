"""Rule-based, read-only SQL migration risk engine.

The analysis is conservative: it reports potential hazards, never asserts that
a migration is safe to run, and never executes statements.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import csv
import io
import json
from typing import Iterable

from sql_lexer import SqlLexError, Statement, Token, redact_literals, split_statements

RANK = {"low": 1, "medium": 2, "high": 3}
SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error"}


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    column: int
    severity: str
    rule_id: str
    reason: str
    recommendation: str
    statement: str

    def __post_init__(self) -> None:
        if self.severity not in RANK:
            raise ValueError("unknown severity")
        if self.line < 1 or self.column < 1:
            raise ValueError("invalid source location")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    reason: str
    recommendation: str


RULES = {
    "DDL-DROP": Rule("DDL-DROP", "high", "destructive DROP operation",
                     "Verify backup, dependencies and rollback before dropping objects."),
    "DDL-TRUNCATE": Rule("DDL-TRUNCATE", "high", "table truncation",
                         "Confirm retention policy and backup before truncating."),
    "DDL-DROP-COLUMN": Rule("DDL-DROP-COLUMN", "high", "column removal",
                            "Deprecate readers and verify data retention first."),
    "DML-DELETE-ALL": Rule("DML-DELETE-ALL", "high", "DELETE without restrictive WHERE",
                           "Use a reviewed predicate and validate affected row counts."),
    "DML-UPDATE-ALL": Rule("DML-UPDATE-ALL", "high", "UPDATE without restrictive WHERE",
                           "Use a reviewed predicate and validate affected row counts."),
    "DML-MERGE": Rule("DML-MERGE", "high", "MERGE without ON condition",
                      "Provide a reviewed join condition before running."),
    "DDL-NOT-NULL": Rule("DDL-NOT-NULL", "high", "required column without default",
                         "Backfill existing rows before enforcing NOT NULL."),
    "DDL-VACUUM-FULL": Rule("DDL-VACUUM-FULL", "high", "blocking VACUUM FULL",
                            "Schedule maintenance and evaluate lock duration."),
    "SEC-GRANT-ALL": Rule("SEC-GRANT-ALL", "high", "broad GRANT ALL privileges",
                          "Grant only required permissions to specific roles."),
    "DYN-SQL": Rule("DYN-SQL", "high", "dynamic SQL requires security review",
                     "Review interpolated values and use parameter binding."),
    "DDL-INDEX": Rule("DDL-INDEX", "medium", "index creation may lock writes",
                      "Check dialect-specific online/concurrent index options."),
    "DDL-ALTER": Rule("DDL-ALTER", "medium", "table alteration requires review",
                      "Evaluate locks, backfills and rollback strategy."),
    "DDL-RENAME": Rule("DDL-RENAME", "medium", "schema object rename",
                       "Coordinate with dependent applications and queries."),
    "DDL-INDEX-DROP": Rule("DDL-INDEX-DROP", "medium", "index removal",
                            "Review query plans and dependent workloads."),
    "DML-WRITE": Rule("DML-WRITE", "medium", "data mutation requires review",
                      "Verify idempotency, row counts and rollback."),
    "DDL-LOCK": Rule("DDL-LOCK", "medium", "explicit table lock",
                      "Review concurrency impact and timeout policy."),
    "SEC-REVOKE": Rule("SEC-REVOKE", "medium", "permission revocation",
                       "Verify applications retain required access."),
    "DDL-EXTENSION": Rule("DDL-EXTENSION", "medium", "extension installation",
                          "Review extension privileges and supply chain."),
    "DDL-GENERIC": Rule("DDL-GENERIC", "medium", "DDL requires manual review",
                        "Validate syntax and impact in a staging environment."),
    "UNRECOGNIZED": Rule("UNRECOGNIZED", "medium", "unrecognized SQL operation",
                          "Review the statement using a dialect-aware parser."),
    "DDL-CREATE": Rule("DDL-CREATE", "low", "create-only schema change",
                       "Verify naming and repeatability before deployment."),
    "READ-ONLY": Rule("READ-ONLY", "low", "read-only or transaction statement",
                      "Confirm the statement's execution context."),
    "LEX-ERROR": Rule("LEX-ERROR", "high", "malformed SQL lexical input",
                      "Fix quoting or comments before migration review."),
}


def _words(statement: Statement) -> list[str]:
    return [token.upper for token in statement.tokens if token.kind == "WORD"]


def _has_pair(words: list[str], first: str, second: str) -> bool:
    return any(a == first and b == second for a, b in zip(words, words[1:]))


def _where_is_unrestricted(tokens: tuple[Token, ...]) -> bool:
    """Detect common tautological WHERE predicates, without reading strings."""
    where = next((index for index, token in enumerate(tokens)
                  if token.upper == "WHERE"), None)
    if where is None:
        return True
    rest = [token for token in tokens[where + 1:]
            if token.kind not in ("SEMI",)]
    while rest and rest[0].value == "(":
        rest.pop(0)
    if not rest:
        return True
    if rest[0].upper == "TRUE":
        return True
    if len(rest) >= 3 and rest[0].kind == "NUMBER" and rest[1].value == "=":
        if rest[2].kind == "NUMBER" and rest[0].value == rest[2].value:
            if len(rest) == 3 or rest[3].value == ")":
                return True
    return False


def classify(statement: Statement) -> Rule:
    words = _words(statement)
    if not words:
        return RULES["UNRECOGNIZED"]
    first = words[0]

    if first in ("EXEC", "EXECUTE", "DO"):
        return RULES["DYN-SQL"]
    if first == "DROP":
        if len(words) > 1 and words[1] == "INDEX":
            return RULES["DDL-INDEX-DROP"]
        return RULES["DDL-DROP"]
    if first == "TRUNCATE":
        return RULES["DDL-TRUNCATE"]
    if first == "VACUUM" and "FULL" in words:
        return RULES["DDL-VACUUM-FULL"]
    if first == "DELETE":
        return RULES["DML-DELETE-ALL"] if _where_is_unrestricted(statement.tokens) else RULES["DML-WRITE"]
    if first == "UPDATE":
        return RULES["DML-UPDATE-ALL"] if _where_is_unrestricted(statement.tokens) else RULES["DML-WRITE"]
    if first == "MERGE":
        return RULES["DML-MERGE"] if "ON" not in words else RULES["DML-WRITE"]
    if first == "GRANT" and "ALL" in words:
        return RULES["SEC-GRANT-ALL"]
    if first == "REVOKE":
        return RULES["SEC-REVOKE"]
    if first == "LOCK":
        return RULES["DDL-LOCK"]
    if first == "ALTER":
        if "DROP" in words and "COLUMN" in words:
            return RULES["DDL-DROP-COLUMN"]
        if "RENAME" in words:
            return RULES["DDL-RENAME"]
        if _has_pair(words, "SET", "NOT") and "NULL" in words:
            return RULES["DDL-NOT-NULL"]
        if "ADD" in words and _has_pair(words, "NOT", "NULL") and "DEFAULT" not in words:
            return RULES["DDL-NOT-NULL"]
        return RULES["DDL-ALTER"]
    if first == "CREATE":
        if "EXTENSION" in words:
            return RULES["DDL-EXTENSION"]
        if "INDEX" in words:
            return RULES["DDL-CREATE"] if "CONCURRENTLY" in words else RULES["DDL-INDEX"]
        if "TABLE" in words or "SCHEMA" in words:
            return RULES["DDL-CREATE"]
        return RULES["DDL-GENERIC"]
    if first in ("INSERT", "REPLACE", "UPSERT"):
        return RULES["DML-WRITE"]
    if first in ("SELECT", "SHOW", "EXPLAIN", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT"):
        return RULES["READ-ONLY"]
    return RULES["UNRECOGNIZED"]


def audit_sql(sql: str, filename: str = "<memory>") -> list[Finding]:
    """Return one risk finding per statement; lexical errors are high risk."""
    if not isinstance(filename, str) or not filename:
        raise ValueError("filename is required")
    try:
        statements = split_statements(sql)
    except SqlLexError as error:
        return [Finding(filename, error.line, error.column, "high",
                        "LEX-ERROR", error.message, RULES["LEX-ERROR"].recommendation, "")]
    findings = []
    for statement in statements:
        rule = classify(statement)
        findings.append(Finding(
            file=filename,
            line=statement.line,
            column=statement.column,
            severity=rule.severity,
            rule_id=rule.rule_id,
            reason=rule.reason,
            recommendation=rule.recommendation,
            statement=redact_literals(statement),
        ))
    return findings


def counts(findings: Iterable[Finding]) -> dict[str, int]:
    result = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        result[finding.severity] += 1
    return result


def should_fail(findings: Iterable[Finding], threshold: str = "high") -> bool:
    if threshold == "none":
        return False
    if threshold not in RANK:
        raise ValueError("threshold must be high, medium, low or none")
    return any(RANK[finding.severity] >= RANK[threshold] for finding in findings)


def to_json(findings: Iterable[Finding], pretty: bool = True) -> str:
    records = list(findings)
    report = {
        "version": 1,
        "total": len(records),
        "counts": counts(records),
        "findings": [asdict(finding) for finding in records],
    }
    return json.dumps(report, ensure_ascii=False, indent=2 if pretty else None)


def to_sarif(findings: Iterable[Finding]) -> dict:
    records = list(findings)
    rules: dict[str, dict] = {}
    results = []
    for finding in records:
        rules.setdefault(finding.rule_id, {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.reason},
            "help": {"text": finding.recommendation},
            "defaultConfiguration": {"level": SARIF_LEVEL[finding.severity]},
        })
        results.append({
            "ruleId": finding.rule_id,
            "level": SARIF_LEVEL[finding.severity],
            "message": {"text": finding.reason + ": " + finding.statement},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {"startLine": finding.line,
                               "startColumn": finding.column},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "database-migration-auditor-advanced",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }


def to_markdown(findings: Iterable[Finding]) -> str:
    records = list(findings)
    totals = counts(records)
    output = [
        "# SQL migration risk review",
        "",
        f"Statements: {len(records)} | High: {totals['high']} | "
        f"Medium: {totals['medium']} | Low: {totals['low']}",
        "",
        "| File | Line | Severity | Rule | Reason |",
        "| --- | ---: | --- | --- | --- |",
    ]
    for finding in records:
        cells = (finding.file, str(finding.line), finding.severity,
                 finding.rule_id, finding.reason)
        output.append("| " + " | ".join(
            cell.replace("|", "\\|").replace("\n", " ") for cell in cells) + " |")
    output.append("")
    output.append("Review is advisory and does not execute SQL.")
    return "\n".join(output) + "\n"


def to_csv(findings: Iterable[Finding]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["file", "line", "column", "severity", "rule_id",
                     "reason", "recommendation", "statement"])
    for finding in findings:
        values = [finding.file, finding.line, finding.column, finding.severity,
                  finding.rule_id, finding.reason, finding.recommendation,
                  finding.statement]
        safe = ["'" + value if isinstance(value, str) and value.startswith(
            ("=", "+", "-", "@", "\t", "\r", "\n")) else value for value in values]
        writer.writerow(safe)
    return output.getvalue()


def summary(findings: Iterable[Finding]) -> str:
    records = list(findings)
    totals = counts(records)
    lines = [f"Total: {len(records)} | High: {totals['high']} | "
             f"Medium: {totals['medium']} | Low: {totals['low']}"]
    for finding in records:
        lines.append(f"[{finding.severity.upper()}] {finding.file}:{finding.line}:"
                     f"{finding.column} {finding.rule_id}: {finding.reason}")
    return "\n".join(lines) + "\n"

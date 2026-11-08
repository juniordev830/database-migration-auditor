"""Cross-file SQL migration plan checks; never executes database commands."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from sql_lexer import Statement, split_statements
from sql_risk_engine import Finding, audit_sql

_VERSION = re.compile(r"^(?:V)?(\d+(?:[._]\d+)*)__(.+)\.sql$", re.I)
_SIMPLE_VERSION = re.compile(r"^(\d+)[_-](.+)\.sql$", re.I)


@dataclass(frozen=True)
class Migration:
    name: str
    sql: str

    def __post_init__(self) -> None:
        if not self.name or not self.name.lower().endswith(".sql"):
            raise ValueError("migration name must end with .sql")
        if not isinstance(self.sql, str):
            raise TypeError("migration SQL must be a string")

    @property
    def version(self) -> tuple[int, ...] | None:
        filename = Path(self.name).name
        match = _VERSION.match(filename) or _SIMPLE_VERSION.match(filename)
        if not match:
            return None
        return tuple(int(part) for part in re.split(r"[._]", match.group(1)))


def _issue(migration: Migration, rule_id: str, reason: str,
           severity: str, recommendation: str, line: int = 1) -> Finding:
    return Finding(
        file=migration.name,
        line=line,
        column=1,
        severity=severity,
        rule_id=rule_id,
        reason=reason,
        recommendation=recommendation,
        statement="",
    )


def _object_after_table(statement: Statement) -> str | None:
    tokens = statement.tokens
    for index, token in enumerate(tokens):
        if token.upper != "TABLE":
            continue
        cursor = index + 1
        if cursor + 1 < len(tokens) and tokens[cursor].upper == "IF":
            cursor += 1
            if cursor < len(tokens) and tokens[cursor].upper == "NOT":
                cursor += 1
            if cursor < len(tokens) and tokens[cursor].upper == "EXISTS":
                cursor += 1
        if cursor >= len(tokens) or not tokens[cursor].is_identifier:
            return None
        name = tokens[cursor].identifier()
        if cursor + 2 < len(tokens) and tokens[cursor + 1].value == ".":
            if tokens[cursor + 2].is_identifier:
                name += "." + tokens[cursor + 2].identifier()
        return name.casefold()
    return None


def audit_plan(migrations: list[Migration], check_order: bool = True) -> list[Finding]:
    """Audit SQL plus duplicate versions, order and repeated table creation."""
    if len(migrations) > 1000:
        raise ValueError("too many migration files")
    findings: list[Finding] = []
    versions: dict[tuple[int, ...], str] = {}
    names: set[str] = set()
    created_tables: dict[str, str] = {}
    previous_version: tuple[int, ...] | None = None

    for migration in migrations:
        findings.extend(audit_sql(migration.sql, migration.name))
        if migration.name in names:
            findings.append(_issue(
                migration, "PLAN-DUPLICATE-FILE", "duplicate migration file",
                "high", "Remove duplicate input paths from the migration plan."))
        names.add(migration.name)

        version = migration.version
        if version is not None:
            if version in versions:
                findings.append(_issue(
                    migration, "PLAN-DUPLICATE-VERSION",
                    "migration version already used by " + versions[version],
                    "high", "Assign each migration a unique version."))
            else:
                versions[version] = migration.name
            if check_order and previous_version is not None and version < previous_version:
                findings.append(_issue(
                    migration, "PLAN-OUT-OF-ORDER", "migration version is out of order",
                    "medium", "Apply migrations in ascending version order."))
            previous_version = version

        try:
            statements = split_statements(migration.sql)
        except ValueError:
            continue

        for statement in statements:
            words = statement.words
            if len(words) < 2:
                continue
            if words[0] == "DROP" and words[1] == "TABLE":
                table = _object_after_table(statement)
                if table is not None:
                    created_tables.pop(table, None)
            if words[0] == "CREATE" and words[1] == "TABLE":
                table = _object_after_table(statement)
                if table is None:
                    continue
                if table in created_tables:
                    findings.append(_issue(
                        migration, "PLAN-DUPLICATE-TABLE",
                        "table created more than once: " + table,
                        "medium", "Use a reviewed migration order or explicit idempotency.",
                        statement.line))
                created_tables[table] = migration.name

    return findings


def load_migrations(paths: list[str], max_bytes: int = 2_000_000) -> list[Migration]:
    """Load bounded UTF-8 SQL files without evaluating or executing contents."""
    if not paths:
        raise ValueError("at least one migration file is required")
    if len(paths) > 1000:
        raise ValueError("too many migration paths")
    if max_bytes < 1 or max_bytes > 50_000_000:
        raise ValueError("invalid file size limit")
    migrations = []
    for path in paths:
        file = Path(path)
        if not file.is_file():
            raise ValueError("migration file not found: " + path)
        if file.stat().st_size > max_bytes:
            raise ValueError("migration exceeds size limit: " + path)
        try:
            sql = file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ValueError("cannot read migration: " + path) from error
        if len(sql) > max_bytes:
            raise ValueError("migration exceeds character limit: " + path)
        migrations.append(Migration(path, sql))
    return migrations

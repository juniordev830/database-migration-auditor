"""Advanced static SQL migration auditor CLI.

Usage:
    python advanced_audit.py migrations/V1__users.sql migrations/V2__orders.sql
    python advanced_audit.py migrations/*.sql --format sarif --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import sys

from migration_plan import audit_plan, load_migrations
from sql_risk_engine import should_fail, summary, to_csv, to_json, to_markdown, to_sarif


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Read-only SQL migration review; no database connections")
    cli.add_argument("files", nargs="+", help="SQL files in intended migration order")
    cli.add_argument("--format", choices=("json", "sarif", "csv", "markdown", "summary"),
                     default="json", help="report format")
    cli.add_argument("--fail-on", choices=("high", "medium", "low", "none"),
                     default="high", help="minimum risk that produces exit status 2")
    cli.add_argument("--max-file-bytes", type=int, default=2_000_000,
                     help="per-file UTF-8 size cap, default 2 MB")
    cli.add_argument("--no-order-check", action="store_true",
                     help="skip ascending migration version check")
    cli.add_argument("--output", default="-",
                     help="write report to a UTF-8 file instead of stdout")
    return cli


def render(findings: list, format_name: str) -> str:
    if format_name == "json":
        return to_json(findings) + "\n"
    if format_name == "sarif":
        return json.dumps(to_sarif(findings), ensure_ascii=False, indent=2) + "\n"
    if format_name == "csv":
        return to_csv(findings)
    if format_name == "markdown":
        return to_markdown(findings)
    if format_name == "summary":
        return summary(findings)
    raise ValueError("unknown report format")


def main(argv: list[str] | None = None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        migrations = load_migrations(args.files, args.max_file_bytes)
        findings = audit_plan(migrations, check_order=not args.no_order_check)
        report = render(findings, args.format)
        if args.output == "-":
            sys.stdout.write(report)
        else:
            from pathlib import Path
            destination = Path(args.output)
            if destination.is_symlink():
                raise ValueError("refusing to overwrite a symlink")
            if any(destination.resolve() == Path(source).resolve()
                   or (destination.exists() and destination.samefile(source))
                   for source in args.files):
                raise ValueError("report output must not overwrite a migration input")
            destination.write_text(report, encoding="utf-8")
    except (ValueError, OSError, UnicodeError) as error:
        cli.error(str(error))
    return 2 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())

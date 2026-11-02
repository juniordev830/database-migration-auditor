"""Static SQL migration risk review; NEVER executes database commands."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

HIGH = [
    (re.compile(r'^DROP\s+(?:TABLE|DATABASE|SCHEMA)\b', re.I), 'destructive drop'),
    (re.compile(r'^TRUNCATE\b', re.I), 'table truncation'),
    (re.compile(r'^ALTER\s+TABLE\b.*\bDROP\s+COLUMN\b', re.I|re.S), 'column removal'),
    (re.compile(r'^DELETE\s+FROM\b(?!.*\bWHERE\b)', re.I|re.S), 'delete without WHERE'),
    (re.compile(r'^UPDATE\b(?!.*\bWHERE\b)', re.I|re.S), 'update without WHERE'),
]
LOW = re.compile(r'^CREATE\s+(?:TABLE|INDEX|SCHEMA)\b', re.I)

def audit(sql: str) -> list[dict[str,str]]:
    # Training parser: SQL comments removed; semicolons in string literals are unsupported.
    cleaned = re.sub(r'/\*.*?\*/|--[^\n]*', '', sql, flags=re.S)
    result=[]
    for raw in cleaned.split(';'):
        statement=raw.strip()
        if not statement: continue
        normalized=' '.join(statement.split())
        matched=next((reason for pattern,reason in HIGH if pattern.search(normalized)),None)
        if matched: severity,reason='high',matched
        elif LOW.search(normalized): severity,reason='low','create-only statement'
        else: severity,reason='medium','manual review required'
        result.append({'severity':severity,'reason':reason,'statement':normalized[:160]})
    return result

def main():
    cli=argparse.ArgumentParser(description='Read-only SQL migration audit')
    cli.add_argument('file', help='SQL migration file')
    cli.add_argument('--fail-on', choices=('high', 'medium', 'low', 'none'), default='high',
                     help='minimum severity that causes exit code 2 (default: high)')
    cli.add_argument('--format', choices=('json', 'summary'), default='json',
                     help='output format (default: json)')
    args=cli.parse_args()
    try:
        sql=Path(args.file).read_text(encoding='utf-8')
    except (OSError, UnicodeError) as error:
        cli.error(f'cannot read migration file: {error}')
    findings=audit(sql)
    counts={level:sum(f['severity']==level for f in findings) for level in ('high', 'medium', 'low')}
    if args.format == 'json':
        print(json.dumps({'findings':findings,'high_risk':counts['high']},indent=2))
    else:
        print(f"Total: {len(findings)} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']}")
        for finding in findings:
            print(f"[{finding['severity'].upper()}] {finding['reason']}: {finding['statement']}")
    thresholds={'high': 3, 'medium': 2, 'low': 1, 'none': 4}
    severities={'high': 3, 'medium': 2, 'low': 1}
    return 2 if any(severities[f['severity']] >= thresholds[args.fail_on] for f in findings) else 0
if __name__=='__main__':raise SystemExit(main())

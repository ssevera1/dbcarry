"""Per-table content checksums and snapshot diffing.

The checksum orders row hashes by their own value with COLLATE "C", so
it is deterministic, collation-independent, and works on tables with no
primary key. Snapshots run read-only.
"""
import argparse
import json
import sys

from db_drift import pg

SYSTEM_SCHEMAS = "('pg_catalog', 'information_schema')"
TABLES_SQL = (
    "SELECT n.nspname, c.relname FROM pg_class c "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    f"WHERE c.relkind = 'r' AND n.nspname NOT IN {SYSTEM_SCHEMAS} "
    "ORDER BY 1, 2")
SEQ_SQL = ("SELECT schemaname, sequencename, coalesce(last_value::text, '') "
           "FROM pg_sequences ORDER BY 1, 2")
CHECKSUM_SQL = (
    "SELECT count(*), coalesce(md5(string_agg(h, '' "
    "ORDER BY h COLLATE \"C\")), 'empty') "
    "FROM (SELECT md5(t::text) AS h FROM {table} t) s")


def take_snapshot(ci):
    snapshot = {"tables": {}, "sequences": {}}
    for schema, name in pg.query_rows(ci, TABLES_SQL, readonly=True):
        qualified = f'"{schema}"."{name}"'
        row = pg.query_rows(ci, CHECKSUM_SQL.format(table=qualified),
                            readonly=True)[0]
        snapshot["tables"][f"{schema}.{name}"] = {
            "rows": int(row[0]), "checksum": row[1]}
    for schema, name, last in pg.query_rows(ci, SEQ_SQL, readonly=True):
        snapshot["sequences"][f"{schema}.{name}"] = int(last) if last else None
    return snapshot


def diff_snapshots(left, right, ignore_sequences=False):
    lt, rt = left["tables"], right["tables"]
    report = {
        "missing_tables": sorted(set(lt) - set(rt)),
        "extra_tables": sorted(set(rt) - set(lt)),
        "table_mismatches": sorted(
            k for k in set(lt) & set(rt) if lt[k] != rt[k]),
        "sequence_mismatches": [],
    }
    if not ignore_sequences:
        ls, rs = left["sequences"], right["sequences"]
        report["sequence_mismatches"] = sorted(
            k for k in set(ls) | set(rs) if ls.get(k) != rs.get(k))
    report["match"] = not any(
        report[k] for k in ("missing_tables", "extra_tables",
                            "table_mismatches", "sequence_mismatches"))
    return report


def main(argv):
    parser = argparse.ArgumentParser(prog="dbdrift.py checksum")
    sub = parser.add_subparsers(dest="verb", required=True)
    p = sub.add_parser("snapshot")
    pg.add_conn_args(p)
    p.add_argument("--out", required=True)
    p = sub.add_parser("diff")
    p.add_argument("--left", required=True)
    p.add_argument("--right", required=True)
    p.add_argument("--ignore-sequences", action="store_true")
    args = parser.parse_args(argv[1:])
    try:
        if args.verb == "snapshot":
            snapshot = take_snapshot(pg.conn_from_args(args))
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh, indent=2)
            print(f"wrote {args.out} "
                  f"({len(snapshot['tables'])} tables)")
            return 0
        with open(args.left, encoding="utf-8") as fh:
            left = json.load(fh)
        with open(args.right, encoding="utf-8") as fh:
            right = json.load(fh)
        report = diff_snapshots(left, right, args.ignore_sequences)
        print(json.dumps(report, indent=2))
        return 0 if report["match"] else 1
    except pg.PgError as exc:
        print(f"CHECKSUM ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(["checksum"] + sys.argv[1:])

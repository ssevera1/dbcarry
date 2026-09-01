"""Read-only source inventory, emitted as JSON.

All sessions run with readonly=True. build_inventory is pure so it can
be unit tested without a database.
"""
import argparse
import json
import sys

from db_drift import pg

SYSTEM_SCHEMAS = "('pg_catalog', 'information_schema')"

QUERIES = {
    "server": (
        "SELECT current_setting('server_version'), "
        "current_setting('wal_level'), "
        "pg_encoding_to_char(encoding) "
        "FROM pg_database WHERE datname = current_database()"),
    "tables": (
        "SELECT n.nspname, c.relname, c.reltuples::bigint, "
        "pg_total_relation_size(c.oid), "
        "EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid "
        "AND i.indisprimary), c.relreplident "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        f"WHERE c.relkind = 'r' AND n.nspname NOT IN {SYSTEM_SCHEMAS} "
        "ORDER BY 1, 2"),
    "sequences": (
        "SELECT schemaname, sequencename, coalesce(last_value::text, '') "
        "FROM pg_sequences ORDER BY 1, 2"),
    "views": (
        f"SELECT schemaname, viewname FROM pg_views "
        f"WHERE schemaname NOT IN {SYSTEM_SCHEMAS} ORDER BY 1, 2"),
    "matviews": (
        "SELECT schemaname, matviewname FROM pg_matviews ORDER BY 1, 2"),
    "extensions": (
        "SELECT extname, extversion FROM pg_extension ORDER BY 1"),
    "roles": (
        "SELECT rolname, rolcanlogin FROM pg_roles "
        "WHERE rolname NOT LIKE 'pg\\_%' AND rolname <> 'postgres' "
        "ORDER BY 1"),
    "indexes": (
        f"SELECT count(*) FROM pg_indexes "
        f"WHERE schemaname NOT IN {SYSTEM_SCHEMAS}"),
    "constraints": (
        "SELECT count(*) FROM pg_constraint c "
        "JOIN pg_namespace n ON n.oid = c.connamespace "
        f"WHERE n.nspname NOT IN {SYSTEM_SCHEMAS}"),
}


def _bool(cell):
    return cell == "t"


def build_inventory(raw):
    server = raw["server"][0]
    return {
        "server": {"version": server[0], "wal_level": server[1],
                   "encoding": server[2]},
        "tables": [
            {"schema": r[0], "name": r[1], "rows": int(r[2]),
             "bytes": int(r[3]), "has_pk": _bool(r[4]),
             "replica_identity": r[5]}
            for r in raw["tables"]],
        "sequences": [
            {"schema": r[0], "name": r[1],
             "last_value": int(r[2]) if r[2] else None}
            for r in raw["sequences"]],
        "views": [f"{r[0]}.{r[1]}" for r in raw["views"]],
        "matviews": [f"{r[0]}.{r[1]}" for r in raw["matviews"]],
        "extensions": [{"name": r[0], "version": r[1]}
                       for r in raw["extensions"]],
        "roles": [{"name": r[0], "can_login": _bool(r[1])}
                  for r in raw["roles"]],
        "counts": {"indexes": int(raw["indexes"][0][0]),
                   "constraints": int(raw["constraints"][0][0])},
    }


def main(argv):
    parser = argparse.ArgumentParser(prog="dbdrift.py inventory")
    pg.add_conn_args(parser)
    parser.add_argument("--out", default=None)
    parser.add_argument("--exact", action="store_true",
                        help="replace row estimates with exact counts")
    parser.add_argument("--server-only", action="store_true",
                        help="connectivity check: server facts only")
    args = parser.parse_args(argv[1:])
    ci = pg.conn_from_args(args)
    try:
        if args.server_only:
            row = pg.query_rows(ci, QUERIES["server"], readonly=True)[0]
            print(json.dumps({"version": row[0], "wal_level": row[1],
                              "encoding": row[2]}))
            return 0
        raw = {key: pg.query_rows(ci, sql, readonly=True)
               for key, sql in QUERIES.items()}
        inv = build_inventory(raw)
        if args.exact:
            for table in inv["tables"]:
                exact = pg.query_rows(
                    ci, f'SELECT count(*) FROM "{table["schema"]}"'
                        f'."{table["name"]}"', readonly=True)
                table["rows"] = int(exact[0][0])
        text = json.dumps(inv, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0
    except pg.PgError as exc:
        print(f"INVENTORY ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(["inventory"] + sys.argv[1:])

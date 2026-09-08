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
    # v0.2.0 additions: column-level detail for schema translation. Text
    # columns that may contain whitespace are collapsed to single spaces
    # because psql output is one row per line, tab separated.
    "columns": (
        "SELECT c.table_schema, c.table_name, c.column_name, "
        "c.ordinal_position, c.data_type, c.udt_name, c.is_nullable, "
        "coalesce(regexp_replace(c.column_default, '\\s+', ' ', 'g'), ''), "
        "coalesce(c.numeric_precision::text, ''), "
        "coalesce(c.numeric_scale::text, ''), "
        "coalesce(c.character_maximum_length::text, ''), "
        "coalesce(et.typname, '') "
        "FROM information_schema.columns c "
        "JOIN pg_namespace n ON n.nspname = c.table_schema "
        "JOIN pg_class cl ON cl.relnamespace = n.oid "
        "AND cl.relname = c.table_name AND cl.relkind IN ('r', 'p') "
        "JOIN pg_attribute a ON a.attrelid = cl.oid "
        "AND a.attname = c.column_name "
        "JOIN pg_type t ON t.oid = a.atttypid "
        "LEFT JOIN pg_type et ON et.oid = t.typelem AND t.typcategory = 'A' "
        f"WHERE c.table_schema NOT IN {SYSTEM_SCHEMAS} "
        "ORDER BY 1, 2, 4"),
    "primary_keys": (
        "SELECT n.nspname, c.relname, con.conname, "
        "string_agg(a.attname, ',' ORDER BY k.ord) "
        "FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) "
        "ON true "
        "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum "
        f"WHERE con.contype = 'p' AND n.nspname NOT IN {SYSTEM_SCHEMAS} "
        "GROUP BY 1, 2, 3 ORDER BY 1, 2"),
    "foreign_keys": (
        "SELECT n.nspname, c.relname, con.conname, "
        "string_agg(a.attname, ',' ORDER BY k.ord), "
        "rn.nspname, rc.relname, "
        "string_agg(ra.attname, ',' ORDER BY k.ord) "
        "FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "JOIN pg_class rc ON rc.oid = con.confrelid "
        "JOIN pg_namespace rn ON rn.oid = rc.relnamespace "
        "JOIN LATERAL unnest(con.conkey, con.confkey) WITH ORDINALITY "
        "AS k(attnum, refattnum, ord) ON true "
        "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum "
        "JOIN pg_attribute ra ON ra.attrelid = rc.oid "
        "AND ra.attnum = k.refattnum "
        f"WHERE con.contype = 'f' AND n.nspname NOT IN {SYSTEM_SCHEMAS} "
        "GROUP BY 1, 2, 3, 5, 6 ORDER BY 1, 2, 3"),
    "view_definitions": (
        "SELECT n.nspname, c.relname, "
        "CASE c.relkind WHEN 'v' THEN 'view' ELSE 'matview' END, "
        "regexp_replace(pg_get_viewdef(c.oid, false), '\\s+', ' ', 'g') "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        f"WHERE c.relkind IN ('v', 'm') AND n.nspname NOT IN {SYSTEM_SCHEMAS} "
        "ORDER BY 1, 2"),
    "view_dependencies": (
        "SELECT DISTINCT vn.nspname, v.relname, bn.nspname, b.relname "
        "FROM pg_depend d JOIN pg_rewrite r ON r.oid = d.objid "
        "JOIN pg_class v ON v.oid = r.ev_class AND v.relkind IN ('v', 'm') "
        "JOIN pg_namespace vn ON vn.oid = v.relnamespace "
        "JOIN pg_class b ON b.oid = d.refobjid "
        "AND b.relkind IN ('r', 'p', 'v', 'm') "
        "JOIN pg_namespace bn ON bn.oid = b.relnamespace "
        "WHERE d.classid = 'pg_rewrite'::regclass "
        "AND d.refclassid = 'pg_class'::regclass "
        f"AND v.oid <> b.oid AND vn.nspname NOT IN {SYSTEM_SCHEMAS} "
        "ORDER BY 1, 2, 3, 4"),
}


def _int_or_none(cell):
    return int(cell) if cell not in ("", None) else None


def _split_cols(cell):
    return [c for c in cell.split(",") if c]


def _bool(cell):
    return cell == "t"


def quote_ident(schema, name):
    esc_schema = schema.replace('"', '""')
    esc_name = name.replace('"', '""')
    return f'"{esc_schema}"."{esc_name}"'


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
        # v0.2.0 sections; optional in raw so v0.1.0 fixtures stay valid.
        "columns": [
            {"schema": r[0], "table": r[1], "name": r[2],
             "ordinal": int(r[3]), "data_type": r[4], "udt_name": r[5],
             "nullable": r[6] == "YES", "default": r[7] or None,
             "precision": _int_or_none(r[8]), "scale": _int_or_none(r[9]),
             "max_length": _int_or_none(r[10]),
             "element_type": r[11] or None}
            for r in raw.get("columns", [])],
        "primary_keys": [
            {"schema": r[0], "table": r[1], "name": r[2],
             "columns": _split_cols(r[3])}
            for r in raw.get("primary_keys", [])],
        "foreign_keys": [
            {"schema": r[0], "table": r[1], "name": r[2],
             "columns": _split_cols(r[3]), "ref_schema": r[4],
             "ref_table": r[5], "ref_columns": _split_cols(r[6])}
            for r in raw.get("foreign_keys", [])],
        "view_definitions": [
            {"schema": r[0], "name": r[1], "kind": r[2], "definition": r[3]}
            for r in raw.get("view_definitions", [])],
        "view_dependencies": [
            {"view": f"{r[0]}.{r[1]}", "base": f"{r[2]}.{r[3]}"}
            for r in raw.get("view_dependencies", [])],
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
                qualified = quote_ident(table["schema"], table["name"])
                exact = pg.query_rows(
                    ci, f"SELECT count(*) FROM {qualified}", readonly=True)
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
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"INVENTORY ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(["inventory"] + sys.argv[1:])

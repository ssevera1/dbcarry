"""Security inventory, diff, and Postgres role sync.

`security inventory` reads roles, memberships, schema, relation, and
column privileges, row-level security flags and policies, default
privileges, and security-barrier views from the PostgreSQL catalogs. It
runs read-only and reads no data rows. build_security_inventory is pure
so it can be unit tested from fixtures.

`security diff` compares two inventories on the fields that survive a
dump and restore, ignoring owner names and owner-derived rows because
restore changes ownership.

`security sync-roles` creates missing roles and memberships on a
Postgres target (pg_dump does not carry role attributes). It never emits
SUPERUSER and never sets passwords; the operator does that out of band.

Cloud targets: every query uses pg_roles and aclexplode/acldefault, which
do not need superuser. pg_authid is never read.
"""
import argparse
import json
import sys

from db_drift import pg

SYSTEM_SCHEMAS = "('pg_catalog', 'information_schema', 'pg_toast')"

POLICY_COMMANDS = {"r": "SELECT", "a": "INSERT", "w": "UPDATE",
                   "d": "DELETE", "*": "ALL"}

# The plan's queries, with one PG17 fix: acldefault takes a "char", so
# the relkind CASE is cast explicitly. psql output is one row per line,
# tab separated, so expression text has whitespace collapsed in SQL and
# booleans arrive as t/f.
QUERIES = {
    "roles": (
        "SELECT rolname, rolcanlogin, rolsuper, rolinherit, rolbypassrls, "
        "rolcreaterole, rolcreatedb "
        "FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ORDER BY 1"),
    "memberships": (
        "SELECT m.rolname, g.rolname, am.admin_option FROM pg_auth_members am "
        "JOIN pg_roles m ON m.oid = am.member "
        "JOIN pg_roles g ON g.oid = am.roleid "
        "WHERE m.rolname NOT LIKE 'pg\\_%' AND g.rolname NOT LIKE 'pg\\_%' "
        "ORDER BY 1, 2"),
    "schema_acl": (
        "SELECT n.nspname, pg_get_userbyid(n.nspowner), "
        "CASE WHEN a.grantee = 0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(a.grantee) END, "
        "a.privilege_type, a.is_grantable "
        "FROM pg_namespace n, "
        "aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a "
        f"WHERE n.nspname NOT IN {SYSTEM_SCHEMAS} ORDER BY 1, 3, 4"),
    "relation_acl": (
        "SELECT n.nspname, c.relname, "
        "CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'matview' "
        "WHEN 'S' THEN 'sequence' ELSE 'table' END, "
        "pg_get_userbyid(c.relowner), "
        "CASE WHEN a.grantee = 0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(a.grantee) END, "
        "a.privilege_type, a.is_grantable "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, "
        "aclexplode(coalesce(c.relacl, acldefault("
        "(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END)::\"char\", "
        "c.relowner))) a "
        "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S') "
        f"AND n.nspname NOT IN {SYSTEM_SCHEMAS} ORDER BY 1, 2, 5, 6"),
    "column_acl": (
        "SELECT n.nspname, c.relname, at.attname, "
        "CASE WHEN a.grantee = 0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(a.grantee) END, a.privilege_type "
        "FROM pg_attribute at JOIN pg_class c ON c.oid = at.attrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace, "
        "aclexplode(at.attacl) a "
        "WHERE at.attacl IS NOT NULL AND at.attnum > 0 "
        "AND NOT at.attisdropped "
        f"AND n.nspname NOT IN {SYSTEM_SCHEMAS} ORDER BY 1, 2, 3, 4, 5"),
    "rls": (
        "SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relkind IN ('r', 'p') "
        "AND (c.relrowsecurity OR c.relforcerowsecurity) "
        f"AND n.nspname NOT IN {SYSTEM_SCHEMAS} ORDER BY 1, 2"),
    "policies": (
        "SELECT n.nspname, c.relname, p.polname, p.polcmd, p.polpermissive, "
        "coalesce((SELECT string_agg(CASE WHEN r = 0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(r) END, ',' ORDER BY r) "
        "FROM unnest(p.polroles) r), 'PUBLIC'), "
        "coalesce(regexp_replace(pg_get_expr(p.polqual, p.polrelid), "
        "'\\s+', ' ', 'g'), ''), "
        "coalesce(regexp_replace(pg_get_expr(p.polwithcheck, p.polrelid), "
        "'\\s+', ' ', 'g'), '') "
        "FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        f"WHERE n.nspname NOT IN {SYSTEM_SCHEMAS} ORDER BY 1, 2, 3"),
    "default_acl": (
        "SELECT pg_get_userbyid(d.defaclrole), coalesce(n.nspname, ''), "
        "CASE d.defaclobjtype WHEN 'r' THEN 'table' WHEN 'S' THEN 'sequence' "
        "WHEN 'f' THEN 'function' WHEN 'T' THEN 'type' "
        "WHEN 'n' THEN 'schema' END, "
        "CASE WHEN a.grantee = 0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(a.grantee) END, a.privilege_type "
        "FROM pg_default_acl d "
        "LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace, "
        "aclexplode(d.defaclacl) a ORDER BY 1, 2, 3, 4, 5"),
    "security_barrier_views": (
        "SELECT n.nspname, c.relname FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        f"WHERE c.relkind = 'v' AND n.nspname NOT IN {SYSTEM_SCHEMAS} "
        "AND EXISTS (SELECT 1 FROM unnest(c.reloptions) o "
        "WHERE lower(o) ~ '^security_barrier=(true|on|yes|1|t)$') "
        "ORDER BY 1, 2"),
}


def _bool(cell):
    return cell == "t"


def _text_or_none(cell):
    return cell if cell else None


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


# ------------------------------------------------------------------ inventory

def build_security_inventory(raw):
    """Shape raw psql rows into the security inventory (spec section 6)."""
    memberships = sorted(
        ({"member": r[0], "group": r[1], "admin_option": _bool(r[2])}
         for r in raw.get("memberships", [])),
        key=lambda m: (m["member"], m["group"]))
    member_of = {}
    for m in memberships:
        member_of.setdefault(m["member"], []).append(m["group"])
    return {
        "roles": [
            {"name": r[0], "can_login": _bool(r[1]), "superuser": _bool(r[2]),
             "inherit": _bool(r[3]), "bypass_rls": _bool(r[4]),
             "create_role": _bool(r[5]), "create_db": _bool(r[6]),
             "member_of": sorted(member_of.get(r[0], []))}
            for r in raw.get("roles", [])],
        "memberships": memberships,
        "schema_privileges": [
            {"schema": r[0], "owner": r[1], "grantee": r[2],
             "privilege": r[3], "grantable": _bool(r[4])}
            for r in raw.get("schema_acl", [])],
        "relation_privileges": [
            {"schema": r[0], "relation": r[1], "kind": r[2], "owner": r[3],
             "grantee": r[4], "privilege": r[5], "grantable": _bool(r[6])}
            for r in raw.get("relation_acl", [])],
        "column_privileges": [
            {"schema": r[0], "relation": r[1], "column": r[2],
             "grantee": r[3], "privilege": r[4]}
            for r in raw.get("column_acl", [])],
        "rls": [
            {"schema": r[0], "relation": r[1], "enabled": _bool(r[2]),
             "forced": _bool(r[3])}
            for r in raw.get("rls", [])],
        "policies": [
            {"schema": r[0], "relation": r[1], "name": r[2],
             "command": POLICY_COMMANDS.get(r[3], r[3]),
             "permissive": _bool(r[4]),
             "roles": [x for x in r[5].split(",") if x],
             "using": _text_or_none(r[6]), "with_check": _text_or_none(r[7])}
            for r in raw.get("policies", [])],
        "default_privileges": [
            {"for_role": r[0], "schema": _text_or_none(r[1]),
             "object_type": r[2], "grantee": r[3], "privilege": r[4]}
            for r in raw.get("default_acl", [])],
        "security_barrier_views": [
            f"{r[0]}.{r[1]}" for r in raw.get("security_barrier_views", [])],
    }


def take_inventory(ci):
    """Run every catalog query read-only and shape the result."""
    raw = {key: pg.query_rows(ci, sql, readonly=True)
           for key, sql in QUERIES.items()}
    return build_security_inventory(raw)


# ----------------------------------------------------------------------- diff

_ROLE_FIELDS = ("name", "can_login", "inherit", "bypass_rls")
_MEMBER_FIELDS = ("member", "group")
_SCHEMA_FIELDS = ("schema", "grantee", "privilege", "grantable")
_RELATION_FIELDS = ("schema", "relation", "kind", "grantee", "privilege",
                    "grantable")
_COLUMN_FIELDS = ("schema", "relation", "column", "grantee", "privilege")
_RLS_FIELDS = ("schema", "relation", "enabled", "forced")
_POLICY_FIELDS = ("schema", "relation", "name", "command", "permissive",
                  "roles", "using", "with_check")
DIFF_SECTIONS = ("roles", "memberships", "schema_privileges",
                 "relation_privileges", "column_privileges", "rls",
                 "policies")


def synced_role_names(security_inv):
    """Roles the sync creates: everything except postgres, superusers,
    and pg_* system roles."""
    return {r["name"] for r in security_inv.get("roles", [])
            if r["name"] != "postgres" and not r.get("superuser")
            and not r["name"].startswith("pg_")}


def _memberships(security_inv):
    """(member, group) pairs; falls back to roles[].member_of when the
    inventory carries no memberships section."""
    rows = security_inv.get("memberships")
    if rows is None:
        rows = [{"member": r["name"], "group": g}
                for r in security_inv.get("roles", [])
                for g in r.get("member_of", [])]
    return rows


def _key(row, fields):
    return tuple(tuple(row[f]) if isinstance(row[f], list) else row[f]
                 for f in fields)


def _unkey(key, fields):
    return {f: (sorted(v) if isinstance(v, tuple) else v)
            for f, v in zip(fields, key)}


def _compare(left_rows, right_rows, fields):
    left = {_key(r, fields) for r in left_rows}
    right = {_key(r, fields) for r in right_rows}
    return {"missing": [_unkey(k, fields) for k in sorted(left - right,
                                                          key=repr)],
            "extra": [_unkey(k, fields) for k in sorted(right - left,
                                                        key=repr)]}


def _comparable(inv):
    """Rows of one inventory that a dump and restore should reproduce."""
    synced = synced_role_names(inv)
    return {
        "roles": [r for r in inv.get("roles", []) if r["name"] in synced],
        "memberships": [m for m in _memberships(inv)
                        if m["member"] in synced and m["group"] in synced],
        "schema_privileges": [r for r in inv.get("schema_privileges", [])
                              if r["grantee"] != r["owner"]],
        "relation_privileges": [r for r in inv.get("relation_privileges", [])
                                if r["grantee"] != r["owner"]],
        "column_privileges": inv.get("column_privileges", []),
        "rls": inv.get("rls", []),
        "policies": inv.get("policies", []),
    }


def diff_security(left, right, ignore_roles=False):
    """Compare two inventories on the fields that survive dump and restore.

    Owner-derived privilege rows (grantee equal to the owner) are dropped
    because restore changes ownership; grantor names are never part of
    the inventory. Roles compare can_login, inherit, and bypass_rls only,
    and only for roles the sync would create.
    """
    fields = {
        "roles": _ROLE_FIELDS, "memberships": _MEMBER_FIELDS,
        "schema_privileges": _SCHEMA_FIELDS,
        "relation_privileges": _RELATION_FIELDS,
        "column_privileges": _COLUMN_FIELDS, "rls": _RLS_FIELDS,
        "policies": _POLICY_FIELDS,
    }
    lc, rc = _comparable(left), _comparable(right)
    report = {section: _compare(lc[section], rc[section], fields[section])
              for section in DIFF_SECTIONS}
    checked = [s for s in DIFF_SECTIONS if not (ignore_roles and s == "roles")]
    report["match"] = not any(
        report[s]["missing"] or report[s]["extra"] for s in checked)
    return report


# ------------------------------------------------------------------ role sync

def _role_attrs(role, allow_bypassrls, explicit_no_bypass):
    parts = ["LOGIN" if role["can_login"] else "NOLOGIN",
             "INHERIT" if role["inherit"] else "NOINHERIT"]
    if allow_bypassrls:
        if role["bypass_rls"]:
            parts.append("BYPASSRLS")
        elif explicit_no_bypass:
            parts.append("NOBYPASSRLS")
    return " ".join(parts)


def sync_roles_sql(security_inv, allow_bypassrls=True):
    """Idempotent statements that reproduce roles and memberships.

    Never emits SUPERUSER, CREATEROLE, CREATEDB, or a password. Roles
    named postgres and superusers are skipped, as are memberships that
    involve a skipped role. With allow_bypassrls=False no BYPASSRLS or
    NOBYPASSRLS clause is emitted at all, because setting that attribute
    needs superuser and cloud targets refuse it.
    """
    synced = synced_role_names(security_inv)
    roles = sorted((r for r in security_inv.get("roles", [])
                    if r["name"] in synced), key=lambda r: r["name"])
    creates, alters, grants = [], [], []
    for role in roles:
        name = _quote(role["name"])
        creates.append(
            f"DO $$ BEGIN CREATE ROLE {name} "
            f"{_role_attrs(role, allow_bypassrls, False)}; "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;")
        alters.append(
            f"ALTER ROLE {name} {_role_attrs(role, allow_bypassrls, True)};")
    for m in sorted(_memberships(security_inv),
                    key=lambda m: (m["member"], m["group"])):
        if m["member"] not in synced or m["group"] not in synced:
            continue
        admin = " WITH ADMIN OPTION" if m.get("admin_option") else ""
        grants.append(
            f"DO $$ BEGIN GRANT {_quote(m['group'])} TO "
            f"{_quote(m['member'])}{admin}; "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;")
    return creates + alters + grants


# ------------------------------------------------------------------------ CLI

def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _summary(inv):
    return (f"{len(inv['roles'])} roles, {len(inv['memberships'])} "
            f"memberships, {len(inv['relation_privileges'])} relation "
            f"privileges, {len(inv['column_privileges'])} column privileges, "
            f"{len(inv['rls'])} rls tables, {len(inv['policies'])} policies")


def main(argv):
    parser = argparse.ArgumentParser(prog="dbdrift.py security")
    sub = parser.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("inventory", help="read-only security inventory")
    pg.add_conn_args(p)
    p.add_argument("--out", default=None)

    p = sub.add_parser("diff", help="compare two inventories; exit 1 on "
                                    "any difference")
    p.add_argument("--left", required=True)
    p.add_argument("--right", required=True)
    p.add_argument("--ignore-roles", action="store_true",
                   help="ignore role attribute differences (memberships "
                        "are still compared)")

    p = sub.add_parser("sync-roles", help="create roles and memberships "
                                          "on a Postgres target")
    p.add_argument("--from", dest="source_file", required=True,
                   metavar="SECURITY_JSON")
    pg.add_conn_args(p)
    p.add_argument("--no-bypassrls", action="store_true",
                   help="never emit BYPASSRLS (cloud targets)")
    p.add_argument("--dry-run", action="store_true",
                   help="print the statements, execute nothing")
    args = parser.parse_args(argv[1:])

    try:
        if args.verb == "inventory":
            inv = take_inventory(pg.conn_from_args(args))
            text = json.dumps(inv, indent=2)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(text + "\n")
                print(f"wrote {args.out} ({_summary(inv)})")
            else:
                print(text)
            return 0
        if args.verb == "diff":
            report = diff_security(_load_json(args.left),
                                   _load_json(args.right),
                                   ignore_roles=args.ignore_roles)
            print(json.dumps(report, indent=2))
            return 0 if report["match"] else 1
        # sync-roles
        inv = _load_json(args.source_file)
        statements = sync_roles_sql(
            inv, allow_bypassrls=not args.no_bypassrls)
        if args.dry_run:
            for stmt in statements:
                print(stmt)
            return 0
        ci = pg.conn_from_args(args)
        for stmt in statements:
            pg.run_sql(ci, stmt)
        print(f"executed {len(statements)} statements on "
              f"{ci['host']}:{ci['port']}/{ci['dbname']}")
        return 0
    except pg.PgError as exc:
        print(f"SECURITY ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"SECURITY ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(["security"] + sys.argv[1:])

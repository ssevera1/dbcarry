"""Security inventory, diff, and Postgres role sync.

`security inventory` reads roles, memberships, schema, relation, and
column privileges, row-level security flags and policies, default
privileges, and security-barrier views from the PostgreSQL catalogs. It
runs read-only and reads no data rows. build_security_inventory is pure
so it can be unit tested from fixtures.

Shape notes (spec section 6):

- memberships[] rows carry admin_option plus the PostgreSQL 16
  per-membership inherit_option and set_option. Older servers have no
  such options and the inventory records true for both, which is what
  those servers enforce. roles[].member_of stays a plain list of names.
- default_privileges[].schema is null for a global default ACL (ALTER
  DEFAULT PRIVILEGES without IN SCHEMA), which applies in every schema.
- policies[].roles is sorted by name.

`security diff` compares two inventories on the fields that survive a
dump and restore, ignoring owner names and owner-derived rows because
restore changes ownership. Target roles the source never mentioned
(platform roles on a managed service, for example) are listed under
unsynced_target_roles and do not affect the match.

`security sync-roles` creates missing roles and memberships on a
Postgres target (pg_dump does not carry role attributes). It never emits
SUPERUSER and never sets passwords; the operator does that out of band.
Role and group names are quoted identifiers inside DO blocks tagged
$dbdrift$; a name containing that tag is refused rather than let it end
the block early.

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

# Separator for a role list aggregated into one psql cell. A role name
# may legally contain a comma, so the query joins with the ASCII unit
# separator, which neither psql nor str.splitlines treats specially.
LIST_SEP = "\x1f"

# Dollar-quote tag for the DO blocks sync-roles emits. Quoting an
# identifier does not protect against a name that contains the tag
# itself, so sync_roles_sql refuses such names.
DOLLAR_TAG = "$dbdrift$"

# PostgreSQL 16 added per-membership INHERIT and SET options
# (pg_auth_members.inherit_option and set_option).
MEMBERSHIP_OPTIONS_MIN_VERSION = 160000
VERSION_QUERY = "SELECT current_setting('server_version_num')"

_MEMBERSHIPS_TAIL = (
    "FROM pg_auth_members am "
    "JOIN pg_roles m ON m.oid = am.member "
    "JOIN pg_roles g ON g.oid = am.roleid "
    "WHERE m.rolname NOT LIKE 'pg\\_%' AND g.rolname NOT LIKE 'pg\\_%' "
    "ORDER BY 1, 2")

# The plan's queries, with one PG17 fix: acldefault takes a "char", so
# the relkind CASE is cast explicitly. psql output is one row per line,
# tab separated, so expression text has whitespace collapsed in SQL and
# booleans arrive as t/f. The memberships entry is the pre-16 form;
# take_inventory swaps in memberships_query(version) for 16+ servers.
QUERIES = {
    "roles": (
        "SELECT rolname, rolcanlogin, rolsuper, rolinherit, rolbypassrls, "
        "rolcreaterole, rolcreatedb "
        "FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ORDER BY 1"),
    "memberships": (
        "SELECT m.rolname, g.rolname, am.admin_option " + _MEMBERSHIPS_TAIL),
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
        "ELSE pg_get_userbyid(r) END, E'\\x1f' ORDER BY r) "
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
    # The server parses the option value, so every boolean spelling it
    # accepts (true, on, yes, y, t, tr, 1, ...) is matched.
    "security_barrier_views": (
        "SELECT n.nspname, c.relname FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        f"WHERE c.relkind = 'v' AND n.nspname NOT IN {SYSTEM_SCHEMAS} "
        "AND EXISTS (SELECT 1 FROM unnest(c.reloptions) o "
        "WHERE o LIKE 'security_barrier=%' "
        "AND split_part(o, '=', 2)::boolean) "
        "ORDER BY 1, 2"),
}


def memberships_query(version_num):
    """Membership query for a server version number such as 170005.

    From 16 on the row also carries inherit_option and set_option.
    """
    if version_num >= MEMBERSHIP_OPTIONS_MIN_VERSION:
        return ("SELECT m.rolname, g.rolname, am.admin_option, "
                "am.inherit_option, am.set_option " + _MEMBERSHIPS_TAIL)
    return QUERIES["memberships"]


def server_version_num(ci):
    """Read server_version_num (for example 170005), read-only."""
    rows = pg.query_rows(ci, VERSION_QUERY, readonly=True)
    return int(rows[0][0])


def _bool(cell):
    return cell == "t"


def _text_or_none(cell):
    return cell if cell else None


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


# ------------------------------------------------------------------ inventory

def _membership_row(r):
    """Three cells from a pre-16 server, five from 16 on."""
    return {"member": r[0], "group": r[1], "admin_option": _bool(r[2]),
            "inherit_option": _bool(r[3]) if len(r) > 3 else True,
            "set_option": _bool(r[4]) if len(r) > 4 else True}


def build_security_inventory(raw):
    """Shape raw psql rows into the security inventory (spec section 6)."""
    memberships = sorted(
        (_membership_row(r) for r in raw.get("memberships", [])),
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
             "roles": sorted(x for x in r[5].split(LIST_SEP) if x),
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
    """Run every catalog query read-only and shape the result.

    The server version is read first so the memberships query can ask
    for the 16+ per-membership options only where they exist.
    """
    version = server_version_num(ci)
    raw = {}
    for key, sql in QUERIES.items():
        if key == "memberships":
            sql = memberships_query(version)
        raw[key] = pg.query_rows(ci, sql, readonly=True)
    return build_security_inventory(raw)


# ----------------------------------------------------------------------- diff

_ROLE_FIELDS = ("name", "can_login", "inherit", "bypass_rls")
_MEMBER_FIELDS = ("member", "group", "inherit_option", "set_option")
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

# Values assumed for fields an older inventory file or a spec-shaped
# fixture may omit.
_FIELD_DEFAULTS = {"grantable": False, "inherit_option": True,
                   "set_option": True}


def synced_role_names(security_inv):
    """Roles the sync creates: everything except postgres, superusers,
    and pg_* system roles."""
    return {r["name"] for r in security_inv.get("roles", [])
            if r["name"] != "postgres" and not r.get("superuser")
            and not r["name"].startswith("pg_")}


def _memberships(security_inv):
    """Membership rows; falls back to roles[].member_of when the
    inventory carries no memberships section."""
    rows = security_inv.get("memberships")
    if rows is None:
        rows = [{"member": r["name"], "group": g}
                for r in security_inv.get("roles", [])
                for g in r.get("member_of", [])]
    return rows


def _key(row, fields):
    """Comparison key; list-valued fields compare as sets."""
    values = []
    for f in fields:
        v = row.get(f, _FIELD_DEFAULTS.get(f))
        values.append(tuple(sorted(v)) if isinstance(v, list) else v)
    return tuple(values)


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
                              if r.get("grantee") != r.get("owner")],
        "relation_privileges": [r for r in inv.get("relation_privileges", [])
                                if r.get("grantee") != r.get("owner")],
        "column_privileges": inv.get("column_privileges", []),
        "rls": inv.get("rls", []),
        "policies": inv.get("policies", []),
    }


def diff_security(left, right, ignore_roles=False):
    """Compare two inventories on the fields that survive dump and restore.

    Owner-derived privilege rows (grantee equal to the owner) are dropped
    because restore changes ownership; grantor names are never part of
    the inventory. Roles compare can_login, inherit, and bypass_rls only,
    and only for roles the sync would create. Memberships compare
    (member, group) plus the 16+ inherit and set options.

    Roles on the right that the left never mentions (platform roles on a
    managed target) are not "extra": they and their memberships are
    reported under unsynced_target_roles, which does not affect match.
    """
    fields = {
        "roles": _ROLE_FIELDS, "memberships": _MEMBER_FIELDS,
        "schema_privileges": _SCHEMA_FIELDS,
        "relation_privileges": _RELATION_FIELDS,
        "column_privileges": _COLUMN_FIELDS, "rls": _RLS_FIELDS,
        "policies": _POLICY_FIELDS,
    }
    lc, rc = _comparable(left), _comparable(right)
    source_names = {r["name"] for r in left.get("roles", [])}
    unsynced = sorted(r["name"] for r in rc["roles"]
                      if r["name"] not in source_names)
    rc["roles"] = [r for r in rc["roles"] if r["name"] in source_names]
    rc["memberships"] = [m for m in rc["memberships"]
                         if m["member"] in source_names
                         and m["group"] in source_names]
    report = {section: _compare(lc[section], rc[section], fields[section])
              for section in DIFF_SECTIONS}
    report["unsynced_target_roles"] = unsynced
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


def _tf(value):
    return "TRUE" if value else "FALSE"


def _check_name(name):
    if DOLLAR_TAG in name:
        raise ValueError(
            f"role name {name!r} contains the dollar-quote tag {DOLLAR_TAG}; "
            "refusing to build sync statements for it")


def _do_block(statement):
    return (f"DO {DOLLAR_TAG} BEGIN {statement}; "
            f"EXCEPTION WHEN duplicate_object THEN NULL; END {DOLLAR_TAG};")


def membership_option_rows(security_inv):
    """Memberships with inherit or set switched off. A pre-16 target has
    no such options and replays these as ordinary inheriting grants."""
    return [m for m in _memberships(security_inv)
            if not m.get("inherit_option", True)
            or not m.get("set_option", True)]


def sync_roles_sql(security_inv, allow_bypassrls=True,
                   membership_options=True):
    """Idempotent statements that reproduce roles and memberships.

    Never emits SUPERUSER, CREATEROLE, CREATEDB, or a password. Roles
    named postgres and superusers are skipped, as are memberships that
    involve a skipped role. With allow_bypassrls=False no BYPASSRLS or
    NOBYPASSRLS clause is emitted at all, because setting that attribute
    needs superuser and managed targets refuse it.

    membership_options=True emits every GRANT as WITH ADMIN x, INHERIT y,
    SET z (PostgreSQL 16+ syntax, which also updates the options of an
    existing membership). False emits the pre-16 form, WITH ADMIN OPTION
    only, which cannot express INHERIT FALSE or SET FALSE.

    Raises ValueError for a role or group name containing DOLLAR_TAG.
    """
    synced = synced_role_names(security_inv)
    roles = sorted((r for r in security_inv.get("roles", [])
                    if r["name"] in synced), key=lambda r: r["name"])
    creates, alters, grants = [], [], []
    for role in roles:
        _check_name(role["name"])
        name = _quote(role["name"])
        creates.append(_do_block(
            f"CREATE ROLE {name} "
            f"{_role_attrs(role, allow_bypassrls, False)}"))
        alters.append(
            f"ALTER ROLE {name} {_role_attrs(role, allow_bypassrls, True)};")
    for m in sorted(_memberships(security_inv),
                    key=lambda m: (m["member"], m["group"])):
        if m["member"] not in synced or m["group"] not in synced:
            continue
        _check_name(m["group"])
        _check_name(m["member"])
        if membership_options:
            opts = (f" WITH ADMIN {_tf(m.get('admin_option'))}, "
                    f"INHERIT {_tf(m.get('inherit_option', True))}, "
                    f"SET {_tf(m.get('set_option', True))}")
        else:
            opts = " WITH ADMIN OPTION" if m.get("admin_option") else ""
        grants.append(_do_block(
            f"GRANT {_quote(m['group'])} TO {_quote(m['member'])}{opts}"))
    return creates + alters + grants


# ------------------------------------------------------------------------ CLI

# memberships is optional on load because diff falls back to
# roles[].member_of (the spec's example document has no memberships key).
REQUIRED_SECTIONS = ("roles",) + tuple(
    s for s in DIFF_SECTIONS if s != "memberships")


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _load_inventory(path):
    """Load a security inventory document and check its top-level shape."""
    doc = _load_json(path)
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: expected a JSON object holding a security "
                         f"inventory, got {type(doc).__name__}")
    bad = [s for s in REQUIRED_SECTIONS if not isinstance(doc.get(s), list)]
    if "memberships" in doc and not isinstance(doc["memberships"], list):
        bad.append("memberships")
    if bad:
        raise ValueError(f"{path}: not a security inventory; missing or "
                         f"malformed sections: {', '.join(bad)}")
    return doc


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
                   help="never emit BYPASSRLS or NOBYPASSRLS; both need "
                        "superuser, so the playbook passes this for every "
                        "provider except local")
    p.add_argument("--dry-run", action="store_true",
                   help="print the statements, execute nothing; the target "
                        "version is not probed, so PostgreSQL 16+ GRANT "
                        "syntax is assumed")
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
            report = diff_security(_load_inventory(args.left),
                                   _load_inventory(args.right),
                                   ignore_roles=args.ignore_roles)
            print(json.dumps(report, indent=2))
            return 0 if report["match"] else 1
        # sync-roles
        inv = _load_inventory(args.source_file)
        if args.dry_run:
            for stmt in sync_roles_sql(
                    inv, allow_bypassrls=not args.no_bypassrls):
                print(stmt)
            return 0
        ci = pg.conn_from_args(args)
        version = server_version_num(ci)
        options = version >= MEMBERSHIP_OPTIONS_MIN_VERSION
        if not options:
            print(f"WARNING: target server_version_num {version} predates "
                  "per-membership INHERIT and SET options; emitting plain "
                  f"GRANT ({len(membership_option_rows(inv))} membership(s) "
                  "with those options switched off cannot be reproduced)",
                  file=sys.stderr)
        statements = sync_roles_sql(
            inv, allow_bypassrls=not args.no_bypassrls,
            membership_options=options)
        for stmt in statements:
            pg.run_sql(ci, stmt)
        print(f"executed {len(statements)} statements on "
              f"{ci['host']}:{ci['port']}/{ci['dbname']}")
        return 0
    except pg.PgError as exc:
        print(f"SECURITY ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError, TypeError,
            AttributeError) as exc:
        print(f"SECURITY ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(["security"] + sys.argv[1:])

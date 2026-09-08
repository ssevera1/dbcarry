import copy
import json

import pytest

from db_drift import pg, security
from db_drift.security import (build_security_inventory, diff_security,
                               sync_roles_sql)

SEP = security.LIST_SEP

# Raw rows as psql returns them: tab-separated cells, booleans as t/f,
# expression text already whitespace-collapsed by the query. Membership
# rows carry the PostgreSQL 16+ five-cell shape.
RAW = {
    "roles": [
        ["app_ro", "t", "f", "t", "f", "f", "f"],
        ["app_rw", "t", "f", "t", "f", "f", "f"],
        ["auditor", "t", "f", "f", "t", "f", "f"],
        ["postgres", "t", "t", "t", "t", "t", "t"],
        ["reporting", "f", "f", "t", "f", "f", "f"],
    ],
    "memberships": [["reporting", "app_ro", "f", "t", "t"],
                    ["auditor", "app_ro", "t", "t", "t"]],
    "schema_acl": [
        ["public", "pg_database_owner", "PUBLIC", "USAGE", "f"],
        ["public", "pg_database_owner", "pg_database_owner", "CREATE", "f"],
        ["public", "pg_database_owner", "pg_database_owner", "USAGE", "f"],
    ],
    "relation_acl": [
        ["public", "customers", "table", "postgres", "app_rw", "INSERT", "f"],
        ["public", "customers", "table", "postgres", "app_rw", "SELECT", "f"],
        ["public", "customers", "table", "postgres", "postgres", "INSERT", "f"],
        ["public", "customers", "table", "postgres", "postgres", "SELECT", "f"],
        ["public", "orders", "table", "postgres", "PUBLIC", "SELECT", "f"],
        ["public", "orders", "table", "postgres", "app_ro", "SELECT", "f"],
        ["public", "orders", "table", "postgres", "app_rw", "SELECT", "t"],
        ["public", "orders", "table", "postgres", "postgres", "SELECT", "f"],
        ["public", "orders_id_seq", "sequence", "postgres", "app_rw", "USAGE", "f"],
        ["public", "orders_id_seq", "sequence", "postgres", "postgres", "UPDATE", "f"],
        ["public", "recent_orders", "view", "postgres", "reporting", "SELECT", "f"],
        ["public", "sales_by_product", "matview", "postgres", "reporting", "SELECT", "f"],
    ],
    "column_acl": [
        ["public", "customers", "full_name", "app_ro", "SELECT"],
        ["public", "customers", "id", "app_ro", "SELECT"],
    ],
    "rls": [["public", "audit_log", "t", "t"], ["public", "orders", "t", "f"]],
    "policies": [
        ["public", "audit_log", "audit_self", "r", "t", "app_ro",
         "(actor = CURRENT_USER)", ""],
        ["public", "orders", "orders_all_rw", "*", "t", "app_rw", "true", ""],
        ["public", "orders", "orders_not_void", "r", "f", "PUBLIC",
         "(status <> 'void'::text)", "(status <> 'void'::text)"],
        ["public", "orders", "orders_region_eu", "r", "t", "reporting",
         "(region = 'eu'::text)", ""],
    ],
    "default_acl": [["postgres", "public", "table", "app_ro", "SELECT"],
                    ["postgres", "", "sequence", "app_rw", "USAGE"]],
    "security_barrier_views": [["public", "safe_orders"]],
}

PG17 = 170005
PG15 = 150000


def _inv():
    return build_security_inventory(copy.deepcopy(RAW))


# ------------------------------------------------------------ inventory shape

def test_roles_and_memberships():
    inv = _inv()
    roles = {r["name"]: r for r in inv["roles"]}
    assert set(roles) == {"app_ro", "app_rw", "auditor", "postgres", "reporting"}
    assert roles["app_ro"] == {
        "name": "app_ro", "can_login": True, "superuser": False,
        "inherit": True, "bypass_rls": False, "create_role": False,
        "create_db": False, "member_of": []}
    assert roles["postgres"]["superuser"] is True
    assert roles["postgres"]["bypass_rls"] is True
    assert roles["reporting"]["can_login"] is False
    assert roles["reporting"]["member_of"] == ["app_ro"]
    assert roles["auditor"]["inherit"] is False
    assert inv["memberships"] == [
        {"member": "auditor", "group": "app_ro", "admin_option": True,
         "inherit_option": True, "set_option": True},
        {"member": "reporting", "group": "app_ro", "admin_option": False,
         "inherit_option": True, "set_option": True}]


def test_membership_options_from_pg16_rows_and_pre16_rows():
    raw = copy.deepcopy(RAW)
    raw["memberships"] = [["reporting", "app_ro", "f", "f", "t"],
                          ["auditor", "app_ro", "t", "t", "f"]]
    mem = {m["member"]: m for m in build_security_inventory(raw)["memberships"]}
    assert mem["reporting"]["inherit_option"] is False
    assert mem["reporting"]["set_option"] is True
    assert mem["auditor"]["inherit_option"] is True
    assert mem["auditor"]["set_option"] is False
    # A pre-16 server returns three cells; the options default to true,
    # which is what such a server enforces.
    raw["memberships"] = [["reporting", "app_ro", "f"]]
    inv = build_security_inventory(raw)
    assert inv["memberships"] == [
        {"member": "reporting", "group": "app_ro", "admin_option": False,
         "inherit_option": True, "set_option": True}]
    assert inv["roles"][4]["member_of"] == ["app_ro"]


def test_schema_and_relation_privileges():
    inv = _inv()
    schema = inv["schema_privileges"]
    assert {"schema": "public", "owner": "pg_database_owner",
            "grantee": "PUBLIC", "privilege": "USAGE",
            "grantable": False} in schema
    rel = inv["relation_privileges"]
    assert {"schema": "public", "relation": "orders", "kind": "table",
            "owner": "postgres", "grantee": "PUBLIC", "privilege": "SELECT",
            "grantable": False} in rel
    assert {"schema": "public", "relation": "orders", "kind": "table",
            "owner": "postgres", "grantee": "app_rw", "privilege": "SELECT",
            "grantable": True} in rel
    kinds = {(r["relation"], r["kind"]) for r in rel}
    assert ("orders_id_seq", "sequence") in kinds
    assert ("recent_orders", "view") in kinds
    assert ("sales_by_product", "matview") in kinds
    # Owner rows from acldefault are kept in the inventory (diff drops them).
    assert any(r["grantee"] == "postgres" and r["relation"] == "customers"
               for r in rel)


def test_column_privileges_rls_policies():
    inv = _inv()
    assert inv["column_privileges"] == [
        {"schema": "public", "relation": "customers", "column": "full_name",
         "grantee": "app_ro", "privilege": "SELECT"},
        {"schema": "public", "relation": "customers", "column": "id",
         "grantee": "app_ro", "privilege": "SELECT"}]
    assert inv["rls"] == [
        {"schema": "public", "relation": "audit_log", "enabled": True,
         "forced": True},
        {"schema": "public", "relation": "orders", "enabled": True,
         "forced": False}]
    pols = {p["name"]: p for p in inv["policies"]}
    assert len(pols) == 4
    assert pols["orders_all_rw"] == {
        "schema": "public", "relation": "orders", "name": "orders_all_rw",
        "command": "ALL", "permissive": True, "roles": ["app_rw"],
        "using": "true", "with_check": None}
    assert pols["orders_region_eu"]["command"] == "SELECT"
    assert pols["orders_region_eu"]["using"] == "(region = 'eu'::text)"
    assert pols["orders_not_void"]["permissive"] is False
    assert pols["orders_not_void"]["roles"] == ["PUBLIC"]
    assert pols["orders_not_void"]["with_check"] == "(status <> 'void'::text)"
    assert pols["audit_self"]["roles"] == ["app_ro"]


def test_policy_command_map_and_multi_role():
    raw = copy.deepcopy(RAW)
    raw["policies"] = [
        ["public", "t", "p_ins", "a", "t", "reporting" + SEP + "app_rw",
         "", "(x > 0)"],
        ["public", "t", "p_upd", "w", "t", "app_rw", "(x > 0)", ""],
        ["public", "t", "p_del", "d", "t", "app_rw", "(x > 0)", ""],
    ]
    pols = {p["name"]: p for p in build_security_inventory(raw)["policies"]}
    assert pols["p_ins"]["command"] == "INSERT"
    # The query orders roles by OID; the inventory sorts them by name.
    assert pols["p_ins"]["roles"] == ["app_rw", "reporting"]
    assert pols["p_ins"]["using"] is None
    assert pols["p_ins"]["with_check"] == "(x > 0)"
    assert pols["p_upd"]["command"] == "UPDATE"
    assert pols["p_del"]["command"] == "DELETE"
    assert security.POLICY_COMMANDS["*"] == "ALL"


def test_policy_role_containing_comma_survives():
    raw = copy.deepcopy(RAW)
    raw["policies"] = [["public", "t", "p", "r", "t",
                        "team a,b" + SEP + "c", "true", ""]]
    pols = build_security_inventory(raw)["policies"]
    assert pols[0]["roles"] == ["c", "team a,b"]
    assert "E'\\x1f'" in security.QUERIES["policies"]
    assert "',' ORDER BY r" not in security.QUERIES["policies"]


def test_default_privileges_and_barrier_views():
    inv = _inv()
    assert inv["default_privileges"] == [
        {"for_role": "postgres", "schema": "public", "object_type": "table",
         "grantee": "app_ro", "privilege": "SELECT"},
        {"for_role": "postgres", "schema": None, "object_type": "sequence",
         "grantee": "app_rw", "privilege": "USAGE"}]
    assert inv["security_barrier_views"] == ["public.safe_orders"]


def test_missing_raw_sections_become_empty():
    inv = build_security_inventory({"roles": RAW["roles"]})
    for key in ("memberships", "schema_privileges", "relation_privileges",
                "column_privileges", "rls", "policies",
                "default_privileges", "security_barrier_views"):
        assert inv[key] == []
    assert inv["roles"][0]["member_of"] == []


def test_inventory_is_json_serializable():
    text = json.dumps(_inv())
    assert '"PUBLIC"' in text


# --------------------------------------------------------------------- diff

def test_diff_identical_matches():
    report = diff_security(_inv(), _inv())
    assert report["match"] is True
    assert report["unsynced_target_roles"] == []
    for key in ("roles", "memberships", "schema_privileges",
                "relation_privileges", "column_privileges", "rls",
                "policies"):
        assert report[key] == {"missing": [], "extra": []}


def test_diff_reports_missing_column_grant_and_extra_policy():
    left = _inv()
    raw = copy.deepcopy(RAW)
    raw["column_acl"] = [["public", "customers", "id", "app_ro", "SELECT"]]
    raw["policies"].append(
        ["public", "orders", "orders_extra", "r", "t", "app_ro", "true", ""])
    right = build_security_inventory(raw)
    report = diff_security(left, right)
    assert report["match"] is False
    assert report["column_privileges"]["missing"] == [
        {"schema": "public", "relation": "customers", "column": "full_name",
         "grantee": "app_ro", "privilege": "SELECT"}]
    assert report["column_privileges"]["extra"] == []
    assert [p["name"] for p in report["policies"]["extra"]] == ["orders_extra"]
    assert report["policies"]["missing"] == []
    assert report["relation_privileges"] == {"missing": [], "extra": []}


def test_diff_policy_role_order_is_irrelevant():
    # The catalog orders polroles by OID and sync-roles creates roles
    # alphabetically, so the same policy can list roles in a different
    # order on each side.
    raw_left = copy.deepcopy(RAW)
    raw_left["policies"] = [["public", "orders", "two_roles", "r", "t",
                             "reporting" + SEP + "app_rw", "true", ""]]
    raw_right = copy.deepcopy(RAW)
    raw_right["policies"] = [["public", "orders", "two_roles", "r", "t",
                              "app_rw" + SEP + "reporting", "true", ""]]
    report = diff_security(build_security_inventory(raw_left),
                           build_security_inventory(raw_right))
    assert report["match"] is True
    assert report["policies"] == {"missing": [], "extra": []}
    # Also for hand-built documents whose lists were never sorted.
    left = {"roles": [], "policies": [{"schema": "s", "relation": "t",
                                       "name": "p", "command": "SELECT",
                                       "permissive": True,
                                       "roles": ["b", "a"], "using": "true",
                                       "with_check": None}]}
    right = copy.deepcopy(left)
    right["policies"][0]["roles"] = ["a", "b"]
    assert diff_security(left, right)["match"] is True


def test_diff_ignores_owner_rows_and_owner_names():
    left = _inv()
    raw = copy.deepcopy(RAW)
    # Restore under a different owner: owner rows now name "migrator" and
    # the old owner rows for postgres are gone.
    raw["relation_acl"] = [
        [s, r, k, "migrator", "migrator" if g == "postgres" else g, p, gr]
        for s, r, k, o, g, p, gr in raw["relation_acl"]]
    raw["relation_acl"].append(
        ["public", "customers", "table", "migrator", "migrator",
         "TRUNCATE", "f"])
    raw["schema_acl"] = [
        ["public", "migrator", "PUBLIC", "USAGE", "f"],
        ["public", "migrator", "migrator", "CREATE", "f"],
        ["public", "migrator", "migrator", "USAGE", "f"],
    ]
    right = build_security_inventory(raw)
    report = diff_security(left, right)
    assert report["relation_privileges"] == {"missing": [], "extra": []}
    assert report["schema_privileges"] == {"missing": [], "extra": []}
    assert report["match"] is True


def test_diff_roles_compare_login_inherit_bypass_only():
    left = _inv()
    raw = copy.deepcopy(RAW)
    # create_role and superuser differences are not compared.
    raw["roles"] = [
        ["app_ro", "t", "f", "t", "f", "t", "t"],
        ["app_rw", "t", "f", "t", "f", "f", "f"],
        ["auditor", "t", "f", "f", "t", "f", "f"],
        ["postgres", "t", "f", "t", "f", "t", "t"],
        ["reporting", "f", "f", "t", "f", "f", "f"],
    ]
    right = build_security_inventory(raw)
    assert diff_security(left, right)["roles"] == {"missing": [], "extra": []}
    raw["roles"][4] = ["reporting", "t", "f", "t", "f", "f", "f"]
    raw["memberships"] = [["auditor", "app_ro", "t", "t", "t"]]
    report = diff_security(left, build_security_inventory(raw))
    assert report["match"] is False
    assert [r["name"] for r in report["roles"]["missing"]] == ["reporting"]
    assert [r["name"] for r in report["roles"]["extra"]] == ["reporting"]
    assert report["memberships"]["missing"] == [
        {"member": "reporting", "group": "app_ro", "inherit_option": True,
         "set_option": True}]


def test_diff_sees_membership_inherit_and_set_options():
    left = _inv()
    raw = copy.deepcopy(RAW)
    raw["memberships"] = [["reporting", "app_ro", "f", "f", "t"],
                          ["auditor", "app_ro", "t", "t", "t"]]
    report = diff_security(left, build_security_inventory(raw))
    assert report["match"] is False
    assert report["memberships"]["missing"] == [
        {"member": "reporting", "group": "app_ro", "inherit_option": True,
         "set_option": True}]
    assert report["memberships"]["extra"] == [
        {"member": "reporting", "group": "app_ro", "inherit_option": False,
         "set_option": True}]
    # An inventory written before the options existed compares as true.
    old = _inv()
    for m in old["memberships"]:
        del m["inherit_option"], m["set_option"]
    assert diff_security(old, _inv())["match"] is True


def test_diff_rls_flags():
    left = _inv()
    raw = copy.deepcopy(RAW)
    raw["rls"] = [["public", "orders", "t", "f"]]
    report = diff_security(left, build_security_inventory(raw))
    assert report["rls"]["missing"] == [
        {"schema": "public", "relation": "audit_log", "enabled": True,
         "forced": True}]


def test_diff_scopes_target_platform_roles_out_of_extra():
    left = _inv()
    raw = copy.deepcopy(RAW)
    raw["roles"] += [["cloudsqlsuperuser", "t", "f", "t", "f", "t", "t"],
                     ["cloudsqliamuser", "t", "f", "t", "f", "f", "f"]]
    raw["memberships"] += [["cloudsqliamuser", "cloudsqlsuperuser", "f", "t", "t"],
                           ["app_rw", "cloudsqlsuperuser", "f", "t", "t"]]
    report = diff_security(left, build_security_inventory(raw))
    assert report["match"] is True
    assert report["roles"] == {"missing": [], "extra": []}
    assert report["memberships"] == {"missing": [], "extra": []}
    assert report["unsynced_target_roles"] == ["cloudsqliamuser",
                                               "cloudsqlsuperuser"]
    # A membership between roles the source knows is still an extra.
    raw["memberships"].append(["app_rw", "app_ro", "f", "t", "t"])
    report = diff_security(left, build_security_inventory(raw))
    assert report["match"] is False
    assert report["memberships"]["extra"] == [
        {"member": "app_rw", "group": "app_ro", "inherit_option": True,
         "set_option": True}]


def test_diff_accepts_spec_shaped_inventory():
    # Spec section 6 shows schema_privileges without owner or grantable
    # and no memberships section at all.
    spec = {
        "roles": [{"name": "app_ro", "can_login": True, "superuser": False,
                   "inherit": True, "bypass_rls": False,
                   "create_role": False, "create_db": False,
                   "member_of": ["reporting"]},
                  {"name": "reporting", "can_login": False,
                   "superuser": False, "inherit": True, "bypass_rls": False,
                   "create_role": False, "create_db": False,
                   "member_of": []}],
        "schema_privileges": [{"schema": "public", "grantee": "app_ro",
                               "privilege": "USAGE"}],
        "relation_privileges": [], "column_privileges": [], "rls": [],
        "policies": [],
    }
    report = diff_security(spec, copy.deepcopy(spec))
    assert report["match"] is True
    other = copy.deepcopy(spec)
    other["schema_privileges"] = []
    report = diff_security(spec, other)
    assert report["schema_privileges"]["missing"] == [
        {"schema": "public", "grantee": "app_ro", "privilege": "USAGE",
         "grantable": False}]
    other["roles"][0]["member_of"] = []
    assert diff_security(spec, other)["memberships"]["missing"] == [
        {"member": "app_ro", "group": "reporting", "inherit_option": True,
         "set_option": True}]


# --------------------------------------------------------------- role sync

def test_sync_roles_sql_skips_superusers_and_postgres():
    sql = sync_roles_sql(_inv())
    joined = "\n".join(sql)
    assert "SUPERUSER" not in joined
    assert '"postgres"' not in joined
    created = [s for s in sql if "CREATE ROLE" in s]
    names = [s.split('CREATE ROLE "')[1].split('"')[0] for s in created]
    assert names == ["app_ro", "app_rw", "auditor", "reporting"]


def test_sync_roles_sql_attributes():
    sql = sync_roles_sql(_inv())
    create = {s.split('CREATE ROLE "')[1].split('"')[0]: s
              for s in sql if "CREATE ROLE" in s}
    assert 'CREATE ROLE "reporting" NOLOGIN INHERIT;' in create["reporting"]
    assert "duplicate_object" in create["reporting"]
    assert create["reporting"].startswith("DO $dbdrift$ BEGIN")
    assert create["reporting"].endswith("END $dbdrift$;")
    assert 'CREATE ROLE "app_ro" LOGIN INHERIT;' in create["app_ro"]
    assert 'CREATE ROLE "auditor" LOGIN NOINHERIT BYPASSRLS;' \
        in create["auditor"]
    alters = [s for s in sql if s.startswith("ALTER ROLE")]
    assert 'ALTER ROLE "reporting" NOLOGIN INHERIT NOBYPASSRLS;' in alters
    assert 'ALTER ROLE "auditor" LOGIN NOINHERIT BYPASSRLS;' in alters


def test_sync_roles_sql_memberships_after_roles():
    sql = sync_roles_sql(_inv())
    grants = [s for s in sql if "GRANT" in s]
    assert len(grants) == 2
    assert any('GRANT "app_ro" TO "reporting" WITH ADMIN FALSE, '
               'INHERIT TRUE, SET TRUE;' in s for s in grants)
    assert any('GRANT "app_ro" TO "auditor" WITH ADMIN TRUE, '
               'INHERIT TRUE, SET TRUE;' in s for s in grants)
    assert all("duplicate_object" in s for s in grants)
    last_create = max(i for i, s in enumerate(sql) if "CREATE ROLE" in s)
    first_grant = min(i for i, s in enumerate(sql) if "GRANT" in s)
    assert last_create < first_grant


def test_sync_roles_sql_membership_options_forms():
    raw = copy.deepcopy(RAW)
    raw["memberships"] = [["reporting", "app_ro", "f", "f", "t"],
                          ["auditor", "app_ro", "t", "t", "f"]]
    inv = build_security_inventory(raw)
    grants = [s for s in sync_roles_sql(inv) if "GRANT" in s]
    assert any('GRANT "app_ro" TO "reporting" WITH ADMIN FALSE, '
               'INHERIT FALSE, SET TRUE;' in s for s in grants)
    assert any('GRANT "app_ro" TO "auditor" WITH ADMIN TRUE, '
               'INHERIT TRUE, SET FALSE;' in s for s in grants)
    # Pre-16 targets get the plain form, which cannot carry the options.
    grants = [s for s in sync_roles_sql(inv, membership_options=False)
              if "GRANT" in s]
    assert any('GRANT "app_ro" TO "reporting";' in s for s in grants)
    assert any('GRANT "app_ro" TO "auditor" WITH ADMIN OPTION;' in s
               for s in grants)
    assert all("INHERIT" not in s for s in grants)
    assert [m["member"] for m in security.membership_option_rows(inv)] == [
        "auditor", "reporting"]
    assert security.membership_option_rows(_inv()) == []


def test_sync_roles_sql_without_bypassrls():
    sql = sync_roles_sql(_inv(), allow_bypassrls=False)
    assert all("BYPASSRLS" not in s for s in sql)
    assert any('CREATE ROLE "auditor" LOGIN NOINHERIT;' in s for s in sql)
    assert 'ALTER ROLE "reporting" NOLOGIN INHERIT;' in sql


def test_sync_roles_skips_memberships_involving_skipped_roles():
    raw = copy.deepcopy(RAW)
    raw["memberships"].append(["postgres", "app_ro", "f", "t", "t"])
    raw["memberships"].append(["app_rw", "postgres", "f", "t", "t"])
    sql = sync_roles_sql(build_security_inventory(raw))
    assert not any('"postgres"' in s for s in sql)


def test_sync_roles_quotes_names_with_dollar_dollar_and_double_quote():
    raw = copy.deepcopy(RAW)
    raw["roles"] = [['x$$; DROP ROLE app_ro; --', "t", "f", "t", "f", "f", "f"],
                    ['sa"y', "f", "f", "t", "f", "f", "f"]]
    raw["memberships"] = [['x$$; DROP ROLE app_ro; --', 'sa"y', "f", "t", "t"]]
    sql = sync_roles_sql(build_security_inventory(raw))
    blocks = [s for s in sql if s.startswith("DO ")]
    assert len(blocks) == 3
    for s in blocks:
        # The block is delimited by the distinctive tag, so $$ inside a
        # quoted identifier never ends it early.
        assert s.startswith("DO $dbdrift$ BEGIN ")
        assert s.endswith("; EXCEPTION WHEN duplicate_object THEN NULL; "
                          "END $dbdrift$;")
        assert s.count("$dbdrift$") == 2
    joined = "\n".join(sql)
    assert 'CREATE ROLE "x$$; DROP ROLE app_ro; --" LOGIN INHERIT;' in joined
    assert 'CREATE ROLE "sa""y" NOLOGIN INHERIT;' in joined
    assert 'ALTER ROLE "sa""y" NOLOGIN INHERIT NOBYPASSRLS;' in sql
    assert 'GRANT "sa""y" TO "x$$; DROP ROLE app_ro; --" WITH ADMIN FALSE' \
        in sql[-1]


def test_sync_roles_refuses_names_containing_the_tag(tmp_path, capsys):
    raw = copy.deepcopy(RAW)
    raw["roles"].append(["evil$dbdrift$; DROP ROLE app_ro; --", "t", "f",
                         "t", "f", "f", "f"])
    inv = build_security_inventory(raw)
    with pytest.raises(ValueError) as exc:
        sync_roles_sql(inv)
    assert "$dbdrift$" in str(exc.value)
    # A group name carrying the tag is refused too, even when the role
    # list itself is clean.
    inv = _inv()
    inv["memberships"].append({"member": "app_rw",
                               "group": "g$dbdrift$", "admin_option": False})
    inv["roles"].append({"name": "g$dbdrift$", "can_login": False,
                         "superuser": False, "inherit": True,
                         "bypass_rls": False, "create_role": False,
                         "create_db": False, "member_of": []})
    with pytest.raises(ValueError):
        sync_roles_sql(inv)
    src = tmp_path / "security.json"
    src.write_text(json.dumps(inv), encoding="utf-8")
    rc = security.main(["security", "sync-roles", "--from", str(src),
                        "--port", "5", "--dbname", "target", "--dry-run"])
    assert rc == 1
    err = capsys.readouterr().err
    assert err.startswith("SECURITY ERROR") and "$dbdrift$" in err


# ---------------------------------------------------------------------- CLI

def _write(path, inv):
    path.write_text(json.dumps(inv), encoding="utf-8")
    return str(path)


def test_cli_diff_exit_codes(tmp_path, capsys):
    left = _write(tmp_path / "a.json", _inv())
    raw = copy.deepcopy(RAW)
    raw["column_acl"] = []
    right = _write(tmp_path / "b.json", build_security_inventory(raw))
    assert security.main(["security", "diff", "--left", left,
                          "--right", left]) == 0
    assert json.loads(capsys.readouterr().out)["match"] is True
    assert security.main(["security", "diff", "--left", left,
                          "--right", right]) == 1
    assert json.loads(capsys.readouterr().out)["match"] is False


def test_cli_diff_prints_report(tmp_path, capsys):
    left = _write(tmp_path / "a.json", _inv())
    raw = copy.deepcopy(RAW)
    raw["column_acl"] = []
    right = _write(tmp_path / "b.json", build_security_inventory(raw))
    rc = security.main(["security", "diff", "--left", left, "--right", right])
    report = json.loads(capsys.readouterr().out)
    assert rc == 1 and report["match"] is False
    assert len(report["column_privileges"]["missing"]) == 2
    assert report["unsynced_target_roles"] == []


def test_cli_diff_ignore_roles(tmp_path):
    left = _write(tmp_path / "a.json", _inv())
    raw = copy.deepcopy(RAW)
    raw["roles"][0] = ["app_ro", "f", "f", "t", "f", "f", "f"]
    right = _write(tmp_path / "b.json", build_security_inventory(raw))
    assert security.main(["security", "diff", "--left", left,
                          "--right", right]) == 1
    assert security.main(["security", "diff", "--left", left,
                          "--right", right, "--ignore-roles"]) == 0


def test_cli_diff_missing_file_is_error(tmp_path, capsys):
    rc = security.main(["security", "diff", "--left", str(tmp_path / "x"),
                        "--right", str(tmp_path / "y")])
    assert rc == 1
    assert "SECURITY ERROR" in capsys.readouterr().err


def test_cli_rejects_wrong_top_level_shape(tmp_path, capsys):
    good = _write(tmp_path / "good.json", _inv())
    empty = _write(tmp_path / "empty.json", {})
    listed = _write(tmp_path / "list.json", [])
    partial = _inv()
    del partial["policies"]
    partial_path = _write(tmp_path / "partial.json", partial)
    for bad, marker in ((empty, "roles"), (listed, "list"),
                        (partial_path, "policies")):
        rc = security.main(["security", "diff", "--left", good,
                            "--right", bad])
        out, err = capsys.readouterr()
        assert rc == 1 and out == ""
        assert err.startswith("SECURITY ERROR: ValueError")
        assert bad in err and marker in err
    rc = security.main(["security", "sync-roles", "--from", listed,
                        "--port", "5", "--dbname", "target", "--dry-run"])
    out, err = capsys.readouterr()
    assert rc == 1 and out == "" and "SECURITY ERROR" in err
    # An empty object never counts as a match.
    rc = security.main(["security", "diff", "--left", empty,
                        "--right", empty])
    assert rc == 1


def test_cli_sync_roles_dry_run_executes_nothing(tmp_path, capsys, monkeypatch):
    src = _write(tmp_path / "security.json", _inv())

    def boom(*args, **kwargs):
        raise AssertionError("must not run SQL in dry-run")
    monkeypatch.setattr(pg, "run_sql", boom)
    rc = security.main(["security", "sync-roles", "--from", src,
                        "--port", "5", "--dbname", "target", "--dry-run"])
    assert rc == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines == sync_roles_sql(_inv())


def _fake_sync_target(monkeypatch, version, calls):
    def fake_run_sql(ci, sql, readonly=False, writable=False):
        calls.append((ci["dbname"], sql, readonly, writable))
        return f"{version}\n" if sql == security.VERSION_QUERY else ""
    monkeypatch.setattr(pg, "run_sql", fake_run_sql)


def test_cli_sync_roles_runs_each_statement_not_readonly(tmp_path, capsys,
                                                         monkeypatch):
    src = _write(tmp_path / "security.json", _inv())
    calls = []
    _fake_sync_target(monkeypatch, PG17, calls)
    rc = security.main(["security", "sync-roles", "--from", src,
                        "--port", "5", "--dbname", "target",
                        "--no-bypassrls"])
    assert rc == 0
    probe, statements = calls[0], calls[1:]
    assert probe[1] == security.VERSION_QUERY and probe[2] is True
    assert [c[1] for c in statements] == sync_roles_sql(
        _inv(), allow_bypassrls=False)
    assert all(c[0] == "target" and c[2] is False and c[3] is False
               for c in statements)
    out, err = capsys.readouterr()
    assert "executed" in out and "WARNING" not in err


def test_cli_sync_roles_pre16_target_warns_and_uses_plain_grant(
        tmp_path, capsys, monkeypatch):
    raw = copy.deepcopy(RAW)
    raw["memberships"] = [["reporting", "app_ro", "f", "f", "t"],
                          ["auditor", "app_ro", "t", "t", "t"]]
    inv = build_security_inventory(raw)
    src = _write(tmp_path / "security.json", inv)
    calls = []
    _fake_sync_target(monkeypatch, PG15, calls)
    rc = security.main(["security", "sync-roles", "--from", src,
                        "--port", "5", "--dbname", "target"])
    assert rc == 0
    assert [c[1] for c in calls[1:]] == sync_roles_sql(
        inv, membership_options=False)
    err = capsys.readouterr().err
    assert err.startswith("WARNING") and "150000" in err and "1 membership" in err


def test_cli_sync_roles_reports_pg_error(tmp_path, capsys, monkeypatch):
    src = _write(tmp_path / "security.json", _inv())

    def fail(ci, sql, readonly=False, writable=False):
        raise pg.PgError("psql failed (1): permission denied")
    monkeypatch.setattr(pg, "run_sql", fail)
    rc = security.main(["security", "sync-roles", "--from", src,
                        "--port", "5", "--dbname", "target"])
    assert rc == 1
    assert "SECURITY ERROR" in capsys.readouterr().err


def _fake_inventory_source(monkeypatch, version, seen, membership_rows):
    def fake_query_rows(ci, sql, readonly=False, writable=False):
        seen.append((sql, readonly))
        if sql == security.VERSION_QUERY:
            return [[str(version)]]
        if sql == security.memberships_query(version):
            return copy.deepcopy(membership_rows)
        key = next(k for k, q in security.QUERIES.items()
                   if q == sql and k != "memberships")
        return copy.deepcopy(RAW[key])
    monkeypatch.setattr(pg, "query_rows", fake_query_rows)


def test_cli_inventory_writes_json(tmp_path, capsys, monkeypatch):
    seen = []
    _fake_inventory_source(monkeypatch, PG17, seen, RAW["memberships"])
    out = tmp_path / "security.json"
    rc = security.main(["security", "inventory", "--port", "5",
                        "--dbname", "retail", "--out", str(out)])
    assert rc == 0
    assert seen and all(readonly for _, readonly in seen)
    assert len(seen) == len(security.QUERIES) + 1
    assert seen[0][0] == security.VERSION_QUERY
    assert security.memberships_query(PG17) in [s for s, _ in seen]
    text = out.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert json.loads(text) == _inv()
    assert "wrote" in capsys.readouterr().out


def test_cli_inventory_pre16_source_uses_admin_only_query(capsys, monkeypatch):
    seen = []
    _fake_inventory_source(monkeypatch, PG15, seen,
                           [["reporting", "app_ro", "f"]])
    rc = security.main(["security", "inventory", "--port", "5",
                        "--dbname", "retail"])
    assert rc == 0
    queries = [s for s, _ in seen]
    assert security.QUERIES["memberships"] in queries
    assert security.memberships_query(PG17) not in queries
    inv = json.loads(capsys.readouterr().out)
    assert inv["memberships"] == [
        {"member": "reporting", "group": "app_ro", "admin_option": False,
         "inherit_option": True, "set_option": True}]


def test_cli_inventory_reports_pg_error(capsys, monkeypatch):
    def fail(ci, sql, readonly=False, writable=False):
        raise pg.PgError("psql failed (2): connection refused")
    monkeypatch.setattr(pg, "query_rows", fail)
    rc = security.main(["security", "inventory", "--port", "5",
                        "--dbname", "retail"])
    assert rc == 1
    assert capsys.readouterr().err.startswith("SECURITY ERROR")


def test_queries_collapse_whitespace_and_skip_system_schemas():
    assert set(security.QUERIES) == {
        "roles", "memberships", "schema_acl", "relation_acl", "column_acl",
        "rls", "policies", "default_acl", "security_barrier_views"}
    assert "regexp_replace" in security.QUERIES["policies"]
    for key in ("schema_acl", "relation_acl", "column_acl", "rls",
                "policies", "security_barrier_views"):
        assert security.SYSTEM_SCHEMAS in security.QUERIES[key]
    assert "pg_authid" not in "\n".join(security.QUERIES.values())
    assert "inherit_option" not in security.QUERIES["memberships"]


def test_memberships_query_by_server_version():
    old = security.memberships_query(PG15)
    new = security.memberships_query(security.MEMBERSHIP_OPTIONS_MIN_VERSION)
    assert old == security.QUERIES["memberships"]
    assert "am.inherit_option, am.set_option" in new
    assert new.endswith("ORDER BY 1, 2") and old.endswith("ORDER BY 1, 2")
    assert security.memberships_query(PG17) == new


def test_security_barrier_query_lets_the_server_parse_the_boolean():
    q = security.QUERIES["security_barrier_views"]
    assert "o LIKE 'security_barrier=%'" in q
    assert "split_part(o, '=', 2)::boolean" in q
    assert "~" not in q

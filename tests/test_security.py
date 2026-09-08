import copy
import json

import pytest

from db_drift import pg, security
from db_drift.security import (build_security_inventory, diff_security,
                               sync_roles_sql)

# Raw rows as psql returns them: tab-separated cells, booleans as t/f,
# expression text already whitespace-collapsed by the query.
RAW = {
    "roles": [
        ["app_ro", "t", "f", "t", "f", "f", "f"],
        ["app_rw", "t", "f", "t", "f", "f", "f"],
        ["auditor", "t", "f", "f", "t", "f", "f"],
        ["postgres", "t", "t", "t", "t", "t", "t"],
        ["reporting", "f", "f", "t", "f", "f", "f"],
    ],
    "memberships": [["reporting", "app_ro", "f"], ["auditor", "app_ro", "t"]],
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
        {"member": "auditor", "group": "app_ro", "admin_option": True},
        {"member": "reporting", "group": "app_ro", "admin_option": False}]


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
        ["public", "t", "p_ins", "a", "t", "app_rw,reporting", "", "(x > 0)"],
        ["public", "t", "p_upd", "w", "t", "app_rw", "(x > 0)", ""],
        ["public", "t", "p_del", "d", "t", "app_rw", "(x > 0)", ""],
    ]
    pols = {p["name"]: p for p in build_security_inventory(raw)["policies"]}
    assert pols["p_ins"]["command"] == "INSERT"
    assert pols["p_ins"]["roles"] == ["app_rw", "reporting"]
    assert pols["p_ins"]["using"] is None
    assert pols["p_ins"]["with_check"] == "(x > 0)"
    assert pols["p_upd"]["command"] == "UPDATE"
    assert pols["p_del"]["command"] == "DELETE"
    assert security.POLICY_COMMANDS["*"] == "ALL"


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
    raw["memberships"] = [["auditor", "app_ro", "t"]]
    report = diff_security(left, build_security_inventory(raw))
    assert report["match"] is False
    assert [r["name"] for r in report["roles"]["missing"]] == ["reporting"]
    assert [r["name"] for r in report["roles"]["extra"]] == ["reporting"]
    assert report["memberships"]["missing"] == [
        {"member": "reporting", "group": "app_ro"}]


def test_diff_rls_flags():
    left = _inv()
    raw = copy.deepcopy(RAW)
    raw["rls"] = [["public", "orders", "t", "f"]]
    report = diff_security(left, build_security_inventory(raw))
    assert report["rls"]["missing"] == [
        {"schema": "public", "relation": "audit_log", "enabled": True,
         "forced": True}]


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
    assert create["reporting"].startswith("DO $$ BEGIN")
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
    assert any('GRANT "app_ro" TO "reporting";' in s for s in grants)
    assert any('GRANT "app_ro" TO "auditor" WITH ADMIN OPTION;' in s
               for s in grants)
    assert all("duplicate_object" in s for s in grants)
    last_create = max(i for i, s in enumerate(sql) if "CREATE ROLE" in s)
    first_grant = min(i for i, s in enumerate(sql) if "GRANT" in s)
    assert last_create < first_grant


def test_sync_roles_sql_without_bypassrls():
    sql = sync_roles_sql(_inv(), allow_bypassrls=False)
    assert all("BYPASSRLS" not in s for s in sql)
    assert any('CREATE ROLE "auditor" LOGIN NOINHERIT;' in s for s in sql)


def test_sync_roles_skips_memberships_involving_skipped_roles():
    raw = copy.deepcopy(RAW)
    raw["memberships"].append(["postgres", "app_ro", "f"])
    raw["memberships"].append(["app_rw", "postgres", "f"])
    sql = sync_roles_sql(build_security_inventory(raw))
    assert not any('"postgres"' in s for s in sql)


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


def test_cli_sync_roles_runs_each_statement_writable(tmp_path, capsys,
                                                     monkeypatch):
    src = _write(tmp_path / "security.json", _inv())
    calls = []

    def fake_run_sql(ci, sql, readonly=False, writable=False):
        calls.append((ci["dbname"], sql, readonly, writable))
        return ""
    monkeypatch.setattr(pg, "run_sql", fake_run_sql)
    rc = security.main(["security", "sync-roles", "--from", src,
                        "--port", "5", "--dbname", "target",
                        "--no-bypassrls"])
    assert rc == 0
    assert [c[1] for c in calls] == sync_roles_sql(_inv(), allow_bypassrls=False)
    assert all(c[0] == "target" and c[2] is False for c in calls)
    assert "executed" in capsys.readouterr().out


def test_cli_sync_roles_reports_pg_error(tmp_path, capsys, monkeypatch):
    src = _write(tmp_path / "security.json", _inv())

    def fail(ci, sql, readonly=False, writable=False):
        raise pg.PgError("psql failed (1): permission denied")
    monkeypatch.setattr(pg, "run_sql", fail)
    rc = security.main(["security", "sync-roles", "--from", src,
                        "--port", "5", "--dbname", "target"])
    assert rc == 1
    assert "SECURITY ERROR" in capsys.readouterr().err


def test_cli_inventory_writes_json(tmp_path, capsys, monkeypatch):
    seen = []

    def fake_query_rows(ci, sql, readonly=False, writable=False):
        seen.append(readonly)
        key = next(k for k, q in security.QUERIES.items() if q == sql)
        return copy.deepcopy(RAW[key])
    monkeypatch.setattr(pg, "query_rows", fake_query_rows)
    out = tmp_path / "security.json"
    rc = security.main(["security", "inventory", "--port", "5",
                        "--dbname", "retail", "--out", str(out)])
    assert rc == 0
    assert seen and all(seen)
    assert len(seen) == len(security.QUERIES)
    text = out.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert json.loads(text) == _inv()
    assert "wrote" in capsys.readouterr().out


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

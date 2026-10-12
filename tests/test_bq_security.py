import copy
import gzip
import json
from pathlib import Path

import pytest

from db_carry import bq_backend as bb
from db_carry import bq_security as bs
from db_carry import bq_types, config, pg

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT = "proj"
RW = "group:retail-app-rw@example.com"
RO = "group:retail-app-ro@example.com"
REPORTING = "group:retail-reporting@example.com"
ADMIN = "user:operator@example.com"
SUPER = "user:dba@example.com"
EVERYONE = "group:everyone@example.com"

STATE_FILE = "state" + ".json"   # spelled indirectly for the guard hook

PRINCIPAL_MAP = {"roles": {
    "app_rw": {"principal": RW, "probe_service_account": ""},
    "app_ro": {"principal": RO, "probe_service_account": ""},
    "reporting": {"principal": REPORTING, "probe_service_account": ""},
}}

BQ_CFG = {
    "mode": "emulated", "project": PROJECT, "location": "US",
    "dataset_map": {"public": "retail"},
    "principal_map": "security/principal-map.yaml",
    "admin_principal": ADMIN, "public_principal": "",
    "column_security": "policy_tags", "binding_granularity": "auto",
    "gcs_bucket": "", "migration": "demo", "dbname": "retail",
}

IDENTITY_SQL = "(actor = SESSION_USER())"
TENANT_USING = "(tenant_id = (current_setting('app.tenant'::text))::integer)"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def demo_sec():
    return load_fixture("demo-security.json")


@pytest.fixture
def demo_inv():
    return load_fixture("demo-inventory.json")


def demo_plan(sec, inv, cfg=None, pmap=None, resolutions=None):
    return bs.plan_security(sec, inv, cfg or BQ_CFG, pmap or PRINCIPAL_MAP,
                            resolutions)


def codes(plan):
    return {f["code"] for f in plan["findings"]}


def findings(plan, code):
    return [f for f in plan["findings"] if f["code"] == code]


def bindings_for(plan, member):
    return [b for b in plan["bindings"] if b["member"] == member]


def policy_tuples(plan):
    return [(p["dataset"], p["table"], p["name"], p["filter"],
             p["confidence"]) for p in plan["row_policies"]]


# --------------------------------------------------------- hand fixtures

def role(name, superuser=False, inherit=True, bypass=False, login=True,
         member_of=()):
    return {"name": name, "can_login": login, "superuser": superuser,
            "inherit": inherit, "bypass_rls": bypass, "create_role": False,
            "create_db": False, "member_of": sorted(member_of)}


def rel(relation, grantee, privilege, kind="table", schema="public",
        owner="postgres"):
    return {"schema": schema, "relation": relation, "kind": kind,
            "owner": owner, "grantee": grantee, "privilege": privilege,
            "grantable": False}


def policy(relation, name, roles, using, command="SELECT", permissive=True,
           with_check=None, schema="public"):
    return {"schema": schema, "relation": relation, "name": name,
            "command": command, "permissive": permissive,
            "roles": sorted(roles), "using": using, "with_check": with_check}


def column(table, name, ordinal, data_type="text", udt="text", nullable=False,
           schema="public"):
    return {"schema": schema, "table": table, "name": name,
            "ordinal": ordinal, "data_type": data_type, "udt_name": udt,
            "nullable": nullable, "default": None, "precision": None,
            "scale": None, "max_length": None, "element_type": None}


def rls(relation, forced=False, schema="public"):
    return {"schema": schema, "relation": relation, "enabled": True,
            "forced": forced}


def small_inventory():
    """Two tables and one view over both, in schema public."""
    return {
        "server": {"version": "17", "wal_level": "logical",
                   "encoding": "UTF8"},
        "tables": [
            {"schema": "public", "name": "orders", "rows": 3, "bytes": 1,
             "has_pk": True, "replica_identity": "d"},
            {"schema": "public", "name": "customers", "rows": 2, "bytes": 1,
             "has_pk": True, "replica_identity": "d"}],
        "sequences": [], "views": ["public.recent_orders"], "matviews": [],
        "extensions": [], "roles": [], "counts": {"indexes": 0,
                                                  "constraints": 0},
        "columns": [
            column("orders", "id", 1, "bigint", "int8"),
            column("orders", "region", 2),
            column("orders", "status", 3),
            column("orders", "tenant_id", 4, "integer", "int4"),
            column("customers", "id", 1, "bigint", "int8"),
            column("customers", "email", 2),
            column("customers", "full_name", 3),
        ],
        "primary_keys": [], "foreign_keys": [],
        "view_definitions": [
            {"schema": "public", "name": "recent_orders", "kind": "view",
             "definition": "SELECT o.id, c.email FROM orders o JOIN "
                           "customers c ON c.id = o.customer_id"}],
        "view_dependencies": [
            {"view": "public.recent_orders", "base": "public.orders"},
            {"view": "public.recent_orders", "base": "public.customers"}],
    }


def small_security(**overrides):
    sec = {
        "roles": [role("app_ro"), role("app_rw"), role("reporting",
                                                        login=False)],
        "memberships": [],
        "schema_privileges": [
            {"schema": "public", "owner": "pg_database_owner",
             "grantee": "PUBLIC", "privilege": "USAGE", "grantable": False}],
        "relation_privileges": [
            rel("orders", "app_ro", "SELECT"),
            rel("orders", "app_rw", "SELECT"),
            rel("orders", "app_rw", "INSERT"),
            rel("orders", "app_rw", "UPDATE"),
            rel("orders", "app_rw", "DELETE"),
            rel("customers", "app_ro", "SELECT"),
            rel("customers", "app_rw", "SELECT"),
            rel("recent_orders", "reporting", "SELECT", kind="view"),
        ],
        "column_privileges": [],
        "rls": [],
        "policies": [],
        "default_privileges": [],
        "security_barrier_views": [],
    }
    sec.update(overrides)
    return sec


def membership(member, group, inherit=True):
    return {"member": member, "group": group, "admin_option": False,
            "inherit_option": inherit, "set_option": True}


# --------------------------------------------------- effective privileges

def test_effective_privileges_flattens_membership(demo_sec):
    eff = bs.effective_privileges(demo_sec)
    assert set(eff) == {"app_ro", "app_rw", "postgres", "reporting"}
    rep = eff["reporting"]
    assert rep["inherits_from"] == ["app_ro"]
    # reporting's own grant plus everything app_ro holds
    assert "SELECT" in rep["relations"]["public.recent_orders"]
    assert rep["relations"]["public.orders"] == {"SELECT"}
    assert rep["relations"]["public.audit_log"] == {"SELECT"}
    assert set(rep["columns"]["public.customers"]) == {
        "id", "full_name", "created_at"}
    assert rep["columns"]["public.customers"]["id"] == {"SELECT"}
    # PUBLIC's schema USAGE is folded into every role
    for name in eff:
        assert eff[name]["schemas"]["public"] >= {"USAGE"}
    assert eff["app_ro"]["inherits_from"] == []
    assert eff["app_rw"]["relations"]["public.orders"] == {
        "SELECT", "INSERT", "UPDATE", "DELETE"}
    assert eff["app_rw"]["relations"]["public.orders_id_seq"] == {
        "SELECT", "USAGE"}
    assert eff["postgres"]["superuser"] is True
    assert eff["app_ro"]["superuser"] is False
    assert eff["postgres"]["bypass_rls"] is True


def test_effective_privileges_transitive_and_noinherit():
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"),
               role("reporting", login=False, member_of=["app_ro"]),
               role("analyst", member_of=["reporting"]),
               role("auditor", inherit=False, member_of=["app_rw"])],
        memberships=[membership("reporting", "app_ro"),
                     membership("analyst", "reporting"),
                     membership("auditor", "app_rw")])
    eff = bs.effective_privileges(sec)
    assert eff["analyst"]["inherits_from"] == ["app_ro", "reporting"]
    assert eff["analyst"]["relations"]["public.orders"] == {"SELECT"}
    assert eff["analyst"]["relations"]["public.recent_orders"] == {"SELECT"}
    # NOINHERIT with an unknown server version: the conservative rule
    # (membership gives SET ROLE only, nothing is flattened)
    assert eff["auditor"]["inherits_from"] == []
    assert "public.orders" not in eff["auditor"]["relations"]
    # on a pre-16 server the role attribute decides
    inv = small_inventory()
    inv["server"]["version"] = "15.6"
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    warn = findings(plan, "noinherit_not_flattened")
    assert len(warn) == 1 and warn[0]["severity"] == "WARNING"
    assert warn[0]["subject"] == "auditor"
    assert plan["effective"]["auditor"] == {}
    # on 16+ the membership's own inherit option decides, and this one is
    # on, so auditor inherits app_rw although the role says NOINHERIT
    plan = bs.plan_security(sec, small_inventory(), BQ_CFG, PRINCIPAL_MAP)
    assert not findings(plan, "noinherit_not_flattened")
    assert plan["effective"]["auditor"]["public.orders"] == [
        "DELETE", "INSERT", "SELECT", "UPDATE"]
    assert bs.effective_privileges(sec, server_version="17.5")["auditor"][
        "inherits_from"] == ["app_rw"]
    assert bs.effective_privileges(sec, server_version="15")["auditor"][
        "inherits_from"] == []


def test_membership_inherit_option_false_is_not_flattened():
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"),
               role("reporting", login=False, member_of=["app_ro"])],
        memberships=[membership("reporting", "app_ro", inherit=False)])
    eff = bs.effective_privileges(sec)
    assert eff["reporting"]["inherits_from"] == []
    assert "public.orders" not in eff["reporting"]["relations"]
    plan = bs.plan_security(sec, small_inventory(), BQ_CFG, PRINCIPAL_MAP)
    assert findings(plan, "noinherit_not_flattened")[0]["subject"] == \
        "reporting"


def test_effective_privileges_without_memberships_section():
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"),
               role("reporting", login=False, member_of=["app_ro"])])
    del sec["memberships"]
    eff = bs.effective_privileges(sec)
    assert eff["reporting"]["inherits_from"] == ["app_ro"]
    assert eff["reporting"]["relations"]["public.orders"] == {"SELECT"}


# ----------------------------------------------------- readable columns

def test_readable_and_restricted_columns(demo_sec, demo_inv):
    eff = bs.effective_privileges(demo_sec)
    readable = bs.readable_columns(eff, demo_inv)
    cust = readable["public.customers"]
    assert cust["app_ro"] == {"id", "full_name", "created_at"}
    assert cust["reporting"] == {"id", "full_name", "created_at"}
    assert cust["app_rw"] == {"id", "email", "full_name", "created_at"}
    # superusers bypass column privileges and do not shape the analysis
    assert "postgres" not in cust
    assert readable["public.orders"]["app_ro"] == {
        "id", "customer_id", "status", "ordered_at", "region"}
    restricted = bs.restricted_columns(readable, demo_inv)
    assert restricted == {"public.customers": {"email": frozenset({"app_rw"})}}


def test_restricted_columns_groups_by_reader_set():
    inv = small_inventory()
    sec = small_security(
        relation_privileges=[
            rel("customers", "app_rw", "SELECT"),
            rel("customers", "reporting", "SELECT"),
        ],
        column_privileges=[
            {"schema": "public", "relation": "customers", "column": "id",
             "grantee": "app_ro", "privilege": "SELECT"}])
    eff = bs.effective_privileges(sec)
    readable = bs.readable_columns(eff, inv)
    restricted = bs.restricted_columns(readable, inv)
    assert restricted["public.customers"] == {
        "email": frozenset({"app_rw", "reporting"}),
        "full_name": frozenset({"app_rw", "reporting"})}
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert [t["name"] for t in plan["policy_tags"]] == [
        "customers__email_and_1_more"]
    tag = plan["policy_tags"][0]
    assert [c["column"] for c in tag["columns"]] == ["email", "full_name"]
    assert [r["member"] for r in tag["readers"]] == [RW, REPORTING]


# ----------------------------------------------------------- demo plan

def test_plan_demo_principals_and_bindings(demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    assert plan["principals"] == {"app_ro": RO, "app_rw": RW,
                                  "reporting": REPORTING}
    assert plan["taxonomy"] == {"display_name": "dbcarry_demo",
                                "activated": ["FINE_GRAINED_ACCESS_CONTROL"]}
    assert plan["datasets"] == {"retail": {"source_schema": "public"}}
    assert plan["project"] == PROJECT and plan["mode"] == "emulated"
    # app_ro reads every relation in the dataset: one dataset binding
    ro = bindings_for(plan, RO)
    assert [(b["scope"], b["resource"], b["role"]) for b in ro] == [
        ("dataset", "retail", bs.ROLE_VIEWER),
        ("project", PROJECT, bs.ROLE_JOBUSER)]
    # reporting inherits app_ro and reads the two views directly
    rep = bindings_for(plan, REPORTING)
    assert [(b["scope"], b["resource"], b["role"]) for b in rep] == [
        ("dataset", "retail", bs.ROLE_VIEWER),
        ("project", PROJECT, bs.ROLE_JOBUSER)]
    # app_rw writes the five tables and only reads the two views
    rw = bindings_for(plan, RW)
    table_roles = {b["resource"]: b["role"] for b in rw
                   if b["scope"] == "table"}
    assert table_roles == {
        "retail.audit_log": bs.ROLE_EDITOR, "retail.customers": bs.ROLE_EDITOR,
        "retail.order_items": bs.ROLE_EDITOR, "retail.orders": bs.ROLE_EDITOR,
        "retail.products": bs.ROLE_EDITOR,
        "retail.recent_orders": bs.ROLE_VIEWER,
        "retail.sales_by_product": bs.ROLE_VIEWER}
    assert [b for b in rw if b["scope"] == "project"] == [
        {"scope": "project", "resource": PROJECT, "role": bs.ROLE_JOBUSER,
         "member": RW, "source_role": "app_rw",
         "reason": "needed to run queries"}]
    # nothing for the unmapped superuser
    assert all(b["source_role"] != "postgres" for b in plan["bindings"])
    assert not findings(plan, "unmapped_role")
    assert findings(plan, "superuser_unmapped")[0]["subject"] == "postgres"
    # deterministic order
    keys = [(b["scope"], b["resource"], b["role"], b["member"])
            for b in plan["bindings"]]
    assert keys == sorted(keys)
    assert plan["effective"]["reporting"]["public.customers"] == [
        "SELECT(created_at, full_name, id)"]
    assert plan["effective"]["app_rw"]["public.orders"] == [
        "DELETE", "INSERT", "SELECT", "UPDATE"]


def test_plan_demo_policy_tags(demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    assert plan["policy_tags"] == [{
        "name": "customers__email",
        "columns": [{"dataset": "retail", "table": "customers",
                     "column": "email"}],
        "readers": [{"member": RW, "source_role": "app_rw"}],
        "source_columns": ["public.customers.email"],
        "description": "dbcarry: public.customers.email readable by app_rw"}]
    assert plan["masking"] == []


def test_plan_demo_row_policies(demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    assert policy_tuples(plan) == [
        ("retail", "audit_log", "rls_app_ro", IDENTITY_SQL, "auto"),
        ("retail", "audit_log", "rls_app_rw", "TRUE", "auto"),
        ("retail", "audit_log", "rls_reporting", IDENTITY_SQL, "auto"),
        ("retail", "orders", "rls_app_rw", "TRUE", "auto"),
        ("retail", "orders", "rls_reporting", "(region = 'eu')", "auto"),
    ]
    by_name = {(p["table"], p["name"]): p for p in plan["row_policies"]}
    rep = by_name[("audit_log", "rls_reporting")]
    assert rep["members"] == [REPORTING]
    assert rep["source_roles"] == ["reporting"]
    assert [s["name"] for s in rep["source_policies"]] == ["audit_self"]
    assert rep["source_policies"][0]["using"] == "(actor = CURRENT_USER)"
    assert rep["source_policies"][0]["via"] == "app_ro"
    assert rep["source_policies"][0]["sql"] == IDENTITY_SQL
    assert any("SESSION_USER()" in n for n in rep["notes"])
    assert any("SESSION_USER" in n for n in plan["identity_notes"])
    eu = by_name[("orders", "rls_reporting")]
    assert eu["source_policies"][0]["name"] == "orders_region_eu"
    assert eu["source_policies"][0]["via"] == "reporting"
    assert eu["notes"] == []
    # app_ro reads orders but no policy names it: no rows, as on PostgreSQL
    denied = findings(plan, "rls_denies_role")
    assert [(f["subject"], f["severity"]) for f in denied] == [
        ("public.orders/app_ro", "INFO")]
    assert findings(plan, "identity_predicate")


def test_plan_demo_authorized_views_and_findings(demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    assert plan["authorized_views"] == [
        {"view": "retail.recent_orders", "dataset": "retail"}]
    seen = codes(plan)
    for code in ("superuser_unmapped", "rls_denies_role", "sequence_unmapped",
                 "view_write_unmapped", "default_privileges_note",
                 "identity_predicate", "authorized_view",
                 "public_schema_usage", "ownership_not_mapped",
                 "privilege_unmapped"):
        assert code in seen, code
    for code in ("unmapped_role", "public_unmapped", "rls_deny_all",
                 "translation_review", "widened_by_granularity",
                 "editor_widens"):
        assert code not in seen, code
    order = [bs.SEVERITY_RANK[f["severity"]] for f in plan["findings"]]
    assert order == sorted(order)
    for f in plan["findings"]:
        assert set(f) == {"severity", "code", "subject", "message", "action"}
        assert f["severity"] in bs.SEVERITY_RANK
        assert f["message"] and f["action"]
    note = findings(plan, "default_privileges_note")[0]
    assert note["subject"] == "public/app_ro" and note["severity"] == "NOTE"
    assert findings(plan, "privilege_unmapped")[0]["subject"] == "postgres"


def test_plan_is_deterministic(demo_sec, demo_inv):
    a = json.dumps(demo_plan(demo_sec, demo_inv), sort_keys=True)
    b = json.dumps(demo_plan(copy.deepcopy(demo_sec),
                             copy.deepcopy(demo_inv)), sort_keys=True)
    assert a == b
    json.dumps(demo_plan(demo_sec, demo_inv))   # JSON serializable as is


# --------------------------------------------------------- PUBLIC grants

def test_public_grant_unmapped_and_mapped():
    sec = small_security(relation_privileges=[
        rel("orders", "PUBLIC", "SELECT"),
        rel("customers", "app_rw", "SELECT")])
    plan = bs.plan_security(sec, small_inventory(), BQ_CFG, PRINCIPAL_MAP)
    warn = findings(plan, "public_unmapped")
    assert len(warn) == 1 and warn[0]["severity"] == "WARNING"
    assert "public.orders" in warn[0]["message"]
    # every role still receives the folded grant
    for member in (RO, RW, REPORTING):
        assert any(b["resource"] == "retail.orders"
                   and b["role"] == bs.ROLE_VIEWER
                   for b in bindings_for(plan, member))
    assert all(b["member"] != EVERYONE for b in plan["bindings"])

    cfg = dict(BQ_CFG, public_principal=EVERYONE)
    plan = bs.plan_security(sec, small_inventory(), cfg, PRINCIPAL_MAP)
    direct = bindings_for(plan, EVERYONE)
    assert [(b["scope"], b["resource"], b["role"], b["source_role"])
            for b in direct] == [
        ("project", PROJECT, bs.ROLE_JOBUSER, "PUBLIC"),
        ("table", "retail.orders", bs.ROLE_VIEWER, "PUBLIC")]
    assert findings(plan, "public_mapped")[0]["severity"] == "NOTE"
    assert not findings(plan, "public_unmapped")


def test_public_principal_never_everyone():
    sec = small_security(relation_privileges=[
        rel("orders", "PUBLIC", "SELECT")])
    for bad in ("allUsers", "allAuthenticatedUsers",
                "specialGroup:allAuthenticatedUsers"):
        cfg = dict(BQ_CFG, public_principal=bad)
        with pytest.raises(bs.SecurityPlanError, match="every user"):
            bs.plan_security(sec, small_inventory(), cfg, PRINCIPAL_MAP)


def test_principal_map_rejects_everyone_and_untyped():
    for bad in ("allUsers", "retail@example.com"):
        pmap = copy.deepcopy(PRINCIPAL_MAP)
        pmap["roles"]["app_ro"]["principal"] = bad
        with pytest.raises(bs.SecurityPlanError, match="app_ro"):
            bs.plan_security(small_security(), small_inventory(), BQ_CFG,
                             pmap)


# --------------------------------------------------------- unmapped roles

def test_unmapped_role_warning(demo_sec, demo_inv):
    pmap = {"roles": {k: v for k, v in PRINCIPAL_MAP["roles"].items()
                      if k != "reporting"}}
    plan = demo_plan(demo_sec, demo_inv, pmap=pmap)
    warn = findings(plan, "unmapped_role")
    assert len(warn) == 1 and warn[0]["subject"] == "reporting"
    assert warn[0]["severity"] == "WARNING"
    assert "dataViewer" in warn[0]["message"]
    assert "rls_reporting" in warn[0]["message"]
    assert not bindings_for(plan, REPORTING)
    assert "reporting" not in plan["principals"]
    assert not [p for p in plan["row_policies"]
                if p["name"] == "rls_reporting"]
    # an empty principal string counts as unmapped too
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["reporting"]["principal"] = ""
    plan = demo_plan(demo_sec, demo_inv, pmap=pmap)
    assert findings(plan, "unmapped_role")[0]["subject"] == "reporting"


def test_principal_map_entry_for_unknown_role_is_flagged(demo_sec, demo_inv):
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["ghost"] = {"principal": "group:g@example.com",
                              "probe_service_account": ""}
    plan = demo_plan(demo_sec, demo_inv, pmap=pmap)
    assert findings(plan, "principal_without_role")[0]["subject"] == "ghost"
    assert "ghost" not in plan["principals"]


# ------------------------------------------------------- superuser mapped

def test_superuser_mapped(demo_sec, demo_inv):
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["postgres"] = {"principal": SUPER,
                                 "probe_service_account": ""}
    plan = demo_plan(demo_sec, demo_inv, pmap=pmap)
    su = bindings_for(plan, SUPER)
    assert [(b["scope"], b["resource"], b["role"]) for b in su] == [
        ("dataset", "retail", bs.ROLE_OWNER),
        ("project", PROJECT, bs.ROLE_JOBUSER)]
    tag = plan["policy_tags"][0]
    assert {"member": SUPER, "source_role": "postgres"} in tag["readers"]
    bypass = [(p["table"], p["filter"]) for p in plan["row_policies"]
              if p["name"] == "rls_bypass_postgres"]
    assert bypass == [("audit_log", "TRUE"), ("orders", "TRUE")]
    assert findings(plan, "superuser_mapped")[0]["severity"] == "WARNING"
    assert not findings(plan, "superuser_unmapped")


def test_bypassrls_and_owner_get_bypass_policies():
    inv = small_inventory()
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"), role("reporting", login=False),
               role("auditor", bypass=True), role("owner_role")],
        relation_privileges=[
            rel("orders", "app_ro", "SELECT"),
            rel("orders", "auditor", "SELECT"),
            rel("orders", "owner_role", "SELECT", owner="owner_role"),
            rel("customers", "app_ro", "SELECT")],
        rls=[rls("orders")],
        policies=[policy("orders", "ro_eu", ["app_ro"],
                         "(region = 'eu'::text)")])
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["auditor"] = {"principal": "group:aud@example.com",
                                "probe_service_account": ""}
    pmap["roles"]["owner_role"] = {"principal": "group:own@example.com",
                                   "probe_service_account": ""}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    names = {p["name"]: p for p in plan["row_policies"]}
    assert set(names) == {"rls_app_ro", "rls_bypass_auditor",
                          "rls_bypass_owner_role"}
    assert names["rls_bypass_auditor"]["filter"] == "TRUE"
    assert names["rls_bypass_auditor"]["confidence"] == "auto"
    assert names["rls_bypass_owner_role"]["source_roles"] == ["owner_role"]
    # a forced RLS table does not exempt the owner
    sec["rls"][0]["forced"] = True
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    names = {p["name"] for p in plan["row_policies"]}
    assert names == {"rls_app_ro", "rls_bypass_auditor"}
    assert findings(plan, "rls_denies_role")[0]["subject"] == \
        "public.orders/owner_role"


# ------------------------------------------------------------- granularity

def test_granularity_auto_dataset_and_table(demo_sec, demo_inv):
    # take one relation away from app_ro: no promotion under auto
    sec = copy.deepcopy(demo_sec)
    sec["relation_privileges"] = [
        r for r in sec["relation_privileges"]
        if not (r["grantee"] == "app_ro" and r["relation"] == "products")]
    plan = demo_plan(sec, demo_inv)
    ro = bindings_for(plan, RO)
    assert all(b["scope"] != "dataset" for b in ro)
    assert {b["resource"] for b in ro if b["scope"] == "table"} == {
        "retail.audit_log", "retail.customers", "retail.order_items",
        "retail.orders", "retail.recent_orders", "retail.sales_by_product"}
    # forced dataset scope widens and says so
    plan = demo_plan(sec, demo_inv,
                     cfg=dict(BQ_CFG, binding_granularity="dataset"))
    ro = bindings_for(plan, RO)
    assert [(b["scope"], b["resource"], b["role"]) for b in ro] == [
        ("dataset", "retail", bs.ROLE_VIEWER),
        ("project", PROJECT, bs.ROLE_JOBUSER)]
    widened = findings(plan, "widened_by_granularity")
    assert any(f["subject"] == f"retail/{RO}" for f in widened)
    assert any("products" in f["message"] for f in widened)
    # app_rw holds editor on tables and viewer on views: both promote, and
    # dataEditor already includes dataViewer, so one dataset binding
    rw = bindings_for(plan, RW)
    assert {(b["scope"], b["role"]) for b in rw
            if b["scope"] != "project"} == {("dataset", bs.ROLE_EDITOR)}
    assert findings(plan, "widened_by_granularity")
    # forced table scope never promotes
    plan = demo_plan(demo_sec, demo_inv,
                     cfg=dict(BQ_CFG, binding_granularity="table"))
    ro = bindings_for(plan, RO)
    assert all(b["scope"] != "dataset" for b in ro)
    assert len([b for b in ro if b["scope"] == "table"]) == 7
    assert not findings(plan, "widened_by_granularity")


def test_schema_privileges_without_relations():
    inv = small_inventory()
    sec = small_security(
        schema_privileges=[
            {"schema": "public", "owner": "pg_database_owner",
             "grantee": "reporting", "privilege": "USAGE",
             "grantable": False},
            {"schema": "public", "owner": "pg_database_owner",
             "grantee": "app_rw", "privilege": "CREATE",
             "grantable": False}],
        relation_privileges=[rel("orders", "app_ro", "SELECT"),
                             rel("orders", "app_rw", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    rep = bindings_for(plan, REPORTING)
    assert [(b["scope"], b["resource"], b["role"]) for b in rep] == [
        ("dataset", "retail", bs.ROLE_META),
        ("project", PROJECT, bs.ROLE_JOBUSER)]
    rw = bindings_for(plan, RW)
    assert ("dataset", "retail", bs.ROLE_EDITOR) in [
        (b["scope"], b["resource"], b["role"]) for b in rw]
    warn = findings(plan, "schema_create_widens")
    assert warn and warn[0]["subject"] == "public/app_rw"
    # app_ro holds relation grants, so no metadataViewer for it
    assert all(b["role"] != bs.ROLE_META for b in bindings_for(plan, RO))


def test_write_without_select_warns_editor_widens():
    inv = small_inventory()
    sec = small_security(relation_privileges=[
        rel("orders", "app_rw", "INSERT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    rw = bindings_for(plan, RW)
    assert [(b["resource"], b["role"]) for b in rw
            if b["scope"] == "table"] == [("retail.orders", bs.ROLE_EDITOR)]
    warn = findings(plan, "editor_widens")
    assert warn[0]["subject"] == "public.orders/app_rw"
    assert "SELECT" in warn[0]["message"]
    # never viewer and editor on the same resource for the same member
    pairs = [(b["resource"], b["member"]) for b in plan["bindings"]
             if b["scope"] != "project"]
    assert len(pairs) == len(set(pairs))


def test_column_write_grant_warns():
    inv = small_inventory()
    sec = small_security(column_privileges=[
        {"schema": "public", "relation": "orders", "column": "status",
         "grantee": "app_ro", "privilege": "UPDATE"}])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    warn = findings(plan, "column_write_unmapped")
    assert warn[0]["subject"] == "public.orders.status/app_ro"


# ------------------------------------------------------- authorized views

def test_authorized_view_when_base_table_unreadable():
    inv = small_inventory()
    sec = small_security()   # reporting reads the view, neither base table
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert plan["authorized_views"] == [
        {"view": "retail.recent_orders", "dataset": "retail"}]
    note = findings(plan, "authorized_view")[0]
    assert note["subject"] == "public.recent_orders"
    assert "reporting" in note["message"]
    # app_ro reads both bases and the view: no authorized view needed
    sec = small_security(relation_privileges=[
        rel("orders", "app_ro", "SELECT"),
        rel("customers", "app_ro", "SELECT"),
        rel("recent_orders", "app_ro", "SELECT", kind="view")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert plan["authorized_views"] == []


def test_authorized_view_crosses_datasets():
    inv = small_inventory()
    inv["tables"][1]["schema"] = "crm"
    for c in inv["columns"]:
        if c["table"] == "customers":
            c["schema"] = "crm"
    inv["view_dependencies"][1]["base"] = "crm.customers"
    sec = small_security(relation_privileges=[
        rel("orders", "reporting", "SELECT"),
        rel("recent_orders", "reporting", "SELECT", kind="view")])
    cfg = dict(BQ_CFG, dataset_map={"public": "retail", "crm": "crm_ds"})
    plan = bs.plan_security(sec, inv, cfg, PRINCIPAL_MAP)
    assert plan["authorized_views"] == [
        {"view": "retail.recent_orders", "dataset": "crm_ds"}]
    assert plan["datasets"] == {"crm_ds": {"source_schema": "crm"},
                                "retail": {"source_schema": "public"}}


# ---------------------------------------------------------- row policies

def test_restrictive_policies_combine_with_and():
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        policies=[
            policy("orders", "eu", ["reporting"], "(region = 'eu'::text)"),
            policy("orders", "paid", ["reporting"],
                   "(status = 'paid'::text)"),
            policy("orders", "not_void", ["PUBLIC"],
                   "(status <> 'void'::text)", permissive=False),
            policy("orders", "rw_all", ["app_rw"], "true", command="ALL"),
        ],
        relation_privileges=[rel("orders", "reporting", "SELECT"),
                             rel("orders", "app_rw", "SELECT"),
                             rel("orders", "app_ro", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    by_name = {p["name"]: p for p in plan["row_policies"]}
    assert by_name["rls_reporting"]["filter"] == \
        "((region = 'eu') OR (status = 'paid')) AND (status <> 'void')"
    assert [s["name"] for s in by_name["rls_reporting"]["source_policies"]] \
        == ["eu", "not_void", "paid"]
    assert by_name["rls_app_rw"]["filter"] == "(TRUE) AND (status <> 'void')"
    # a restrictive policy alone allows nothing: no policy for app_ro
    assert "rls_app_ro" not in by_name
    assert findings(plan, "rls_denies_role")[0]["subject"] == \
        "public.orders/app_ro"


def test_review_predicate_blocks_apply_until_resolved(tmp_path):
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        policies=[policy("orders", "tenant", ["app_ro"], TENANT_USING)],
        relation_privileges=[rel("orders", "app_ro", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    pol = plan["row_policies"][0]
    assert pol["name"] == "rls_app_ro" and pol["confidence"] == "review"
    assert "current_setting" in pol["filter"]
    assert any("current_setting" in n for n in pol["notes"])
    warn = findings(plan, "translation_review")
    assert warn[0]["severity"] == "WARNING"
    assert warn[0]["subject"] == "public.orders/tenant"
    review = bs.review_items(plan)
    assert set(review) == {"public.orders/tenant"}
    item = review["public.orders/tenant"]
    assert set(item) == {"source_sql", "auto_sql", "notes", "context_tables"}
    assert item["source_sql"] == TENANT_USING
    assert item["context_tables"]["orders"] == "`proj.retail.orders`"
    assert item["context_tables"]["public.recent_orders"] == \
        "`proj.retail.recent_orders`"
    backend = bb.EmulatedBackend(tmp_path / "emu", PROJECT, "US")
    with pytest.raises(bs.SecurityPlanError, match="rls_app_ro"):
        bs.apply_plan(plan, backend)
    assert backend.list_datasets() == []
    resolutions = {"policies": {"public.orders/tenant": {
        "sql": "(tenant_id = 7)", "rationale": "single tenant on target"}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, resolutions)
    pol = plan["row_policies"][0]
    assert pol["confidence"] == "resolved"
    assert pol["filter"] == "(tenant_id = 7)"
    assert any("single tenant" in n for n in pol["notes"])
    assert not findings(plan, "translation_review")
    assert bs.review_items(plan) == {}
    assert findings(plan, "translation_resolved")[0]["severity"] == "NOTE"
    # an empty resolution does not count
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP,
                            {"policies": {"public.orders/tenant": {"sql": ""}}})
    assert plan["row_policies"][0]["confidence"] == "review"


def test_rls_without_policies_denies_all():
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        relation_privileges=[rel("orders", "app_ro", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert policy_tuples(plan) == [
        ("retail", "orders", "rls_deny_all", "FALSE", "auto")]
    assert plan["row_policies"][0]["members"] == [ADMIN]
    warn = findings(plan, "rls_deny_all")
    assert warn[0]["severity"] == "WARNING"
    assert warn[0]["subject"] == "public.orders"
    # without an admin principal no policy can be written: the table would
    # be open, which the plan says loudly
    plan = bs.plan_security(sec, inv, dict(BQ_CFG, admin_principal=""),
                            PRINCIPAL_MAP)
    assert plan["row_policies"] == []
    warn = findings(plan, "rls_deny_all_unassigned")
    assert warn[0]["severity"] == "WARNING"
    # policies only for unmapped roles also leave the table open
    sec["policies"] = [policy("orders", "ghost", ["ghost"], "true")]
    sec["roles"].append(role("ghost"))
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert [p["name"] for p in plan["row_policies"]] == ["rls_deny_all"]


def test_policy_commands_and_with_check_are_flagged():
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        policies=[
            policy("orders", "ins", ["app_rw"], None, command="INSERT",
                   with_check="(region = 'eu'::text)"),
            policy("orders", "all_rw", ["app_rw"], "true", command="ALL",
                   with_check="(status <> 'void'::text)"),
            policy("orders", "upd", ["app_rw"], "true", command="UPDATE"),
        ],
        relation_privileges=[rel("orders", "app_rw", "SELECT"),
                             rel("orders", "app_rw", "INSERT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert policy_tuples(plan) == [
        ("retail", "orders", "rls_app_rw", "TRUE", "auto")]
    warn = findings(plan, "policy_command_unmapped")
    assert sorted(f["subject"] for f in warn) == [
        "public.orders/all_rw", "public.orders/ins", "public.orders/upd"]
    assert all(f["severity"] == "WARNING" for f in warn)


def test_security_barrier_view_is_flagged():
    sec = small_security(security_barrier_views=["public.recent_orders"])
    plan = bs.plan_security(sec, small_inventory(), BQ_CFG, PRINCIPAL_MAP)
    warn = findings(plan, "security_barrier_view")
    assert warn[0]["subject"] == "public.recent_orders"
    assert warn[0]["severity"] == "WARNING"


def test_identifiers_are_sanitized():
    inv = small_inventory()
    inv["tables"][0]["name"] = "order-lines"
    for c in inv["columns"]:
        if c["table"] == "orders":
            c["table"] = "order-lines"
    inv["view_dependencies"][0]["base"] = "public.order-lines"
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"),
               role("report-er", login=False)],
        rls=[rls("order-lines")],
        policies=[policy("order-lines", "eu", ["report-er"],
                         "(region = 'eu'::text)")],
        relation_privileges=[rel("order-lines", "report-er", "SELECT"),
                             rel("order-lines", "app_rw", "SELECT")],
        column_privileges=[
            {"schema": "public", "relation": "order-lines",
             "column": "status", "grantee": "app_ro",
             "privilege": "SELECT"}])
    pmap = {"roles": {"report-er": {"principal": REPORTING,
                                    "probe_service_account": ""},
                      "app_rw": PRINCIPAL_MAP["roles"]["app_rw"],
                      "app_ro": PRINCIPAL_MAP["roles"]["app_ro"]}}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    assert [p["name"] for p in plan["row_policies"]] == ["rls_report_er"]
    assert plan["row_policies"][0]["table"] == "order_lines"
    assert plan["policy_tags"][0]["name"] == "order_lines__id_and_2_more"
    assert plan["policy_tags"][0]["columns"][0]["table"] == "order_lines"
    assert any(b["resource"] == "retail.order_lines"
               for b in plan["bindings"])


# ------------------------------------------------------------ masking

def test_masking_requests(demo_sec, demo_inv):
    cfg = dict(BQ_CFG, column_security="policy_tags_with_masking")
    plan = demo_plan(demo_sec, demo_inv, cfg=cfg)
    assert plan["masking"] == [{
        "tag": "customers__email",
        "data_policy_id": "mask_customers__email",
        "rule": "ALWAYS_NULL", "masked_readers": [RO, REPORTING]}]
    scripts = bs.render_apply_scripts(plan, cfg)
    doc = json.loads(scripts["60-masking-requests.json"])
    assert doc[0]["dataPolicyId"] == "mask_customers__email"
    assert doc[0]["dataMaskingPolicy"] == {
        "predefinedExpression": "ALWAYS_NULL"}
    assert doc[0]["bindings"][0]["role"] == \
        "roles/bigquerydatapolicy.maskedReader"
    assert doc[0]["bindings"][0]["members"] == [RO, REPORTING]


# ------------------------------------------------------- render scripts

def test_render_apply_scripts(demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    scripts = bs.render_apply_scripts(plan, BQ_CFG)
    assert set(scripts) == {"30-iam.sh", "40-policy-tags.sh",
                            "50-row-policies.sql", "70-identity-notes.md"}
    iam = scripts["30-iam.sh"]
    assert iam.startswith("#!/usr/bin/env bash")
    assert ("gcloud projects add-iam-policy-binding 'proj' "
            f"--member='{RW}' --role='{bs.ROLE_JOBUSER}' --condition=None") in iam
    assert (f"bq --project_id='proj' add-iam-policy-binding --member='{RW}' "
            f"--role='{bs.ROLE_EDITOR}' 'proj:retail.orders'") in iam
    assert '"groupByEmail": "retail-app-ro@example.com"' in iam
    assert '"tableId": "recent_orders"' in iam
    tags = scripts["40-policy-tags.sh"]
    assert "FINE_GRAINED_ACCESS_CONTROL" in tags and "dbcarry_demo" in tags
    assert "customers__email" in tags
    assert "policy-tags add-iam-policy-binding" in tags
    assert f"--member='{RW}' --role={bs.ROLE_FGR}" in tags
    assert "print-access-token" in tags and "Bearer" in tags
    sql = scripts["50-row-policies.sql"]
    assert ("CREATE OR REPLACE ROW ACCESS POLICY rls_reporting ON "
            f"`proj.retail.orders` GRANT TO (\"{REPORTING}\") "
            "FILTER USING ((region = 'eu'));") in sql
    assert ("CREATE OR REPLACE ROW ACCESS POLICY rls_app_rw ON "
            f"`proj.retail.orders` GRANT TO (\"{RW}\") "
            "FILTER USING (TRUE);") in sql
    notes = scripts["70-identity-notes.md"]
    assert "reporting" in notes and "app_ro" in notes
    assert "SESSION_USER" in notes
    assert "never executed" in notes.lower()
    for text in scripts.values():
        assert "\u2014" not in text and "\u2013" not in text
        assert text.endswith("\n")


def test_render_review_policy_is_commented_out():
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        policies=[policy("orders", "tenant", ["app_ro"], TENANT_USING)],
        relation_privileges=[rel("orders", "app_ro", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    sql = bs.render_apply_scripts(plan, BQ_CFG)["50-row-policies.sql"]
    lines = [l for l in sql.splitlines() if "rls_app_ro" in l]
    assert lines and all(l.startswith("--") for l in lines)
    assert "REVIEW" in sql


def test_render_plan_markdown(demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    md = bs.render_plan_markdown(plan)
    for heading in ("## Principals", "## Bindings", "## Policy tags",
                    "## Row access policies", "## Authorized views",
                    "## Findings"):
        assert heading in md
    assert "customers__email" in md and "rls_reporting" in md
    assert "| WARNING |" not in md or "unmapped" in md
    assert "\u2014" not in md and "\u2013" not in md
    # a pipe inside a predicate must not break the table
    plan["row_policies"][0]["filter"] = "(a = 'x|y')"
    assert "x\\|y" in bs.render_plan_markdown(plan)


# --------------------------------------------------- emulated end to end

def table_ddl(inv, project, dataset, table):
    cols = sorted((c for c in inv["columns"] if c["table"] == table),
                  key=lambda c: c["ordinal"])
    parts = []
    for c in cols:
        bq_type = bq_types.map_type(c)[0]
        parts.append(f"  {c['name']} {bq_type}"
                     + ("" if c["nullable"] else " NOT NULL"))
    return (f"CREATE TABLE `{project}.{dataset}.{table}` (\n"
            + ",\n".join(parts) + "\n);\n")


ORDER_ROWS = [
    {"id": 1, "customer_id": 1, "status": "paid",
     "ordered_at": "2025-01-01T00:00:00+00:00", "region": "eu"},
    {"id": 2, "customer_id": 1, "status": "paid",
     "ordered_at": "2025-01-02T00:00:00+00:00", "region": "us-east"},
    {"id": 3, "customer_id": 2, "status": "cancelled",
     "ordered_at": "2025-01-03T00:00:00+00:00", "region": "eu"},
]
AUDIT_ROWS = [
    {"logged_at": "2025-01-01T00:00:00+00:00", "actor": "app_ro",
     "action": "login", "detail": None},
    {"logged_at": "2025-01-02T00:00:00+00:00", "actor": "postgres",
     "action": "seed", "detail": "x"},
]
CUSTOMER_ROWS = [
    {"id": 1, "email": "a@example.com", "full_name": "A",
     "created_at": "2025-01-01T00:00:00+00:00"},
    {"id": 2, "email": "b@example.com", "full_name": "B",
     "created_at": "2025-01-01T00:00:00+00:00"},
]

PG_COUNTS = {
    'SELECT count(*) FROM "public"."orders" WHERE (region = \'eu\'::text)': 2,
    'SELECT count(*) FROM "public"."orders"': 3,
    'SELECT count(*) FROM "public"."audit_log"': 2,
    'SELECT count(*) FROM "public"."customers"': 2,
    'SELECT count(*) FROM "public"."order_items"': 0,
    'SELECT count(*) FROM "public"."products"': 0,
}


def write_ndjson(path, rows):
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return path


def create_demo_objects(backend, inv):
    backend.create_dataset("retail")
    for t in inv["tables"]:
        backend.run_ddl(table_ddl(inv, PROJECT, "retail", t["name"]))
    backend.run_ddl(f"CREATE VIEW `{PROJECT}.retail.recent_orders` AS "
                    "SELECT id FROM `proj.retail.orders`")
    backend.run_ddl(f"CREATE MATERIALIZED VIEW "
                    f"`{PROJECT}.retail.sales_by_product` "
                    "AS SELECT id FROM `proj.retail.products`")


def load_demo_rows(backend, root):
    for name, rows in (("orders", ORDER_ROWS), ("audit_log", AUDIT_ROWS),
                       ("customers", CUSTOMER_ROWS)):
        path = write_ndjson(root / f"{name}.ndjson.gz", rows)
        backend.load_ndjson("retail", name, path,
                            backend.get_table_schema("retail", name))


def build_emulator(root, inv, load=True):
    backend = bb.EmulatedBackend(root / "emu", PROJECT, "US",
                                 log=bb.OperationLog(root / "ops.log"))
    create_demo_objects(backend, inv)
    if load:
        load_demo_rows(backend, root)
    return backend


def read_state(root):
    return json.loads((root / "emu" / STATE_FILE).read_text(encoding="utf-8"))


def write_state(root, state):
    (root / "emu" / STATE_FILE).write_text(json.dumps(state, indent=2) + "\n",
                                           encoding="utf-8")


def one(results, role_name, kind, table):
    hits = [r for r in results if r["source_role"] == role_name
            and r["kind"] == kind and r["table"] == table]
    assert len(hits) == 1, hits
    return hits[0]


def test_apply_verify_tamper_and_probes(tmp_path, demo_sec, demo_inv,
                                        monkeypatch):
    plan = demo_plan(demo_sec, demo_inv)
    backend = build_emulator(tmp_path, demo_inv)
    result = bs.apply_plan(plan, backend)
    assert result["taxonomy"].startswith(
        "projects/proj/locations/US/taxonomies/")
    assert set(result["tags"]) == {"customers__email"}
    assert result["ops"] > 0
    assert plan["applied"] == {"taxonomy": result["taxonomy"],
                               "tags": result["tags"]}
    tag = result["tags"]["customers__email"]
    # read back what the emulator holds
    assert backend.describe_taxonomy(result["taxonomy"])[
        "activatedPolicyTypes"] == ["FINE_GRAINED_ACCESS_CONTROL"]
    assert backend.get_policy_tag_bindings(tag) == [
        {"role": bs.ROLE_FGR, "member": RW}]
    fields = {f["name"]: f
              for f in backend.get_table_schema("retail", "customers")}
    assert fields["email"]["policyTags"] == {"names": [tag]}
    assert "policyTags" not in fields["full_name"]
    access = backend.get_dataset_access("retail")
    assert {"view": "retail.recent_orders"} in access
    assert {"role": bs.ROLE_VIEWER, "member": RO} in access
    assert backend.get_table_bindings("retail", "orders") == [
        {"role": bs.ROLE_EDITOR, "member": RW}]
    assert {"role": bs.ROLE_JOBUSER, "member": REPORTING} in \
        backend.get_project_bindings()
    names = {p["name"]: p
             for p in backend.list_row_policies("retail", "orders")}
    assert names["rls_reporting"] == {"name": "rls_reporting",
                                      "members": [REPORTING],
                                      "filter": "(region = 'eu')"}

    verdict = bs.verify_plan(plan, backend)
    assert verdict["enforcement_active"] is True
    assert verdict["pass"] is True, [c for c in verdict["checks"]
                                     if not c["pass"]]
    check_names = [c["name"] for c in verdict["checks"]]
    assert "taxonomy_enforcement" in check_names
    enforcement = next(c for c in verdict["checks"]
                       if c["name"] == "taxonomy_enforcement")
    assert enforcement["expected"] == "FINE_GRAINED_ACCESS_CONTROL"
    assert f"tag_reader:customers__email:{RW}" in check_names
    assert "column_tag:retail.customers.email" in check_names
    assert "row_policy:retail.orders/rls_reporting" in check_names
    assert "authorized_view:retail:retail.recent_orders" in check_names
    assert all(set(c) == {"name", "expected", "actual", "pass"}
               for c in verdict["checks"])
    assert check_names == sorted(check_names)

    # applying twice is idempotent
    again = bs.apply_plan(plan, backend)
    assert again["taxonomy"] == result["taxonomy"]
    assert again["tags"] == result["tags"]
    assert bs.verify_plan(plan, backend)["pass"] is True

    # tamper: remove the tag reader behind the backend's back
    state = read_state(tmp_path)
    tax_state = state["taxonomies"][result["taxonomy"]]
    tax_state["policyTags"][tag]["bindings"] = []
    write_state(tmp_path, state)
    reopened = bb.EmulatedBackend(tmp_path / "emu", PROJECT, "US")
    verdict = bs.verify_plan(plan, reopened)
    assert verdict["pass"] is False and verdict["enforcement_active"] is True
    failed = [c for c in verdict["checks"] if not c["pass"]]
    assert [c["name"] for c in failed] == [
        f"tag_reader:customers__email:{RW}"]
    assert failed[0]["expected"] == "present"
    assert failed[0]["actual"] == "missing"
    # a taxonomy created without enforcement fails too, even when every
    # other check passes
    tax_state["policyTags"][tag]["bindings"] = [
        {"role": bs.ROLE_FGR, "member": RW}]
    tax_state["activatedPolicyTypes"] = []
    write_state(tmp_path, state)
    verdict = bs.verify_plan(plan, bb.EmulatedBackend(tmp_path / "emu",
                                                      PROJECT, "US"))
    assert verdict["enforcement_active"] is False and verdict["pass"] is False
    # restore and run the probes
    tax_state["activatedPolicyTypes"] = ["FINE_GRAINED_ACCESS_CONTROL"]
    write_state(tmp_path, state)
    backend = bb.EmulatedBackend(tmp_path / "emu", PROJECT, "US")

    probes = bs.probe_set(plan, demo_sec, demo_inv, PRINCIPAL_MAP, BQ_CFG)
    calls = []

    def fake_query_rows(ci, sql, readonly=False, writable=False):
        calls.append((ci, sql, readonly))
        return [[str(PG_COUNTS[sql])]]
    monkeypatch.setattr(pg, "query_rows", fake_query_rows)
    pg_ci = {"host": "h", "port": 1, "dbname": "retail", "user": "postgres",
             "password_env": None}
    results = bs.run_probes(probes, backend, pg_ci)
    assert calls and all(c[2] is True for c in calls)
    assert all(c[0] is pg_ci for c in calls)

    rep_orders = one(results, "reporting", "row_count", "orders")
    assert rep_orders["actual"]["status"] == "ok"
    assert rep_orders["actual"]["row_count"] == 2
    assert rep_orders["expected"]["row_count"] == 2
    assert rep_orders["pass"] is True
    rw_orders = one(results, "app_rw", "row_count", "orders")
    assert rw_orders["actual"]["row_count"] == 3 and rw_orders["pass"] is True
    ro_orders = one(results, "app_ro", "row_count", "orders")
    assert ro_orders["expected"]["row_count"] == 0
    assert ro_orders["expected"]["row_count_sql_pg"] is None
    assert ro_orders["actual"]["row_count"] == 0 and ro_orders["pass"] is True
    ro_email = one(results, "app_ro", "column_denied", "customers")
    assert ro_email["columns"] == ["email"]
    assert ro_email["actual"]["status"] == "denied"
    assert ro_email["pass"] is True
    rw_email = one(results, "app_rw", "column_allowed", "customers")
    assert rw_email["actual"]["status"] == "ok" and rw_email["pass"] is True
    ro_cust = one(results, "app_ro", "row_count", "customers")
    assert ro_cust["columns"] == ["id", "full_name", "created_at"]
    assert ro_cust["actual"]["status"] == "ok"
    assert ro_cust["actual"]["row_count"] == 2
    assert backend.probe(RO, "", "retail", "customers", ["id", "full_name"])[
        "status"] == "ok"
    # identity predicates: the count is not comparable across engines
    ro_audit = one(results, "app_ro", "row_count", "audit_log")
    assert ro_audit["expected"]["row_count_sql_pg"] is None
    assert ro_audit["expected"]["row_count"] is None
    assert "identity" in ro_audit["expected"]["note"].lower()
    assert ro_audit["actual"]["status"] == "ok" and ro_audit["pass"] is True
    one(results, "reporting", "column_denied", "customers")
    assert all(r["kind"] != "table_denied" for r in results)
    assert all(r["pass"] for r in results), [r for r in results
                                             if not r["pass"]]
    assert bs.probes_pass(results) is True

    # an unevaluable answer never passes
    backend.create_row_policy("retail", "orders", "rls_reporting",
                              [REPORTING], "(id = 1)")
    results = bs.run_probes(probes, backend, None)
    rep_orders = one(results, "reporting", "row_count", "orders")
    assert rep_orders["actual"]["status"] == "unevaluable"
    assert rep_orders["pass"] is False
    assert rep_orders["expected"]["row_count"] is None
    assert all(r["expected"]["row_count"] in (None, 0) for r in results)
    assert bs.probes_pass(results) is False


def test_verify_reports_missing_controls(tmp_path, demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    backend = build_emulator(tmp_path, demo_inv, load=False)
    verdict = bs.verify_plan(plan, backend)
    assert verdict["pass"] is False and verdict["enforcement_active"] is False
    failed = {c["name"]: c for c in verdict["checks"] if not c["pass"]}
    assert "taxonomy" in failed and failed["taxonomy"]["actual"] == "missing"
    assert failed["taxonomy_enforcement"]["actual"] == "missing"
    assert f"project_binding:{bs.ROLE_JOBUSER}:{RW}" in failed
    assert f"table_binding:retail.orders:{bs.ROLE_EDITOR}:{RW}" in failed
    assert f"dataset_access:retail:{bs.ROLE_VIEWER}:{RO}" in failed
    assert "authorized_view:retail:retail.recent_orders" in failed
    assert "row_policy:retail.orders/rls_reporting" in failed
    assert "policy_tag:customers__email" in failed
    assert "column_tag:retail.customers.email" in failed
    # a policy with the wrong filter or member set is a mismatch
    bs.apply_plan(plan, backend)
    assert bs.verify_plan(plan, backend)["pass"] is True
    backend.create_row_policy("retail", "orders", "rls_reporting",
                              [REPORTING], "(region  =  'eu')")
    assert bs.verify_plan(plan, backend)["pass"] is True   # whitespace only
    backend.create_row_policy("retail", "orders", "rls_reporting",
                              [REPORTING, RO], "(region = 'eu')")
    verdict = bs.verify_plan(plan, backend)
    bad = [c for c in verdict["checks"] if not c["pass"]]
    assert [c["name"] for c in bad] == [
        "row_policy:retail.orders/rls_reporting"]
    assert RO in bad[0]["actual"]


def test_verify_survives_missing_tables(tmp_path, demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    backend = bb.EmulatedBackend(tmp_path / "emu", PROJECT, "US")
    verdict = bs.verify_plan(plan, backend)   # no dataset at all
    assert verdict["pass"] is False
    assert all(isinstance(c["actual"], str) for c in verdict["checks"])


def test_verify_without_tags_does_not_need_a_taxonomy(tmp_path):
    inv = small_inventory()
    sec = small_security(relation_privileges=[
        rel("orders", "app_ro", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert plan["policy_tags"] == []
    backend = bb.EmulatedBackend(tmp_path / "emu", PROJECT, "US")
    backend.create_dataset("retail")
    backend.run_ddl(table_ddl(inv, PROJECT, "retail", "orders"))
    result = bs.apply_plan(plan, backend)
    assert result["taxonomy"] is None and result["tags"] == {}
    assert backend.list_taxonomies() == []
    verdict = bs.verify_plan(plan, backend)
    assert verdict["pass"] is True and verdict["enforcement_active"] is True
    assert not any(c["name"].startswith("taxonomy")
                   for c in verdict["checks"])


def test_apply_records_operations_in_order(tmp_path, demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    backend = build_emulator(tmp_path, demo_inv, load=False)
    log = bb.OperationLog(tmp_path / "plan-ops.log")
    bs.apply_plan(plan, backend, log=log)
    lines = [json.loads(l) for l in (tmp_path / "plan-ops.log").read_text(
        encoding="utf-8").splitlines()]
    assert lines[0]["op"] == "security_apply_start"
    assert lines[-1]["op"] == "security_apply_done"
    ops = [json.loads(l)["op"] for l in (tmp_path / "ops.log").read_text(
        encoding="utf-8").splitlines()]
    first = {op: ops.index(op) for op in set(ops)}
    assert first["create_taxonomy"] < first["create_policy_tag"] \
        < first["add_policy_tag_binding"] < first["add_project_binding"] \
        < first["add_dataset_access"] < first["add_table_binding"] \
        < first["update_table_schema"] < first["create_row_policy"]


# --------------------------------------------------------------- probes

def test_probe_set_shape(demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    probes = bs.probe_set(plan, demo_sec, demo_inv, PRINCIPAL_MAP, BQ_CFG)
    for p in probes:
        assert set(p) == {"kind", "principal", "probe_service_account",
                          "source_role", "dataset", "table", "columns",
                          "expected"}
        assert set(p["expected"]) == {"status", "row_count_sql_pg",
                                      "row_count", "note"}
        assert p["dataset"] == "retail" and p["probe_service_account"] == ""
    keys = [(p["source_role"], p["kind"], p["table"], tuple(p["columns"]))
            for p in probes]
    assert keys == sorted(keys)
    by = {(p["source_role"], p["kind"], p["table"]): p for p in probes}
    rep = by[("reporting", "row_count", "orders")]
    assert rep["expected"] == {
        "status": "ok", "row_count": None, "note": "",
        "row_count_sql_pg":
            'SELECT count(*) FROM "public"."orders" '
            'WHERE (region = \'eu\'::text)'}
    assert rep["principal"] == REPORTING
    assert rep["columns"] == ["id", "customer_id", "status", "ordered_at",
                              "region"]
    rw = by[("app_rw", "row_count", "orders")]
    assert rw["expected"]["row_count_sql_pg"] == \
        'SELECT count(*) FROM "public"."orders"'
    ro = by[("app_ro", "row_count", "orders")]
    assert ro["expected"]["status"] == "ok"
    assert ro["expected"]["row_count"] == 0
    assert ro["expected"]["row_count_sql_pg"] is None
    assert ro["expected"]["note"]
    denied = by[("app_ro", "column_denied", "customers")]
    assert denied["columns"] == ["email"]
    assert denied["expected"]["status"] == "denied"
    assert denied["expected"]["row_count_sql_pg"] is None
    allowed = by[("app_rw", "column_allowed", "customers")]
    assert allowed["columns"] == ["email"]
    assert allowed["expected"]["status"] == "ok"
    assert allowed["expected"]["row_count_sql_pg"] == \
        'SELECT count(*) FROM "public"."customers"'
    ro_cust = by[("app_ro", "row_count", "customers")]
    assert ro_cust["columns"] == ["id", "full_name", "created_at"]
    audit = by[("reporting", "row_count", "audit_log")]
    assert audit["expected"]["row_count_sql_pg"] is None
    assert "identity" in audit["expected"]["note"].lower()
    # views are not probed and nobody is denied a whole table in the demo
    assert all(p["table"] not in ("recent_orders", "sales_by_product")
               for p in probes)
    assert not [p for p in probes if p["kind"] == "table_denied"]


def test_probe_set_restrictive_and_bypass_sql():
    inv = small_inventory()
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"), role("reporting", login=False),
               role("auditor", bypass=True)],
        rls=[rls("orders")],
        policies=[
            policy("orders", "eu", ["reporting"], "(region = 'eu'::text)"),
            policy("orders", "paid", ["reporting"],
                   "(status = 'paid'::text)"),
            policy("orders", "not_void", ["PUBLIC"],
                   "(status <> 'void'::text)", permissive=False)],
        relation_privileges=[rel("orders", "reporting", "SELECT"),
                             rel("orders", "auditor", "SELECT")])
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["auditor"] = {"principal": "group:aud@example.com",
                                "probe_service_account": ""}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    probes = bs.probe_set(plan, sec, inv, pmap, BQ_CFG)
    by = {(p["source_role"], p["kind"], p["table"]): p for p in probes}
    assert by[("reporting", "row_count", "orders")]["expected"][
        "row_count_sql_pg"] == (
        'SELECT count(*) FROM "public"."orders" WHERE '
        "((region = 'eu'::text) OR (status = 'paid'::text)) "
        "AND (status <> 'void'::text)")
    assert by[("auditor", "row_count", "orders")]["expected"][
        "row_count_sql_pg"] == 'SELECT count(*) FROM "public"."orders"'


def test_probe_set_table_denied_and_live_mode():
    inv = small_inventory()
    sec = small_security(relation_privileges=[
        rel("orders", "app_ro", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    probes = bs.probe_set(plan, sec, inv, PRINCIPAL_MAP, BQ_CFG)
    kinds = {(p["source_role"], p["kind"], p["table"]) for p in probes}
    assert ("app_ro", "table_denied", "customers") in kinds
    assert ("app_rw", "table_denied", "orders") in kinds
    assert ("app_ro", "row_count", "orders") in kinds
    denied = next(p for p in probes if p["kind"] == "table_denied")
    assert denied["columns"] == [] and denied["expected"]["status"] == "denied"
    # live mode: only roles with a probe service account
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    sa = "probe-ro@p.iam.gserviceaccount.com"
    pmap["roles"]["app_ro"]["probe_service_account"] = sa
    live = bs.probe_set(plan, sec, inv, pmap, dict(BQ_CFG, mode="live"))
    assert live and all(p["source_role"] == "app_ro" for p in live)
    assert all(p["probe_service_account"] == sa for p in live)
    assert bs.probe_set(plan, sec, inv, PRINCIPAL_MAP,
                        dict(BQ_CFG, mode="live")) == []


def test_run_probes_with_fake_backend_and_pg(monkeypatch):
    probes = [
        {"kind": "row_count", "principal": RO, "probe_service_account": "",
         "source_role": "app_ro", "dataset": "retail", "table": "orders",
         "columns": ["id"],
         "expected": {"status": "ok", "row_count": None, "note": "",
                      "row_count_sql_pg": "SELECT count(*) FROM x"}},
        {"kind": "column_denied", "principal": RO, "probe_service_account": "",
         "source_role": "app_ro", "dataset": "retail", "table": "customers",
         "columns": ["email"],
         "expected": {"status": "denied", "row_count": None, "note": "",
                      "row_count_sql_pg": None}},
    ]

    class Fake:
        mode = "emulated"

        def __init__(self, answers):
            self.answers = answers

        def probe(self, principal, probe_sa, dataset, table, columns):
            return self.answers[(table, tuple(columns))]

    def answers(orders, customers):
        return Fake({("orders", ("id",)): orders,
                     ("customers", ("email",)): customers})

    monkeypatch.setattr(pg, "query_rows",
                        lambda ci, sql, readonly=False, writable=False: [["5"]])
    backend = answers({"status": "ok", "row_count": 5, "reason": "5 rows"},
                      {"status": "denied", "row_count": None, "reason": "tag"})
    out = bs.run_probes(copy.deepcopy(probes), backend, {"dbname": "d"})
    assert [r["pass"] for r in out] == [True, True]
    assert out[0]["expected"]["row_count"] == 5
    assert out[0]["actual"]["reason"] == "5 rows"
    # count mismatch fails, status mismatch fails
    backend = answers({"status": "ok", "row_count": 4, "reason": ""},
                      {"status": "ok", "row_count": 2, "reason": ""})
    out = bs.run_probes(copy.deepcopy(probes), backend, {"dbname": "d"})
    assert [r["pass"] for r in out] == [False, False]
    # unevaluable and error never pass
    backend = answers({"status": "unevaluable", "row_count": None,
                       "reason": "x"},
                      {"status": "error", "row_count": None, "reason": "y"})
    out = bs.run_probes(copy.deepcopy(probes), backend, None)
    assert [r["pass"] for r in out] == [False, False]
    assert out[0]["expected"]["row_count"] is None
    # without a source connection the count is unknown and status decides
    backend = answers({"status": "ok", "row_count": 9, "reason": ""},
                      {"status": "denied", "row_count": None, "reason": ""})
    out = bs.run_probes(copy.deepcopy(probes), backend, None)
    assert [r["pass"] for r in out] == [True, True]
    assert bs.probes_pass(out) is True
    out[0]["pass"] = False
    assert bs.probes_pass(out) is False
    # an empty probe set proves nothing
    assert bs.probes_pass([]) is False


# ------------------------------------------------------------------ CLI

MIGRATION_YAML = """migration: demo
engine: postgres
provider: bigquery
downtime_tolerance: flexible
source:
  host: 127.0.0.1
  port: 55432
  dbname: retail
  user: postgres
  password_env: ""
bigquery:
  mode: emulated
  project: proj
  location: US
  dataset_map:
    public: retail
  admin_principal: "user:operator@example.com"
"""

PRINCIPAL_YAML = """roles:
  app_rw:
    principal: "group:retail-app-rw@example.com"
    probe_service_account: ""
  app_ro:
    principal: "group:retail-app-ro@example.com"
  reporting:
    principal: "group:retail-reporting@example.com"
"""


def make_workspace(tmp_path, monkeypatch, with_map=True):
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    ws = tmp_path / "migrations" / "demo"
    (ws / "artifacts").mkdir(parents=True)
    (ws / "migration.yaml").write_text(MIGRATION_YAML, encoding="utf-8")
    for name in ("security", "inventory"):
        (ws / "artifacts" / f"{name}.json").write_text(
            (FIXTURES / f"demo-{name}.json").read_text(encoding="utf-8"),
            encoding="utf-8")
    if with_map:
        (ws / "security").mkdir()
        (ws / "security" / "principal-map.yaml").write_text(
            PRINCIPAL_YAML, encoding="utf-8")
    return ws


def run(argv):
    return bs.main(["bq-security"] + argv)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_cli_plan_template(tmp_path, monkeypatch, capsys):
    ws = make_workspace(tmp_path, monkeypatch, with_map=False)
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo",
              "--template"])
    assert rc == 0
    path = ws / "security" / "principal-map.yaml"
    text = path.read_text(encoding="utf-8")
    assert "wrote" in capsys.readouterr().out
    pm = config.load_principal_map(str(path))
    assert set(pm["roles"]) == {"app_ro", "app_rw", "reporting"}
    assert all(v["principal"] == "" and v["probe_service_account"] == ""
               for v in pm["roles"].values())
    assert "postgres" in text and "superuser" in text
    assert "\u2014" not in text
    # nothing else was written
    assert not (ws / "artifacts" / "security-plan.json").exists()
    # refuse to overwrite the operator's work unless forced
    path.write_text(PRINCIPAL_YAML, encoding="utf-8")
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo",
              "--template"])
    assert rc == 1 and "BQ-SECURITY ERROR" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == PRINCIPAL_YAML
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo",
              "--template", "--force"])
    assert rc == 0 and path.read_text(encoding="utf-8") != PRINCIPAL_YAML


def test_cli_plan_writes_artifacts(tmp_path, monkeypatch, capsys):
    ws = make_workspace(tmp_path, monkeypatch)
    art = ws / "artifacts"
    (art / "translation-review.json").write_text(json.dumps(
        {"views": {"public.v": {"source_sql": "x", "auto_sql": "y",
                                "notes": [], "context_tables": {}}}}),
        encoding="utf-8")
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo"])
    out = capsys.readouterr().out
    assert rc == 0 and "security-plan.json" in out
    plan = read_json(art / "security-plan.json")
    assert plan["principals"]["reporting"] == REPORTING
    assert plan["taxonomy"]["display_name"] == "dbcarry_demo"
    assert (art / "security-plan.json").read_text(
        encoding="utf-8").endswith("}\n")
    md = (art / "security-plan.md").read_text(encoding="utf-8")
    for heading in ("## Principals", "## Bindings", "## Policy tags",
                    "## Row access policies", "## Authorized views",
                    "## Findings"):
        assert heading in md
    assert "customers__email" in md and "rls_reporting" in md
    for name in ("30-iam.sh", "40-policy-tags.sh", "50-row-policies.sql",
                 "70-identity-notes.md"):
        assert (art / "bq-apply" / name).exists()
    assert not (art / "bq-apply" / "60-masking-requests.json").exists()
    review = read_json(art / "translation-review.json")
    assert set(review) == {"views", "policies"}
    assert review["views"]["public.v"]["source_sql"] == "x"
    assert review["policies"] == {}
    # findings summary on stdout for the playbook
    assert "WARNING" in out and "INFO" in out


def test_cli_plan_uses_resolutions_and_review_out(tmp_path, monkeypatch,
                                                  capsys):
    ws = make_workspace(tmp_path, monkeypatch)
    art = ws / "artifacts"
    sec = read_json(art / "security.json")
    sec["policies"].append(policy("orders", "tenant", ["app_ro"],
                                  TENANT_USING))
    (art / "security.json").write_text(json.dumps(sec), encoding="utf-8")
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo",
              "--review-out", str(tmp_path / "rev.json")])
    assert rc == 0
    review = read_json(tmp_path / "rev.json")
    assert set(review["policies"]) == {"public.orders/tenant"}
    assert not (art / "translation-review.json").exists()
    plan = read_json(art / "security-plan.json")
    # reporting inherits app_ro, so the unresolved policy reaches it too
    assert [p["name"] for p in plan["row_policies"]
            if p["confidence"] == "review"] == ["rls_app_ro", "rls_reporting"]
    assert "review" in capsys.readouterr().out.lower()
    (art / "translation-resolutions.json").write_text(json.dumps(
        {"views": {}, "policies": {"public.orders/tenant": {
            "sql": "(tenant_id = 7)", "rationale": "single tenant"}}}),
        encoding="utf-8")
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo"])
    assert rc == 0
    plan = read_json(art / "security-plan.json")
    pol = next(p for p in plan["row_policies"] if p["name"] == "rls_app_ro"
               and p["table"] == "orders")
    assert pol["confidence"] == "resolved"
    assert pol["filter"] == "(tenant_id = 7)"
    rep = next(p for p in plan["row_policies"] if p["name"] == "rls_reporting"
               and p["table"] == "orders")
    assert rep["confidence"] == "resolved"
    assert rep["filter"] == "(region = 'eu') OR (tenant_id = 7)"
    assert not [p for p in plan["row_policies"] if p["confidence"] == "review"]
    review = read_json(art / "translation-review.json")
    assert review["policies"] == {}


def test_cli_apply_verify_probes(tmp_path, monkeypatch, capsys, demo_inv):
    ws = make_workspace(tmp_path, monkeypatch)
    art = ws / "artifacts"
    # apply before plan is an error
    rc = run(["apply", "--root", str(tmp_path), "--migration", "demo"])
    assert rc == 1 and "security-plan.json" in capsys.readouterr().err
    assert run(["plan", "--root", str(tmp_path), "--migration", "demo"]) == 0
    capsys.readouterr()
    # the emulator needs the tables the schema phase would have created
    backend = bb.make_backend(BQ_CFG, "demo", ws)
    create_demo_objects(backend, demo_inv)
    rc = run(["apply", "--root", str(tmp_path), "--migration", "demo"])
    out = capsys.readouterr().out
    assert rc == 0 and "applied" in out
    applied = read_json(art / "security-applied.json")
    assert applied["taxonomy"].startswith("projects/proj/")
    assert set(applied["tags"]) == {"customers__email"}
    assert applied["ops"] > 0 and applied["mode"] == "emulated"
    assert (art / "bq-operations.log").exists()
    rc = run(["verify", "--root", str(tmp_path), "--migration", "demo"])
    out = capsys.readouterr().out
    assert rc == 0 and "SECURITY VERIFY PASSED" in out
    verdict = read_json(art / "security-verify.json")
    assert verdict["pass"] is True and verdict["enforcement_active"] is True
    assert verdict["mode"] == "emulated"
    # probes without --run only write the set
    rc = run(["probes", "--root", str(tmp_path), "--migration", "demo"])
    assert rc == 0
    doc = read_json(art / "security-probes.json")
    assert doc["ran"] is False and doc["probes"]
    assert all("actual" not in p for p in doc["probes"])
    capsys.readouterr()
    # --run with --no-source: status-only expectations
    load_demo_rows(backend, tmp_path)
    calls = []
    monkeypatch.setattr(pg, "query_rows",
                        lambda *a, **k: calls.append(a) or [["0"]])
    rc = run(["probes", "--root", str(tmp_path), "--migration", "demo",
              "--run", "--no-source"])
    out = capsys.readouterr().out
    assert rc == 0 and "SECURITY PROBES PASSED" in out and calls == []
    doc = read_json(art / "security-probes.json")
    assert doc["ran"] is True and doc["pass"] is True
    assert doc["skipped"] is False
    assert doc["mode"] == "emulated"
    rep = one(doc["probes"], "reporting", "row_count", "orders")
    assert rep["actual"]["row_count"] == 2
    assert rep["expected"]["row_count"] is None
    # --run with the source: the pipeline user counts on PostgreSQL

    def fake_counts(ci, sql, readonly=False, writable=False):
        assert readonly is True and ci["dbname"] == "retail"
        return [["2"]] if "eu" in sql else [["0"]]
    monkeypatch.setattr(pg, "query_rows", fake_counts)
    rc = run(["probes", "--root", str(tmp_path), "--migration", "demo",
              "--run"])
    out = capsys.readouterr().out
    doc = read_json(art / "security-probes.json")
    rep = one(doc["probes"], "reporting", "row_count", "orders")
    assert rep["expected"]["row_count"] == 2 and rep["pass"] is True
    # app_rw expects 0 from the fake source but the emulator holds 3 rows
    assert rc == 1 and "SECURITY PROBES FAILED" in out
    rw = one(doc["probes"], "app_rw", "row_count", "orders")
    assert rw["pass"] is False and rw["actual"]["row_count"] == 3
    # tamper the emulator and verify fails with exit 1
    state_path = bb.emulated_root("demo") / STATE_FILE
    state = read_json(state_path)
    tag = applied["tags"]["customers__email"]
    state["taxonomies"][applied["taxonomy"]]["policyTags"][tag][
        "bindings"] = []
    state_path.write_text(json.dumps(state), encoding="utf-8")
    rc = run(["verify", "--root", str(tmp_path), "--migration", "demo"])
    out = capsys.readouterr().out
    assert rc == 1 and "SECURITY VERIFY FAILED" in out
    assert f"tag_reader:customers__email:{RW}" in out
    assert read_json(art / "security-verify.json")["pass"] is False


def test_cli_apply_refuses_review_policies(tmp_path, monkeypatch, capsys):
    ws = make_workspace(tmp_path, monkeypatch)
    art = ws / "artifacts"
    sec = read_json(art / "security.json")
    sec["policies"].append(policy("orders", "tenant", ["app_ro"],
                                  TENANT_USING))
    (art / "security.json").write_text(json.dumps(sec), encoding="utf-8")
    assert run(["plan", "--root", str(tmp_path), "--migration", "demo"]) == 0
    capsys.readouterr()
    rc = run(["apply", "--root", str(tmp_path), "--migration", "demo"])
    err = capsys.readouterr().err
    assert rc == 1 and "rls_app_ro" in err and "public.orders/tenant" in err
    assert not (art / "security-applied.json").exists()
    assert not (art / "bq-operations.log").exists()


def test_cli_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    rc = run(["plan", "--root", str(tmp_path), "--migration", "nope"])
    assert rc == 1 and "BQ-SECURITY ERROR" in capsys.readouterr().err
    ws = make_workspace(tmp_path, monkeypatch)
    (ws / "artifacts" / "security.json").unlink()
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo"])
    err = capsys.readouterr().err
    assert rc == 1 and "security.json" in err
    (ws / "artifacts" / "security.json").write_text("[]", encoding="utf-8")
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo"])
    assert rc == 1 and "security.json" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        run(["plan"])
    # a non bigquery provider has no security plan
    (ws / "artifacts" / "security.json").write_text(
        (FIXTURES / "demo-security.json").read_text(encoding="utf-8"),
        encoding="utf-8")
    (ws / "migration.yaml").write_text(
        MIGRATION_YAML.replace("provider: bigquery", "provider: local"),
        encoding="utf-8")
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo"])
    assert rc == 1 and "provider" in capsys.readouterr().err
    # verify and probes need the plan artifact
    (ws / "migration.yaml").write_text(MIGRATION_YAML, encoding="utf-8")
    for verb in ("verify", "probes"):
        rc = run([verb, "--root", str(tmp_path), "--migration", "demo"])
        assert rc == 1 and "security-plan.json" in capsys.readouterr().err


def test_cli_plan_without_principal_map_flags_every_role(tmp_path, monkeypatch,
                                                         capsys):
    # the assess phase state: security.json exists, no principal map yet
    ws = make_workspace(tmp_path, monkeypatch, with_map=False)
    rc = run(["--root", str(tmp_path), "--migration", "demo", "plan"])
    out = capsys.readouterr().out
    assert rc == 0
    plan = read_json(ws / "artifacts" / "security-plan.json")
    assert plan["principals"] == {} and plan["bindings"] == []
    assert plan["policy_tags"][0]["readers"] == []
    # every RLS table falls back to the deny-all policy for the admin
    assert [(p["table"], p["name"]) for p in plan["row_policies"]] == [
        ("audit_log", "rls_deny_all"), ("orders", "rls_deny_all")]
    warned = {f["subject"] for f in plan["findings"]
              if f["code"] == "unmapped_role"}
    assert warned == {"app_ro", "app_rw", "reporting"}
    assert "WARNING unmapped_role reporting" in out
    assert "WARNING rls_deny_all public.orders" in out


# ------------------------------------------------ review findings, round 2

def hyphen_inventory():
    inv = small_inventory()
    inv["tables"][0]["name"] = "order-lines"
    for c in inv["columns"]:
        if c["table"] == "orders":
            c["table"] = "order-lines"
    inv["view_dependencies"][0]["base"] = "public.order-lines"
    return inv


def test_review_key_is_the_source_table_name(tmp_path):
    # the review key must be the key translate_policy resolves under, even
    # when the BigQuery name differs from the PostgreSQL name
    inv = hyphen_inventory()
    sec = small_security(
        rls=[rls("order-lines")],
        policies=[policy("order-lines", "tenant", ["app_ro"], TENANT_USING)],
        relation_privileges=[rel("order-lines", "app_ro", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    pol = plan["row_policies"][0]
    assert pol["table"] == "order_lines"
    assert pol["source_table"] == "public.order-lines"
    assert set(bs.review_items(plan)) == {"public.order-lines/tenant"}
    assert findings(plan, "translation_review")[0]["subject"] == \
        "public.order-lines/tenant"
    with pytest.raises(bs.SecurityPlanError, match="public.order-lines/tenant"):
        bs.refuse_unresolved(plan)
    sql = bs.render_apply_scripts(plan, BQ_CFG)["50-row-policies.sql"]
    assert "public.order-lines" in sql
    # the round trip: review key -> resolutions file -> resolved plan
    resolutions = {"policies": {}}
    for key in bs.review_items(plan):
        resolutions["policies"][key] = {"sql": "(tenant_id = 7)",
                                        "rationale": "single tenant"}
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, resolutions)
    assert plan["row_policies"][0]["confidence"] == "resolved"
    assert plan["row_policies"][0]["filter"] == "(tenant_id = 7)"
    assert bs.review_items(plan) == {}
    bs.refuse_unresolved(plan)


def test_review_key_when_two_schemas_share_a_dataset():
    inv = small_inventory()
    inv["tables"][0]["schema"] = "sales"
    for c in inv["columns"]:
        if c["table"] == "orders":
            c["schema"] = "sales"
    inv["view_dependencies"][0]["base"] = "sales.orders"
    sec = small_security(
        rls=[rls("orders", schema="sales")],
        policies=[policy("orders", "tenant", ["app_ro"], TENANT_USING,
                         schema="sales")],
        relation_privileges=[rel("orders", "app_ro", "SELECT",
                                 schema="sales")])
    cfg = dict(BQ_CFG, dataset_map={"public": "retail", "sales": "retail"})
    plan = bs.plan_security(sec, inv, cfg, PRINCIPAL_MAP)
    assert plan["row_policies"][0]["source_table"] == "sales.orders"
    assert set(bs.review_items(plan)) == {"sales.orders/tenant"}
    with pytest.raises(bs.SecurityPlanError, match="sales.orders/tenant"):
        bs.refuse_unresolved(plan)
    resolutions = {"policies": {"sales.orders/tenant": {
        "sql": "(tenant_id = 7)", "rationale": "x"}}}
    plan = bs.plan_security(sec, inv, cfg, PRINCIPAL_MAP, resolutions)
    assert plan["row_policies"][0]["confidence"] == "resolved"


def test_probe_expectations_follow_the_plan_when_it_widens(tmp_path):
    inv = small_inventory()
    # INSERT only: the plan grants dataEditor (editor_widens), so the
    # principal can read on BigQuery although it cannot on PostgreSQL
    sec = small_security(relation_privileges=[
        rel("orders", "app_rw", "INSERT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert findings(plan, "editor_widens")
    probes = bs.probe_set(plan, sec, inv, PRINCIPAL_MAP, BQ_CFG)
    by = {(p["source_role"], p["kind"], p["table"]): p for p in probes}
    rw = by[("app_rw", "row_count", "orders")]
    assert rw["expected"]["status"] == "ok"
    assert rw["expected"]["row_count"] is None
    assert rw["expected"]["row_count_sql_pg"] is None
    assert "editor_widens" in rw["expected"]["note"]
    assert rw["columns"] == ["id", "region", "status", "tenant_id"]
    assert ("app_rw", "table_denied", "orders") not in by
    assert by[("app_rw", "table_denied", "customers")]["expected"] == {
        "status": "denied", "row_count": None, "row_count_sql_pg": None,
        "note": ""}
    # the probes pass against the emulator that holds the applied plan
    backend = bb.EmulatedBackend(tmp_path / "emu", PROJECT, "US")
    backend.create_dataset("retail")
    for t in inv["tables"]:
        backend.run_ddl(table_ddl(inv, PROJECT, "retail", t["name"]))
    bs.apply_plan(plan, backend)
    results = bs.run_probes(probes, backend, None)
    assert all(r["pass"] for r in results), [r for r in results
                                             if not r["pass"]]
    # binding_granularity dataset: app_ro reads orders only on the source
    # and the whole dataset on BigQuery
    sec = small_security(relation_privileges=[
        rel("orders", "app_ro", "SELECT")])
    cfg = dict(BQ_CFG, binding_granularity="dataset")
    plan = bs.plan_security(sec, inv, cfg, PRINCIPAL_MAP)
    probes = bs.probe_set(plan, sec, inv, PRINCIPAL_MAP, cfg)
    by = {(p["source_role"], p["kind"], p["table"]): p for p in probes}
    cust = by[("app_ro", "row_count", "customers")]
    assert cust["expected"]["status"] == "ok"
    assert cust["expected"]["row_count"] is None
    assert "widened_by_granularity" in cust["expected"]["note"]
    assert ("app_ro", "table_denied", "customers") not in by
    orders = by[("app_ro", "row_count", "orders")]
    assert orders["expected"]["row_count_sql_pg"] == \
        'SELECT count(*) FROM "public"."orders"'
    assert orders["expected"]["note"] == ""


def test_probe_expectations_with_a_shared_principal():
    # two roles on one principal: the plan (and BigQuery) see the union
    inv = small_inventory()
    sec = small_security(
        relation_privileges=[rel("orders", "app_ro", "SELECT"),
                             rel("customers", "app_rw", "SELECT")],
        column_privileges=[
            {"schema": "public", "relation": "customers", "column": "id",
             "grantee": "app_ro", "privilege": "SELECT"}])
    pmap = {"roles": {"app_ro": {"principal": RO}, "app_rw": {"principal": RO}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    probes = bs.probe_set(plan, sec, inv, pmap, BQ_CFG)
    by = {(p["source_role"], p["kind"], p["table"], tuple(p["columns"]))
          for p in probes}
    # app_ro alone cannot read customers.email, but its principal holds
    # the tag reader role through app_rw
    assert ("app_ro", "column_allowed", "customers", ("email",)) in by
    assert ("app_ro", "column_denied", "customers", ("email",)) not in by
    assert ("app_rw", "row_count", "orders", ("id", "region", "status",
                                              "tenant_id")) in by


def test_probe_set_counts_resolved_predicates_with_the_source_predicate():
    # a resolution replaces the target filter; the ORIGINAL source
    # predicate stays the ground truth for the expected count, and the
    # note says which policy was resolved (a source predicate that cannot
    # run for the pipeline user becomes an error in run_probes, not an
    # abort)
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        policies=[policy("orders", "tenant", ["app_ro"], TENANT_USING),
                  policy("orders", "eu", ["app_rw"], "(region = 'eu'::text)")],
        relation_privileges=[rel("orders", "app_ro", "SELECT"),
                             rel("orders", "app_rw", "SELECT")])
    resolutions = {"policies": {"public.orders/tenant": {
        "sql": "(tenant_id = 7)", "rationale": "single tenant"}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, resolutions)
    probes = bs.probe_set(plan, sec, inv, PRINCIPAL_MAP, BQ_CFG)
    by = {(p["source_role"], p["kind"], p["table"]): p for p in probes}
    ro = by[("app_ro", "row_count", "orders")]
    assert ro["expected"]["status"] == "ok"
    assert ro["expected"]["row_count_sql_pg"] == \
        f'SELECT count(*) FROM "public"."orders" WHERE {TENANT_USING}'
    assert ro["expected"]["row_count"] is None
    assert "resolved" in ro["expected"]["note"]
    assert "(tenant_id = 7)" in ro["expected"]["note"]
    assert TENANT_USING in ro["expected"]["note"]
    # an auto policy on the same table: the same source count, no note
    rw = by[("app_rw", "row_count", "orders")]
    assert rw["expected"]["row_count_sql_pg"] == (
        'SELECT count(*) FROM "public"."orders" WHERE '
        "(region = 'eu'::text)")
    assert rw["expected"]["note"] == ""
    # a review predicate that reached the probe set counts the same way
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    probes = bs.probe_set(plan, sec, inv, PRINCIPAL_MAP, BQ_CFG)
    ro = next(p for p in probes if p["source_role"] == "app_ro"
              and p["kind"] == "row_count")
    assert ro["expected"]["row_count_sql_pg"].endswith(f"WHERE {TENANT_USING}")
    assert "review" in ro["expected"]["note"]


def test_run_probes_survives_a_failing_source_count(monkeypatch):
    probes = [
        {"kind": "row_count", "principal": RO, "probe_service_account": "",
         "source_role": "app_ro", "dataset": "retail", "table": "orders",
         "columns": ["id"],
         "expected": {"status": "ok", "row_count": None, "note": "",
                      "row_count_sql_pg": "SELECT count(*) FROM broken"}},
        {"kind": "row_count", "principal": RO, "probe_service_account": "",
         "source_role": "app_ro", "dataset": "retail", "table": "customers",
         "columns": ["id"],
         "expected": {"status": "ok", "row_count": None, "note": "",
                      "row_count_sql_pg": "SELECT count(*) FROM fine"}},
    ]

    def fake_query_rows(ci, sql, readonly=False, writable=False):
        if "broken" in sql:
            raise pg.PgError('psql failed (1): ERROR: unrecognized '
                             'configuration parameter "app.tenant"')
        return [["2"]]
    monkeypatch.setattr(pg, "query_rows", fake_query_rows)

    class Fake:
        mode = "emulated"

        def probe(self, principal, probe_sa, dataset, table, columns):
            return {"status": "ok", "row_count": 2, "reason": "2 rows"}

    out = bs.run_probes(probes, Fake(), {"dbname": "d"})
    assert [r["pass"] for r in out] == [False, True]
    assert out[0]["expected"]["status"] == "error"
    assert out[0]["expected"]["row_count"] is None
    assert "app.tenant" in out[0]["expected"]["note"]
    assert out[0]["actual"]["status"] == "ok"
    assert out[1]["expected"]["status"] == "ok"
    assert out[1]["expected"]["row_count"] == 2
    assert bs.probes_pass(out) is False


def test_cli_artifacts_use_lf_newlines(tmp_path, monkeypatch):
    ws = make_workspace(tmp_path, monkeypatch)
    assert run(["plan", "--root", str(tmp_path), "--migration", "demo"]) == 0
    art = ws / "artifacts"
    cr = chr(13)
    for name in ("30-iam.sh", "40-policy-tags.sh", "50-row-policies.sql",
                 "70-identity-notes.md"):
        data = (art / "bq-apply" / name).read_bytes()
        assert cr.encode() not in data, name
        assert data.endswith(b"\n")
    for name in ("security-plan.json", "security-plan.md",
                 "translation-review.json"):
        assert cr.encode() not in (art / name).read_bytes(), name


def test_shared_principal_never_gets_viewer_beside_editor():
    inv = small_inventory()
    sec = small_security(relation_privileges=[
        rel("orders", "app_ro", "SELECT"), rel("orders", "app_rw", "INSERT"),
        rel("customers", "app_ro", "SELECT"),
        rel("customers", "app_rw", "SELECT")])
    pmap = {"roles": {"app_ro": {"principal": RO}, "app_rw": {"principal": RO}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    table = [(b["resource"], b["role"], b["source_role"])
             for b in plan["bindings"] if b["scope"] == "table"]
    assert table == [("retail.customers", bs.ROLE_VIEWER, "app_ro"),
                     ("retail.orders", bs.ROLE_EDITOR, "app_rw")]
    pairs = [(b["scope"], b["resource"], b["member"])
             for b in plan["bindings"] if b["scope"] != "project"]
    assert len(pairs) == len(set(pairs))
    note = findings(plan, "principal_shared")
    assert len(note) == 1 and note[0]["severity"] == "NOTE"
    assert note[0]["subject"] == RO
    assert "app_ro" in note[0]["message"] and "app_rw" in note[0]["message"]
    assert "dataViewer on retail.orders" in note[0]["message"]
    # distinct principals: no note
    assert not findings(bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP),
                        "principal_shared")
    # dataset scope: a superuser's dataOwner absorbs a viewer from another
    # role on the same principal
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"), role("reporting", login=False),
               role("postgres", superuser=True, bypass=True)],
        relation_privileges=[rel("orders", "app_ro", "SELECT"),
                             rel("customers", "app_ro", "SELECT"),
                             rel("recent_orders", "app_ro", "SELECT",
                                 kind="view")])
    pmap = {"roles": {"app_ro": {"principal": SUPER},
                      "postgres": {"principal": SUPER}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    assert [(b["scope"], b["resource"], b["role"]) for b in plan["bindings"]
            if b["scope"] == "dataset"] == [("dataset", "retail",
                                             bs.ROLE_OWNER)]


def test_inventory_without_columns_keeps_table_reads():
    sec = small_security(
        rls=[rls("orders")],
        policies=[policy("orders", "eu", ["app_ro"], "(region = 'eu'::text)")],
        relation_privileges=[rel("orders", "app_ro", "SELECT"),
                             rel("customers", "app_ro", "SELECT")])
    # a v0.1.0 inventory (no columns section at all) is refused outright
    # rather than degrading to nobody-can-read
    plan = bs.plan_security(sec, small_inventory(), BQ_CFG, PRINCIPAL_MAP)
    inv = small_inventory()
    del inv["columns"]
    with pytest.raises(bs.SecurityPlanError, match="assess"):
        bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    with pytest.raises(bs.SecurityPlanError, match="assess"):
        bs.probe_set(plan, sec, inv, PRINCIPAL_MAP, BQ_CFG)
    # a table without column rows keeps its table-level read, its row
    # policy, and its probes, and the plan says the rows are missing
    inv = small_inventory()
    inv["columns"] = [c for c in inv["columns"] if c["table"] != "orders"]
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    ro = bindings_for(plan, RO)
    assert ("table", "retail.orders", bs.ROLE_VIEWER) in [
        (b["scope"], b["resource"], b["role"]) for b in ro]
    assert policy_tuples(plan) == [
        ("retail", "orders", "rls_app_ro", "(region = 'eu')", "auto")]
    warn = findings(plan, "inventory_without_columns")
    assert warn and all(f["severity"] == "WARNING" for f in warn)
    assert [f["subject"] for f in warn] == ["public.orders"]
    assert "app_ro" in warn[0]["message"]
    probes = bs.probe_set(plan, sec, inv, PRINCIPAL_MAP, BQ_CFG)
    kinds = {(p["source_role"], p["kind"], p["table"]) for p in probes}
    assert ("app_ro", "row_count", "orders") in kinds
    assert ("app_ro", "table_denied", "orders") not in kinds
    orders = next(p for p in probes if p["source_role"] == "app_ro"
                  and p["kind"] == "row_count" and p["table"] == "orders")
    assert orders["columns"] == []
    # a table nobody reads is not flagged
    inv = small_inventory()
    inv["columns"] = [c for c in inv["columns"] if c["table"] != "customers"]
    sec = small_security(relation_privileges=[rel("orders", "app_ro", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert not findings(plan, "inventory_without_columns")


def test_translation_review_only_for_emitted_policies():
    inv = small_inventory()
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"), role("reporting", login=False),
               role("ghost")],
        rls=[rls("orders")],
        policies=[policy("orders", "tenant", ["ghost"], TENANT_USING)],
        relation_privileges=[rel("orders", "app_ro", "SELECT"),
                             rel("orders", "ghost", "SELECT")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert [p["name"] for p in plan["row_policies"]] == ["rls_deny_all"]
    assert not findings(plan, "translation_review")
    info = findings(plan, "translation_review_unmapped")
    assert len(info) == 1 and info[0]["severity"] == "INFO"
    assert info[0]["subject"] == "public.orders/tenant"
    assert "ghost" in info[0]["message"]
    assert bs.review_items(plan) == {}
    bs.refuse_unresolved(plan)
    # mapping the role turns it into the blocking WARNING
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["ghost"] = {"principal": "group:ghost@example.com"}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    assert findings(plan, "translation_review")[0]["subject"] == \
        "public.orders/tenant"
    assert not findings(plan, "translation_review_unmapped")
    assert set(bs.review_items(plan)) == {"public.orders/tenant"}


def test_widened_by_granularity_distinguishes_lesser_grants(demo_sec,
                                                            demo_inv):
    plan = demo_plan(demo_sec, demo_inv,
                     cfg=dict(BQ_CFG, binding_granularity="dataset"))
    rw = [f for f in findings(plan, "widened_by_granularity")
          if f["subject"] == f"retail/{RW}"]
    assert len(rw) == 1
    msg = rw[0]["message"]
    assert "dataEditor" in msg
    assert "read only" in msg
    assert "public.recent_orders" in msg and "public.sales_by_product" in msg
    assert "no grant on the source" not in msg
    # app_ro reads every relation: nothing to widen
    assert not [f for f in findings(plan, "widened_by_granularity")
                if f["subject"] == f"retail/{RO}"]
    # take products away from app_ro: one WARNING naming it as ungranted
    sec = copy.deepcopy(demo_sec)
    sec["relation_privileges"] = [
        r for r in sec["relation_privileges"]
        if not (r["grantee"] == "app_ro" and r["relation"] == "products")]
    plan = demo_plan(sec, demo_inv,
                     cfg=dict(BQ_CFG, binding_granularity="dataset"))
    ro = [f for f in findings(plan, "widened_by_granularity")
          if f["subject"] == f"retail/{RO}"]
    assert len(ro) == 1
    assert "no grant on the source: public.products" in ro[0]["message"]
    assert "read only" not in ro[0]["message"]


def test_write_only_grant_on_a_view_warns():
    inv = small_inventory()
    sec = small_security(relation_privileges=[
        rel("recent_orders", "reporting", "INSERT", kind="view")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert [(b["resource"], b["role"]) for b in bindings_for(plan, REPORTING)
            if b["scope"] == "table"] == [
        ("retail.recent_orders", bs.ROLE_VIEWER)]
    warn = findings(plan, "view_write_widens")
    assert len(warn) == 1 and warn[0]["severity"] == "WARNING"
    assert warn[0]["subject"] == "public.recent_orders/reporting"
    assert not findings(plan, "view_write_unmapped")
    # SELECT plus writes on a view stays the INFO
    sec = small_security(relation_privileges=[
        rel("recent_orders", "reporting", "INSERT", kind="view"),
        rel("recent_orders", "reporting", "SELECT", kind="view")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert findings(plan, "view_write_unmapped")
    assert not findings(plan, "view_write_widens")


def test_column_grant_on_a_view_warns():
    inv = small_inventory()
    sec = small_security(
        relation_privileges=[],
        column_privileges=[{"schema": "public", "relation": "recent_orders",
                            "column": "id", "grantee": "app_ro",
                            "privilege": "SELECT"}])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    ro = [b for b in bindings_for(plan, RO) if b["scope"] == "table"]
    assert [(b["resource"], b["role"]) for b in ro] == [
        ("retail.recent_orders", bs.ROLE_VIEWER)]
    assert "policy tag" not in ro[0]["reason"]
    assert plan["policy_tags"] == []
    warn = findings(plan, "view_column_grant_widens")
    assert len(warn) == 1 and warn[0]["severity"] == "WARNING"
    assert warn[0]["subject"] == "public.recent_orders/app_ro"
    assert "id" in warn[0]["message"]
    # a column grant on a table keeps the policy tag reason
    sec = small_security(
        relation_privileges=[rel("customers", "app_rw", "SELECT")],
        column_privileges=[{"schema": "public", "relation": "customers",
                            "column": "id", "grantee": "app_ro",
                            "privilege": "SELECT"}])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    ro = [b for b in bindings_for(plan, RO) if b["scope"] == "table"]
    assert "policy tag" in ro[0]["reason"]
    assert plan["policy_tags"]
    # a column grant covering every column claims no tag either
    sec = small_security(
        relation_privileges=[],
        column_privileges=[{"schema": "public", "relation": "customers",
                            "column": c, "grantee": "app_ro",
                            "privilege": "SELECT"}
                           for c in ("id", "email", "full_name")])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    ro = [b for b in bindings_for(plan, RO) if b["scope"] == "table"]
    assert "policy tag" not in ro[0]["reason"]
    assert plan["policy_tags"] == []


def test_inherited_ownership_bypasses_rls(demo_sec, demo_inv):
    inv = small_inventory()
    sec = small_security(
        roles=[role("app_ro"), role("app_rw"), role("reporting", login=False),
               role("owner_role"), role("deployer", member_of=["owner_role"])],
        memberships=[membership("deployer", "owner_role")],
        relation_privileges=[
            rel("orders", "app_ro", "SELECT"),
            rel("orders", "owner_role", "SELECT", owner="owner_role")],
        rls=[rls("orders")],
        policies=[policy("orders", "ro_eu", ["app_ro"], "(region = 'eu'::text)")])
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["owner_role"] = {"principal": "group:own@example.com"}
    pmap["roles"]["deployer"] = {"principal": "group:dep@example.com"}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    names = {p["name"]: p for p in plan["row_policies"]}
    assert set(names) == {"rls_app_ro", "rls_bypass_owner_role",
                          "rls_bypass_deployer"}
    assert names["rls_bypass_deployer"]["filter"] == "TRUE"
    assert names["rls_bypass_deployer"]["members"] == ["group:dep@example.com"]
    assert any("owner_role" in n for n in names["rls_bypass_deployer"]["notes"])
    assert not [f for f in findings(plan, "rls_denies_role")
                if f["subject"] == "public.orders/deployer"]
    # forced RLS binds the owner and its members alike
    sec["rls"][0]["forced"] = True
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    assert {p["name"] for p in plan["row_policies"]} == {"rls_app_ro"}
    assert {f["subject"] for f in findings(plan, "rls_denies_role")} == {
        "public.orders/deployer", "public.orders/owner_role"}
    # a member of the superuser that owns everything inherits ownership
    # (not superuser status), so it bypasses RLS on non-forced tables
    sec = copy.deepcopy(demo_sec)
    sec["roles"].append(role("analyst", member_of=["postgres"]))
    sec["memberships"].append(membership("analyst", "postgres"))
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["analyst"] = {"principal": "group:analyst@example.com"}
    plan = demo_plan(sec, demo_inv, pmap=pmap)
    bypass = [(p["table"], p["filter"]) for p in plan["row_policies"]
              if p["name"] == "rls_bypass_analyst"]
    assert bypass == [("audit_log", "TRUE"), ("orders", "TRUE")]
    assert not [f for f in findings(plan, "rls_denies_role")
                if f["subject"].endswith("/analyst")]
    # the probe for the bypass expects the full source count
    probes = bs.probe_set(plan, sec, demo_inv, pmap, BQ_CFG)
    an = next(p for p in probes if p["source_role"] == "analyst"
              and p["kind"] == "row_count" and p["table"] == "orders")
    assert an["expected"]["row_count_sql_pg"] == \
        'SELECT count(*) FROM "public"."orders"'


class _NumberedTagBackend:
    """Data Catalog spells the project by number, BigQuery by id."""
    mode = "live"
    tax = "projects/123456/locations/us/taxonomies/777"
    tag = tax + "/policyTags/999"

    def __init__(self, schema_tag):
        self.schema_tag = schema_tag

    def get_project_bindings(self):
        return [{"role": bs.ROLE_JOBUSER, "member": RW}]

    def get_dataset_access(self, dataset):
        return [{"role": bs.ROLE_VIEWER, "member": RW}]

    def get_table_bindings(self, dataset, table):
        return [{"role": bs.ROLE_VIEWER, "member": RW}]

    def list_taxonomies(self):
        return [{"name": self.tax, "displayName": "dbcarry_demo"}]

    def describe_taxonomy(self, name):
        return {"name": name, "displayName": "dbcarry_demo",
                "activatedPolicyTypes": ["FINE_GRAINED_ACCESS_CONTROL"]}

    def list_policy_tags(self, taxonomy):
        return [{"name": self.tag, "displayName": "customers__email"}]

    def get_policy_tag_bindings(self, tag):
        return [{"role": bs.ROLE_FGR, "member": RW}]

    def get_table_schema(self, dataset, table):
        return [{"name": "id", "type": "INT64"},
                {"name": "email", "type": "STRING",
                 "policyTags": {"names": [self.schema_tag]}}]

    def list_row_policies(self, dataset, table):
        return []


def test_verify_compares_tag_names_by_taxonomy_suffix():
    plan = {"taxonomy": {"display_name": "dbcarry_demo",
                         "activated": ["FINE_GRAINED_ACCESS_CONTROL"]},
            "bindings": [], "authorized_views": [], "row_policies": [],
            "policy_tags": [{"name": "customers__email",
                             "columns": [{"dataset": "retail",
                                          "table": "customers",
                                          "column": "email"}],
                             "readers": [{"member": RW,
                                          "source_role": "app_rw"}]}],
            "applied": {"tags": {"customers__email":
                                 "projects/proj/locations/us/taxonomies/777"
                                 "/policyTags/999"}}}
    same = "projects/proj/locations/us/taxonomies/777/policyTags/999"
    verdict = bs.verify_plan(plan, _NumberedTagBackend(same))
    assert verdict["pass"] is True, [c for c in verdict["checks"]
                                     if not c["pass"]]
    col = next(c for c in verdict["checks"]
               if c["name"] == "column_tag:retail.customers.email")
    assert "999" in col["actual"] and "123456" not in col["expected"]
    assert not [c for c in verdict["checks"]
                if c["name"].startswith("tag_resource")]
    other = "projects/proj/locations/us/taxonomies/777/policyTags/111"
    verdict = bs.verify_plan(plan, _NumberedTagBackend(other))
    assert verdict["pass"] is False
    col = next(c for c in verdict["checks"]
               if c["name"] == "column_tag:retail.customers.email")
    assert col["pass"] is False and "111" in col["actual"]


def test_verify_flags_extra_row_policies_and_tag_readers(tmp_path, demo_sec,
                                                         demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    backend = build_emulator(tmp_path, demo_inv)
    result = bs.apply_plan(plan, backend)
    assert bs.verify_plan(plan, backend)["pass"] is True
    tag = result["tags"]["customers__email"]
    backend.create_row_policy("retail", "orders", "rls_everyone", [EVERYONE],
                              "TRUE")
    backend.add_policy_tag_binding(tag, bs.ROLE_FGR, EVERYONE)
    backend.add_table_binding("retail", "customers", bs.ROLE_VIEWER, EVERYONE)
    assert backend.probe(EVERYONE, "", "retail", "customers", ["email"])[
        "status"] == "ok"
    verdict = bs.verify_plan(plan, backend)
    assert verdict["pass"] is False
    failed = {c["name"]: c for c in verdict["checks"] if not c["pass"]}
    assert set(failed) == {
        "row_policy_extra:retail.orders/rls_everyone",
        f"tag_reader_extra:customers__email:{EVERYONE}",
        f"table_binding_extra:retail.customers:{bs.ROLE_VIEWER}:{EVERYONE}"}
    assert failed["row_policy_extra:retail.orders/rls_everyone"][
        "expected"] == "absent"
    assert EVERYONE in failed["row_policy_extra:retail.orders/rls_everyone"][
        "actual"]
    assert failed[f"tag_reader_extra:customers__email:{EVERYONE}"][
        "expected"] == "absent"


def test_cli_probes_skipped_without_probes(tmp_path, monkeypatch, capsys,
                                           demo_inv):
    ws = make_workspace(tmp_path, monkeypatch)
    art = ws / "artifacts"
    assert run(["plan", "--root", str(tmp_path), "--migration", "demo"]) == 0
    backend = bb.make_backend(BQ_CFG, "demo", ws)
    create_demo_objects(backend, demo_inv)
    assert run(["apply", "--root", str(tmp_path), "--migration", "demo"]) == 0
    capsys.readouterr()
    # live mode without any probe_service_account: nothing can run
    (ws / "migration.yaml").write_text(
        MIGRATION_YAML.replace("mode: emulated", "mode: live"),
        encoding="utf-8")
    rc = run(["probes", "--root", str(tmp_path), "--migration", "demo",
              "--run", "--no-source"])
    out = capsys.readouterr().out
    # not an error (exit 0) but never a pass: the file says skipped and
    # the playbook treats that as not-a-pass in live mode
    assert rc == 0
    assert "SECURITY PROBES SKIPPED" in out and "PASSED" not in out
    assert "probe_service_account" in out
    doc = read_json(art / "security-probes.json")
    assert doc["ran"] is True and doc["pass"] is False
    assert doc["skipped"] is True
    assert doc["probes"] == []
    # without --run the set is written and marked skipped as well
    rc = run(["probes", "--root", str(tmp_path), "--migration", "demo"])
    assert rc == 0
    doc = read_json(art / "security-probes.json")
    assert doc["ran"] is False and doc["skipped"] is True


# ------------------------------------------------ review round 2 fixes

def test_verify_flags_extra_bindings_at_every_scope(tmp_path, demo_sec,
                                                     demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    backend = build_emulator(tmp_path, demo_inv)
    bs.apply_plan(plan, backend)
    assert bs.verify_plan(plan, backend)["pass"] is True
    backend.add_dataset_access("retail", {"role": bs.ROLE_VIEWER,
                                          "member": EVERYONE})
    backend.add_dataset_access("retail", {"role": bs.ROLE_OWNER,
                                          "member": "user:evil@example.com"})
    backend.add_table_binding("retail", "customers", bs.ROLE_VIEWER, EVERYONE)
    # the emulator refuses allUsers through its API; tamper the state
    state = read_state(tmp_path)
    state["project_bindings"].append({"role": bb.ROLE_ADMIN,
                                      "member": "allUsers"})
    state["project_bindings"].append({"role": bs.ROLE_VIEWER,
                                      "member": "user:owner@example.com"})
    state["datasets"]["retail"]["access"].append({"view": "retail.exfil"})
    write_state(tmp_path, state)
    backend = bb.EmulatedBackend(tmp_path / "emu", PROJECT, "US")
    verdict = bs.verify_plan(plan, backend)
    assert verdict["pass"] is False
    failed = {c["name"]: c for c in verdict["checks"] if not c["pass"]}
    assert set(failed) == {
        f"dataset_access_extra:retail:{bs.ROLE_VIEWER}:{EVERYONE}",
        f"dataset_access_extra:retail:{bs.ROLE_OWNER}:user:evil@example.com",
        f"table_binding_extra:retail.customers:{bs.ROLE_VIEWER}:{EVERYONE}",
        f"project_binding_extra:{bb.ROLE_ADMIN}:allUsers",
        "authorized_view_extra:retail:retail.exfil"}
    assert all(c["expected"] == "absent" for c in failed.values())
    # a project binding for an ordinary member is not pipeline-owned
    assert not [n for n in failed if "owner@example.com" in n]


def test_verify_flags_a_retired_role_still_bound(tmp_path, demo_sec,
                                                  demo_inv):
    backend = build_emulator(tmp_path, demo_inv)
    bs.apply_plan(demo_plan(demo_sec, demo_inv), backend)
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["app_ro"]["principal"] = ""
    plan = demo_plan(demo_sec, demo_inv, pmap=pmap)
    assert findings(plan, "unmapped_role")
    bs.apply_plan(plan, backend)
    verdict = bs.verify_plan(plan, backend)
    assert verdict["pass"] is False
    names = {c["name"] for c in verdict["checks"] if not c["pass"]}
    assert f"dataset_access_extra:retail:{bs.ROLE_VIEWER}:{RO}" in names
    # project IAM is not pipeline-owned, so the stale jobUser binding is
    # not an extra; the dataset entry is what grants data access
    assert not [n for n in names if n.startswith("project_binding_extra")]


def test_verify_live_defaults_are_not_extras(tmp_path, demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv, cfg=dict(BQ_CFG, mode="live"))
    backend = build_emulator(tmp_path, demo_inv)
    bs.apply_plan(plan, backend)
    for group in bb.PROJECT_SPECIAL_GROUPS:
        backend.add_dataset_access("retail", {
            "role": bs.ROLE_VIEWER, "member": f"specialGroup:{group}"})
    backend.add_dataset_access("retail", {
        "role": bs.ROLE_OWNER, "member": "user:creator@example.com"})
    verdict = bs.verify_plan(plan, backend)
    assert verdict["pass"] is True
    owner = [c for c in verdict["checks"]
             if c["name"].startswith("dataset_owner_identity:")]
    assert owner and owner[0]["pass"] is True
    assert "creator@example.com" in owner[0]["name"]
    # the same owner entry in emulated mode is an extra
    plan = demo_plan(demo_sec, demo_inv)
    names = {c["name"] for c in bs.verify_plan(plan, backend)["checks"]
             if not c["pass"]}
    assert (f"dataset_access_extra:retail:{bs.ROLE_OWNER}:"
            "user:creator@example.com") in names


def test_public_column_grant_gets_a_tag_not_full_read():
    inv = small_inventory()
    sec = small_security(
        relation_privileges=[rel("customers", "app_ro", "SELECT"),
                             rel("customers", "app_rw", "SELECT")],
        column_privileges=[{"schema": "public", "relation": "customers",
                            "column": "id", "grantee": "PUBLIC",
                            "privilege": "SELECT"}])
    cfg = dict(BQ_CFG, public_principal=EVERYONE)
    plan = bs.plan_security(sec, inv, cfg, PRINCIPAL_MAP)
    tags = plan["policy_tags"]
    assert len(tags) == 1
    assert [c["column"] for c in tags[0]["columns"]] == ["email", "full_name"]
    readers = {r["member"] for r in tags[0]["readers"]}
    assert readers == {RO, RW}
    mine = [b for b in bindings_for(plan, EVERYONE)
            if b["role"] == bs.ROLE_VIEWER]
    assert mine and "policy tag" in mine[0]["reason"]
    assert "covers every column" not in mine[0]["reason"]
    # without a public principal the PUBLIC grant still folds into every
    # role (reporting reads id only, so the tag stays), but no principal
    # stands for PUBLIC itself
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert not bindings_for(plan, EVERYONE)
    assert EVERYONE not in {r["member"] for t in plan["policy_tags"]
                            for r in t["readers"]}


def test_resolution_is_ignored_for_auto_and_stale_predicates():
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        policies=[policy("orders", "eu", ["app_ro"], "(region = 'eu'::text)")],
        relation_privileges=[rel("orders", "app_ro", "SELECT")])
    res = {"policies": {"public.orders/eu": {"sql": "TRUE",
                                             "rationale": "open it"}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, res)
    pol = plan["row_policies"][0]
    assert pol["filter"] == "(region = 'eu')" and pol["confidence"] == "auto"
    warn = findings(plan, "translation_resolution_ignored")
    assert warn and warn[0]["severity"] == "WARNING"
    # a review predicate whose resolution names another source predicate
    sec["policies"] = [policy("orders", "tenant", ["app_ro"],
                              TENANT_USING + " AND (status = 'paid'::text)")]
    res = {"policies": {"public.orders/tenant": {
        "sql": "(tenant_id = 7)", "rationale": "reviewed",
        "source_sql": TENANT_USING}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, res)
    pol = plan["row_policies"][0]
    assert pol["confidence"] == "review"
    assert findings(plan, "translation_resolution_stale")[0][
        "severity"] == "WARNING"
    assert bs.review_items(plan)
    # the same resolution with the matching source_sql is accepted
    res["policies"]["public.orders/tenant"]["source_sql"] = \
        TENANT_USING + " AND (status = 'paid'::text)"
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, res)
    assert plan["row_policies"][0]["confidence"] == "resolved"
    # a resolution without a rationale is not accepted
    res["policies"]["public.orders/tenant"]["rationale"] = ""
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, res)
    assert plan["row_policies"][0]["confidence"] == "review"
    assert findings(plan, "translation_resolution_unjustified")


def test_resolution_must_be_one_balanced_expression():
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        policies=[policy("orders", "tenant", ["app_ro"], TENANT_USING)],
        relation_privileges=[rel("orders", "app_ro", "SELECT")])
    for bad in ["a = 1) OR (1 = 1",
                "TRUE); DROP TABLE `proj.retail.orders`; SELECT (TRUE",
                "(tenant_id = 7);"]:
        res = {"policies": {"public.orders/tenant": {
            "sql": bad, "rationale": "crafted"}}}
        plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, res)
        assert plan["row_policies"][0]["confidence"] == "review", bad
        assert findings(plan, "translation_resolution_malformed"), bad
    res = {"policies": {"public.orders/tenant": {
        "sql": "(status = ');') AND (tenant_id = 7)", "rationale": "ok"}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP, res)
    assert plan["row_policies"][0]["confidence"] == "resolved"


def test_open_rls_table_probe_expects_zero_and_apply_refuses(tmp_path):
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        relation_privileges=[rel("orders", "app_ro", "SELECT")])
    cfg = dict(BQ_CFG, admin_principal="")
    plan = bs.plan_security(sec, inv, cfg, PRINCIPAL_MAP)
    assert findings(plan, "rls_deny_all_unassigned")
    probes = bs.probe_set(plan, sec, inv, PRINCIPAL_MAP, cfg)
    probe = one(probes, "app_ro", "row_count", "orders")
    assert probe["expected"]["row_count"] == 0
    backend = bb.EmulatedBackend(tmp_path / "emu", PROJECT, "US")
    with pytest.raises(bs.SecurityPlanError, match="rls_deny_all_unassigned"):
        bs.apply_plan(plan, backend)
    assert backend.list_datasets() == []


def test_apply_and_render_accept_only_known_confidences(demo_sec, demo_inv):
    for value in ["Review", "REVIEW", "needs_review", "", None, "pending"]:
        plan = demo_plan(demo_sec, demo_inv)
        plan["row_policies"][0]["confidence"] = value
        with pytest.raises(bs.SecurityPlanError, match="confidence"):
            bs.refuse_unresolved(plan)
        sql = bs.render_apply_scripts(plan, BQ_CFG)["50-row-policies.sql"]
        stmt = [l for l in sql.splitlines()
                if plan["row_policies"][0]["name"] in l
                and "CREATE OR REPLACE" in l]
        assert stmt and all(l.startswith("-- ") for l in stmt), value
        with pytest.raises(bs.SecurityPlanError, match="confidence"):
            bs.check_plan(plan)


def test_column_grant_on_unknown_column_is_not_bound():
    inv = small_inventory()
    sec = small_security(
        relation_privileges=[rel("customers", "app_rw", "SELECT")],
        column_privileges=[{"schema": "public", "relation": "customers",
                            "column": "ssn", "grantee": "app_ro",
                            "privilege": "SELECT"}])
    plan = bs.plan_security(sec, inv, BQ_CFG, PRINCIPAL_MAP)
    assert not [b for b in bindings_for(plan, RO)
                if b["role"] in bb.DATA_READ_ROLES]
    warn = findings(plan, "column_grant_unknown_column")
    assert warn and warn[0]["severity"] == "WARNING"
    assert "ssn" in warn[0]["message"]


def test_principal_case_variants_are_one_principal():
    inv = small_inventory()
    sec = small_security(
        relation_privileges=[rel("customers", "app_rw", "SELECT")],
        column_privileges=[{"schema": "public", "relation": "customers",
                            "column": "id", "grantee": "app_ro",
                            "privilege": "SELECT"}])
    pmap = {"roles": {
        "app_ro": {"principal": "group:Team@Example.com"},
        "app_rw": {"principal": "group:team@example.com"},
        "reporting": {"principal": ""}}}
    plan = bs.plan_security(sec, inv, BQ_CFG, pmap)
    assert plan["principals"] == {"app_ro": "group:team@example.com",
                                  "app_rw": "group:team@example.com"}
    assert findings(plan, "principal_shared")
    members = {b["member"] for b in plan["bindings"]}
    assert members == {"group:team@example.com"}
    assert {r["member"] for t in plan["policy_tags"]
            for r in t["readers"]} == {"group:team@example.com"}


def test_cli_probes_no_source_is_labeled(tmp_path, monkeypatch, capsys,
                                         demo_inv):
    ws = make_workspace(tmp_path, monkeypatch)
    art = ws / "artifacts"
    assert run(["plan", "--root", str(tmp_path), "--migration", "demo"]) == 0
    backend = bb.make_backend(BQ_CFG, "demo", ws)
    create_demo_objects(backend, demo_inv)
    assert run(["apply", "--root", str(tmp_path), "--migration", "demo"]) == 0
    load_demo_rows(backend, tmp_path)
    capsys.readouterr()
    rc = run(["probes", "--root", str(tmp_path), "--migration", "demo",
              "--run", "--no-source"])
    out = capsys.readouterr().out
    assert rc == 0
    assert ("SECURITY PROBES PASSED (emulated, status only, counts not "
            "compared)") in out
    doc = read_json(art / "security-probes.json")
    assert doc["source_compared"] is False and doc["pass"] is True


def test_render_quotes_members_and_planner_rejects_metacharacters(
        demo_sec, demo_inv):
    plan = demo_plan(demo_sec, demo_inv)
    scripts = bs.render_apply_scripts(plan, BQ_CFG)
    assert f"--member='{RW}'" in scripts["30-iam.sh"]
    assert f"--member='{RW}'" in scripts["40-policy-tags.sh"]
    pmap = copy.deepcopy(PRINCIPAL_MAP)
    pmap["roles"]["app_ro"]["principal"] = "group:x$(id)@example.com;pwned"
    with pytest.raises(bs.SecurityPlanError, match="app_ro"):
        demo_plan(demo_sec, demo_inv, pmap=pmap)


def test_public_rls_policy_is_noted_for_the_public_principal():
    inv = small_inventory()
    sec = small_security(
        rls=[rls("orders")],
        policies=[policy("orders", "eu", ["PUBLIC"], "(region = 'eu'::text)")],
        relation_privileges=[rel("orders", "PUBLIC", "SELECT")])
    cfg = dict(BQ_CFG, public_principal=EVERYONE)
    plan = bs.plan_security(sec, inv, cfg, PRINCIPAL_MAP)
    info = findings(plan, "public_rls_denied")
    assert info and info[0]["severity"] == "INFO"
    assert "public.orders" in info[0]["subject"]
    assert not [p for p in plan["row_policies"] if EVERYONE in p["members"]]


def test_cli_plan_rejects_malformed_resolutions(tmp_path, monkeypatch,
                                                capsys):
    ws = make_workspace(tmp_path, monkeypatch)
    (ws / "artifacts" / "translation-resolutions.json").write_text(
        json.dumps({"views": {}, "policies": []}), encoding="utf-8")
    rc = run(["plan", "--root", str(tmp_path), "--migration", "demo"])
    err = capsys.readouterr().err
    assert rc == 1 and "policies" in err and "object" in err

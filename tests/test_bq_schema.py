import json
from pathlib import Path

import pytest

from db_drift import bq_backend as bb
from db_drift import bq_schema as bs
from db_drift import pg

FIXTURES = Path(__file__).resolve().parent / "fixtures"

BQ_CFG = {
    "mode": "emulated", "project": "proj", "location": "US",
    "dataset_map": {"public": "retail"},
    "principal_map": "security/principal-map.yaml",
    "admin_principal": "", "public_principal": "",
    "column_security": "policy_tags", "binding_granularity": "auto",
    "gcs_bucket": "", "migration": "demo", "dbname": "retail",
}

ORDERS_DDL = """CREATE TABLE IF NOT EXISTS `proj.retail.orders` (
  id INT64 NOT NULL,
  customer_id INT64 NOT NULL,
  status STRING NOT NULL,
  ordered_at TIMESTAMP NOT NULL,
  region STRING NOT NULL,
  PRIMARY KEY (id) NOT ENFORCED,
  FOREIGN KEY (customer_id) REFERENCES `proj.retail.customers` (id) NOT ENFORCED
)
CLUSTER BY id
OPTIONS (description = 'migrated from public.orders by db-drift');"""

RECENT_ORDERS_SQL = (
    "SELECT o.id, c.email, o.status, o.ordered_at FROM (`proj.retail.orders` "
    "o JOIN `proj.retail.customers` c ON ((c.id = o.customer_id))) WHERE "
    "(o.ordered_at > (CURRENT_TIMESTAMP() - INTERVAL 90 DAY))")

SALES_BY_PRODUCT_SQL = (
    "SELECT p.id, p.sku, sum(oi.quantity) AS qty, sum((oi.quantity * "
    "oi.unit_price_cents)) AS revenue_cents FROM (`proj.retail.order_items` "
    "oi JOIN `proj.retail.products` p ON ((p.id = oi.product_id))) "
    "GROUP BY p.id, p.sku")

MIGRATION_YAML = """migration: m1
engine: postgres
provider: bigquery
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
"""


# ------------------------------------------------------------- fixtures

def demo_inventory():
    with open(FIXTURES / "demo-inventory.json", encoding="utf-8") as fh:
        return json.load(fh)


def col(table, name, ordinal, data_type, udt, nullable=True, default=None,
        precision=None, scale=None, element_type=None, schema="public"):
    return {"schema": schema, "table": table, "name": name,
            "ordinal": ordinal, "data_type": data_type, "udt_name": udt,
            "nullable": nullable, "default": default, "precision": precision,
            "scale": scale, "max_length": None, "element_type": element_type}


def make_inventory(columns, primary_keys=(), foreign_keys=(),
                   view_definitions=(), view_dependencies=(), sequences=(),
                   indexes=0):
    """A minimal v0.2.0 inventory around hand-built columns."""
    names = sorted({(c["schema"], c["table"]) for c in columns})
    views = [f"{v['schema']}.{v['name']}" for v in view_definitions
             if v["kind"] == "view"]
    matviews = [f"{v['schema']}.{v['name']}" for v in view_definitions
                if v["kind"] == "matview"]
    return {
        "server": {"version": "17.5", "wal_level": "logical",
                   "encoding": "UTF8"},
        "tables": [{"schema": s, "name": n, "rows": 0, "bytes": 0,
                    "has_pk": any(p["table"] == n and p["schema"] == s
                                  for p in primary_keys),
                    "replica_identity": "d"} for s, n in names],
        "sequences": list(sequences),
        "views": views, "matviews": matviews, "extensions": [], "roles": [],
        "counts": {"indexes": indexes, "constraints": 0},
        "columns": list(columns),
        "primary_keys": list(primary_keys),
        "foreign_keys": list(foreign_keys),
        "view_definitions": list(view_definitions),
        "view_dependencies": list(view_dependencies),
    }


def by_name(plan, kind="tables"):
    return {f"{t['schema']}.{t['name']}": t for t in plan[kind]}


def findings(plan, code):
    return [f for f in plan["findings"] if f["code"] == code]


@pytest.fixture
def emu(tmp_path):
    log = bb.OperationLog(tmp_path / "ops.log")
    return bb.EmulatedBackend(tmp_path / "emu", "proj", "US", log=log)


# ------------------------------------------------------ demo inventory

def test_demo_orders_ddl_matches_plan_shape():
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    orders = by_name(plan)["public.orders"]
    assert orders["ddl"] == ORDERS_DDL
    assert orders["dataset"] == "retail" and orders["bq_name"] == "orders"
    assert orders["qualified"] == "`proj.retail.orders`"
    assert orders["cluster_by"] == ["id"]
    assert [f["name"] for f in orders["fields"]] == [
        "id", "customer_id", "status", "ordered_at", "region"]
    assert all(f["mode"] == "REQUIRED" for f in orders["fields"])
    assert orders["fields"][3] == {"name": "ordered_at", "type": "TIMESTAMP",
                                   "mode": "REQUIRED"}


def test_demo_plan_covers_every_table_and_view():
    inv = demo_inventory()
    plan = bs.translate_schema(inv, BQ_CFG)
    assert plan["project"] == "proj" and plan["location"] == "US"
    assert plan["datasets"] == {"retail": {"source_schema": "public"}}
    tables = by_name(plan)
    assert set(tables) == {"public.audit_log", "public.customers",
                           "public.order_items", "public.orders",
                           "public.products"}
    # hstore becomes JSON, nullable stays NULLABLE, composite key clusters
    products = tables["public.products"]
    assert products["fields"][-1] == {"name": "attributes", "type": "JSON",
                                      "mode": "NULLABLE"}
    assert "attributes JSON," in products["ddl"]
    items = tables["public.order_items"]
    assert items["cluster_by"] == ["order_id", "product_id"]
    assert "PRIMARY KEY (order_id, product_id) NOT ENFORCED" in items["ddl"]
    assert ("FOREIGN KEY (order_id) REFERENCES `proj.retail.orders` (id) "
            "NOT ENFORCED") in items["ddl"]
    assert ("FOREIGN KEY (product_id) REFERENCES `proj.retail.products` (id) "
            "NOT ENFORCED") in items["ddl"]
    # no primary key: no key clause and no clustering
    audit = tables["public.audit_log"]
    assert audit["cluster_by"] == []
    assert "PRIMARY KEY" not in audit["ddl"]
    assert "CLUSTER BY" not in audit["ddl"]
    assert audit["ddl"].endswith(
        ")\nOPTIONS (description = 'migrated from public.audit_log by "
        "db-drift');")

    views = by_name(plan, "views")
    assert set(views) == {"public.recent_orders", "public.sales_by_product"}
    recent = views["public.recent_orders"]
    assert recent["kind"] == "view" and recent["confidence"] == "auto"
    assert recent["resolved"] is False and recent["materialized"] is False
    assert recent["sql"] == RECENT_ORDERS_SQL
    assert recent["ddl"] == ("CREATE OR REPLACE VIEW `proj.retail.recent_orders`"
                             " AS\n" + RECENT_ORDERS_SQL + ";")
    assert recent["source_sql"].startswith("SELECT o.id")
    assert not recent["source_sql"].endswith(";")
    sales = views["public.sales_by_product"]
    assert sales["kind"] == "matview" and sales["confidence"] == "auto"
    assert sales["materialized"] is True
    assert sales["sql"] == SALES_BY_PRODUCT_SQL
    assert sales["ddl"] == ("CREATE MATERIALIZED VIEW IF NOT EXISTS "
                            "`proj.retail.sales_by_product` AS\n"
                            + SALES_BY_PRODUCT_SQL + ";")
    # findings: indexes and sequences are dropped with a note
    assert len(findings(plan, "index_dropped")) == 1
    assert findings(plan, "index_dropped")[0]["severity"] == "INFO"
    assert {f["subject"] for f in findings(plan, "sequence_dropped")} == {
        "public.customers_id_seq", "public.orders_id_seq",
        "public.products_id_seq"}
    assert findings(plan, "view_review") == []
    for f in plan["findings"]:
        assert set(f) == {"severity", "code", "subject", "message", "action"}
        assert f["severity"] in ("WARNING", "INFO", "NOTE")


def test_demo_apply_then_verify_on_emulated_backend(emu):
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    ops = bs.apply_schema(plan, emu)
    assert ops[0] == {"op": "create_dataset", "name": "retail",
                      "status": "created"}
    assert [o["name"] for o in ops if o["op"] == "create_table"] == [
        t["qualified"] for t in plan["tables"]]
    assert [o["name"] for o in ops if o["op"] == "create_view"] == [
        "`proj.retail.recent_orders`", "`proj.retail.sales_by_product`"]
    listed = {t["name"]: t["type"] for t in emu.list_tables("retail")}
    assert listed == {"audit_log": "TABLE", "customers": "TABLE",
                      "order_items": "TABLE", "orders": "TABLE",
                      "products": "TABLE", "recent_orders": "VIEW",
                      "sales_by_product": "MATERIALIZED_VIEW"}
    assert emu.get_table_schema("retail", "orders") == \
        by_name(plan)["public.orders"]["fields"]
    report = bs.verify_schema(plan, emu)
    assert report == {"expected": {"tables": 5, "views": 2},
                      "actual": {"tables": 5, "views": 2},
                      "missing": [], "mismatched": [], "pass": True}
    # a second apply is idempotent: the dataset exists, IF NOT EXISTS holds
    ops2 = bs.apply_schema(plan, emu)
    assert ops2[0]["status"] == "exists"
    assert bs.verify_schema(plan, emu)["pass"] is True


# ------------------------------------------------------------ field modes

def test_field_modes_and_types():
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8", nullable=False),
        col("t", "tags", 2, "ARRAY", "_text", nullable=True,
            element_type="text"),
        col("t", "must_tags", 3, "ARRAY", "_int4", nullable=False,
            element_type="int4"),
        col("t", "doc", 4, "jsonb", "jsonb"),
        col("t", "amount", 5, "numeric", "numeric", precision=12, scale=2),
        col("t", "big", 6, "numeric", "numeric", precision=50, scale=20),
        col("t", "raw", 7, "bytea", "bytea"),
        col("t", "when_local", 8, "timestamp without time zone",
            "timestamp"),
        col("t", "span", 9, "interval", "interval"),
    ])
    plan = bs.translate_schema(inv, BQ_CFG)
    t = plan["tables"][0]
    assert t["fields"] == [
        {"name": "id", "type": "INT64", "mode": "REQUIRED"},
        {"name": "tags", "type": "STRING", "mode": "REPEATED"},
        {"name": "must_tags", "type": "INT64", "mode": "REPEATED"},
        {"name": "doc", "type": "JSON", "mode": "NULLABLE"},
        {"name": "amount", "type": "NUMERIC", "mode": "NULLABLE"},
        {"name": "big", "type": "BIGNUMERIC", "mode": "NULLABLE"},
        {"name": "raw", "type": "BYTES", "mode": "NULLABLE"},
        {"name": "when_local", "type": "DATETIME", "mode": "NULLABLE"},
        {"name": "span", "type": "STRING", "mode": "NULLABLE"},
    ]
    assert "  tags ARRAY<STRING>,\n" in t["ddl"]
    # BigQuery arrays cannot be NOT NULL: the constraint is dropped
    assert "  must_tags ARRAY<INT64>,\n" in t["ddl"]
    assert "must_tags ARRAY<INT64> NOT NULL" not in t["ddl"]
    assert findings(plan, "array_not_null_dropped")[0]["subject"] == \
        "public.t.must_tags"
    assert "  raw BYTES,\n" in t["ddl"]
    # type warnings surface as WARNING findings, plain notes as NOTE
    warn = findings(plan, "type_warning")
    assert [f["subject"] for f in warn] == ["public.t.span"]
    assert "STRING" in warn[0]["message"]
    assert any(f["subject"] == "public.t.raw" and "base64" in f["message"]
               for f in findings(plan, "type_note"))


def test_cluster_by_capped_at_four_primary_key_columns():
    cols = [col("wide", f"k{i}", i, "integer", "int4", nullable=False)
            for i in range(1, 7)]
    inv = make_inventory(cols, primary_keys=[
        {"schema": "public", "table": "wide", "name": "wide_pkey",
         "columns": ["k1", "k2", "k3", "k4", "k5", "k6"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    t = plan["tables"][0]
    assert t["cluster_by"] == ["k1", "k2", "k3", "k4"]
    assert "CLUSTER BY k1, k2, k3, k4\n" in t["ddl"]
    assert "PRIMARY KEY (k1, k2, k3, k4, k5, k6) NOT ENFORCED" in t["ddl"]


def test_defaults_are_dropped_with_a_note():
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8", nullable=False,
            default="nextval('t_id_seq'::regclass)"),
        col("t", "created", 2, "timestamp with time zone", "timestamptz",
            nullable=False, default="now()"),
    ])
    plan = bs.translate_schema(inv, BQ_CFG)
    ddl = plan["tables"][0]["ddl"]
    assert "DEFAULT" not in ddl and "nextval" not in ddl
    dropped = findings(plan, "default_dropped")
    assert {f["subject"] for f in dropped} == {"public.t.id",
                                                "public.t.created"}
    assert all(f["severity"] == "NOTE" for f in dropped)
    assert any("nextval" in f["message"] for f in dropped)


def test_reserved_column_names_are_backticked_in_ddl_only():
    inv = make_inventory([
        col("t", "order", 1, "text", "text", nullable=False),
        col("t", "from", 2, "text", "text"),
        col("t", "plain", 3, "text", "text"),
    ], primary_keys=[{"schema": "public", "table": "t", "name": "pk",
                      "columns": ["order"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    t = plan["tables"][0]
    assert "  `order` STRING NOT NULL,\n" in t["ddl"]
    assert "  `from` STRING,\n" in t["ddl"]
    assert "  plain STRING" in t["ddl"]
    assert "PRIMARY KEY (`order`) NOT ENFORCED" in t["ddl"]
    assert "CLUSTER BY `order`\n" in t["ddl"]
    assert [f["name"] for f in t["fields"]] == ["order", "from", "plain"]


def test_identifiers_are_sanitized_and_collisions_refused():
    inv = make_inventory([
        col("odd-table", "id", 1, "bigint", "int8", nullable=False),
        col("odd-table", "país", 2, "text", "text"),
    ])
    plan = bs.translate_schema(inv, BQ_CFG)
    t = plan["tables"][0]
    assert t["bq_name"] == "odd_table"
    assert t["qualified"] == "`proj.retail.odd_table`"
    assert [f["name"] for f in t["fields"]] == ["id", "pa_s"]
    assert t["renamed_columns"] == {"país": "pa_s"}
    renamed = findings(plan, "identifier_renamed")
    assert {f["subject"] for f in renamed} == {"public.odd-table",
                                                "public.odd-table.país"}
    # two source names that sanitize to the same target are an error
    clash = make_inventory([
        col("a-b", "id", 1, "bigint", "int8"),
        col("a_b", "id", 1, "bigint", "int8"),
    ])
    with pytest.raises(bs.SchemaError, match="a_b"):
        bs.translate_schema(clash, BQ_CFG)
    clash_cols = make_inventory([
        col("t", "a-b", 1, "bigint", "int8"),
        col("t", "a_b", 2, "bigint", "int8"),
    ])
    with pytest.raises(bs.SchemaError, match="a_b"):
        bs.translate_schema(clash_cols, BQ_CFG)


def test_inventory_without_columns_is_refused():
    inv = make_inventory([col("t", "id", 1, "bigint", "int8")])
    inv["columns"] = []
    with pytest.raises(bs.SchemaError, match="public.t"):
        bs.translate_schema(inv, BQ_CFG)


def test_dataset_naming_follows_dataset_map_and_dbname():
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8"),
        col("u", "id", 1, "bigint", "int8", schema="sales"),
    ])
    cfg = dict(BQ_CFG, dataset_map={})
    plan = bs.translate_schema(inv, cfg)
    assert plan["datasets"] == {"retail": {"source_schema": "public"},
                                "sales": {"source_schema": "sales"}}
    tables = by_name(plan)
    assert tables["public.t"]["qualified"] == "`proj.retail.t`"
    assert tables["sales.u"]["qualified"] == "`proj.sales.u`"
    cfg = dict(BQ_CFG, dataset_map={"public": "core", "sales": "core"})
    plan = bs.translate_schema(inv, cfg)
    assert plan["datasets"]["core"]["source_schemas"] == ["public", "sales"]
    assert set(by_name(plan)) == {"public.t", "sales.u"}
    # two schemas mapped to one dataset cannot both carry the same table
    inv2 = make_inventory([
        col("t", "id", 1, "bigint", "int8"),
        col("t", "id", 1, "bigint", "int8", schema="sales"),
    ])
    with pytest.raises(bs.SchemaError, match="core.t"):
        bs.translate_schema(inv2, cfg)


# -------------------------------------------------------- ordering rules

def test_tables_are_ordered_so_referenced_tables_come_first():
    inv = make_inventory([
        col("a_items", "id", 1, "bigint", "int8", nullable=False),
        col("a_items", "parent_id", 2, "bigint", "int8", nullable=False),
        col("m_middle", "id", 1, "bigint", "int8", nullable=False),
        col("z_parent", "id", 1, "bigint", "int8", nullable=False),
    ], primary_keys=[
        {"schema": "public", "table": "z_parent", "name": "p", "columns": ["id"]},
        {"schema": "public", "table": "a_items", "name": "i", "columns": ["id"]},
    ], foreign_keys=[
        {"schema": "public", "table": "a_items", "name": "fk",
         "columns": ["parent_id"], "ref_schema": "public",
         "ref_table": "z_parent", "ref_columns": ["id"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    assert [t["name"] for t in plan["tables"]] == ["m_middle", "z_parent",
                                                   "a_items"]
    sql = bs.render_tables_sql(plan)
    assert sql.index("`proj.retail.z_parent`") < sql.index("`proj.retail.a_items`")


def test_foreign_key_cycle_drops_one_constraint_with_a_warning():
    inv = make_inventory([
        col("x", "id", 1, "bigint", "int8", nullable=False),
        col("x", "y_id", 2, "bigint", "int8"),
        col("y", "id", 1, "bigint", "int8", nullable=False),
        col("y", "x_id", 2, "bigint", "int8"),
    ], primary_keys=[
        {"schema": "public", "table": "x", "name": "x_pk", "columns": ["id"]},
        {"schema": "public", "table": "y", "name": "y_pk", "columns": ["id"]},
    ], foreign_keys=[
        {"schema": "public", "table": "x", "name": "x_y", "columns": ["y_id"],
         "ref_schema": "public", "ref_table": "y", "ref_columns": ["id"]},
        {"schema": "public", "table": "y", "name": "y_x", "columns": ["x_id"],
         "ref_schema": "public", "ref_table": "x", "ref_columns": ["id"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    ddls = "\n".join(t["ddl"] for t in plan["tables"])
    assert ddls.count("FOREIGN KEY") == 1
    dropped = findings(plan, "foreign_key_dropped")
    assert len(dropped) == 1 and dropped[0]["severity"] == "WARNING"
    assert "ALTER TABLE" in dropped[0]["action"]
    assert {t["name"] for t in plan["tables"]} == {"x", "y"}


def test_foreign_key_to_unknown_table_is_dropped():
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8", nullable=False),
        col("t", "ext_id", 2, "bigint", "int8"),
    ], foreign_keys=[
        {"schema": "public", "table": "t", "name": "t_ext", "columns": ["ext_id"],
         "ref_schema": "other", "ref_table": "gone", "ref_columns": ["id"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    assert "FOREIGN KEY" not in plan["tables"][0]["ddl"]
    dropped = findings(plan, "foreign_key_dropped")
    assert dropped[0]["subject"] == "public.t.t_ext"
    assert "other.gone" in dropped[0]["message"]


def test_views_are_ordered_by_dependency():
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8", nullable=False),
        col("t", "kind", 2, "text", "text"),
    ], view_definitions=[
        {"schema": "public", "name": "a_top", "kind": "view",
         "definition": " SELECT id FROM z_base WHERE (kind = 'x'::text);"},
        {"schema": "public", "name": "z_base", "kind": "view",
         "definition": " SELECT t.id, t.kind FROM t;"},
    ], view_dependencies=[
        {"view": "public.a_top", "base": "public.z_base"},
        {"view": "public.z_base", "base": "public.t"}])
    plan = bs.translate_schema(inv, BQ_CFG)
    assert [v["name"] for v in plan["views"]] == ["z_base", "a_top"]
    top = by_name(plan, "views")["public.a_top"]
    # the view-on-view reference resolves through the shared table context
    assert top["sql"] == "SELECT id FROM `proj.retail.z_base` WHERE (kind = 'x')"
    assert top["confidence"] == "auto"
    sql = bs.render_tables_sql(plan)
    assert sql.index("`proj.retail.t`") < sql.index("`proj.retail.z_base` AS") \
        < sql.index("`proj.retail.a_top` AS")


def test_view_dependency_cycle_is_refused():
    inv = make_inventory([col("t", "id", 1, "bigint", "int8")],
                         view_definitions=[
        {"schema": "public", "name": "v1", "kind": "view",
         "definition": "SELECT id FROM v2"},
        {"schema": "public", "name": "v2", "kind": "view",
         "definition": "SELECT id FROM v1"}],
                         view_dependencies=[
        {"view": "public.v1", "base": "public.v2"},
        {"view": "public.v2", "base": "public.v1"}])
    with pytest.raises(bs.SchemaError, match="circular"):
        bs.translate_schema(inv, BQ_CFG)


# --------------------------------------------------- review and resolution

REVIEW_VIEW = {
    "schema": "public", "name": "tenant_rows", "kind": "view",
    "definition": (" SELECT t.id FROM t WHERE (t.tenant_id = "
                   "(current_setting('app.tenant'::text))::integer);")}


def review_inventory(kind="view"):
    view = dict(REVIEW_VIEW, kind=kind)
    return make_inventory([
        col("t", "id", 1, "bigint", "int8", nullable=False),
        col("t", "tenant_id", 2, "integer", "int4", nullable=False),
    ], view_definitions=[view],
        view_dependencies=[{"view": "public.tenant_rows", "base": "public.t"}])


def test_review_view_is_flagged_and_rendered_as_comment():
    plan = bs.translate_schema(review_inventory(), BQ_CFG)
    v = plan["views"][0]
    assert v["confidence"] == "review" and v["resolved"] is False
    assert "current_setting" in v["sql"]
    assert any("current_setting" in n for n in v["notes"])
    assert v["ddl"] == ""
    review = findings(plan, "view_review")
    assert len(review) == 1 and review[0]["severity"] == "WARNING"
    assert review[0]["subject"] == "public.tenant_rows"
    sql = bs.render_tables_sql(plan)
    assert "-- REVIEW public.tenant_rows" in sql
    for line in sql.splitlines():
        if "current_setting" in line:
            assert line.startswith("--")
    assert bs.unresolved_views(plan) == ["public.tenant_rows"]


def test_resolution_overrides_review_view():
    resolutions = {"views": {"public.tenant_rows": {
        "sql": "SELECT t.id FROM `proj.retail.t` t WHERE t.tenant_id = 7",
        "rationale": "the tenant is fixed per deployment"}},
        "policies": {}}
    plan = bs.translate_schema(review_inventory(), BQ_CFG, resolutions)
    v = plan["views"][0]
    assert v["confidence"] == "resolved" and v["resolved"] is True
    assert v["sql"] == "SELECT t.id FROM `proj.retail.t` t WHERE t.tenant_id = 7"
    assert v["ddl"] == ("CREATE OR REPLACE VIEW `proj.retail.tenant_rows` AS\n"
                        "SELECT t.id FROM `proj.retail.t` t WHERE "
                        "t.tenant_id = 7;")
    assert any("tenant is fixed" in n for n in v["notes"])
    assert findings(plan, "view_review") == []
    assert findings(plan, "view_resolved")[0]["subject"] == "public.tenant_rows"
    assert bs.unresolved_views(plan) == []
    # a resolution without sql is ignored, not applied as an empty body
    plan3 = bs.translate_schema(review_inventory(), BQ_CFG,
                                {"views": {"public.tenant_rows": {"sql": ""}}})
    assert plan3["views"][0]["confidence"] == "review"


def test_resolved_matview_stays_a_regular_view():
    resolutions = {"views": {"public.tenant_rows": {
        "sql": "SELECT t.id FROM `proj.retail.t` t", "rationale": "r"}}}
    plan = bs.translate_schema(review_inventory("matview"), BQ_CFG, resolutions)
    v = plan["views"][0]
    assert v["materialized"] is False
    assert v["ddl"].startswith("CREATE OR REPLACE VIEW ")
    assert findings(plan, "matview_as_view")[0]["subject"] == \
        "public.tenant_rows"


@pytest.mark.parametrize("body", [
    "SELECT t.id FROM t ORDER BY t.id",
    "SELECT t.id FROM t LIMIT 10",
    "SELECT t.id, row_number() OVER (ORDER BY t.id) AS rn FROM t",
])
def test_matview_with_unsupported_construct_becomes_view(body):
    inv = make_inventory([col("t", "id", 1, "bigint", "int8")],
                         view_definitions=[{"schema": "public", "name": "mv",
                                            "kind": "matview",
                                            "definition": body}],
                         view_dependencies=[{"view": "public.mv",
                                             "base": "public.t"}])
    plan = bs.translate_schema(inv, BQ_CFG)
    v = plan["views"][0]
    assert v["kind"] == "matview" and v["materialized"] is False
    if v["confidence"] == "auto":
        assert v["ddl"].startswith("CREATE OR REPLACE VIEW `proj.retail.mv`")
    warn = findings(plan, "matview_as_view")
    assert len(warn) == 1 and warn[0]["severity"] == "WARNING"


def test_matview_over_a_view_becomes_view():
    inv = make_inventory([col("t", "id", 1, "bigint", "int8")],
                         view_definitions=[
        {"schema": "public", "name": "base_v", "kind": "view",
         "definition": "SELECT t.id FROM t"},
        {"schema": "public", "name": "mv", "kind": "matview",
         "definition": "SELECT base_v.id FROM base_v"}],
                         view_dependencies=[
        {"view": "public.base_v", "base": "public.t"},
        {"view": "public.mv", "base": "public.base_v"}])
    plan = bs.translate_schema(inv, BQ_CFG)
    mv = by_name(plan, "views")["public.mv"]
    assert mv["materialized"] is False and mv["confidence"] == "auto"
    assert "base_v" in findings(plan, "matview_as_view")[0]["message"]


def test_review_items_for_translation_review_file():
    plan = bs.translate_schema(review_inventory(), BQ_CFG)
    items = bs.review_items(plan)
    assert list(items) == ["public.tenant_rows"]
    item = items["public.tenant_rows"]
    assert set(item) >= {"source_sql", "auto_sql", "notes", "context_tables"}
    assert item["source_sql"] == REVIEW_VIEW["definition"].strip().rstrip(";")
    assert "current_setting" in item["auto_sql"]
    assert item["context_tables"]["t"] == "`proj.retail.t`"
    assert item["context_tables"]["public.tenant_rows"] == \
        "`proj.retail.tenant_rows`"
    assert bs.review_items(bs.translate_schema(demo_inventory(), BQ_CFG)) == {}


# ------------------------------------------------------------- rendering

def test_render_datasets_script():
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8"),
        col("u", "id", 1, "bigint", "int8", schema="sales"),
    ])
    plan = bs.translate_schema(inv, dict(BQ_CFG, dataset_map={}))
    script = bs.render_datasets_script(plan)
    assert script.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in script
    assert 'PROJECT="proj"' in script and 'LOCATION="US"' in script
    assert script.index('"$PROJECT:retail"') < script.index('"$PROJECT:sales"')
    assert 'mk --dataset --location="$LOCATION" "$PROJECT:retail"' in script
    assert script.count("mk --dataset") == 2
    assert script.endswith("\n")


def test_render_tables_sql_has_tables_then_views():
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    sql = bs.render_tables_sql(plan)
    assert sql.startswith("-- 20-tables.sql")
    assert ORDERS_DDL in sql
    last_table = max(sql.index(t["ddl"]) for t in plan["tables"])
    first_view = min(sql.index(v["ddl"]) for v in plan["views"])
    assert last_table < first_view
    assert sql.endswith(";\n")


def test_rendered_script_runs_on_emulated_backend(emu):
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    emu.create_dataset("retail")
    emu.run_ddl(bs.render_tables_sql(plan))
    assert bs.verify_schema(plan, emu)["pass"] is True


# ---------------------------------------------------------- apply, verify

def test_apply_refuses_unresolved_review_views(emu):
    plan = bs.translate_schema(review_inventory(), BQ_CFG)
    with pytest.raises(bs.SchemaError) as ei:
        bs.apply_schema(plan, emu)
    assert "public.tenant_rows" in str(ei.value)
    assert "sql-translator" in str(ei.value)
    # nothing was created, not even the dataset
    assert emu.list_datasets() == []


def test_apply_datasets_only(emu):
    plan = bs.translate_schema(review_inventory(), BQ_CFG)
    ops = bs.apply_schema(plan, emu, datasets_only=True)
    assert ops == [{"op": "create_dataset", "name": "retail",
                    "status": "created"}]
    assert emu.list_datasets() == ["retail"]
    assert emu.list_tables("retail") == []
    assert bs.apply_schema(plan, emu, datasets_only=True) == [
        {"op": "create_dataset", "name": "retail", "status": "exists"}]


def test_apply_logs_progress(emu):
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    lines = []
    bs.apply_schema(plan, emu, log=lines.append)
    assert any("retail" in line for line in lines)
    assert any("`proj.retail.orders`" in line for line in lines)


def test_verify_reports_missing_and_mismatched(emu):
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    report = bs.verify_schema(plan, emu)
    assert report["pass"] is False
    assert report["actual"] == {"tables": 0, "views": 0}
    assert set(report["missing"]) == {t["qualified"] for t in plan["tables"]} | {
        v["qualified"] for v in plan["views"]}
    emu.create_dataset("retail")
    for t in plan["tables"]:
        if t["name"] != "products":
            emu.run_ddl(t["ddl"])
    # a planned materialized view that exists as a plain view is a mismatch
    emu.run_ddl("CREATE VIEW `proj.retail.sales_by_product` AS SELECT 1")
    report = bs.verify_schema(plan, emu)
    assert report["missing"] == ["`proj.retail.products`",
                                 "`proj.retail.recent_orders`"]
    assert report["mismatched"] == [{"name": "`proj.retail.sales_by_product`",
                                     "expected": "MATERIALIZED_VIEW",
                                     "actual": "VIEW"}]
    assert report["actual"] == {"tables": 4, "views": 1}
    assert report["pass"] is False


def test_load_resolutions(tmp_path):
    assert bs.load_resolutions(tmp_path) == {"views": {}, "policies": {}}
    art = tmp_path / "artifacts"
    art.mkdir()
    (art / "translation-resolutions.json").write_text(json.dumps({
        "views": {"public.v": {"sql": "SELECT 1", "rationale": "r"}}}),
        encoding="utf-8")
    res = bs.load_resolutions(tmp_path)
    assert res["views"]["public.v"]["sql"] == "SELECT 1"
    assert res["policies"] == {}
    (art / "translation-resolutions.json").write_text("[]", encoding="utf-8")
    with pytest.raises(bs.SchemaError, match="translation-resolutions"):
        bs.load_resolutions(tmp_path)


# ------------------------------------------------------------------ CLI

def workspace(tmp_path, inventory, yaml_text=MIGRATION_YAML):
    ws = tmp_path / "migrations" / "m1"
    (ws / "artifacts").mkdir(parents=True)
    (ws / "migration.yaml").write_text(yaml_text, encoding="utf-8")
    (ws / "artifacts" / "inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    return ws


def test_cli_translate_apply_verify(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    ws = workspace(tmp_path, demo_inventory())
    argv = ["bq-schema", "--root", str(tmp_path), "--migration", "m1"]

    assert bs.main(argv + ["translate"]) == 0
    out = capsys.readouterr().out
    assert "5 tables" in out and "2 views" in out
    art = ws / "artifacts"
    plan = json.loads((art / "schema-plan.json").read_text(encoding="utf-8"))
    assert plan["migration"] == "m1" and plan["project"] == "proj"
    assert by_name(plan)["public.orders"]["ddl"] == ORDERS_DDL
    assert (art / "bq-apply" / "10-datasets.sh").read_text(
        encoding="utf-8").startswith("#!/usr/bin/env bash")
    assert ORDERS_DDL in (art / "bq-apply" / "20-tables.sql").read_text(
        encoding="utf-8")
    review = json.loads((art / "translation-review.json").read_text(
        encoding="utf-8"))
    assert review == {"views": {}, "policies": {}}

    assert bs.main(argv + ["apply"]) == 0
    assert "applied" in capsys.readouterr().out
    backend = bb.make_backend(
        {"mode": "emulated", "project": "proj", "location": "US"}, "m1", ws)
    assert [t["name"] for t in backend.list_tables("retail")] == [
        "audit_log", "customers", "order_items", "orders", "products",
        "recent_orders", "sales_by_product"]
    applied = json.loads((art / "schema-applied.json").read_text(
        encoding="utf-8"))
    assert applied["ops"][0]["op"] == "create_dataset"
    assert (art / "bq-operations.log").exists()

    assert bs.main(argv + ["verify"]) == 0
    assert "SCHEMA VERIFY PASSED" in capsys.readouterr().out
    report = json.loads((art / "schema-verify.json").read_text(
        encoding="utf-8"))
    assert report["pass"] is True and report["missing"] == []

    # options after the verb work too
    assert bs.main(["bq-schema", "verify", "--migration", "m1", "--root",
                    str(tmp_path)]) == 0
    capsys.readouterr()


def test_cli_translate_merges_translation_review(tmp_path, monkeypatch,
                                                 capsys):
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    ws = workspace(tmp_path, review_inventory())
    art = ws / "artifacts"
    (art / "translation-review.json").write_text(json.dumps({
        "views": {"stale.view": {"source_sql": "x"}},
        "policies": {"public.orders/p": {"source_sql": "true"}}}),
        encoding="utf-8")
    argv = ["bq-schema", "--root", str(tmp_path), "--migration", "m1"]
    assert bs.main(argv + ["translate"]) == 0
    out = capsys.readouterr().out
    assert "1 view" in out and "review" in out
    review = json.loads((art / "translation-review.json").read_text(
        encoding="utf-8"))
    assert list(review["views"]) == ["public.tenant_rows"]
    assert review["policies"] == {"public.orders/p": {"source_sql": "true"}}
    assert "current_setting" in review["views"]["public.tenant_rows"]["auto_sql"]
    # the rendered script carries the review item as a comment only
    sql = (art / "bq-apply" / "20-tables.sql").read_text(encoding="utf-8")
    assert "-- REVIEW public.tenant_rows" in sql

    # apply refuses, names the view, and creates nothing
    assert bs.main(argv + ["apply"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("BQ-SCHEMA ERROR:") and "public.tenant_rows" in err
    backend = bb.make_backend(
        {"mode": "emulated", "project": "proj", "location": "US"}, "m1", ws)
    assert backend.list_datasets() == []

    # --datasets-only still works (provision phase)
    assert bs.main(argv + ["apply", "--datasets-only"]) == 0
    assert "retail" in capsys.readouterr().out
    assert bb.make_backend(
        {"mode": "emulated", "project": "proj", "location": "US"}, "m1",
        ws).list_datasets() == ["retail"]

    # a resolution file makes translate produce an applicable plan
    (art / "translation-resolutions.json").write_text(json.dumps({
        "views": {"public.tenant_rows": {
            "sql": "SELECT t.id FROM `proj.retail.t` t",
            "rationale": "tenant filter moves to a row access policy"}}}),
        encoding="utf-8")
    assert bs.main(argv + ["translate"]) == 0
    review = json.loads((art / "translation-review.json").read_text(
        encoding="utf-8"))
    assert review["views"] == {}
    assert review["policies"] == {"public.orders/p": {"source_sql": "true"}}
    assert bs.main(argv + ["apply"]) == 0
    assert bs.main(argv + ["verify"]) == 0
    capsys.readouterr()


def test_cli_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    argv = ["bq-schema", "--root", str(tmp_path), "--migration", "m1"]
    # no migration.yaml
    assert bs.main(argv + ["translate"]) == 1
    assert "BQ-SCHEMA ERROR" in capsys.readouterr().err
    ws = tmp_path / "migrations" / "m1"
    (ws / "artifacts").mkdir(parents=True)
    (ws / "migration.yaml").write_text(MIGRATION_YAML, encoding="utf-8")
    # no inventory
    assert bs.main(argv + ["translate"]) == 1
    assert "inventory" in capsys.readouterr().err
    # no plan
    assert bs.main(argv + ["apply"]) == 1
    assert "translate" in capsys.readouterr().err
    assert bs.main(argv + ["verify"]) == 1
    assert "translate" in capsys.readouterr().err
    # a v0.1.0 inventory without columns is refused with a clear message
    (ws / "artifacts" / "inventory.json").write_text(json.dumps(
        {"server": {}, "tables": [{"schema": "public", "name": "t"}],
         "views": [], "matviews": [], "sequences": [], "counts": {}}),
        encoding="utf-8")
    assert bs.main(argv + ["translate"]) == 1
    assert "public.t" in capsys.readouterr().err
    # verify fails with exit 1 when objects are missing
    (ws / "artifacts" / "inventory.json").write_text(
        json.dumps(demo_inventory()), encoding="utf-8")
    assert bs.main(argv + ["translate"]) == 0
    assert bs.main(argv + ["verify"]) == 1
    out = capsys.readouterr().out
    assert "SCHEMA VERIFY FAILED" in out and "`proj.retail.orders`" in out
    with pytest.raises(SystemExit):
        bs.main(["bq-schema", "translate", "--root", str(tmp_path)])
    capsys.readouterr()


# ------------------------------------------------- beyond the plan: risks

class FakeRunner:
    """Records argv and stdin; answers from a queue, else an empty list."""

    def __init__(self, outputs=None):
        self.calls = []
        self.outputs = list(outputs or [])

    def __call__(self, argv, stdin=None):
        self.calls.append((list(argv), stdin))
        if self.outputs:
            return self.outputs.pop(0)
        return (0, "[]", "")


def test_apply_and_verify_drive_the_live_backend(tmp_path):
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    runner = FakeRunner([(0, "[]", "")])
    backend = bb.LiveBackend("proj", "US", runner=runner,
                             log=bb.OperationLog(tmp_path / "ops.log"),
                             work_dir=tmp_path / "work")
    ops = bs.apply_schema(plan, backend)
    assert ops[0] == {"op": "create_dataset", "name": "retail",
                      "status": "created"}
    bq = ["bq", "--project_id=proj", "--format=json"]
    assert runner.calls[0] == (bq + ["ls", "--max_results=10000",
                                     "--datasets"], None)
    assert runner.calls[1] == (bq + ["mk", "--dataset", "--location=US",
                                     "proj:retail"], None)
    query = bq + ["query", "--use_legacy_sql=false", "--nouse_cache"]
    ddl_calls = runner.calls[2:]
    assert [c[0] for c in ddl_calls] == [query] * 7
    assert [c[1] for c in ddl_calls] == [t["ddl"] for t in plan["tables"]] + [
        v["ddl"] for v in plan["views"]]
    # the plan survives a JSON round trip, as the CLI reads it back
    plan = json.loads(json.dumps(plan))
    listed = json.dumps([
        {"tableReference": {"tableId": t["bq_name"]}, "type": "TABLE"}
        for t in plan["tables"]] + [
        {"tableReference": {"tableId": "recent_orders"}, "type": "VIEW"},
        {"tableReference": {"tableId": "sales_by_product"},
         "type": "MATERIALIZED_VIEW"}])
    runner.outputs.append((0, listed, ""))
    # verify reads every planned table's schema back with bq show
    for t in plan["tables"]:
        runner.outputs.append((0, json.dumps(t["fields"]), ""))
    report = bs.verify_schema(plan, backend)
    assert report["pass"] is True and report["actual"] == {"tables": 5,
                                                           "views": 2}
    assert runner.calls[-6] == (bq + ["ls", "--max_results=10000",
                                      "proj:retail"], None)
    assert [c[0] for c in runner.calls[-5:]] == [
        bq + ["show", "--schema", f"proj:retail.{t['bq_name']}"]
        for t in plan["tables"]]
    # a schema that does not come back is a mismatch, never a pass
    runner.outputs.append((0, listed, ""))
    runner.outputs.append((1, "", "BigQuery error: Not found: Table"))
    for t in plan["tables"][1:]:
        runner.outputs.append((0, json.dumps(t["fields"]), ""))
    report = bs.verify_schema(plan, backend)
    assert report["pass"] is False and report["missing"] == []
    assert report["mismatched"][0]["name"] == plan["tables"][0]["qualified"]
    # a dataset bq cannot list counts as missing, never as present
    runner.outputs.append((1, "", "BigQuery error: Not found: Dataset"))
    report = bs.verify_schema(plan, backend)
    assert report["pass"] is False and len(report["missing"]) == 7


def test_self_referencing_foreign_key_is_dropped_with_advice():
    inv = make_inventory([
        col("emp", "id", 1, "bigint", "int8", nullable=False),
        col("emp", "manager_id", 2, "bigint", "int8"),
    ], primary_keys=[{"schema": "public", "table": "emp", "name": "pk",
                      "columns": ["id"]}],
        foreign_keys=[{"schema": "public", "table": "emp", "name": "emp_mgr",
                       "columns": ["manager_id"], "ref_schema": "public",
                       "ref_table": "emp", "ref_columns": ["id"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    t = plan["tables"][0]
    assert "FOREIGN KEY" not in t["ddl"] and t["foreign_keys"] == []
    dropped = findings(plan, "foreign_key_dropped")
    assert len(dropped) == 1 and dropped[0]["severity"] == "WARNING"
    assert dropped[0]["subject"] == "public.emp.emp_mgr"
    # BigQuery forbids a foreign key into the same table, so the finding
    # must not tell the reader to add it later with ALTER TABLE
    assert "own table" in dropped[0]["message"]
    assert "cycle" not in dropped[0]["message"]
    assert "ALTER TABLE" not in dropped[0]["action"]
    assert "none" in dropped[0]["action"]


def test_dataset_map_value_is_sanitized_with_a_note():
    inv = make_inventory([col("t", "id", 1, "bigint", "int8")])
    plan = bs.translate_schema(inv, dict(BQ_CFG,
                                         dataset_map={"public": "my-data"}))
    assert list(plan["datasets"]) == ["my_data"]
    assert plan["tables"][0]["qualified"] == "`proj.my_data.t`"
    note = [f for f in findings(plan, "identifier_renamed")
            if f["subject"] == "public"]
    assert len(note) == 1 and "my_data" in note[0]["message"]
    assert '"$PROJECT:my_data"' in bs.render_datasets_script(plan)


def test_matview_construct_check_ignores_string_literals():
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8"),
        col("t", "label", 2, "text", "text"),
    ], view_definitions=[{
        "schema": "public", "name": "mv", "kind": "matview",
        "definition": ("SELECT t.id, 'order by limit over'::text AS label "
                       "FROM t GROUP BY t.id")}],
        view_dependencies=[{"view": "public.mv", "base": "public.t"}])
    plan = bs.translate_schema(inv, BQ_CFG)
    mv = plan["views"][0]
    assert mv["confidence"] == "auto" and mv["materialized"] is True
    assert findings(plan, "matview_as_view") == []
    # no alias in the source, so none in the target (BigQuery gives a
    # qualified table its last name part as the implicit alias)
    assert mv["sql"] == ("SELECT t.id, 'order by limit over' AS label FROM "
                         "`proj.retail.t` GROUP BY t.id")


def test_view_without_dependency_rows_still_translates():
    """A v0.2.0 inventory always records dependencies, but a view over
    no table (SELECT 1) has none; the translator gets every column."""
    inv = make_inventory([col("t", "id", 1, "bigint", "int8")],
                         view_definitions=[{"schema": "public", "name": "one",
                                            "kind": "view",
                                            "definition": "SELECT 1 AS one"}])
    plan = bs.translate_schema(inv, BQ_CFG)
    assert plan["views"][0]["ddl"] == (
        "CREATE OR REPLACE VIEW `proj.retail.one` AS\nSELECT 1 AS one;")


def test_datasets_script_refuses_unsafe_values():
    plan = bs.translate_schema(demo_inventory(), dict(BQ_CFG,
                                                       project="p;rm -rf"))
    with pytest.raises(bs.SchemaError, match="project"):
        bs.render_datasets_script(plan)


# ------------------------------------------- review findings: regressions

def matview_inventory(body, extra_cols=()):
    cols = [col("t", "id", 1, "bigint", "int8"),
            col("t", "g", 2, "text", "text"),
            col("t", "at", 3, "timestamp with time zone", "timestamptz"),
            col("t", "d", 4, "date", "date")] + list(extra_cols)
    return make_inventory(cols, view_definitions=[{
        "schema": "public", "name": "mv", "kind": "matview",
        "definition": body}],
        view_dependencies=[{"view": "public.mv", "base": "public.t"}])


@pytest.mark.parametrize("body,construct", [
    ("SELECT t.g, count(*) AS n FROM t GROUP BY t.g HAVING (count(*) > 1)",
     "HAVING"),
    ("SELECT t.id FROM t UNION ALL SELECT t.id FROM t", "UNION"),
    ("SELECT t.id FROM t INTERSECT SELECT t.id FROM t", "INTERSECT"),
    ("SELECT t.id FROM t EXCEPT SELECT t.id FROM t", "EXCEPT"),
    ("SELECT t.id FROM t WHERE (t.g = CURRENT_USER)", "SESSION_USER"),
    ("SELECT t.id FROM t WHERE (t.at > (now() - '1 day'::interval))",
     "CURRENT_TIMESTAMP"),
    ("SELECT t.id FROM t WHERE (t.d = CURRENT_DATE)", "CURRENT_DATE"),
    ("SELECT t.id, sum(t.id) OVER w AS s FROM t WINDOW w AS "
     "(PARTITION BY t.g)", "window"),
    ("SELECT t.id, sum(t.id) OVER (PARTITION BY t.g) AS s FROM t", "window"),
])
def test_matview_blocked_on_every_unsupported_construct(body, construct):
    """Each body translates with auto confidence, so the construct scan
    itself (not the confidence gate) has to catch it."""
    plan = bs.translate_schema(matview_inventory(body), BQ_CFG)
    v = plan["views"][0]
    assert v["confidence"] == "auto", v["notes"]
    assert v["materialized"] is False
    assert v["ddl"].startswith("CREATE OR REPLACE VIEW `proj.retail.mv`")
    warn = findings(plan, "matview_as_view")
    assert len(warn) == 1 and warn[0]["severity"] == "WARNING"
    assert construct.lower() in warn[0]["message"].lower()


def test_matview_scan_does_not_trip_on_column_names_or_literals():
    body = ("SELECT t.rand, t.having_flag, t.window_id, 'union having over' "
            "AS label FROM t WHERE (t.session_user_name = 'x'::text)")
    plan = bs.translate_schema(matview_inventory(body, [
        col("t", "rand", 5, "bigint", "int8"),
        col("t", "having_flag", 6, "boolean", "bool"),
        col("t", "window_id", 7, "bigint", "int8"),
        col("t", "session_user_name", 8, "text", "text")]), BQ_CFG)
    v = plan["views"][0]
    assert v["confidence"] == "auto", v["notes"]
    assert v["materialized"] is True
    assert findings(plan, "matview_as_view") == []


def test_column_collision_is_case_insensitive():
    """BigQuery column names are case-insensitive; the emulator and the
    live service both reject a table that repeats one by case."""
    inv = make_inventory([
        col("t", "Id", 1, "bigint", "int8"),
        col("t", "id", 2, "bigint", "int8"),
    ])
    with pytest.raises(bs.SchemaError) as ei:
        bs.translate_schema(inv, BQ_CFG)
    assert "Id" in str(ei.value) and " id" in str(ei.value)
    assert "case" in str(ei.value)


def test_foreign_key_to_non_primary_key_columns_is_dropped():
    inv = make_inventory([
        col("a", "id", 1, "bigint", "int8", nullable=False),
        col("a", "code", 2, "text", "text", nullable=False),
        col("b", "id", 1, "bigint", "int8", nullable=False),
        col("b", "a_code", 2, "text", "text"),
        col("b", "a_id", 3, "bigint", "int8"),
    ], primary_keys=[
        {"schema": "public", "table": "a", "name": "a_pk", "columns": ["id"]},
    ], foreign_keys=[
        {"schema": "public", "table": "b", "name": "b_a_code_fkey",
         "columns": ["a_code"], "ref_schema": "public", "ref_table": "a",
         "ref_columns": ["code"]},
        {"schema": "public", "table": "b", "name": "b_a_id_fkey",
         "columns": ["a_id"], "ref_schema": "public", "ref_table": "a",
         "ref_columns": ["id"]},
    ])
    plan = bs.translate_schema(inv, BQ_CFG)
    b = by_name(plan)["public.b"]
    assert [fk["name"] for fk in b["foreign_keys"]] == ["b_a_id_fkey"]
    assert "REFERENCES `proj.retail.a` (code)" not in b["ddl"]
    assert "REFERENCES `proj.retail.a` (id)" in b["ddl"]
    dropped = findings(plan, "foreign_key_dropped")
    assert len(dropped) == 1 and dropped[0]["severity"] == "WARNING"
    assert dropped[0]["subject"] == "public.b.b_a_code_fkey"
    assert "primary key" in dropped[0]["message"]


def test_primary_key_on_unsupported_types_is_dropped():
    inv = make_inventory([
        col("f", "k", 1, "double precision", "float8", nullable=False),
        col("f", "raw", 2, "bytea", "bytea", nullable=False),
        col("g", "id", 1, "bigint", "int8", nullable=False),
        col("g", "f_k", 2, "double precision", "float8"),
        col("g", "f_raw", 3, "bytea", "bytea"),
    ], primary_keys=[
        {"schema": "public", "table": "f", "name": "f_pk",
         "columns": ["k", "raw"]},
        {"schema": "public", "table": "g", "name": "g_pk", "columns": ["id"]},
    ], foreign_keys=[
        {"schema": "public", "table": "g", "name": "g_f_fkey",
         "columns": ["f_k", "f_raw"], "ref_schema": "public",
         "ref_table": "f", "ref_columns": ["k", "raw"]},
    ])
    plan = bs.translate_schema(inv, BQ_CFG)
    f = by_name(plan)["public.f"]
    assert f["primary_key"] == [] and f["cluster_by"] == []
    assert "PRIMARY KEY" not in f["ddl"] and "CLUSTER BY" not in f["ddl"]
    pk = findings(plan, "primary_key_dropped")
    assert len(pk) == 1 and pk[0]["severity"] == "WARNING"
    assert pk[0]["subject"] == "public.f.f_pk"
    assert "FLOAT64" in pk[0]["message"]
    # a foreign key into a table whose primary key was dropped goes too
    g = by_name(plan)["public.g"]
    assert g["foreign_keys"] == [] and "FOREIGN KEY" not in g["ddl"]
    fk = findings(plan, "foreign_key_dropped")
    assert len(fk) == 1 and fk[0]["subject"] == "public.g.g_f_fkey"
    assert "primary key" in fk[0]["message"]
    # no_primary_key is about the source; a dropped key does not add it
    assert findings(plan, "no_primary_key") == []


def test_primary_key_over_sixteen_columns_is_dropped():
    cols = [col("wide", f"k{i}", i, "integer", "int4", nullable=False)
            for i in range(1, 18)]
    inv = make_inventory(cols, primary_keys=[
        {"schema": "public", "table": "wide", "name": "wide_pkey",
         "columns": [f"k{i}" for i in range(1, 18)]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    t = plan["tables"][0]
    assert "PRIMARY KEY" not in t["ddl"]
    assert "16" in findings(plan, "primary_key_dropped")[0]["message"]
    # clustering still uses the leading key columns
    assert t["cluster_by"] == ["k1", "k2", "k3", "k4"]


def test_cluster_by_skips_columns_bigquery_cannot_cluster_on():
    """BYTES is a valid key type but not a clustering type; the key is
    kept and clustering uses the eligible columns only."""
    inv = make_inventory([
        col("t", "raw", 1, "bytea", "bytea", nullable=False),
        col("t", "id", 2, "bigint", "int8", nullable=False),
    ], primary_keys=[{"schema": "public", "table": "t", "name": "t_pk",
                      "columns": ["raw", "id"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    t = plan["tables"][0]
    assert "PRIMARY KEY (raw, id) NOT ENFORCED" in t["ddl"]
    assert t["cluster_by"] == ["id"]
    assert "CLUSTER BY id\n" in t["ddl"]
    note = findings(plan, "cluster_column_skipped")
    assert len(note) == 1 and note[0]["severity"] == "NOTE"
    assert "raw BYTES" in note[0]["message"]
    assert findings(plan, "primary_key_dropped") == []
    # TIME is neither a key type nor a clustering type: the key goes
    inv = make_inventory([
        col("u", "at", 1, "time without time zone", "time", nullable=False),
    ], primary_keys=[{"schema": "public", "table": "u", "name": "u_pk",
                      "columns": ["at"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    assert "PRIMARY KEY" not in plan["tables"][0]["ddl"]
    assert "at TIME" in findings(plan, "primary_key_dropped")[0]["message"]


def test_repeated_column_cannot_be_a_key_or_cluster_column():
    inv = make_inventory([
        col("t", "tags", 1, "ARRAY", "_text", nullable=False,
            element_type="text"),
    ], primary_keys=[{"schema": "public", "table": "t", "name": "t_pk",
                      "columns": ["tags"]}])
    plan = bs.translate_schema(inv, BQ_CFG)
    t = plan["tables"][0]
    assert "PRIMARY KEY" not in t["ddl"] and "CLUSTER BY" not in t["ddl"]
    assert "ARRAY" in findings(plan, "primary_key_dropped")[0]["message"]


def test_description_escapes_quotes_and_backslashes(emu):
    inv = make_inventory([
        col("o'neil", "id", 1, "bigint", "int8"),
        col("back\\slash", "id", 1, "bigint", "int8"),
    ])
    plan = bs.translate_schema(inv, BQ_CFG)
    tables = by_name(plan)
    assert tables["public.o'neil"]["ddl"].endswith(
        "OPTIONS (description = 'migrated from public.o\\'neil by db-drift');")
    assert tables["public.back\\slash"]["ddl"].endswith(
        "OPTIONS (description = 'migrated from public.back\\\\slash by "
        "db-drift');")
    bs.apply_schema(plan, emu)
    assert bs.verify_schema(plan, emu)["pass"] is True


def test_identity_column_is_reported_when_the_inventory_carries_it():
    """information_schema reports no column_default for an identity
    column; an inventory that records is_identity gets a finding."""
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8", nullable=False),
        col("t", "n", 2, "bigint", "int8"),
    ])
    inv["columns"][0]["is_identity"] = True
    inv["columns"][0]["identity_generation"] = "BY DEFAULT"
    plan = bs.translate_schema(inv, BQ_CFG)
    dropped = findings(plan, "default_dropped")
    assert [f["subject"] for f in dropped] == ["public.t.id"]
    assert "identity" in dropped[0]["message"]
    assert "BY DEFAULT" in dropped[0]["message"]
    inv["columns"][0]["is_identity"] = "YES"
    plan = bs.translate_schema(inv, BQ_CFG)
    assert len(findings(plan, "default_dropped")) == 1
    inv["columns"][0]["is_identity"] = "NO"
    plan = bs.translate_schema(inv, BQ_CFG)
    assert findings(plan, "default_dropped") == []


def test_unique_and_check_constraints_are_counted_as_dropped():
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    info = findings(plan, "constraints_dropped")
    assert len(info) == 1 and info[0]["severity"] == "INFO"
    # the demo has 10 constraints: 4 primary keys, 3 foreign keys, and
    # 2 UNIQUE plus 1 CHECK that BigQuery cannot carry
    assert info[0]["message"].startswith("3 ")
    assert "UNIQUE" in info[0]["message"] and "CHECK" in info[0]["message"]
    # nothing to report when the keys account for every constraint
    inv = make_inventory([col("t", "id", 1, "bigint", "int8")],
                         primary_keys=[{"schema": "public", "table": "t",
                                        "name": "pk", "columns": ["id"]}])
    inv["counts"]["constraints"] = 1
    assert findings(bs.translate_schema(inv, BQ_CFG),
                    "constraints_dropped") == []


def test_view_context_prefers_its_own_dependencies():
    """A bare table name in a view body resolves to the base the
    dependency rows name, not to the public table of the same name."""
    inv = make_inventory([
        col("t", "id", 1, "bigint", "int8"),
        col("t", "id", 1, "bigint", "int8", schema="sales"),
    ], view_definitions=[
        {"schema": "sales", "name": "v", "kind": "view",
         "definition": " SELECT t.id FROM t;"},
        {"schema": "public", "name": "pv", "kind": "view",
         "definition": " SELECT t.id FROM t;"},
    ], view_dependencies=[
        {"view": "sales.v", "base": "sales.t"},
        {"view": "public.pv", "base": "public.t"},
    ])
    plan = bs.translate_schema(inv, dict(BQ_CFG, dataset_map={}))
    views = by_name(plan, "views")
    assert views["sales.v"]["sql"] == "SELECT t.id FROM `proj.sales.t`"
    assert views["public.pv"]["sql"] == "SELECT t.id FROM `proj.retail.t`"
    assert views["sales.v"]["confidence"] == "auto"
    # the global map (what the review file shows) still lets public win
    assert plan["context_tables"]["t"] == "`proj.retail.t`"


def test_table_without_columns_gets_a_message_about_the_table():
    inv = make_inventory([col("t", "id", 1, "bigint", "int8")])
    inv["tables"].append({"schema": "public", "name": "empty", "rows": 0,
                          "bytes": 0, "has_pk": False,
                          "replica_identity": "d"})
    with pytest.raises(bs.SchemaError) as ei:
        bs.translate_schema(inv, BQ_CFG)
    msg = str(ei.value)
    assert "public.empty" in msg and "no columns" in msg
    assert "v0.2.0" not in msg
    # an inventory with no column rows at all still blames the version
    inv["columns"] = []
    with pytest.raises(bs.SchemaError, match="v0.2.0"):
        bs.translate_schema(inv, BQ_CFG)


def test_cycle_breaking_drops_only_a_constraint_on_the_cycle():
    """a -> b, b -> c, c -> b: only b and c form a cycle, so a keeps its
    foreign key and exactly one constraint is dropped."""
    inv = make_inventory([
        col("a", "id", 1, "bigint", "int8", nullable=False),
        col("a", "b_id", 2, "bigint", "int8"),
        col("b", "id", 1, "bigint", "int8", nullable=False),
        col("b", "c_id", 2, "bigint", "int8"),
        col("c", "id", 1, "bigint", "int8", nullable=False),
        col("c", "b_id", 2, "bigint", "int8"),
    ], primary_keys=[
        {"schema": "public", "table": n, "name": f"{n}_pk", "columns": ["id"]}
        for n in ("a", "b", "c")
    ], foreign_keys=[
        {"schema": "public", "table": "a", "name": "a_b", "columns": ["b_id"],
         "ref_schema": "public", "ref_table": "b", "ref_columns": ["id"]},
        {"schema": "public", "table": "b", "name": "b_c", "columns": ["c_id"],
         "ref_schema": "public", "ref_table": "c", "ref_columns": ["id"]},
        {"schema": "public", "table": "c", "name": "c_b", "columns": ["b_id"],
         "ref_schema": "public", "ref_table": "b", "ref_columns": ["id"]},
    ])
    plan = bs.translate_schema(inv, BQ_CFG)
    kept = {t["name"]: [fk["name"] for fk in t["foreign_keys"]]
            for t in plan["tables"]}
    assert kept == {"a": ["a_b"], "b": [], "c": ["c_b"]}
    dropped = findings(plan, "foreign_key_dropped")
    assert [f["subject"] for f in dropped] == ["public.b.b_c"]
    assert "cycle" in dropped[0]["message"]
    assert "ALTER TABLE `proj.retail.b` ADD CONSTRAINT b_c" in \
        dropped[0]["action"]
    order = [t["name"] for t in plan["tables"]]
    assert order.index("b") < order.index("a")
    assert order.index("b") < order.index("c")


def test_topological_breaks_a_longer_cycle_with_one_edge():
    dropped = []
    order = bs._topological(
        ["p", "q", "r", "s"],
        [("p", "q"), ("q", "r"), ("r", "s"), ("s", "q")],
        lambda name, unmet: dropped.append((name, unmet)))
    assert sorted(order) == ["p", "q", "r", "s"]
    assert dropped == [("q", ["r"])]
    assert order.index("q") < order.index("p")
    assert order.index("s") < order.index("r")


@pytest.mark.parametrize("sql", [
    "SELECT 1 AS x; DROP TABLE `proj.retail.t`",
    "DROP TABLE `proj.retail.t`",
    "CREATE TABLE `proj.retail.u` (x INT64)",
    "SELECT 1 AS x; SELECT 2 AS y",
    "SELECT 'unterminated",
])
def test_resolution_must_be_a_single_select(sql):
    resolutions = {"views": {"public.tenant_rows": {"sql": sql}}}
    with pytest.raises(bs.SchemaError) as ei:
        bs.translate_schema(review_inventory(), BQ_CFG, resolutions)
    assert "public.tenant_rows" in str(ei.value)


@pytest.mark.parametrize("sql", [
    "SELECT t.id FROM `proj.retail.t` t",
    "WITH x AS (SELECT 1 AS id) SELECT id FROM x",
    "(SELECT t.id FROM `proj.retail.t` t)",
    "select t.id from `proj.retail.t` t;",
])
def test_resolution_accepts_select_and_with_bodies(sql):
    resolutions = {"views": {"public.tenant_rows": {"sql": sql,
                                                    "rationale": "r"}}}
    plan = bs.translate_schema(review_inventory(), BQ_CFG, resolutions)
    assert plan["views"][0]["confidence"] == "resolved"


def test_malformed_resolution_is_a_schema_error(tmp_path, monkeypatch,
                                                capsys):
    for bad in ({"sql": ["SELECT 1"]}, {"sql": 7}, "SELECT 1", ["SELECT 1"]):
        with pytest.raises(bs.SchemaError) as ei:
            bs.translate_schema(review_inventory(), BQ_CFG,
                                {"views": {"public.tenant_rows": bad}})
        assert "public.tenant_rows" in str(ei.value)
        assert "translation-resolutions.json" in str(ei.value)
    # through the CLI it is a clean error line, not a traceback
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    ws = workspace(tmp_path, review_inventory())
    (ws / "artifacts" / "translation-resolutions.json").write_text(
        json.dumps({"views": {"public.tenant_rows": {"sql": ["SELECT 1"]}}}),
        encoding="utf-8")
    argv = ["bq-schema", "--root", str(tmp_path), "--migration", "m1"]
    assert bs.main(argv + ["translate"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("BQ-SCHEMA ERROR:") and "public.tenant_rows" in err


# ------------------------------------------------- review findings, v0.2.0

def test_verify_compares_columns_of_planned_tables(emu, tmp_path):
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    bs.apply_schema(plan, emu)
    assert bs.verify_schema(plan, emu)["pass"] is True
    # tamper with the emulator: one column dropped, one retyped, one with
    # another mode, one extra; policy tags never count as a difference
    state = json.loads((tmp_path / "emu" / bb.STATE_FILE).read_text(
        encoding="utf-8"))
    fields = state["datasets"]["retail"]["tables"]["orders"]["fields"]
    by = {f["name"]: f for f in fields}
    fields.remove(by["region"])
    by["status"]["type"] = "INT64"
    by["ordered_at"]["mode"] = "NULLABLE"
    by["id"]["policyTags"] = {"names": ["projects/p/locations/us/"
                                        "taxonomies/1/policyTags/2"]}
    fields.append({"name": "extra", "type": "STRING", "mode": "NULLABLE"})
    (tmp_path / "emu" / bb.STATE_FILE).write_text(
        json.dumps(state, indent=2) + "\n", encoding="utf-8")
    reopened = bb.EmulatedBackend(tmp_path / "emu", "proj", "US")
    report = bs.verify_schema(plan, reopened)
    assert report["pass"] is False and report["missing"] == []
    assert report["actual"] == {"tables": 5, "views": 2}
    orders = "`proj.retail.orders`"
    assert report["mismatched"] == [
        {"name": orders, "column": "extra", "expected": "absent",
         "actual": "STRING NULLABLE"},
        {"name": orders, "column": "ordered_at",
         "expected": "TIMESTAMP REQUIRED", "actual": "TIMESTAMP NULLABLE"},
        {"name": orders, "column": "region", "expected": "STRING REQUIRED",
         "actual": "missing"},
        {"name": orders, "column": "status", "expected": "STRING REQUIRED",
         "actual": "INT64 REQUIRED"}]
    # a table whose schema cannot be read is a mismatch, never a pass
    state["datasets"]["retail"]["tables"]["orders"]["fields"] = fields[:0]
    (tmp_path / "emu" / bb.STATE_FILE).write_text(
        json.dumps(state, indent=2) + "\n", encoding="utf-8")
    report = bs.verify_schema(plan, bb.EmulatedBackend(tmp_path / "emu",
                                                       "proj", "US"))
    assert report["pass"] is False
    assert all(m["name"] == orders for m in report["mismatched"])
    assert {m["column"] for m in report["mismatched"]} == {
        "id", "customer_id", "status", "ordered_at", "region"}


def test_verify_column_check_normalizes_type_aliases(emu):
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    bs.apply_schema(plan, emu)
    # a plan written with INTEGER, FLOAT, BOOLEAN aliases still verifies
    plan = json.loads(json.dumps(plan))
    for t in plan["tables"]:
        for f in t["fields"]:
            f["type"] = {"INT64": "INTEGER", "FLOAT64": "FLOAT",
                         "BOOL": "BOOLEAN"}.get(f["type"], f["type"])
            if f["mode"] == "NULLABLE":
                del f["mode"]
    assert bs.verify_schema(plan, emu)["pass"] is True


def test_cli_verify_prints_column_mismatches(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    ws = workspace(tmp_path, demo_inventory())
    argv = ["bq-schema", "--root", str(tmp_path), "--migration", "m1"]
    assert bs.main(argv + ["translate"]) == 0
    assert bs.main(argv + ["apply"]) == 0
    capsys.readouterr()
    root = bb.emulated_root("m1")
    state = json.loads((root / bb.STATE_FILE).read_text(encoding="utf-8"))
    fields = state["datasets"]["retail"]["tables"]["customers"]["fields"]
    fields[:] = [f for f in fields if f["name"] != "email"]
    (root / bb.STATE_FILE).write_text(json.dumps(state) + "\n",
                                     encoding="utf-8")
    assert bs.main(argv + ["verify"]) == 1
    out = capsys.readouterr().out
    assert "SCHEMA VERIFY FAILED" in out
    assert ("mismatched: `proj.retail.customers`: column email expected "
            "STRING REQUIRED, actual missing") in out
    report = json.loads((ws / "artifacts" / "schema-verify.json").read_text(
        encoding="utf-8"))
    assert report["mismatched"][0]["column"] == "email"


def test_apply_refuses_a_plan_for_another_project_or_location(tmp_path):
    plan = bs.translate_schema(demo_inventory(), BQ_CFG)
    other = bb.EmulatedBackend(tmp_path / "other", "other-proj", "US")
    with pytest.raises(bs.SchemaError, match="other-proj"):
        bs.apply_schema(plan, other)
    with pytest.raises(bs.SchemaError, match="other-proj"):
        bs.apply_schema(plan, other, datasets_only=True)
    assert other.list_datasets() == []
    asia = bb.EmulatedBackend(tmp_path / "asia", "proj", "asia-northeast1")
    with pytest.raises(bs.SchemaError, match="asia-northeast1"):
        bs.apply_schema(plan, asia)
    assert asia.list_datasets() == []
    # location compares without regard to case
    lower = bb.EmulatedBackend(tmp_path / "lower", "proj", "us")
    assert bs.apply_schema(plan, lower, datasets_only=True)[0]["status"] == \
        "created"
    runner = FakeRunner()
    live = bb.LiveBackend("proj", "EU", runner=runner,
                          work_dir=tmp_path / "work")
    with pytest.raises(bs.SchemaError, match="EU"):
        bs.apply_schema(plan, live)
    assert runner.calls == []


RESOLVED_SQL = "SELECT t.id FROM `proj.retail.t` t WHERE t.tenant_id = 7"


def test_view_resolution_for_an_auto_view_is_ignored():
    plan = bs.translate_schema(demo_inventory(), BQ_CFG, {"views": {
        "public.recent_orders": {"sql": "SELECT 1 AS one",
                                 "rationale": "r"}}})
    recent = by_name(plan, "views")["public.recent_orders"]
    assert recent["confidence"] == "auto" and recent["resolved"] is False
    assert recent["sql"] == recent["auto_sql"] != "SELECT 1 AS one"
    assert recent["ddl"].startswith("CREATE OR REPLACE VIEW")
    ignored = findings(plan, "view_resolution_ignored")
    assert len(ignored) == 1 and ignored[0]["severity"] == "WARNING"
    assert ignored[0]["subject"] == "public.recent_orders"
    assert findings(plan, "view_resolved") == []


def test_view_resolution_without_rationale_stays_review():
    for res in ({"sql": RESOLVED_SQL}, {"sql": RESOLVED_SQL, "rationale": ""},
                {"sql": RESOLVED_SQL, "rationale": "   "}):
        plan = bs.translate_schema(review_inventory(), BQ_CFG,
                                   {"views": {"public.tenant_rows": res}})
        v = plan["views"][0]
        assert v["confidence"] == "review" and v["resolved"] is False
        assert v["ddl"] == "" and "current_setting" in v["sql"]
        codes = [f["code"] for f in plan["findings"]]
        assert "view_resolution_unjustified" in codes
        assert "view_review" in codes and "view_resolved" not in codes
        unjustified = findings(plan, "view_resolution_unjustified")[0]
        assert unjustified["severity"] == "WARNING"
        assert unjustified["subject"] == "public.tenant_rows"
        assert bs.unresolved_views(plan) == ["public.tenant_rows"]


def test_view_resolution_against_an_older_definition_is_stale():
    plan = bs.translate_schema(review_inventory(), BQ_CFG, {"views": {
        "public.tenant_rows": {
            "sql": RESOLVED_SQL, "rationale": "tenant is fixed",
            "source_sql": "SELECT t.id FROM t WHERE t.tenant_id = 1"}}})
    v = plan["views"][0]
    assert v["confidence"] == "review" and v["resolved"] is False
    stale = findings(plan, "view_resolution_stale")
    assert len(stale) == 1 and stale[0]["severity"] == "WARNING"
    assert "tenant_id = 1" in stale[0]["message"]
    assert findings(plan, "view_resolved") == []
    assert bs.unresolved_views(plan) == ["public.tenant_rows"]


def test_view_resolution_with_matching_source_sql_is_applied():
    # the recorded source_sql matches up to whitespace and the trailing
    # semicolon, as translation-review.json records it
    recorded = ("SELECT   t.id FROM t\n  WHERE (t.tenant_id = "
                "(current_setting('app.tenant'::text))::integer)")
    plan = bs.translate_schema(review_inventory(), BQ_CFG, {"views": {
        "public.tenant_rows": {"sql": RESOLVED_SQL, "rationale": "fixed",
                               "source_sql": recorded}}})
    v = plan["views"][0]
    assert v["confidence"] == "resolved" and v["resolved"] is True
    assert v["sql"] == RESOLVED_SQL
    assert findings(plan, "view_resolved")[0]["subject"] == "public.tenant_rows"
    for code in ("view_resolution_ignored", "view_resolution_unjustified",
                 "view_resolution_stale", "view_review"):
        assert findings(plan, code) == [], code
    # the single-statement check still comes first, rationale or not
    with pytest.raises(bs.SchemaError):
        bs.translate_schema(review_inventory(), BQ_CFG, {"views": {
            "public.tenant_rows": {"sql": "SELECT 1; SELECT 2",
                                   "rationale": "fixed",
                                   "source_sql": recorded}}})

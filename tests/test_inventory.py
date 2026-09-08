from db_drift.inventory import build_inventory, quote_ident

RAW = {
    "server": [["17.5", "replica", "UTF8"]],
    "tables": [
        ["public", "customers", "100000", "8192000", "t", "d"],
        ["public", "audit_log", "50000", "4096000", "f", "n"],
    ],
    "sequences": [["public", "customers_id_seq", "100000"],
                  ["public", "unused_seq", ""]],
    "views": [["public", "recent_orders"]],
    "matviews": [["public", "sales_by_product"]],
    "extensions": [["hstore", "1.8"], ["plpgsql", "1.0"]],
    "roles": [["app_rw", "t"], ["reporting", "f"]],
    "indexes": [["7"]],
    "constraints": [["9"]],
}

RAW_FULL = dict(
    RAW,
    columns=[
        ["public", "customers", "id", "1", "bigint", "int8", "NO",
         "", "64", "0", "", ""],
        ["public", "customers", "email", "2", "text", "text", "NO",
         "", "", "", "", ""],
        ["public", "products", "tags", "3", "ARRAY", "_text", "YES",
         "", "", "", "", "text"],
        ["public", "products", "price", "4", "numeric", "numeric", "NO",
         "0", "12", "2", "", ""],
    ],
    primary_keys=[["public", "customers", "customers_pkey", "id"],
                  ["public", "order_items", "order_items_pkey",
                   "order_id,product_id"]],
    foreign_keys=[["public", "orders", "orders_customer_id_fkey",
                   "customer_id", "public", "customers", "id"]],
    view_definitions=[["public", "recent_orders", "view",
                       "SELECT o.id FROM orders o WHERE o.ordered_at > now()"]],
    view_dependencies=[["public", "recent_orders", "public", "orders"]],
)


def test_build_inventory_shapes():
    inv = build_inventory(RAW)
    assert inv["server"] == {"version": "17.5", "wal_level": "replica",
                             "encoding": "UTF8"}
    tables = {t["name"]: t for t in inv["tables"]}
    assert tables["customers"]["rows"] == 100000
    assert tables["customers"]["bytes"] == 8192000
    assert tables["customers"]["has_pk"] is True
    assert tables["audit_log"]["has_pk"] is False
    assert tables["audit_log"]["replica_identity"] == "n"
    assert inv["counts"] == {"indexes": 7, "constraints": 9}


def test_sequences_and_roles():
    inv = build_inventory(RAW)
    seqs = {s["name"]: s for s in inv["sequences"]}
    assert seqs["customers_id_seq"]["last_value"] == 100000
    assert seqs["unused_seq"]["last_value"] is None
    roles = {r["name"]: r for r in inv["roles"]}
    assert roles["app_rw"]["can_login"] is True
    assert roles["reporting"]["can_login"] is False
    assert inv["views"] == ["public.recent_orders"]
    assert inv["matviews"] == ["public.sales_by_product"]


def test_exact_identifier_quoting():
    assert quote_ident("public", 'we"ird') == '"public"."we""ird"'


def test_old_fixture_yields_empty_new_sections():
    inv = build_inventory(RAW)
    for key in ("columns", "primary_keys", "foreign_keys",
                "view_definitions", "view_dependencies"):
        assert inv[key] == []


def test_columns_keys_views_shapes():
    inv = build_inventory(RAW_FULL)
    cols = {(c["table"], c["name"]): c for c in inv["columns"]}
    assert cols[("customers", "id")]["nullable"] is False
    assert cols[("customers", "id")]["precision"] == 64
    assert cols[("customers", "email")]["default"] is None
    assert cols[("products", "tags")]["element_type"] == "text"
    assert cols[("products", "price")]["scale"] == 2
    assert cols[("products", "price")]["default"] == "0"
    pks = {p["table"]: p["columns"] for p in inv["primary_keys"]}
    assert pks["order_items"] == ["order_id", "product_id"]
    fk = inv["foreign_keys"][0]
    assert fk["ref_table"] == "customers" and fk["ref_columns"] == ["id"]
    assert inv["view_definitions"][0]["kind"] == "view"
    assert inv["view_dependencies"] == [{"view": "public.recent_orders",
                                         "base": "public.orders"}]

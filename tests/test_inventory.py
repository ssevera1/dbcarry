from db_drift.inventory import build_inventory

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

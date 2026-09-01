from db_drift.checksum import diff_snapshots

LEFT = {
    "tables": {
        "public.customers": {"rows": 100, "checksum": "aaa"},
        "public.orders": {"rows": 50, "checksum": "bbb"},
        "public.only_left": {"rows": 1, "checksum": "ccc"},
    },
    "sequences": {"public.customers_id_seq": 100},
}
RIGHT = {
    "tables": {
        "public.customers": {"rows": 100, "checksum": "aaa"},
        "public.orders": {"rows": 50, "checksum": "WRONG"},
        "public.only_right": {"rows": 2, "checksum": "ddd"},
    },
    "sequences": {"public.customers_id_seq": 1},
}


def test_diff_finds_everything():
    report = diff_snapshots(LEFT, RIGHT)
    assert report["match"] is False
    assert report["table_mismatches"] == ["public.orders"]
    assert report["missing_tables"] == ["public.only_left"]
    assert report["extra_tables"] == ["public.only_right"]
    assert report["sequence_mismatches"] == ["public.customers_id_seq"]


def test_identical_matches():
    report = diff_snapshots(LEFT, LEFT)
    assert report["match"] is True
    assert report["table_mismatches"] == []


def test_ignore_sequences():
    left = {"tables": LEFT["tables"], "sequences": {"s": 5}}
    right = {"tables": LEFT["tables"], "sequences": {"s": 1}}
    assert diff_snapshots(left, right)["match"] is False
    assert diff_snapshots(left, right, ignore_sequences=True)["match"] is True

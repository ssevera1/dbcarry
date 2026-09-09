import gzip
import io
import json
import sys
from pathlib import Path

import pytest

from db_drift import bq_backend as bb
from db_drift import bq_load as bl
from db_drift import pg


def col(name, data_type, udt, ordinal, **kw):
    base = {"schema": "public", "table": "orders", "name": name,
            "ordinal": ordinal, "data_type": data_type, "udt_name": udt,
            "nullable": True, "default": None, "precision": None,
            "scale": None, "max_length": None, "element_type": None}
    base.update(kw)
    return base


ORDERS = [
    col("id", "bigint", "int8", 1, nullable=False, precision=64, scale=0),
    col("customer_id", "bigint", "int8", 2, nullable=False, precision=64,
        scale=0),
    col("status", "text", "text", 3, nullable=False),
    col("ordered_at", "timestamp with time zone", "timestamptz", 4,
        nullable=False),
    col("region", "text", "text", 5, nullable=False),
]

PRODUCTS = [
    col("id", "bigint", "int8", 1, table="products", nullable=False),
    col("sku", "text", "text", 2, table="products", nullable=False),
    col("name", "text", "text", 3, table="products", nullable=False),
    col("price_cents", "integer", "int4", 4, table="products",
        nullable=False),
    col("attributes", "USER-DEFINED", "hstore", 5, table="products"),
]

ORDER_ROWS = [
    {"id": 1, "customer_id": 6841, "status": "paid",
     "ordered_at": "2025-03-20T19:00:00-05:00", "region": "eu"},
    {"id": 2, "customer_id": 55759, "status": "delivered",
     "ordered_at": "2026-03-26T19:00:00-05:00", "region": "us-west"},
    {"id": 3, "customer_id": 7, "status": "paid",
     "ordered_at": "2025-01-01T00:00:00+00:00", "region": "us-east"},
]
PRODUCT_ROWS = [
    {"id": 1, "sku": "SKU-00001", "name": "Product 1", "price_cents": 3378,
     "attributes": {"color": "green", "weight_g": "962"}},
    {"id": 2, "sku": "SKU-00002", "name": "Product 2", "price_cents": 10,
     "attributes": None},
]
ROWS = {"orders": ORDER_ROWS, "products": PRODUCT_ROWS}

DDL = """CREATE TABLE IF NOT EXISTS `{project}.retail.orders` (
  id INT64 NOT NULL,
  customer_id INT64 NOT NULL,
  status STRING NOT NULL,
  ordered_at TIMESTAMP NOT NULL,
  region STRING NOT NULL
);
CREATE TABLE IF NOT EXISTS `{project}.retail.products` (
  id INT64 NOT NULL,
  sku STRING NOT NULL,
  name STRING NOT NULL,
  price_cents INT64 NOT NULL,
  attributes JSON
);
"""

CI = {"host": "127.0.0.1", "port": 55432, "dbname": "retail",
      "user": "postgres", "password_env": None}


def write_gz(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return Path(path)


def read_gz(path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return fh.read()


def read_log(path):
    return [json.loads(line) for line in
            Path(path).read_text(encoding="utf-8").splitlines() if line]


class FakeExporter:
    """Stands in for export_table: writes the fixture rows for the table
    and reports what it wrote (or lies, when told to)."""

    def __init__(self, rows=ROWS, report_rows=None, fail=None):
        self.rows = rows
        self.report_rows = report_rows or {}
        self.fail = fail or {}
        self.calls = []

    def __call__(self, ci, schema, table, columns, out_path):
        self.calls.append((ci, schema, table, list(columns), Path(out_path)))
        if table in self.fail:
            raise self.fail[table]
        rows = self.rows[table]
        write_gz(out_path, rows)
        return {"rows": self.report_rows.get(table, len(rows)),
                "bytes": Path(out_path).stat().st_size}


def make_plan(backend, project="proj", tables=("orders", "products")):
    return {"project": project, "location": "US",
            "datasets": {"retail": {"source_schema": "public"}},
            "tables": [{"schema": "public", "name": name, "dataset": "retail",
                        "bq_name": name,
                        "fields": backend.get_table_schema("retail", name)}
                       for name in tables],
            "views": [], "findings": []}


@pytest.fixture
def emu(tmp_path):
    log = bb.OperationLog(tmp_path / "ops.log")
    backend = bb.EmulatedBackend(tmp_path / "emu", "proj", "US", log=log)
    backend.create_dataset("retail")
    backend.run_ddl(DDL.format(project="proj"))
    return backend


INVENTORY_COLUMNS = ORDERS + PRODUCTS


# ------------------------------------------------------------ export_sql

def test_export_sql_demo_columns():
    columns = PRODUCTS + [
        col("blob", "bytea", "bytea", 6, table="products"),
        col("tags", "ARRAY", "_text", 7, table="products",
            element_type="text"),
        col("span", "interval", "interval", 8, table="products"),
    ]
    sql = bl.export_sql("public", "products", columns)
    assert sql == (
        'SELECT row_to_json(r) FROM (SELECT "id" AS "id", "sku" AS "sku", '
        '"name" AS "name", "price_cents" AS "price_cents", '
        'hstore_to_json("attributes") AS "attributes", '
        'translate(encode("blob", \'base64\'), E\'\\n\', \'\') AS "blob", '
        'to_json("tags") AS "tags", '
        '("span")::text AS "span" FROM "public"."products") r')
    assert "\n" not in sql


def test_export_sql_keeps_bytea_base64_on_one_line():
    # encode(..., 'base64') follows RFC 2045 and inserts a newline every 76
    # characters, so any bytea longer than 57 bytes would land in the NDJSON
    # with embedded "\n" escapes; bq_types strips them in SQL, and the
    # export SQL itself stays on one line so \copy accepts it.
    blob = col("blob", "bytea", "bytea", 1, table="t")
    sql = bl.export_sql("public", "t", [blob])
    assert ("translate(encode(\"blob\", 'base64'), E'\\n', '') AS \"blob\""
            in sql)
    assert "\n" not in sql
    assert bl.copy_command(sql).startswith("\\copy (SELECT row_to_json(r)")
    # a bytea[] exports one base64 string per element (to_json would
    # render hex text, which bq load rejects for ARRAY<BYTES>)
    tags = col("tags", "ARRAY", "_bytea", 2, table="t", element_type="bytea")
    sql = bl.export_sql("public", "t", [tags])
    assert ("(SELECT to_json(array_agg(translate(encode(e, 'base64'), "
            "E'\\n', ''))) FROM unnest(\"tags\") e) AS \"tags\"") in sql
    assert "\n" not in sql


def test_export_sql_aliases_and_quoting():
    columns = [col('we"ird', "text", "text", 1, table="t"),
               col("c-1", "integer", "int4", 2, table="t", bq_name="c_1")]
    sql = bl.export_sql("my schema", 't"x', columns)
    assert '"we""ird" AS "we""ird"' in sql
    assert '"c-1" AS "c_1"' in sql
    assert sql.endswith('FROM "my schema"."t""x") r')
    with pytest.raises(ValueError, match="no columns"):
        bl.export_sql("public", "empty", [])


def test_copy_command_wraps_export_sql():
    sql = bl.export_sql("public", "orders", ORDERS)
    cmd = bl.copy_command(sql)
    # CSV with a quote and delimiter that never appear in JSON text is
    # what makes psql pass the row_to_json output through verbatim; the
    # default text format doubles every backslash and breaks the JSON.
    assert cmd == ("\\copy (" + sql + ") TO STDOUT WITH (FORMAT csv, "
                   "QUOTE E'\\x01', DELIMITER E'\\x02')")
    with pytest.raises(ValueError, match="single line"):
        bl.copy_command("SELECT 1\nFROM x")


# ----------------------------------------------------------- export_table

class FakePopen:
    instances = []
    stdout_text = '{"id":1}\r\n\n{"id":2}\n'
    stderr_text = ""
    returncode = 0
    start_error = None

    def __init__(self, argv, env=None, stdout=None, stderr=None,
                 encoding=None, **kw):
        if self.start_error:
            raise self.start_error
        self.argv = list(argv)
        self.env = env
        self.encoding = encoding
        self.pipes = (stdout, stderr)
        self.kw = kw
        self.stdout = io.StringIO(self.stdout_text)
        self.stderr = io.StringIO(self.stderr_text)
        FakePopen.instances.append(self)

    def wait(self):
        return self.returncode


@pytest.fixture
def fake_popen(monkeypatch):
    FakePopen.instances = []
    FakePopen.stdout_text = '{"id":1}\r\n\n{"id":2}\n'
    FakePopen.stderr_text = ""
    FakePopen.returncode = 0
    FakePopen.start_error = None
    monkeypatch.setattr(bl.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(pg, "find_bin", lambda name: f"/fake/{name}")
    return FakePopen


def test_export_table_streams_psql_output(tmp_path, fake_popen, monkeypatch):
    monkeypatch.setenv("SRC_PW", "hunter2")
    ci = {"host": "h", "port": 5, "dbname": "db", "user": "u",
          "password_env": "SRC_PW"}
    out = tmp_path / "exp" / "public.orders.ndjson.gz"
    res = bl.export_table(ci, "public", "orders", ORDERS, out)
    assert res == {"rows": 2, "bytes": out.stat().st_size}
    inst = fake_popen.instances[-1]
    assert inst.argv[:7] == ["/fake/psql", "-X", "-q", "-v",
                             "ON_ERROR_STOP=1", "-A", "-t"]
    assert inst.argv[7:15] == ["-h", "h", "-p", "5", "-U", "u", "-d", "db"]
    assert inst.argv[15:] == [
        "-c", bl.copy_command(bl.export_sql("public", "orders", ORDERS))]
    # read-only, and UTC so pre-1883 timestamptz values do not carry the
    # session zone's LMT offset with seconds (-05:50:36), which BigQuery
    # cannot load
    assert inst.env["PGOPTIONS"] == pg.READONLY_OPTS + " -c TimeZone=UTC"
    assert inst.env["PGCLIENTENCODING"] == "UTF8"
    assert inst.env["PGPASSWORD"] == "hunter2"
    assert inst.encoding == "utf-8"
    assert inst.pipes == (bl.subprocess.PIPE, bl.subprocess.PIPE)
    assert inst.kw == {}
    # blank lines are dropped, CRLF is normalized, one row per line
    assert read_gz(out) == '{"id":1}\n{"id":2}\n'


def test_export_table_raises_on_psql_failure(tmp_path, fake_popen,
                                             monkeypatch):
    monkeypatch.setenv("SRC_PW", "hunter2")
    ci = {"host": "h", "port": 5, "dbname": "db", "user": "u",
          "password_env": "SRC_PW"}
    fake_popen.returncode = 1
    fake_popen.stdout_text = ""
    fake_popen.stderr_text = ('ERROR:  relation "nope" does not exist\n'
                              'LINE 1: ' + "x" * 2000)
    out = tmp_path / "public.orders.ndjson.gz"
    with pytest.raises(pg.PgError) as info:
        bl.export_table(ci, "public", "orders", ORDERS, out)
    message = str(info.value)
    assert 'relation "nope" does not exist' in message
    assert message.startswith("psql failed (1): ")
    assert len(message) < 900
    assert "hunter2" not in message
    assert not out.exists()


def test_export_table_reports_missing_psql_and_start_failures(
        tmp_path, fake_popen, monkeypatch):
    out = tmp_path / "x.ndjson.gz"
    fake_popen.start_error = OSError("cannot spawn")
    with pytest.raises(pg.PgError, match="cannot spawn"):
        bl.export_table(CI, "public", "orders", ORDERS, out)
    assert not out.exists()

    def missing(name):
        raise pg.PgError(f"{name} not found on PATH")

    monkeypatch.setattr(pg, "find_bin", missing)
    with pytest.raises(pg.PgError, match="psql not found"):
        bl.export_table(CI, "public", "orders", ORDERS, out)


def test_count_ndjson_lines(tmp_path):
    path = write_gz(tmp_path / "a.ndjson.gz", ORDER_ROWS)
    assert bl.count_ndjson_lines(path) == 3
    with gzip.open(path, "at", encoding="utf-8", newline="\n") as fh:
        fh.write("\n\n")
    assert bl.count_ndjson_lines(path) == 3
    plain = tmp_path / "b.ndjson"
    plain.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
    assert bl.count_ndjson_lines(plain) == 2


# ---------------------------------------------------------------- run_all

def test_run_all_exports_loads_and_verifies_counts(tmp_path, emu):
    plan = make_plan(emu)
    inventory = {"columns": list(reversed(INVENTORY_COLUMNS))}
    exporter = FakeExporter()
    export_dir = tmp_path / "export"
    report = bl.run_all(plan, inventory, CI, emu, export_dir,
                        exporter=exporter)
    assert report["pass"] is True
    assert [t["table"] for t in report["tables"]] == ["public.orders",
                                                      "public.products"]
    orders = report["tables"][0]
    assert orders["exported"] == 3 and orders["loaded"] == 3
    assert orders["pass"] is True
    assert orders["dataset"] == "retail" and orders["bq_name"] == "orders"
    assert orders["path"] == str(export_dir / "public.orders.ndjson.gz")
    assert isinstance(orders["seconds"], float) and orders["seconds"] >= 0
    assert orders["bytes"] == (export_dir / "public.orders.ndjson.gz").stat().st_size
    products = report["tables"][1]
    assert products["exported"] == 2 == products["loaded"]
    assert emu.count_rows("retail", "orders") == 3
    assert emu.count_rows("retail", "products") == 2
    # the exporter received the connection, the columns in ordinal order,
    # and the export path
    ci, schema, table, columns, path = exporter.calls[0]
    assert (ci, schema, table) == (CI, "public", "orders")
    assert [c["name"] for c in columns] == [c["name"] for c in ORDERS]
    assert path == export_dir / "public.orders.ndjson.gz"
    assert [c["name"] for c in exporter.calls[1][3]] == [
        c["name"] for c in PRODUCTS]
    ops = [l["op"] for l in read_log(tmp_path / "ops.log")]
    assert ops.count("load_ndjson") == 2


def test_run_all_refuses_to_load_twice(tmp_path, emu):
    plan = make_plan(emu, tables=("orders",))
    inventory = {"columns": INVENTORY_COLUMNS}
    exporter = FakeExporter()
    first = bl.run_all(plan, inventory, CI, emu, tmp_path / "export",
                       exporter=exporter)
    assert first["pass"] is True
    second = bl.run_all(plan, inventory, CI, emu, tmp_path / "export",
                        exporter=exporter)
    assert second["pass"] is False
    entry = second["tables"][0]
    assert entry["loaded"] == 3 and entry["exported"] == 0
    assert "already holds 3 rows" in entry["reason"]
    assert emu.count_rows("retail", "orders") == 3
    assert len(exporter.calls) == 1


def test_run_all_reports_mismatches_and_errors_per_table(tmp_path, emu):
    plan = make_plan(emu)
    plan["tables"].append({"schema": "public", "name": "ghost",
                           "dataset": "retail", "bq_name": "ghost",
                           "fields": []})
    inventory = {"columns": INVENTORY_COLUMNS}
    exporter = FakeExporter(report_rows={"orders": 5},
                            fail={"products": pg.PgError("psql failed (1): "
                                                         "boom")})
    report = bl.run_all(plan, inventory, CI, emu, tmp_path / "export",
                        exporter=exporter)
    assert report["pass"] is False
    by = {t["table"]: t for t in report["tables"]}
    assert by["public.orders"]["exported"] == 5
    assert by["public.orders"]["loaded"] == 3
    assert by["public.orders"]["pass"] is False
    assert "exported 5" in by["public.orders"]["reason"]
    assert "loaded 3" in by["public.orders"]["reason"]
    assert by["public.products"]["pass"] is False
    assert by["public.products"]["reason"] == "PgError: psql failed (1): boom"
    assert by["public.products"]["exported"] == 0
    assert by["public.ghost"]["pass"] is False
    assert "no columns" in by["public.ghost"]["reason"]
    assert isinstance(by["public.ghost"]["seconds"], float)


def test_run_all_backend_errors_are_reported(tmp_path, emu):
    plan = make_plan(emu, tables=("orders",))
    inventory = {"columns": INVENTORY_COLUMNS}
    bad_rows = {"orders": [dict(ORDER_ROWS[0], stray="x")]}
    report = bl.run_all(plan, inventory, CI, emu, tmp_path / "export",
                        exporter=FakeExporter(rows=bad_rows))
    assert report["pass"] is False
    assert report["tables"][0]["reason"].startswith("BackendError: ")
    assert "stray" in report["tables"][0]["reason"]
    assert emu.count_rows("retail", "orders") == 0


def test_run_all_needs_a_load_schema(tmp_path, emu):
    plan = make_plan(emu, tables=("orders",))
    plan["tables"][0]["fields"] = None
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, emu,
                        tmp_path / "export", exporter=FakeExporter())
    assert report["pass"] is False
    assert report["tables"][0]["exported"] == 3
    assert "no load schema" in report["tables"][0]["reason"]
    assert emu.count_rows("retail", "orders") == 0


def test_run_all_only_filter_and_steps(tmp_path, emu):
    plan = make_plan(emu)
    inventory = {"columns": INVENTORY_COLUMNS}
    exporter = FakeExporter()
    export_dir = tmp_path / "export"
    exported = bl.run_all(plan, inventory, CI, emu, export_dir,
                          only={"public.products"}, steps=("export",),
                          exporter=exporter)
    assert [t["table"] for t in exported["tables"]] == ["public.products"]
    entry = exported["tables"][0]
    assert entry["exported"] == 2 and entry["loaded"] == 0
    assert entry["pass"] is True
    assert exported["pass"] is True
    assert emu.count_rows("retail", "products") == 0
    loaded = bl.run_all(plan, inventory, CI, emu, export_dir,
                        only={"public.products"}, steps=("load",),
                        exporter=exporter)
    assert len(exporter.calls) == 1
    entry = loaded["tables"][0]
    assert entry["exported"] == 2 and entry["loaded"] == 2
    assert entry["pass"] is True and loaded["pass"] is True
    assert emu.count_rows("retail", "products") == 2
    # loading a table that was never exported fails with a clear reason
    missing = bl.run_all(plan, inventory, CI, emu, export_dir,
                         only={"public.orders"}, steps=("load",),
                         exporter=exporter)
    assert missing["pass"] is False
    assert "no export file" in missing["tables"][0]["reason"]
    # an unknown filter selects nothing, and nothing does not pass
    empty = bl.run_all(plan, inventory, CI, emu, export_dir,
                       only={"public.nope"}, exporter=exporter)
    assert empty == {"tables": [], "pass": False}


def test_run_all_aliases_columns_to_plan_field_names(tmp_path, emu):
    emu.run_ddl("CREATE TABLE `proj.retail.odd` (c_1 INT64, plain STRING)")
    plan = make_plan(emu, tables=("odd",))
    inventory = {"columns": [
        col("c-1", "integer", "int4", 1, table="odd"),
        col("plain", "text", "text", 2, table="odd")]}
    exporter = FakeExporter(rows={"odd": [{"c_1": 1, "plain": "x"}]})
    report = bl.run_all(plan, inventory, CI, emu, tmp_path / "export",
                        exporter=exporter)
    assert report["pass"] is True
    columns = exporter.calls[0][3]
    assert [(c["name"], c.get("bq_name")) for c in columns] == [
        ("c-1", "c_1"), ("plain", "plain")]
    assert '"c-1" AS "c_1"' in bl.export_sql("public", "odd", columns)


def test_run_all_ignores_gcs_bucket_in_emulated_mode(tmp_path, emu):
    plan = make_plan(emu, tables=("orders",))
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, emu,
                        tmp_path / "export", gcs_bucket="my-bucket",
                        exporter=FakeExporter())
    assert report["pass"] is True
    assert any("gcs_bucket" in n for n in report["tables"][0]["notes"])


def test_run_all_reports_a_malformed_plan_entry_per_table(tmp_path, emu):
    plan = make_plan(emu, tables=("orders",))
    plan["tables"].insert(0, {"schema": "public", "name": "products"})
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, emu,
                        tmp_path / "export", exporter=FakeExporter())
    assert report["pass"] is False
    by = {t["table"]: t for t in report["tables"]}
    assert by["public.products"]["pass"] is False
    assert by["public.products"]["reason"] == "KeyError: 'dataset'"
    assert by["public.products"]["dataset"] is None
    # the other table still ran
    assert by["public.orders"]["pass"] is True
    assert emu.count_rows("retail", "orders") == 3


def test_run_all_loads_with_the_read_back_schema(tmp_path, emu, monkeypatch):
    # bq-security apply attaches policy tags to the live table only; the
    # plan fields never carry them, so the load must use the read-back
    # schema or the load could strip the controls the data depends on.
    tax = emu.create_taxonomy("dbdrift_m1", ["FINE_GRAINED_ACCESS_CONTROL"])
    tag = emu.create_policy_tag(tax, "orders__region", "")
    fields = emu.get_table_schema("retail", "orders")
    for f in fields:
        if f["name"] == "region":
            f["policyTags"] = {"names": [tag]}
    emu.update_table_schema("retail", "orders", fields)
    plan = make_plan(emu, tables=("orders",))
    for f in plan["tables"][0]["fields"]:
        f.pop("policyTags", None)
    seen = {}
    original = emu.load_ndjson

    def capture(dataset, table, path, load_fields):
        seen["fields"] = load_fields
        return original(dataset, table, path, load_fields)

    monkeypatch.setattr(emu, "load_ndjson", capture)
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, emu,
                        tmp_path / "export", exporter=FakeExporter())
    assert report["pass"] is True
    tagged = [f["name"] for f in seen["fields"] if f.get("policyTags")]
    assert tagged == ["region"]
    assert report["tables"][0]["policy_tagged_columns"] == ["region"]
    assert emu.count_rows("retail", "orders") == 3


def test_run_all_cleanup_in_emulated_mode(tmp_path, emu):
    plan = make_plan(emu)
    export_dir = tmp_path / "export"
    exporter = FakeExporter(report_rows={"products": 9})
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, emu,
                        export_dir, exporter=exporter, cleanup=True)
    by = {t["table"]: t for t in report["tables"]}
    # a passing table loses its plaintext staging copy
    assert by["public.orders"]["pass"] is True
    assert by["public.orders"]["cleanup"] == {"local": True, "gcs": None}
    assert not (export_dir / "public.orders.ndjson.gz").exists()
    # a failing table keeps it for diagnosis
    assert by["public.products"]["pass"] is False
    assert "cleanup" not in by["public.products"]
    assert (export_dir / "public.products.ndjson.gz").exists()
    # export-only runs never clean up (the file is the product)
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, emu,
                        export_dir, only={"public.orders"}, steps=("export",),
                        exporter=FakeExporter(), cleanup=True)
    assert report["pass"] is True
    assert (export_dir / "public.orders.ndjson.gz").exists()


class FakeRunner:
    def __init__(self, outputs=None):
        self.calls = []
        self.outputs = list(outputs or [])

    def __call__(self, argv, stdin=None):
        self.calls.append((list(argv), stdin))
        if self.outputs:
            return self.outputs.pop(0)
        return (0, "[]", "")


def live_backend(tmp_path, outputs):
    runner = FakeRunner(outputs)
    log = bb.OperationLog(tmp_path / "ops.log")
    backend = bb.LiveBackend("proj", "US", runner=runner, log=log,
                             work_dir=tmp_path / "work")
    return backend, runner


PLAN_FIELDS = [{"name": c["name"], "type": "STRING", "mode": "NULLABLE"}
               for c in ORDERS]
# What bq show --schema returns after bq-security apply: the plan fields
# plus the policy tag the security phase attached.
TAG = "projects/proj/locations/us/taxonomies/1/policyTags/2"
LIVE_SCHEMA = [dict(f, policyTags={"names": [TAG]}) if f["name"] == "region"
               else dict(f) for f in PLAN_FIELDS]


def test_run_all_live_uploads_to_gcs_before_load(tmp_path):
    backend, runner = live_backend(tmp_path, [
        (0, '[{"n": "0"}]', ""),          # count before
        (0, json.dumps(LIVE_SCHEMA), ""),  # bq show --schema (read-back)
        (0, "", ""),                      # gcloud storage cp
        (0, "", ""),                      # bq load
        (0, '[{"n": "3"}]', ""),          # count after
    ])
    plan = {"project": "proj", "tables": [
        {"schema": "public", "name": "orders", "dataset": "retail",
         "bq_name": "orders", "fields": PLAN_FIELDS}]}
    export_dir = tmp_path / "export"
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, backend,
                        export_dir, gcs_bucket="my-bucket",
                        gcs_prefix="db-drift/m1", exporter=FakeExporter())
    assert report["pass"] is True
    entry = report["tables"][0]
    # the object name carries the migration so two migrations sharing a
    # bucket never overwrite each other
    uri = "gs://my-bucket/db-drift/m1/retail/public.orders.ndjson.gz"
    assert entry["gcs_uri"] == uri
    local = str(export_dir / "public.orders.ndjson.gz")
    assert runner.calls[1][0] == ["bq", "--project_id=proj", "--format=json",
                                  "show", "--schema", "proj:retail.orders"]
    assert runner.calls[2] == (["gcloud", "storage", "cp", local, uri], None)
    load_argv = runner.calls[3][0]
    assert load_argv[:3] == ["bq", "--project_id=proj", "load"]
    assert load_argv[-2:] == ["proj:retail.orders", uri]
    # the load schema is the read-back, so the policy tags the security
    # phase attached travel with the load instead of the bare plan fields
    schema_arg = [a for a in load_argv if a.startswith("--schema=")][0]
    loaded_schema = json.loads(Path(schema_arg[len("--schema="):]).read_text(
        encoding="utf-8"))
    assert loaded_schema == LIVE_SCHEMA
    assert entry["policy_tagged_columns"] == ["region"]
    ops = read_log(tmp_path / "ops.log")
    upload = [o for o in ops if o["op"] == "gcs_upload"][0]
    assert upload["argv"] == ["gcloud", "storage", "cp", local, uri]
    # nothing is cleaned up unless asked
    assert Path(local).exists() and "cleanup" not in entry


def test_run_all_live_gcs_upload_failure(tmp_path):
    backend, runner = live_backend(tmp_path, [
        (0, '[{"n": "0"}]', ""),
        (0, json.dumps(PLAN_FIELDS), ""),
        (1, "", "AccessDeniedException: 403 no bucket"),
    ])
    plan = {"project": "proj", "tables": [
        {"schema": "public", "name": "orders", "dataset": "retail",
         "bq_name": "orders", "fields": [{"name": "id", "type": "INT64"}]}]}
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, backend,
                        tmp_path / "export", gcs_bucket="my-bucket",
                        exporter=FakeExporter())
    assert report["pass"] is False
    assert "403 no bucket" in report["tables"][0]["reason"]
    assert len(runner.calls) == 3
    failed = [o for o in read_log(tmp_path / "ops.log")
              if o["op"] == "gcs_upload"][0]
    assert failed["rc"] == 1


def test_run_all_live_cleanup_removes_staged_copies(tmp_path):
    backend, runner = live_backend(tmp_path, [
        (0, '[{"n": "0"}]', ""),
        (0, json.dumps(PLAN_FIELDS), ""),
        (0, "", ""),                      # cp
        (0, "", ""),                      # load
        (0, '[{"n": "3"}]', ""),          # count after
        (0, "", ""),                      # gcloud storage rm
    ])
    plan = {"project": "proj", "tables": [
        {"schema": "public", "name": "orders", "dataset": "retail",
         "bq_name": "orders", "fields": PLAN_FIELDS}]}
    export_dir = tmp_path / "export"
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, backend,
                        export_dir, gcs_bucket="my-bucket",
                        exporter=FakeExporter(), cleanup=True)
    assert report["pass"] is True
    entry = report["tables"][0]
    uri = "gs://my-bucket/db-drift/retail/public.orders.ndjson.gz"
    assert runner.calls[-1] == (["gcloud", "storage", "rm", uri], None)
    assert entry["cleanup"] == {"local": True, "gcs": True}
    assert not (export_dir / "public.orders.ndjson.gz").exists()
    ops = read_log(tmp_path / "ops.log")
    assert [o["op"] for o in ops if o["op"].startswith("gcs_")] == [
        "gcs_upload", "gcs_delete"]


def test_run_all_live_cleanup_failure_is_a_note_not_a_failure(tmp_path):
    backend, runner = live_backend(tmp_path, [
        (0, '[{"n": "0"}]', ""),
        (0, json.dumps(PLAN_FIELDS), ""),
        (0, "", ""), (0, "", ""), (0, '[{"n": "3"}]', ""),
        (1, "", "AccessDeniedException: 403 cannot delete"),
    ])
    plan = {"project": "proj", "tables": [
        {"schema": "public", "name": "orders", "dataset": "retail",
         "bq_name": "orders", "fields": PLAN_FIELDS}]}
    report = bl.run_all(plan, {"columns": INVENTORY_COLUMNS}, CI, backend,
                        tmp_path / "export", gcs_bucket="my-bucket",
                        exporter=FakeExporter(), cleanup=True)
    entry = report["tables"][0]
    assert entry["pass"] is True and report["pass"] is True
    assert entry["cleanup"] == {"local": True, "gcs": False}
    assert any("403 cannot delete" in n for n in entry["notes"])


def test_load_table_delegates_to_backend(tmp_path, emu):
    path = write_gz(tmp_path / "o.ndjson.gz", ORDER_ROWS)
    fields = emu.get_table_schema("retail", "orders")
    assert bl.load_table(emu, "retail", "orders", path, fields) == 3
    assert emu.count_rows("retail", "orders") == 3


def test_table_targets_from_plan_and_fallback():
    inventory = {"tables": [{"schema": "public", "name": "orders"},
                            {"schema": "sales", "name": "Line-Items"}],
                 "columns": INVENTORY_COLUMNS}
    bq_cfg = {"dataset_map": {"public": "retail"}, "dbname": "retail"}
    plan = {"tables": [{"schema": "public", "name": "orders",
                        "dataset": "retail", "bq_name": "orders",
                        "fields": [{"name": "id"}]}]}
    targets = bl.table_targets(plan, inventory, bq_cfg)
    assert [(t["schema"], t["name"], t["dataset"], t["bq_name"])
            for t in targets] == [("public", "orders", "retail", "orders")]
    derived = bl.table_targets(None, inventory, bq_cfg)
    assert [(t["schema"], t["name"], t["dataset"], t["bq_name"],
             t["fields"]) for t in derived] == [
        ("public", "orders", "retail", "orders", None),
        ("sales", "Line-Items", "sales", "Line_Items", None)]


# ------------------------------------------------------------------ CLI

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
  project: demo-project
  location: US
  dataset_map:
    public: retail
"""

INVENTORY = {
    "server": {"version": "17.5", "wal_level": "logical", "encoding": "UTF8"},
    "tables": [{"schema": "public", "name": "orders", "rows": 3,
                "bytes": 8192, "has_pk": True, "replica_identity": "d"},
               {"schema": "public", "name": "products", "rows": 2,
                "bytes": 8192, "has_pk": True, "replica_identity": "d"}],
    "sequences": [], "views": [], "matviews": [], "extensions": [],
    "roles": [], "counts": {"indexes": 1, "constraints": 1},
    "columns": INVENTORY_COLUMNS, "primary_keys": [], "foreign_keys": [],
    "view_definitions": [], "view_dependencies": [],
}


def make_workspace(tmp_path, monkeypatch, with_plan=True):
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    ws = tmp_path / "migrations" / "m1"
    (ws / "artifacts").mkdir(parents=True)
    (ws / "migration.yaml").write_text(MIGRATION_YAML, encoding="utf-8")
    (ws / "artifacts" / "inventory.json").write_text(
        json.dumps(INVENTORY, indent=2) + "\n", encoding="utf-8")
    backend = bb.make_backend({"mode": "emulated", "project": "demo-project",
                               "location": "US"}, "m1", ws)
    backend.create_dataset("retail")
    backend.run_ddl(DDL.format(project="demo-project"))
    if with_plan:
        (ws / "artifacts" / "schema-plan.json").write_text(
            json.dumps(make_plan(backend, "demo-project"), indent=2) + "\n",
            encoding="utf-8")
    return ws, backend


def test_cli_run_writes_report(tmp_path, monkeypatch, capsys):
    ws, backend = make_workspace(tmp_path, monkeypatch)
    exporter = FakeExporter()
    monkeypatch.setattr(bl, "export_table", exporter)
    argv = ["bq-load", "run", "--root", str(tmp_path), "--migration", "m1"]
    assert bl.main(argv) == 0
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert report["verb"] == "run" and report["mode"] == "emulated"
    assert report["pass"] is True
    assert [t["table"] for t in report["tables"]] == ["public.orders",
                                                      "public.products"]
    assert (ws / "artifacts" / "export" / "public.orders.ndjson.gz").exists()
    assert exporter.calls[0][0]["dbname"] == "retail"
    assert backend.count_rows("retail", "orders") == 3
    out = capsys.readouterr().out
    assert "public.orders" in out and "3" in out
    # a second run fails (tables already hold rows) and says so
    assert bl.main(argv) == 1
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert report["pass"] is False
    assert "already holds" in report["tables"][0]["reason"]


def test_cli_export_then_load(tmp_path, monkeypatch, capsys):
    ws, backend = make_workspace(tmp_path, monkeypatch)
    exporter = FakeExporter()
    monkeypatch.setattr(bl, "export_table", exporter)
    base = ["bq-load", "--root", str(tmp_path), "--migration", "m1"]
    assert bl.main(base + ["export", "--table", "public.products"]) == 0
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert report["verb"] == "export" and report["pass"] is True
    assert [t["table"] for t in report["tables"]] == ["public.products"]
    assert report["tables"][0]["exported"] == 2
    assert backend.count_rows("retail", "products") == 0
    assert bl.main(base + ["load", "--table", "public.products"]) == 0
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert report["verb"] == "load" and report["pass"] is True
    assert report["tables"][0]["loaded"] == 2
    assert backend.count_rows("retail", "products") == 2
    # loading a table that was never exported fails
    assert bl.main(base + ["load", "--table", "public.orders"]) == 1
    assert "no export file" in capsys.readouterr().out


def test_cli_export_works_without_schema_plan(tmp_path, monkeypatch):
    ws, backend = make_workspace(tmp_path, monkeypatch, with_plan=False)
    monkeypatch.setattr(bl, "export_table", FakeExporter())
    base = ["bq-load", "--root", str(tmp_path), "--migration", "m1"]
    assert bl.main(base + ["export"]) == 0
    assert (ws / "artifacts" / "export" / "public.products.ndjson.gz").exists()
    assert bl.main(base + ["load"]) == 1
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert all("no load schema" in t["reason"] for t in report["tables"])


def test_cli_errors(tmp_path, monkeypatch, capsys):
    ws, backend = make_workspace(tmp_path, monkeypatch)
    monkeypatch.setattr(bl, "export_table", FakeExporter())
    base = ["bq-load", "--root", str(tmp_path), "--migration", "m1"]
    assert bl.main(base + ["run", "--table", "public.nope"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("BQ-LOAD ERROR") and "public.nope" in err
    assert bl.main(["bq-load", "--root", str(tmp_path), "--migration",
                    "missing", "run"]) == 1
    assert "BQ-LOAD ERROR" in capsys.readouterr().err
    (ws / "artifacts" / "inventory.json").unlink()
    assert bl.main(base + ["run"]) == 1
    assert "inventory" in capsys.readouterr().err


def test_cli_report_names_the_staging_copies(tmp_path, monkeypatch):
    ws, backend = make_workspace(tmp_path, monkeypatch)
    monkeypatch.setattr(bl, "export_table", FakeExporter())
    base = ["bq-load", "--root", str(tmp_path), "--migration", "m1"]
    assert bl.main(base + ["run"]) == 0
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    staging = report["staging"]
    assert staging["export_dir"] == str(ws / "artifacts" / "export")
    assert staging["cleanup"] is False
    assert "plain text" in staging["retention"]
    # the emulated run records the state of the security check without
    # enforcing it (the emulator has no exposure window)
    assert report["security_verify"] == {"enforced": False, "verified": False,
                                         "forced": False}


def test_cli_cleanup_flag(tmp_path, monkeypatch):
    ws, backend = make_workspace(tmp_path, monkeypatch)
    monkeypatch.setattr(bl, "export_table", FakeExporter())
    base = ["bq-load", "--root", str(tmp_path), "--migration", "m1"]
    assert bl.main(base + ["run", "--cleanup"]) == 0
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert report["staging"]["cleanup"] is True
    assert all(t["cleanup"]["local"] for t in report["tables"])
    assert not list((ws / "artifacts" / "export").glob("*.ndjson.gz"))
    assert backend.count_rows("retail", "orders") == 3


LIVE_YAML = MIGRATION_YAML.replace("mode: emulated", "mode: live")


def live_workspace(tmp_path, monkeypatch, verify=None):
    ws, _ = make_workspace(tmp_path, monkeypatch)
    (ws / "migration.yaml").write_text(LIVE_YAML, encoding="utf-8")
    if verify is not None:
        (ws / "artifacts" / "security-verify.json").write_text(
            json.dumps(verify) + "\n", encoding="utf-8")
    calls = []

    def fake_run_all(*args, **kwargs):
        calls.append((args, kwargs))
        return {"tables": [], "pass": True}

    monkeypatch.setattr(bl, "run_all", fake_run_all)
    return ws, calls


def test_cli_live_load_refuses_before_security_verify(tmp_path, monkeypatch,
                                                      capsys):
    ws, calls = live_workspace(tmp_path, monkeypatch)
    base = ["bq-load", "--root", str(tmp_path), "--migration", "m1"]
    for verb in ("load", "run"):
        assert bl.main(base + [verb]) == 1
        err = capsys.readouterr().err
        assert err.startswith("BQ-LOAD ERROR")
        assert "security-verify.json" in err and "--force" in err
    assert calls == []
    # a failed verification is refused too
    (ws / "artifacts" / "security-verify.json").write_text(
        json.dumps({"pass": False, "checks": []}) + "\n", encoding="utf-8")
    assert bl.main(base + ["run"]) == 1
    assert "failed" in capsys.readouterr().err
    assert calls == []
    # export alone touches no target and is allowed
    assert bl.main(base + ["export"]) == 0
    assert len(calls) == 1
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert report["security_verify"]["verified"] is False


def test_cli_live_load_runs_after_security_verify_or_force(tmp_path,
                                                           monkeypatch,
                                                           capsys):
    ws, calls = live_workspace(tmp_path, monkeypatch,
                               verify={"pass": True, "checks": []})
    base = ["bq-load", "--root", str(tmp_path), "--migration", "m1"]
    assert bl.main(base + ["run"]) == 0
    assert "WARNING" not in capsys.readouterr().err
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert kwargs["gcs_prefix"] == "db-drift/m1"
    assert kwargs["cleanup"] is False
    assert args[3].mode == "live"
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert report["security_verify"] == {"enforced": True, "verified": True,
                                         "forced": False}
    (ws / "artifacts" / "security-verify.json").unlink()
    assert bl.main(base + ["run", "--force", "--cleanup"]) == 0
    # the override is loud: a WARNING on stderr names what was skipped
    err = capsys.readouterr().err
    assert err.startswith("WARNING") and "security-verify.json" in err
    assert len(calls) == 2
    assert calls[1][1]["cleanup"] is True
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert report["security_verify"] == {"enforced": True, "verified": False,
                                         "forced": True}


def cp1252_console(monkeypatch):
    buf = io.BytesIO()
    stream = io.TextIOWrapper(buf, encoding="cp1252", errors="strict",
                              newline="\n", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    return buf, stream


def test_cli_survives_a_cp1252_console(tmp_path, monkeypatch):
    # The autopilot and the Bash tool run the CLI through a pipe, where
    # Windows gives Python a cp1252 stdout; a reason with a character
    # outside that code page must not lose the report or the exit code.
    ws, backend = make_workspace(tmp_path, monkeypatch)
    monkeypatch.setattr(bl, "export_table", FakeExporter(
        fail={"orders": pg.PgError('psql failed (1): relation "\u4e2d" '
                                   "does not exist")}))
    buf, stream = cp1252_console(monkeypatch)
    rc = bl.main(["bq-load", "run", "--root", str(tmp_path),
                  "--migration", "m1"])
    stream.flush()
    assert rc == 1
    report = json.loads((ws / "artifacts" / "load-report.json").read_text(
        encoding="utf-8"))
    assert "\u4e2d" in report["tables"][0]["reason"]
    printed = buf.getvalue().decode("cp1252")
    assert "public.orders" in printed and "FAIL" in printed

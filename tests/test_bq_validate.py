import copy
import decimal
import gzip
import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from db_carry import bq_backend as bb
from db_carry import bq_validate as v
from db_carry import pg


def col(name, data_type, udt, ordinal, **kw):
    base = {"schema": "public", "table": "orders", "name": name,
            "ordinal": ordinal, "data_type": data_type, "udt_name": udt,
            "nullable": True, "default": None, "precision": None,
            "scale": None, "max_length": None, "element_type": None}
    base.update(kw)
    return base


# The demo's orders table as inventory.py reports it.
ORDERS = [
    col("id", "bigint", "int8", 1, nullable=False, precision=64, scale=0),
    col("customer_id", "bigint", "int8", 2, nullable=False, precision=64,
        scale=0),
    col("status", "text", "text", 3, nullable=False),
    col("ordered_at", "timestamp with time zone", "timestamptz", 4,
        nullable=False),
    col("region", "text", "text", 5, nullable=False),
]

# One column per fingerprint class and per special case.
WIDE = ORDERS + [
    col("amount", "numeric", "numeric", 6, precision=12, scale=2),
    col("ratio", "double precision", "float8", 7),
    col("active", "boolean", "bool", 8),
    col("d", "date", "date", 9),
    col("dt", "timestamp without time zone", "timestamp", 10),
    col("t", "time without time zone", "time", 11),
    col("blob", "bytea", "bytea", 12),
    col("attributes", "USER-DEFINED", "hstore", 13),
    col("tags", "ARRAY", "_text", 14, element_type="text"),
    col("code", "character", "bpchar", 15, max_length=5),
    col("weight", "real", "float4", 16),
    col("lo", "oid", "oid", 17),
    col("meta", "jsonb", "jsonb", 18),
    col("doc", "json", "json", 19),
]

# The rows as the export renders them: char(5) values arrive padded
# (PostgreSQL pads on output), oid travels as text, a JSON null value
# in a json column is exported as NDJSON null.
WIDE_ROWS = [
    {"id": 1, "region": "eu", "ordered_at": "2025-03-20T19:00:00-05:00",
     "amount": 1.5, "ratio": 0.1, "active": True, "d": "2025-01-02",
     "dt": "2025-01-01T12:00:00", "t": "12:00:00", "blob": "AP8=",
     "attributes": {"a": "b"}, "tags": ["x"], "code": "ab   ",
     "weight": 0.1, "lo": "16384", "meta": {"a": 1}, "doc": None},
    {"id": 2, "region": "Zed", "ordered_at": "2025-01-01T00:00:00+00:00",
     "amount": 2.25, "ratio": 0.2, "active": False, "d": "2024-12-31",
     "dt": None, "t": None, "blob": None, "attributes": None, "tags": [],
     "code": None, "weight": 0.2, "lo": "24576", "meta": None,
     "doc": {"k": "v"}},
    {"id": 3, "region": "é", "ordered_at": "2024-12-31T23:30:00Z",
     "amount": None, "ratio": None, "active": None, "d": None,
     "dt": "2025-01-01T13:00:00.5", "t": "01:00:00", "blob": "AA==",
     "attributes": {}, "tags": None, "code": "z    ", "weight": None,
     "lo": None, "meta": None, "doc": None},
]

# What the PostgreSQL fingerprint query returns for WIDE_ROWS, as
# row_to_json renders it: counts and sums as JSON numbers, temporal
# values already formatted in UTC by to_char, keyed by column and metric
# (expand_pg_aliases has already mapped the positional aliases back).
WIDE_PG_RAW = {
    "rows": 3,
    "id__nonnull": 3, "id__sum": 6, "id__min": 1, "id__max": 3,
    "customer_id__nonnull": 0, "customer_id__sum": None,
    "customer_id__min": None, "customer_id__max": None,
    "status__nonnull": 0, "status__len_sum": None, "status__min": None,
    "status__max": None,
    "ordered_at__nonnull": 3,
    "ordered_at__min": "2024-12-31T23:30:00.000000",
    "ordered_at__max": "2025-03-21T00:00:00.000000",
    "region__nonnull": 3, "region__len_sum": 6, "region__min": "Zed",
    "region__max": "é",
    "amount__nonnull": 2, "amount__sum": 3.75, "amount__min": 1.50,
    "amount__max": 2.25,
    "ratio__nonnull": 2, "ratio__sum": 0.30000000000000004,
    "ratio__min": 0.1, "ratio__max": 0.2,
    "active__nonnull": 2, "active__true_count": 1,
    "d__nonnull": 2, "d__min": "2024-12-31", "d__max": "2025-01-02",
    "dt__nonnull": 2, "dt__min": "2025-01-01T12:00:00.000000",
    "dt__max": "2025-01-01T13:00:00.500000",
    "t__nonnull": 2,
    # bytes are measured with octet_length; AP8= is two bytes, AA== one
    "blob__nonnull": 2, "blob__len_sum": 3,
    "attributes__nonnull": 2,
    "tags__nonempty": 1,
    "code__nonnull": 2, "code__len_sum": 10, "code__min": "ab   ",
    "code__max": "z    ",
    # float4 summed after a text round trip: PostgreSQL adds two float8
    # values 0.1 and 0.2 and renders 17 significant digits
    "weight__nonnull": 2, "weight__sum": 0.30000000000000004,
    "weight__min": 0.1, "weight__max": 0.2,
    # row_to_json renders oid as text (the export carries it that way
    # too); sum((lo)::bigint) is a number
    "lo__nonnull": 2, "lo__sum": 40960, "lo__min": "16384",
    "lo__max": "24576",
    # the PostgreSQL side counts a JSON null value as null, like the export
    "meta__nonnull": 1,
    "doc__nonnull": 1,
}

WIDE_NORMALIZED = {
    "rows": "3",
    "columns": {
        "id": {"nonnull": "3", "sum": "6", "min": "1", "max": "3"},
        "customer_id": {"nonnull": "0", "sum": None, "min": None,
                        "max": None},
        "status": {"nonnull": "0", "len_sum": None, "min": None,
                   "max": None},
        "ordered_at": {"nonnull": "3",
                       "min": "2024-12-31T23:30:00.000000",
                       "max": "2025-03-21T00:00:00.000000"},
        "region": {"nonnull": "3", "len_sum": "6", "min": "Zed",
                   "max": "é"},
        "amount": {"nonnull": "2", "sum": "3.75", "min": "1.5",
                   "max": "2.25"},
        "ratio": {"nonnull": "2", "sum": "0.3", "min": "0.1", "max": "0.2"},
        "active": {"nonnull": "2", "true_count": "1"},
        "d": {"nonnull": "2", "min": "2024-12-31", "max": "2025-01-02"},
        "dt": {"nonnull": "2", "min": "2025-01-01T12:00:00.000000",
               "max": "2025-01-01T13:00:00.500000"},
        "t": {"nonnull": "2"},
        "blob": {"nonnull": "2", "len_sum": "3"},
        "attributes": {"nonnull": "2"},
        "tags": {"nonempty": "1"},
        "code": {"nonnull": "2", "len_sum": "10", "min": "ab   ",
                 "max": "z    "},
        "weight": {"nonnull": "2", "sum": "0.3", "min": "0.1", "max": "0.2"},
        "lo": {"nonnull": "2", "sum": "40960", "min": "16384",
               "max": "24576"},
        "meta": {"nonnull": "1"},
        "doc": {"nonnull": "1"},
    },
}


def pg_payload(spec, raw):
    """The JSON row psql returns for raw, keyed by the positional aliases
    pg_fingerprint_sql emits (c<i>__<metric>)."""
    out = {"rows": raw["rows"]}
    for i, e in enumerate(spec):
        for metric in v.metrics_for(e):
            key = f"{e['column']}__{metric}"
            if key in raw:
                out[f"c{i}__{metric}"] = raw[key]
    return json.dumps(out) + "\n"

ORDER_ROWS = [
    {"id": 1, "customer_id": 6841, "status": "paid",
     "ordered_at": "2025-03-20T19:00:00-05:00", "region": "eu"},
    {"id": 2, "customer_id": 55759, "status": "delivered",
     "ordered_at": "2026-03-26T19:00:00-05:00", "region": "us-west"},
    {"id": 3, "customer_id": 7, "status": "paid",
     "ordered_at": "2025-01-01T00:00:00+00:00", "region": "us-east"},
]

ORDERS_DDL = """CREATE TABLE IF NOT EXISTS `{project}.retail.orders` (
  id INT64 NOT NULL,
  customer_id INT64 NOT NULL,
  status STRING NOT NULL,
  ordered_at TIMESTAMP NOT NULL,
  region STRING NOT NULL
);
"""


def write_ndjson(path, rows):
    with gzip.open(path, "wt", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return path


def spec_by_column(columns):
    return {e["column"]: e for e in v.fingerprint_spec(columns)}


# ----------------------------------------------------------------- spec

def test_fingerprint_spec_classes():
    spec = v.fingerprint_spec(list(reversed(WIDE)))
    assert [e["column"] for e in spec] == [c["name"] for c in WIDE]
    by = {e["column"]: e for e in spec}
    expected = {
        "id": ("number", "INT64"), "customer_id": ("number", "INT64"),
        "status": ("string", "STRING"),
        "ordered_at": ("temporal", "TIMESTAMP"),
        "region": ("string", "STRING"),
        "amount": ("number", "NUMERIC"), "ratio": ("number", "FLOAT64"),
        "active": ("bool", "BOOL"), "d": ("temporal", "DATE"),
        "dt": ("temporal", "DATETIME"), "t": ("other", "TIME"),
        "blob": ("other", "BYTES"), "attributes": ("other", "JSON"),
        "tags": ("other", "ARRAY<STRING>"), "code": ("string", "STRING"),
        "weight": ("number", "FLOAT64"), "lo": ("number", "INT64"),
        "meta": ("other", "JSON"), "doc": ("other", "JSON"),
    }
    for name, (cls, bq_type) in expected.items():
        assert (by[name]["class"], by[name]["bq_type"]) == (cls, bq_type), name
        assert set(by[name]) >= {"column", "class", "bq_type"}
    assert by["code"]["max_length"] == 5 and by["code"]["udt_name"] == "bpchar"


def test_metrics_per_class():
    by = spec_by_column(WIDE)
    assert v.metrics_for(by["id"]) == ["nonnull", "sum", "min", "max"]
    assert v.metrics_for(by["region"]) == ["nonnull", "len_sum", "min", "max"]
    assert v.metrics_for(by["active"]) == ["nonnull", "true_count"]
    assert v.metrics_for(by["ordered_at"]) == ["nonnull", "min", "max"]
    assert v.metrics_for(by["blob"]) == ["nonnull", "len_sum"]
    assert v.metrics_for(by["t"]) == ["nonnull"]
    assert v.metrics_for(by["attributes"]) == ["nonnull"]
    # BigQuery stores a NULL array as an empty array, so the only count
    # both engines agree on is the number of non-empty arrays.
    assert v.metrics_for(by["tags"]) == ["nonempty"]


# ------------------------------------------------------------- SQL text

def test_pg_fingerprint_sql_text():
    sql = v.pg_fingerprint_sql("public", "orders", v.fingerprint_spec(WIDE))
    assert "\n" not in sql
    assert sql.startswith(
        'SELECT row_to_json(x) FROM (SELECT count(*) AS "rows", ')
    assert sql.endswith(' FROM "public"."orders") x')
    # Aliases are positional (c<i>__<metric>): PostgreSQL truncates an
    # alias to 63 bytes silently, so <column>__<metric> would lose its
    # metric for long column names. expand_pg_aliases maps them back.
    for piece in [
        'count("id") AS "c0__nonnull"', 'sum("id") AS "c0__sum"',
        'min("id") AS "c0__min"', 'max("id") AS "c0__max"',
        'sum("amount") AS "c5__sum"', 'sum("ratio") AS "c6__sum"',
        'count("region") AS "c4__nonnull"',
        'sum(length(("region")::text)) AS "c4__len_sum"',
        'min(("region")::text COLLATE "C") AS "c4__min"',
        'max(("region")::text COLLATE "C") AS "c4__max"',
        'count("ordered_at") AS "c3__nonnull"',
        # infinity renders as its text form; to_char would return ''
        "CASE WHEN isfinite(min(\"ordered_at\")) THEN "
        "to_char(min(\"ordered_at\") AT TIME ZONE 'UTC', "
        "'YYYY-MM-DD\"T\"HH24:MI:SS.US') ELSE (min(\"ordered_at\"))::text END "
        "AS \"c3__min\"",
        "CASE WHEN isfinite(max(\"ordered_at\")) THEN "
        "to_char(max(\"ordered_at\") AT TIME ZONE 'UTC', "
        "'YYYY-MM-DD\"T\"HH24:MI:SS.US') ELSE (max(\"ordered_at\"))::text END "
        "AS \"c3__max\"",
        "CASE WHEN isfinite(min(\"dt\")) THEN to_char(min(\"dt\"), "
        "'YYYY-MM-DD\"T\"HH24:MI:SS.US') ELSE (min(\"dt\"))::text END "
        "AS \"c9__min\"",
        "CASE WHEN isfinite(max(\"d\")) THEN to_char(max(\"d\"), "
        "'YYYY-MM-DD') ELSE (max(\"d\"))::text END AS \"c8__max\"",
        'count(*) FILTER (WHERE "active") AS "c7__true_count"',
        'count("blob") AS "c11__nonnull"', 'count("t") AS "c10__nonnull"',
        'sum(octet_length("blob")) AS "c11__len_sum"',
        'count("attributes") AS "c12__nonnull"',
        'count(*) FILTER (WHERE cardinality("tags") > 0) AS "c13__nonempty"',
        # char(n) pads on output, so the source pads too before measuring
        'sum(length(rpad(("code")::text, 5))) AS "c14__len_sum"',
        'min(rpad(("code")::text, 5) COLLATE "C") AS "c14__min"',
        # float4 sums in single precision on PostgreSQL; the export renders
        # the shortest text, so the source sums what the consumer parses
        'sum((("weight")::text)::float8) AS "c15__sum"',
        'min("weight") AS "c15__min"', 'max("weight") AS "c15__max"',
        # sum(oid) does not exist
        'sum(("lo")::bigint) AS "c16__sum"', 'min("lo") AS "c16__min"',
        # a JSON null value is exported as NDJSON null, so it counts as null
        "count(*) FILTER (WHERE \"meta\" IS NOT NULL AND "
        "jsonb_typeof(\"meta\") <> 'null') AS \"c17__nonnull\"",
        "count(*) FILTER (WHERE \"doc\" IS NOT NULL AND "
        "json_typeof(\"doc\") <> 'null') AS \"c18__nonnull\"",
    ]:
        assert piece in sql, piece
    assert 'AT TIME ZONE' not in sql.split('"c9__min"')[0].rsplit(", ", 1)[1]
    assert sql.count("AS ") == 1 + sum(
        len(v.metrics_for(e)) for e in v.fingerprint_spec(WIDE))
    # every alias is a valid, untruncated PostgreSQL identifier
    for alias in re.findall(r'AS "([^"]+)"', sql):
        assert len(alias.encode("utf-8")) <= 63


def test_pg_fingerprint_sql_quotes_identifiers():
    spec = [{"column": 'we"ird', "class": "number", "bq_type": "INT64"}]
    sql = v.pg_fingerprint_sql("my schema", 'ta"ble', spec)
    assert 'sum("we""ird") AS "c0__sum"' in sql
    assert sql.endswith('FROM "my schema"."ta""ble") x')


LONG_NAME = "a_very_long_column_name_that_goes_past_sixty_three_bytes_yes"


def test_expand_pg_aliases_survives_long_column_names():
    assert len(LONG_NAME) == 60
    spec = v.fingerprint_spec([
        col(LONG_NAME, "text", "text", 1),
        col(LONG_NAME + "_2", "bigint", "int8", 2)])
    sql = v.pg_fingerprint_sql("public", "t", spec)
    for alias in re.findall(r'AS "([^"]+)"', sql):
        assert len(alias.encode("utf-8")) <= 63, alias
    positional = {"rows": 2, "c0__nonnull": 2, "c0__len_sum": 5,
                  "c0__min": "a", "c0__max": "b", "c1__nonnull": 1,
                  "c1__sum": 9, "c1__min": 9, "c1__max": 9}
    raw = v.expand_pg_aliases(positional, spec)
    assert raw == {"rows": 2, f"{LONG_NAME}__nonnull": 2,
                   f"{LONG_NAME}__len_sum": 5, f"{LONG_NAME}__min": "a",
                   f"{LONG_NAME}__max": "b", f"{LONG_NAME}_2__nonnull": 1,
                   f"{LONG_NAME}_2__sum": 9, f"{LONG_NAME}_2__min": 9,
                   f"{LONG_NAME}_2__max": 9}
    normalized = v.normalize(raw, spec)
    assert normalized["columns"][LONG_NAME]["len_sum"] == "5"
    assert normalized["columns"][LONG_NAME + "_2"]["sum"] == "9"
    # a metric the row lacks is left out, never invented
    assert v.expand_pg_aliases({"rows": 0, "c1__sum": None}, spec) == {
        "rows": 0, f"{LONG_NAME}_2__sum": None}


def wide_columns(n, kind="text"):
    out = []
    for i in range(n):
        name = f"{LONG_NAME[:50]}_{i:04d}"
        if kind == "number":
            out.append(col(name, "numeric", "numeric", i + 1, precision=12,
                           scale=2))
        else:
            out.append(col(name, "text", "text", i + 1))
    return out


def test_chunk_spec_keeps_every_query_under_the_budget():
    spec = v.fingerprint_spec(wide_columns(300))
    chunks = v.chunk_spec(spec)
    assert len(chunks) > 1
    assert [e["column"] for c in chunks for e in c] == \
        [e["column"] for e in spec]
    for chunk in chunks:
        sql = v.pg_fingerprint_sql("public", "t", chunk)
        assert len(sql) <= 20000, len(sql)
    # a small table is one query
    assert v.chunk_spec(v.fingerprint_spec(ORDERS)) == [
        v.fingerprint_spec(ORDERS)]
    # the budget can be tightened; a single column always fits somewhere
    tiny = v.chunk_spec(v.fingerprint_spec(ORDERS), budget=10)
    assert [len(c) for c in tiny] == [1, 1, 1, 1, 1]
    assert v.chunk_spec([]) == []
    # PostgreSQL allows at most 1664 target list entries, so the entry
    # count is capped however generous the character budget
    big = v.chunk_spec(v.fingerprint_spec(wide_columns(600, "number")),
                       budget=10 ** 9)
    assert len(big) == 3
    assert all(1 + sum(len(v.metrics_for(e)) for e in c) <= v.MAX_ENTRIES
               for c in big)
    assert v.MAX_ENTRIES < 1664


def test_bq_fingerprint_sql_text():
    spec = v.fingerprint_spec(WIDE)
    sql = v.bq_fingerprint_sql("proj", "retail", "orders", spec)
    assert "\n" not in sql
    assert sql.startswith("SELECT COUNT(*) AS `rows`, ")
    assert sql.endswith(" FROM `proj.retail.orders`")
    for piece in [
        "COUNT(`id`) AS `id__nonnull`",
        "SUM(CAST(`id` AS NUMERIC)) AS `id__sum`",
        "MIN(`id`) AS `id__min`", "MAX(`id`) AS `id__max`",
        "SUM(`amount`) AS `amount__sum`", "SUM(`ratio`) AS `ratio__sum`",
        # BigQuery's MIN returns NaN when any input is NaN; PostgreSQL's
        # ignores NaN unless every value is NaN, so the FLOAT64 minimum
        # skips NaN and falls back to MAX, which is NaN exactly when every
        # value is NaN and NULL when there are none (as on PostgreSQL)
        "IFNULL(MIN(IF(IS_NAN(`ratio`), NULL, `ratio`)), MAX(`ratio`)) "
        "AS `ratio__min`",
        "MAX(`ratio`) AS `ratio__max`",
        "IFNULL(MIN(IF(IS_NAN(`weight`), NULL, `weight`)), MAX(`weight`)) "
        "AS `weight__min`",
        "MIN(`amount`) AS `amount__min`",
        "SUM(CAST(`lo` AS NUMERIC)) AS `lo__sum`",
        "COUNT(`meta`) AS `meta__nonnull`",
        "SUM(LENGTH(`region`)) AS `region__len_sum`",
        "MIN(`region`) AS `region__min`", "MAX(`region`) AS `region__max`",
        "FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6S', MIN(`ordered_at`)) "
        "AS `ordered_at__min`",
        "FORMAT_DATETIME('%Y-%m-%dT%H:%M:%E6S', MAX(`dt`)) AS `dt__max`",
        "FORMAT_DATE('%Y-%m-%d', MIN(`d`)) AS `d__min`",
        "COUNTIF(`active`) AS `active__true_count`",
        "COUNT(`blob`) AS `blob__nonnull`", "COUNT(`t`) AS `t__nonnull`",
        "SUM(LENGTH(`blob`)) AS `blob__len_sum`",
        "COUNTIF(ARRAY_LENGTH(`tags`) > 0) AS `tags__nonempty`",
        "SUM(LENGTH(`code`)) AS `code__len_sum`",
    ]:
        assert piece in sql, piece
    # one alias per metric plus the row count (CAST has its own AS)
    assert sql.count(") AS `") == 1 + sum(len(v.metrics_for(e)) for e in spec)


def test_bq_fingerprint_sql_honors_bq_column_and_refuses_backticks():
    spec = [{"column": "id", "class": "number", "bq_type": "INT64",
             "bq_column": "id_"}]
    sql = v.bq_fingerprint_sql("proj", "retail", "orders", spec)
    assert "COUNT(`id_`) AS `id__nonnull`" in sql
    assert "SUM(CAST(`id_` AS NUMERIC)) AS `id__sum`" in sql
    with pytest.raises(ValueError, match="backtick"):
        v.bq_fingerprint_sql("proj", "retail", "or`ders", spec)
    with pytest.raises(ValueError, match="backtick"):
        v.bq_fingerprint_sql("proj", "retail", "orders",
                             [{"column": "a`b", "class": "other",
                               "bq_type": "JSON"}])


# ---------------------------------------------------- fingerprint_from_rows

def test_fingerprint_from_rows_hand_computed():
    spec = v.fingerprint_spec(WIDE)
    raw = v.fingerprint_from_rows(WIDE_ROWS, spec)
    assert raw["rows"] == 3
    assert raw["id__sum"] == "6" and raw["id__nonnull"] == 3
    assert raw["region__min"] == "Zed" and raw["region__max"] == "é"
    assert raw["ordered_at__min"] == "2024-12-31T23:30:00.000000"
    assert raw["ordered_at__max"] == "2025-03-21T00:00:00.000000"
    # Decimal arithmetic over the JSON text: no float drift in the sum
    assert raw["ratio__sum"] == "0.3"
    assert raw["customer_id__sum"] is None and raw["status__min"] is None
    assert raw["tags__nonempty"] == 1
    assert v.normalize(raw, spec) == WIDE_NORMALIZED


def test_fingerprint_from_rows_reads_bq_column_and_iterables():
    spec = [{"column": "id", "class": "number", "bq_type": "INT64",
             "bq_column": "id_"},
            {"column": "flag", "class": "bool", "bq_type": "BOOL"}]
    rows = iter([{"id_": 5, "flag": True}, {"id_": 7}])
    raw = v.fingerprint_from_rows(rows, spec)
    assert raw == {"rows": 2, "id__nonnull": 2, "id__sum": "12",
                   "id__min": "5", "id__max": "7", "flag__nonnull": 1,
                   "flag__true_count": 1}


def test_fingerprint_from_rows_empty():
    spec = v.fingerprint_spec(ORDERS)
    raw = v.fingerprint_from_rows([], spec)
    assert raw["rows"] == 0 and raw["id__nonnull"] == 0
    assert raw["id__sum"] is None and raw["region__len_sum"] is None
    assert raw["ordered_at__min"] is None
    norm = v.normalize(raw, spec)
    assert norm["rows"] == "0"
    assert norm["columns"]["region"] == {"nonnull": "0", "len_sum": None,
                                         "min": None, "max": None}


# ----------------------------------------------------------- normalize

def test_normalize_matches_pg_rendering():
    spec = v.fingerprint_spec(WIDE)
    source = v.normalize(WIDE_PG_RAW, spec)
    # PostgreSQL adds floats in its own order; normalize keeps that
    # rendering and compare absorbs it within the tolerance
    expected = copy.deepcopy(WIDE_NORMALIZED)
    expected["columns"]["ratio"]["sum"] = "0.30000000000000004"
    expected["columns"]["weight"]["sum"] = "0.30000000000000004"
    assert source == expected
    assert v.compare(source, WIDE_NORMALIZED, spec) == {"match": True,
                                                        "mismatches": []}
    assert v.compare(source, WIDE_NORMALIZED, None)["mismatches"] == [
        {"column": "ratio", "metric": "sum", "left": "0.30000000000000004",
         "right": "0.3"},
        {"column": "weight", "metric": "sum", "left": "0.30000000000000004",
         "right": "0.3"}]


def test_normalize_canonicalizes_numbers_and_timestamps():
    spec = [{"column": "n", "class": "number", "bq_type": "NUMERIC"},
            {"column": "f", "class": "number", "bq_type": "FLOAT64"},
            {"column": "ts", "class": "temporal", "bq_type": "TIMESTAMP"},
            {"column": "d", "class": "temporal", "bq_type": "DATE"},
            {"column": "dt", "class": "temporal", "bq_type": "DATETIME"},
            {"column": "s", "class": "string", "bq_type": "STRING"}]
    raw = {"rows": "3",
           "n__nonnull": "3", "n__sum": "1.50", "n__min": 1.5,
           "n__max": "1.5E+0",
           "f__nonnull": 1, "f__sum": 100000, "f__min": "100000",
           "f__max": "1E+5",
           "ts__nonnull": 2, "ts__min": "2025-01-01T00:00:00+00:00",
           "ts__max": "2025-01-01 00:00:00 UTC",
           "d__nonnull": 1, "d__min": "2025-01-01", "d__max": None,
           "dt__nonnull": 1, "dt__min": "2025-01-01T00:00:00.000000",
           "dt__max": "2025-01-01 00:00:00+00",
           "s__nonnull": 1, "s__len_sum": "4", "s__min": " x ",
           "s__max": "1.50"}
    out = v.normalize(raw, spec)
    assert out["rows"] == "3"
    assert out["columns"]["n"] == {"nonnull": "3", "sum": "1.5",
                                   "min": "1.5", "max": "1.5"}
    assert out["columns"]["f"] == {"nonnull": "1", "sum": "100000",
                                   "min": "100000", "max": "100000"}
    assert out["columns"]["ts"] == {"nonnull": "2",
                                    "min": "2025-01-01T00:00:00.000000",
                                    "max": "2025-01-01T00:00:00.000000"}
    assert out["columns"]["d"] == {"nonnull": "1", "min": "2025-01-01",
                                   "max": None}
    assert out["columns"]["dt"]["max"] == "2025-01-01T00:00:00.000000"
    # strings compare verbatim: no trimming, no numeric interpretation
    assert out["columns"]["s"] == {"nonnull": "1", "len_sum": "4",
                                   "min": " x ", "max": "1.50"}
    # a metric the raw dict lacks is left out rather than invented
    assert v.normalize({"rows": 1}, spec)["columns"]["n"] == {}


@pytest.mark.parametrize("text", [
    "2025-01-01T00:00:00+00:00", "2025-01-01T00:00:00Z",
    "2025-01-01 00:00:00 UTC", "2025-01-01 00:00:00+00",
    "2025-01-01T00:00:00.000000", "2025-01-01T00:00:00",
    "2024-12-31T19:00:00-05:00", "2025-01-01T05:30:00+05:30",
    "2024-12-31 19:00:00-0500", "2025-01-01T00:00:00.0000004",
    "2025-01-01T00:00:00.000000Z", "2025-01-01 00:00:00.000000+00:00",
    "2025-01-01",
])
def test_canonical_temporal_timestamp_renderings(text):
    assert v.canonical_temporal(text, "TIMESTAMP") == \
        "2025-01-01T00:00:00.000000"


def test_canonical_temporal_dates_and_datetimes():
    assert v.canonical_temporal("2025-01-01", "DATE") == "2025-01-01"
    assert v.canonical_temporal("2025-01-01T00:00:00", "DATE") == "2025-01-01"
    assert v.canonical_temporal("2025-01-01T12:34:56.5", "DATETIME") == \
        "2025-01-01T12:34:56.500000"
    assert v.canonical_temporal("2025-01-01", "DATETIME") == \
        "2025-01-01T00:00:00.000000"
    assert v.canonical_temporal("0999-02-03", "DATE") == "0999-02-03"
    assert v.canonical_temporal(None, "DATE") is None
    for bad in ["garbage", "2025-13-01", "2025-01-01T25:00:00", "", "20250101"]:
        with pytest.raises(ValueError):
            v.canonical_temporal(bad, "TIMESTAMP")


@pytest.mark.parametrize("value,expected", [
    ("1.50", "1.5"), (1.5, "1.5"), ("1.5E+0", "1.5"), (100000, "100000"),
    ("100000", "100000"), ("1E+5", "100000"), (1e-07, "0.0000001"),
    ("-0.0", "0"), (0, "0"), ("0.000", "0"), (-2.5, "-2.5"),
    (20000100000, "20000100000"), ("12345678901234567890.123456789",
                                   "12345678901234567890.123456789"),
    (True, "1"), (None, None), ("NaN", "NaN"), ("Infinity", "Infinity"),
])
def test_canonical_number(value, expected):
    assert v.canonical_number(value) == expected


def test_canonical_number_rejects_text():
    with pytest.raises(ValueError):
        v.canonical_number("eu")


# ------------------------------------------------------------- compare

COMPARE_SPEC = [
    {"column": "id", "class": "number", "bq_type": "INT64"},
    {"column": "ratio", "class": "number", "bq_type": "FLOAT64"},
    {"column": "region", "class": "string", "bq_type": "STRING"},
]
LEFT = {"rows": "3", "columns": {
    "id": {"nonnull": "3", "sum": "6", "min": "1", "max": "3"},
    "ratio": {"nonnull": "2", "sum": "0.3", "min": "0.1", "max": "0.2"},
    "region": {"nonnull": "3", "len_sum": "6", "min": "Zed", "max": "eu"}}}


def test_compare_identical_and_float_tolerance():
    right = copy.deepcopy(LEFT)
    assert v.compare(LEFT, right, COMPARE_SPEC) == {"match": True,
                                                     "mismatches": []}
    right["columns"]["ratio"]["sum"] = "0.30000000000000004"
    assert v.compare(LEFT, right, COMPARE_SPEC)["match"] is True
    right["columns"]["ratio"]["sum"] = "0.31"
    report = v.compare(LEFT, right, COMPARE_SPEC)
    assert report == {"match": False, "mismatches": [
        {"column": "ratio", "metric": "sum", "left": "0.3", "right": "0.31"}]}
    # the tolerance is relative and adjustable
    right["columns"]["ratio"]["sum"] = "0.3000003"
    assert v.compare(LEFT, right, COMPARE_SPEC)["match"] is False
    assert v.compare(LEFT, right, COMPARE_SPEC, float_rel_tol=1e-5)["match"]


def test_compare_exact_for_integers_rows_and_strings():
    right = copy.deepcopy(LEFT)
    right["columns"]["id"]["sum"] = "7"
    right["rows"] = "4"
    right["columns"]["region"]["max"] = "eu "
    report = v.compare(LEFT, right, COMPARE_SPEC)
    assert report["match"] is False
    assert report["mismatches"] == [
        {"column": "*", "metric": "rows", "left": "3", "right": "4"},
        {"column": "id", "metric": "sum", "left": "6", "right": "7"},
        {"column": "region", "metric": "max", "left": "eu", "right": "eu "}]


def test_compare_missing_and_null_metrics():
    right = copy.deepcopy(LEFT)
    del right["columns"]["region"]
    report = v.compare(LEFT, right, COMPARE_SPEC)
    assert [m["metric"] for m in report["mismatches"]] == [
        "nonnull", "len_sum", "min", "max"]
    assert report["mismatches"][0] == {
        "column": "region", "metric": "nonnull", "left": "3",
        "right": "<missing>"}
    left = copy.deepcopy(LEFT)
    left["columns"]["ratio"]["sum"] = None
    right = copy.deepcopy(left)
    assert v.compare(left, right, COMPARE_SPEC)["match"] is True
    right["columns"]["ratio"]["sum"] = "0"
    assert v.compare(left, right, COMPARE_SPEC)["mismatches"] == [
        {"column": "ratio", "metric": "sum", "left": None, "right": "0"}]


def test_compare_without_spec_is_exact_over_every_metric():
    right = copy.deepcopy(LEFT)
    right["columns"]["ratio"]["sum"] = "0.30000000000000004"
    right["columns"]["extra"] = {"nonnull": "1"}
    report = v.compare(LEFT, right, None)
    assert report["match"] is False
    assert {(m["column"], m["metric"]) for m in report["mismatches"]} == {
        ("ratio", "sum"), ("extra", "nonnull")}


# ------------------------------------------------ emulated backend path

def test_emulated_fingerprint_matches_source_rendering(tmp_path):
    emu = bb.EmulatedBackend(tmp_path / "emu", "proj", "US")
    emu.create_dataset("retail")
    emu.run_ddl(ORDERS_DDL.format(project="proj"))
    emu.load_ndjson("retail", "orders",
                    write_ndjson(tmp_path / "o.ndjson.gz", ORDER_ROWS),
                    emu.get_table_schema("retail", "orders"))
    spec = v.fingerprint_spec(ORDERS)
    target = v.normalize(emu.query_fingerprint("retail", "orders", spec), spec)
    # the same rows fingerprinted on PostgreSQL, as row_to_json renders it
    source_raw = {
        "rows": 3, "id__nonnull": 3, "id__sum": 6, "id__min": 1,
        "id__max": 3, "customer_id__nonnull": 3, "customer_id__sum": 62607,
        "customer_id__min": 7, "customer_id__max": 55759,
        "status__nonnull": 3, "status__len_sum": 17, "status__min":
        "delivered", "status__max": "paid", "ordered_at__nonnull": 3,
        "ordered_at__min": "2025-01-01T00:00:00.000000",
        "ordered_at__max": "2026-03-27T00:00:00.000000",
        "region__nonnull": 3, "region__len_sum": 16, "region__min": "eu",
        "region__max": "us-west"}
    source = v.normalize(source_raw, spec)
    assert target == source
    assert v.compare(source, target, spec) == {"match": True,
                                               "mismatches": []}


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
                "bytes": 8192, "has_pk": True, "replica_identity": "d"}],
    "sequences": [], "views": [], "matviews": [], "extensions": [],
    "roles": [], "counts": {"indexes": 1, "constraints": 1},
    "columns": ORDERS, "primary_keys": [], "foreign_keys": [],
    "view_definitions": [], "view_dependencies": [],
}


def make_workspace(tmp_path, monkeypatch, with_plan=True, load_rows=True):
    monkeypatch.setattr(pg, "TOOLS_ROOT", tmp_path / "home")
    ws = tmp_path / "migrations" / "m1"
    (ws / "artifacts").mkdir(parents=True)
    (ws / "migration.yaml").write_text(MIGRATION_YAML, encoding="utf-8")
    (ws / "artifacts" / "inventory.json").write_text(
        json.dumps(INVENTORY, indent=2) + "\n", encoding="utf-8")
    backend = bb.make_backend({"mode": "emulated", "project": "demo-project",
                               "location": "US"}, "m1", ws)
    backend.create_dataset("retail")
    backend.run_ddl(ORDERS_DDL.format(project="demo-project"))
    fields = backend.get_table_schema("retail", "orders")
    if with_plan:
        plan = {"project": "demo-project", "location": "US",
                "datasets": {"retail": {"source_schema": "public"}},
                "tables": [{"schema": "public", "name": "orders",
                            "dataset": "retail", "bq_name": "orders",
                            "fields": fields}],
                "views": [], "findings": []}
        (ws / "artifacts" / "schema-plan.json").write_text(
            json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    if load_rows:
        backend.load_ndjson("retail", "orders",
                            write_ndjson(tmp_path / "o.ndjson.gz", ORDER_ROWS),
                            fields)
    return ws, backend


def test_cli_fingerprint_target_emulated(tmp_path, monkeypatch, capsys):
    ws, _ = make_workspace(tmp_path, monkeypatch)
    out = tmp_path / "target.json"
    rc = v.main(["bq-validate", "fingerprint", "--root", str(tmp_path),
                 "--migration", "m1", "--side", "target", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert list(doc) == ["public.orders"]
    entry = doc["public.orders"]
    assert entry["rows"] == "3" and entry["side"] == "target"
    assert entry["mode"] == "emulated"
    assert entry["columns"]["region"]["max"] == "us-west"
    assert entry["columns"]["ordered_at"]["min"] == "2025-01-01T00:00:00.000000"
    assert [e["column"] for e in entry["spec"]] == [c["name"] for c in ORDERS]
    assert "public.orders" in capsys.readouterr().out


def test_cli_fingerprint_target_without_schema_plan_derives_names(
        tmp_path, monkeypatch):
    ws, _ = make_workspace(tmp_path, monkeypatch, with_plan=False)
    out = tmp_path / "target.json"
    rc = v.main(["bq-validate", "fingerprint", "--root", str(tmp_path),
                 "--migration", "m1", "--side", "target", "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["public.orders"][
        "rows"] == "3"


def test_cli_fingerprint_source_runs_pg_readonly(tmp_path, monkeypatch):
    ws, _ = make_workspace(tmp_path, monkeypatch, load_rows=False)
    raw = {"rows": 3, "id__nonnull": 3, "id__sum": 6, "id__min": 1,
           "id__max": 3, "customer_id__nonnull": 3,
           "customer_id__sum": 62607, "customer_id__min": 7,
           "customer_id__max": 55759, "status__nonnull": 3,
           "status__len_sum": 17, "status__min": "delivered",
           "status__max": "paid", "ordered_at__nonnull": 3,
           "ordered_at__min": "2025-01-01T00:00:00.000000",
           "ordered_at__max": "2026-03-27T00:00:00.000000",
           "region__nonnull": 3, "region__len_sum": 16,
           "region__min": "eu", "region__max": "us-west"}
    calls = fake_psql(monkeypatch, lambda sql: pg_payload(
        v.fingerprint_spec(ORDERS), raw))
    out = tmp_path / "source.json"
    rc = v.main(["bq-validate", "fingerprint", "--root", str(tmp_path),
                 "--migration", "m1", "--side", "source", "--table",
                 "public.orders", "--out", str(out)])
    assert rc == 0
    assert len(calls) == 1
    call = calls[0]
    # read-only session, the migration's source connection, and the SQL
    # over stdin rather than as a -c argument
    assert call["env"]["PGOPTIONS"] == pg.READONLY_OPTS
    assert call["argv"][7:15] == ["-h", "127.0.0.1", "-p", "55432",
                                  "-U", "postgres", "-d", "retail"]
    assert call["argv"][-2:] == ["-f", "-"] and "-c" not in call["argv"]
    assert call["sql"] == v.pg_fingerprint_sql(
        "public", "orders", v.fingerprint_spec(ORDERS))
    entry = json.loads(out.read_text(encoding="utf-8"))["public.orders"]
    assert entry["side"] == "source" and entry["mode"] == "postgres"
    assert entry["columns"]["customer_id"]["sum"] == "62607"


def test_cli_fingerprint_errors(tmp_path, monkeypatch, capsys):
    ws, _ = make_workspace(tmp_path, monkeypatch)
    base = ["bq-validate", "fingerprint", "--root", str(tmp_path),
            "--migration", "m1", "--out", str(tmp_path / "x.json")]
    assert v.main(base + ["--side", "target", "--table", "public.nope"]) == 1
    assert "public.nope" in capsys.readouterr().err
    (ws / "artifacts" / "inventory.json").unlink()
    assert v.main(base + ["--side", "target"]) == 1
    assert "BQ-VALIDATE ERROR" in capsys.readouterr().err
    assert v.main(["bq-validate", "fingerprint", "--root", str(tmp_path),
                   "--migration", "missing", "--side", "source",
                   "--out", str(tmp_path / "y.json")]) == 1
    assert "BQ-VALIDATE ERROR" in capsys.readouterr().err
    assert not (tmp_path / "x.json").exists()


def test_cli_fingerprint_source_reports_pg_errors(tmp_path, monkeypatch,
                                                  capsys):
    make_workspace(tmp_path, monkeypatch, load_rows=False)
    fake_psql(monkeypatch, lambda sql: (
        2, "", "psql: error: connection to server failed: connection refused"))
    rc = v.main(["bq-validate", "fingerprint", "--root", str(tmp_path),
                 "--migration", "m1", "--side", "source", "--out",
                 str(tmp_path / "s.json")])
    assert rc == 1
    err = capsys.readouterr().err
    assert err.startswith("BQ-VALIDATE ERROR: psql failed (2)")
    assert "connection refused" in err
    assert not (tmp_path / "s.json").exists()


def test_cli_compare(tmp_path, capsys):
    left = {"public.orders": dict(LEFT, spec=COMPARE_SPEC, side="source"),
            "public.items": dict(LEFT, spec=COMPARE_SPEC)}
    right = copy.deepcopy(left)
    right["public.orders"]["side"] = "target"
    lp, rp = tmp_path / "l.json", tmp_path / "r.json"
    lp.write_text(json.dumps(left), encoding="utf-8")
    rp.write_text(json.dumps(right), encoding="utf-8")
    assert v.main(["bq-validate", "compare", "--left", str(lp),
                   "--right", str(rp)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["match"] is True
    assert report["tables"]["public.orders"] == {"match": True,
                                                 "mismatches": []}
    right["public.orders"]["columns"]["ratio"]["sum"] = "0.30000000000000004"
    right["public.orders"]["columns"]["id"]["max"] = "9"
    del right["public.items"]
    right["public.extra"] = dict(LEFT)
    rp.write_text(json.dumps(right), encoding="utf-8")
    out = tmp_path / "report.json"
    assert v.main(["bq-validate", "compare", "--left", str(lp),
                   "--right", str(rp), "--out", str(out)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["match"] is False
    assert report["tables"]["public.orders"]["mismatches"] == [
        {"column": "id", "metric": "max", "left": "3", "right": "9"}]
    assert report["missing_in_right"] == ["public.items"]
    assert report["missing_in_left"] == ["public.extra"]
    assert json.loads(out.read_text(encoding="utf-8")) == report


def test_cli_compare_errors(tmp_path, capsys):
    lp = tmp_path / "l.json"
    lp.write_text("{}", encoding="utf-8")
    assert v.main(["bq-validate", "compare", "--left", str(lp),
                   "--right", str(tmp_path / "missing.json")]) == 1
    assert "BQ-VALIDATE ERROR" in capsys.readouterr().err
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    assert v.main(["bq-validate", "compare", "--left", str(lp),
                   "--right", str(bad)]) == 1
    assert "mapping" in capsys.readouterr().err


# ------------------------------------------------- values at the edges

@pytest.mark.parametrize("text,expected", [
    # pre-1883 timestamptz values rendered in a session zone carry the
    # local mean time offset with seconds
    ("0001-01-01T00:00:00-05:50:36", "0001-01-01T05:50:36.000000"),
    ("1883-11-18T11:00:00-05:50:36", "1883-11-18T16:50:36.000000"),
    ("2025-01-01T00:00:00+05:30:00", "2024-12-31T18:30:00.000000"),
    ("2025-01-01 00:00:00-055036", "2025-01-01T05:50:36.000000"),
])
def test_parse_temporal_accepts_seconds_in_the_offset(text, expected):
    assert v.canonical_temporal(text, "TIMESTAMP") == expected


def test_canonical_temporal_reports_out_of_range_conversions():
    with pytest.raises(ValueError, match="out of range"):
        v.canonical_temporal("0001-01-01T00:00:00+05:00", "TIMESTAMP")


def test_canonical_temporal_passes_infinity_through():
    assert v.canonical_temporal("infinity", "TIMESTAMP") == "infinity"
    assert v.canonical_temporal("-infinity", "DATE") == "-infinity"
    assert v.canonical_temporal(" Infinity ", "DATETIME") == "infinity"


def test_fingerprint_from_rows_infinite_temporal_values():
    spec = [{"column": "t", "class": "temporal", "bq_type": "TIMESTAMP"},
            {"column": "d", "class": "temporal", "bq_type": "DATE"}]
    rows = [{"t": "infinity", "d": "-infinity"},
            {"t": "2025-01-01T00:00:00+00:00", "d": "2025-01-01"},
            {"t": None, "d": "infinity"}]
    raw = v.fingerprint_from_rows(rows, spec)
    assert raw["t__nonnull"] == 2 and raw["t__max"] == "infinity"
    assert raw["t__min"] == "2025-01-01T00:00:00.000000"
    assert raw["d__min"] == "-infinity" and raw["d__max"] == "infinity"
    only = v.fingerprint_from_rows([{"t": "infinity", "d": "-infinity"}], spec)
    assert only["t__min"] == "infinity" and only["d__max"] == "-infinity"
    # what the PostgreSQL CASE renders for the same rows
    source = v.normalize({"rows": 3, "t__nonnull": 2, "t__max": "infinity",
                          "t__min": "2025-01-01T00:00:00.000000",
                          "d__nonnull": 3, "d__min": "-infinity",
                          "d__max": "infinity"}, spec)
    assert v.compare(source, v.normalize(raw, spec), spec)["match"] is True


def test_fingerprint_from_rows_nan():
    spec = [{"column": "r", "class": "number", "bq_type": "FLOAT64"}]
    # PostgreSQL orders NaN above every number: sum and max become NaN,
    # min ignores NaN unless every value is NaN
    raw = v.fingerprint_from_rows([{"r": "NaN"}, {"r": 1.5}], spec)
    assert raw == {"rows": 2, "r__nonnull": 2, "r__sum": "NaN",
                   "r__min": "1.5", "r__max": "NaN"}
    pg_raw = {"rows": 2, "r__nonnull": 2, "r__sum": "NaN", "r__min": 1.5,
              "r__max": "NaN"}
    assert v.compare(v.normalize(pg_raw, spec), v.normalize(raw, spec),
                     spec)["match"] is True
    all_nan = v.fingerprint_from_rows([{"r": "NaN"}, {"r": "NaN"}], spec)
    assert all_nan["r__min"] == "NaN" and all_nan["r__max"] == "NaN"
    inf = v.fingerprint_from_rows([{"r": "Infinity"}, {"r": "-Infinity"},
                                   {"r": 2}], spec)
    assert inf["r__sum"] == "NaN"
    assert inf["r__min"] == "-Infinity" and inf["r__max"] == "Infinity"


# ---------------------------------------------- source fingerprint path

SOURCE_CI = {"host": "127.0.0.1", "port": 55432, "dbname": "retail",
             "user": "postgres", "password_env": None}


def fake_psql(monkeypatch, respond):
    """Fake subprocess.run under run_source_sql: respond(sql) -> the raw
    dict keyed by the positional aliases in sql (rows included), the
    stdout text itself, or a (returncode, stdout, stderr) triple.
    Records every call as {"argv", "sql", "env", "encoding",
    "capture_output"}."""
    calls = []

    def fake(argv, input=None, env=None, capture_output=False,
             encoding=None, **kw):
        calls.append({"argv": list(argv), "sql": input, "env": env,
                      "encoding": encoding, "capture_output": capture_output})
        body = respond(input)
        if isinstance(body, tuple):
            rc, out, err = body
        else:
            rc, err = 0, ""
            out = body if isinstance(body, str) else json.dumps(body) + "\n"
        return subprocess.CompletedProcess(list(argv), rc, out, err)

    monkeypatch.setattr(v.subprocess, "run", fake)
    monkeypatch.setattr(pg, "find_bin", lambda name: f"/fake/{name}")
    return calls


def aliases_of(sql):
    return re.findall(r'AS "([^"]+)"', sql)


def test_run_source_sql_feeds_psql_over_stdin(monkeypatch):
    monkeypatch.setenv("SRC_PW", "hunter2")
    ci = dict(SOURCE_CI, password_env="SRC_PW")
    calls = fake_psql(monkeypatch, lambda sql: '{"rows":1}\n')
    # longer than the 32767 character Windows command line: the SQL is
    # the program's stdin, never an argument
    sql = "SELECT " + "x" * 40000
    assert v.run_source_sql(ci, sql) == '{"rows":1}\n'
    call = calls[0]
    assert call["argv"] == ["/fake/psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                            "-A", "-t", "-h", "127.0.0.1", "-p", "55432",
                            "-U", "postgres", "-d", "retail", "-f", "-"]
    assert call["sql"] == sql
    assert call["encoding"] == "utf-8" and call["capture_output"] is True
    assert call["env"]["PGOPTIONS"] == pg.READONLY_OPTS
    assert call["env"]["PGCLIENTENCODING"] == "UTF8"
    assert call["env"]["PGPASSWORD"] == "hunter2"


def test_run_source_sql_reports_failures_without_the_password(monkeypatch):
    monkeypatch.setenv("SRC_PW", "hunter2")
    ci = dict(SOURCE_CI, password_env="SRC_PW")
    fake_psql(monkeypatch, lambda sql: (
        2, "", "psql: error: connection to server failed: refused\n"
        + "x" * 2000))
    with pytest.raises(pg.PgError) as info:
        v.run_source_sql(ci, "SELECT 1")
    message = str(info.value)
    assert message.startswith("psql failed (2): ")
    assert "refused" in message and "hunter2" not in message
    assert len(message) < 900

    def cannot_start(*args, **kwargs):
        raise OSError("cannot spawn")

    monkeypatch.setattr(v.subprocess, "run", cannot_start)
    with pytest.raises(pg.PgError, match="cannot spawn"):
        v.run_source_sql(ci, "SELECT 1")


def test_source_fingerprint_batches_wide_tables(monkeypatch):
    columns = wide_columns(300)
    spec = v.fingerprint_spec(columns)
    calls = fake_psql(monkeypatch, lambda sql: {
        alias: 7 if alias == "rows" else 1 for alias in aliases_of(sql)})
    raw = v.pg_table_fingerprint(SOURCE_CI, "public", "t", spec)
    assert len(calls) > 1
    assert all(c["env"]["PGOPTIONS"] == pg.READONLY_OPTS for c in calls)
    assert all(c["argv"][-2:] == ["-f", "-"] for c in calls)
    assert all(len(c["sql"]) <= 20000 for c in calls)
    assert raw["rows"] == 7
    assert all(raw[f"{c['name']}__nonnull"] == 1 for c in columns)
    assert len(raw) == 1 + 4 * 300
    # one line of SQL per batch
    assert all("\n" not in c["sql"] for c in calls)


def test_source_fingerprint_refuses_a_moving_table(monkeypatch):
    spec = v.fingerprint_spec(wide_columns(300))
    counts = iter([7, 7, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7])
    fake_psql(monkeypatch, lambda sql: {
        alias: next(counts) if alias == "rows" else 1
        for alias in aliases_of(sql)})
    with pytest.raises(v.ValidateError, match="changed"):
        v.pg_table_fingerprint(SOURCE_CI, "public", "t", spec)


def test_source_fingerprint_of_a_table_without_columns(monkeypatch):
    calls = fake_psql(monkeypatch, lambda sql: {"rows": 4})
    assert v.pg_table_fingerprint(SOURCE_CI, "public", "t", []) == {"rows": 4}
    assert len(calls) == 1
    assert calls[0]["sql"] == v.pg_fingerprint_sql("public", "t", [])


def test_source_fingerprint_keeps_numeric_precision(monkeypatch):
    spec = v.fingerprint_spec([col("amount", "numeric", "numeric", 1,
                                   precision=20, scale=2)])
    fake_psql(monkeypatch, lambda sql: (
        '{"rows":1,"c0__nonnull":1,"c0__sum":12345678901234567.89,'
        '"c0__min":12345678901234567.89,"c0__max":12345678901234567.89}\n'))
    raw = v.pg_table_fingerprint(SOURCE_CI, "public", "t", spec)
    assert isinstance(raw["amount__sum"], decimal.Decimal)
    out = v.normalize(raw, spec)
    assert out["columns"]["amount"]["sum"] == "12345678901234567.89"
    # plain json.loads would have rounded it through a float
    assert str(json.loads("12345678901234567.89")) == "1.2345678901234568e+16"


def test_source_fingerprint_survives_unicode_line_separators(monkeypatch):
    # str.splitlines() (what pg.query_rows uses) splits at U+2028, U+0085
    # and friends, which row_to_json leaves unescaped; the single JSON row
    # must be parsed whole
    spec = v.fingerprint_spec([col("s", "text", "text", 1)])
    value = "a\u2028b\u0085c"
    assert len(value.splitlines()) == 3
    fake_psql(monkeypatch, lambda sql: json.dumps(
        {"rows": 1, "c0__nonnull": 1, "c0__len_sum": 5, "c0__min": value,
         "c0__max": value}, ensure_ascii=False) + "\n")
    raw = v.pg_table_fingerprint(SOURCE_CI, "public", "t", spec)
    assert raw["s__min"] == value and raw["s__max"] == value
    fake_psql(monkeypatch, lambda sql: "\n")
    with pytest.raises(v.ValidateError, match="no JSON row"):
        v.pg_table_fingerprint(SOURCE_CI, "public", "t", spec)
    fake_psql(monkeypatch, lambda sql: "[1, 2]\n")
    with pytest.raises(v.ValidateError, match="no JSON row"):
        v.pg_table_fingerprint(SOURCE_CI, "public", "t", spec)


def test_cli_fingerprint_reports_arithmetic_errors(tmp_path, monkeypatch,
                                                   capsys):
    make_workspace(tmp_path, monkeypatch)

    def boom(*args, **kwargs):
        raise decimal.InvalidOperation("bad decimal")

    monkeypatch.setattr(v, "table_fingerprints", boom)
    rc = v.main(["bq-validate", "fingerprint", "--root", str(tmp_path),
                 "--migration", "m1", "--side", "target", "--out",
                 str(tmp_path / "t.json")])
    assert rc == 1
    assert "BQ-VALIDATE ERROR: InvalidOperation" in capsys.readouterr().err


def test_cli_compare_survives_a_cp1252_console(tmp_path, monkeypatch):
    # The report is what the operator needs on a mismatch; a string value
    # outside the console code page must not lose it or the exit code.
    left = {"public.orders": dict(LEFT, spec=COMPARE_SPEC)}
    right = copy.deepcopy(left)
    right["public.orders"]["columns"]["region"]["max"] = "中"
    lp, rp = tmp_path / "l.json", tmp_path / "r.json"
    lp.write_text(json.dumps(left), encoding="utf-8")
    rp.write_text(json.dumps(right, ensure_ascii=False), encoding="utf-8")
    buf = io.BytesIO()
    stream = io.TextIOWrapper(buf, encoding="cp1252", errors="strict",
                              newline="\n", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    out = tmp_path / "report.json"
    rc = v.main(["bq-validate", "compare", "--left", str(lp), "--right",
                 str(rp), "--out", str(out)])
    stream.flush()
    assert rc == 1
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["tables"]["public.orders"]["mismatches"] == [
        {"column": "region", "metric": "max", "left": "eu", "right": "中"}]
    printed = json.loads(buf.getvalue().decode("cp1252"))
    assert printed == report


def test_bytes_length_agrees_across_the_three_paths():
    """BYTES columns carry a byte length sum on every side: octet_length
    on PostgreSQL, LENGTH over BYTES on BigQuery, and the decoded base64
    length over NDJSON in the emulator."""
    spec = v.fingerprint_spec([col("blob", "bytea", "bytea", 1)])
    assert spec[0]["class"] == "other" and spec[0]["bq_type"] == "BYTES"
    assert v.metrics_for(spec[0]) == ["nonnull", "len_sum"]
    pg_sql = v.pg_fingerprint_sql("public", "t", spec)
    assert 'sum(octet_length("blob")) AS "c0__len_sum"' in pg_sql
    assert 'count("blob") AS "c0__nonnull"' in pg_sql
    bq_sql = v.bq_fingerprint_sql("proj", "retail", "t", spec)
    assert "SUM(LENGTH(`blob`)) AS `blob__len_sum`" in bq_sql
    # 0x00 0xFF (2 bytes), 0x00 (1 byte), "hello" (5 bytes), null
    rows = [{"blob": "AP8="}, {"blob": "AA=="}, {"blob": "aGVsbG8="},
            {"blob": None}]
    raw = v.fingerprint_from_rows(rows, spec)
    assert raw == {"rows": 4, "blob__nonnull": 3, "blob__len_sum": 8}
    # what PostgreSQL and BigQuery report for the same bytes normalizes
    # to the same fingerprint
    pg_raw = v.expand_pg_aliases({"rows": 4, "c0__nonnull": 3,
                                  "c0__len_sum": 8}, spec)
    bq_raw = {"rows": "4", "blob__nonnull": "3", "blob__len_sum": "8"}
    assert v.normalize(raw, spec) == v.normalize(pg_raw, spec) == \
        v.normalize(bq_raw, spec) == {
            "rows": "4", "columns": {"blob": {"nonnull": "3",
                                              "len_sum": "8"}}}
    assert v.compare(v.normalize(pg_raw, spec), v.normalize(raw, spec),
                     spec)["match"] is True
    # an empty column reports no length, like the SQL sum of nothing
    assert v.fingerprint_from_rows([{"blob": None}], spec) == {
        "rows": 1, "blob__nonnull": 0, "blob__len_sum": None}
    with pytest.raises(ValueError):
        v.fingerprint_from_rows([{"blob": "not base64!"}], spec)

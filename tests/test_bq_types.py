import pytest

from db_drift import bq_types as t


def col(data_type, udt, **kw):
    base = {"name": "c", "data_type": data_type, "udt_name": udt,
            "precision": None, "scale": None, "element_type": None}
    base.update(kw)
    return base


@pytest.mark.parametrize("data_type,udt,expected", [
    ("bigint", "int8", "INT64"),
    ("integer", "int4", "INT64"),
    ("smallint", "int2", "INT64"),
    ("real", "float4", "FLOAT64"),
    ("double precision", "float8", "FLOAT64"),
    ("boolean", "bool", "BOOL"),
    ("text", "text", "STRING"),
    ("character varying", "varchar", "STRING"),
    ("character", "bpchar", "STRING"),
    ("uuid", "uuid", "STRING"),
    ("bytea", "bytea", "BYTES"),
    ("date", "date", "DATE"),
    ("timestamp with time zone", "timestamptz", "TIMESTAMP"),
    ("timestamp without time zone", "timestamp", "DATETIME"),
    ("time without time zone", "time", "TIME"),
    ("json", "json", "JSON"),
    ("jsonb", "jsonb", "JSON"),
    ("USER-DEFINED", "hstore", "JSON"),
    ("USER-DEFINED", "citext", "STRING"),
])
def test_scalar_map(data_type, udt, expected):
    assert t.map_type(col(data_type, udt))[0] == expected


def test_numeric_precision_rules():
    assert t.map_type(col("numeric", "numeric", precision=12, scale=2))[0] \
        == "NUMERIC"
    assert t.map_type(col("numeric", "numeric", precision=50, scale=10))[0] \
        == "BIGNUMERIC"
    big, notes = t.map_type(col("numeric", "numeric", precision=100, scale=50))
    assert big == "STRING" and any("WARNING" in n for n in notes)
    unconstrained, notes = t.map_type(col("numeric", "numeric"))
    assert unconstrained == "NUMERIC" and notes


def test_arrays_and_warnings():
    assert t.map_type(col("ARRAY", "_text", element_type="text"))[0] \
        == "ARRAY<STRING>"
    assert t.map_type(col("ARRAY", "_int4", element_type="int4"))[0] \
        == "ARRAY<INT64>"
    interval, notes = t.map_type(col("interval", "interval"))
    assert interval == "STRING" and any("WARNING" in n for n in notes)
    unknown, notes = t.map_type(col("USER-DEFINED", "mood"))
    assert unknown == "STRING" and any("unknown" in n for n in notes)


def test_cast_type_name():
    assert t.cast_type_name("text") == "STRING"
    assert t.cast_type_name("character varying") == "STRING"
    assert t.cast_type_name("character varying(20)") == "STRING"
    assert t.cast_type_name("timestamp with time zone") == "TIMESTAMP"
    assert t.cast_type_name("integer") == "INT64"
    assert t.cast_type_name("text[]") is None


def test_identifiers_and_datasets():
    assert t.sanitize_identifier("orders") == ("orders", None)
    safe, note = t.sanitize_identifier("order-items 2")
    assert safe == "order_items_2" and note
    assert t.sanitize_identifier("1abc")[0] == "_1abc"
    assert t.dataset_for("public", {}, "retail") == "retail"
    assert t.dataset_for("public", {"public": "warehouse"}, "retail") \
        == "warehouse"
    assert t.dataset_for("sales", {}, "retail") == "sales"
    assert t.qualified("p", "d", "t") == "`p.d.t`"


def test_export_expressions():
    assert t.export_expression(col("text", "text")) == '"c"'
    assert t.export_expression(col("bytea", "bytea")) \
        == "translate(encode(\"c\", 'base64'), E'\\n', '')"
    assert t.export_expression(col("USER-DEFINED", "hstore")) \
        == 'hstore_to_json("c")'
    assert t.export_expression(col("ARRAY", "_text", element_type="text")) \
        == 'to_json("c")'
    assert t.export_expression(col("interval", "interval")) == '("c")::text'

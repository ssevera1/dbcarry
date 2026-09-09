"""PostgreSQL to BigQuery type map, identifier rules, export expressions.

map_type is the single place the type mapping lives; docs restate it.
"""
import re

INT_TYPES = {"int2", "int4", "int8", "smallint", "integer", "bigint",
             "serial", "bigserial", "smallserial", "oid"}
FLOAT_TYPES = {"float4", "float8", "real", "double precision"}
STRING_TYPES = {"text", "varchar", "character varying", "bpchar", "character",
                "char", "citext", "uuid", "name", "inet", "cidr", "macaddr",
                "macaddr8"}
BOOL_TYPES = {"bool", "boolean"}
JSON_TYPES = {"json", "jsonb", "hstore"}
STRING_WITH_WARNING = {"interval", "money", "xml", "geometry", "geography",
                       "tsvector", "tsquery", "point", "line", "lseg", "box",
                       "path", "polygon", "circle", "bit", "varbit",
                       "bit varying"}

JSON_NATIVE_UDT = {"int2", "int4", "int8", "float4", "float8", "numeric",
                   "bool", "text", "varchar", "bpchar", "uuid", "date",
                   "timestamp", "timestamptz", "time", "json", "jsonb",
                   "citext", "name", "inet", "cidr", "macaddr", "macaddr8"}

MULTI_WORD_TYPES = ("character varying", "double precision",
                    "timestamp with time zone", "timestamp without time zone",
                    "time with time zone", "time without time zone",
                    "bit varying")

CAST_NAMES = {
    "text": "STRING", "varchar": "STRING", "character varying": "STRING",
    "bpchar": "STRING", "character": "STRING", "char": "STRING",
    "citext": "STRING", "uuid": "STRING", "name": "STRING",
    "int2": "INT64", "int4": "INT64", "int8": "INT64", "smallint": "INT64",
    "integer": "INT64", "int": "INT64", "bigint": "INT64",
    "numeric": "NUMERIC", "decimal": "NUMERIC",
    "float4": "FLOAT64", "float8": "FLOAT64", "real": "FLOAT64",
    "double precision": "FLOAT64", "float": "FLOAT64",
    "bool": "BOOL", "boolean": "BOOL",
    "date": "DATE",
    "timestamptz": "TIMESTAMP", "timestamp with time zone": "TIMESTAMP",
    "timestamp": "DATETIME", "timestamp without time zone": "DATETIME",
    "time": "TIME", "time without time zone": "TIME",
    "json": "JSON", "jsonb": "JSON", "bytea": "BYTES",
}

IDENT_RE = re.compile(r"[^A-Za-z0-9_]")


def map_type(column):
    """Return (bigquery_type, notes) for one inventory column dict."""
    notes = []
    data_type = (column.get("data_type") or "").lower().strip()
    udt = (column.get("udt_name") or "").lower().strip()
    element = (column.get("element_type") or "").lower().strip()

    if data_type == "array" or (udt.startswith("_") and element):
        elem_col = dict(column, data_type="", udt_name=element or udt[1:],
                        element_type="")
        inner, inner_notes = map_type(elem_col)
        notes.extend(inner_notes)
        if inner.startswith("ARRAY<"):
            notes.append("nested arrays are not supported in BigQuery; "
                         "mapped to ARRAY<JSON>")
            return "ARRAY<JSON>", notes
        return f"ARRAY<{inner}>", notes

    name = udt if data_type in ("user-defined", "") else data_type
    if name in INT_TYPES or udt in INT_TYPES:
        return "INT64", notes
    if name in ("numeric", "decimal"):
        precision = column.get("precision")
        scale = column.get("scale")
        if precision is None:
            return "NUMERIC", notes + [
                "unconstrained numeric mapped to NUMERIC (38 digits, "
                "scale 9); values beyond that lose precision"]
        if precision <= 38 and (scale or 0) <= 9:
            return "NUMERIC", notes
        if precision <= 76 and (scale or 0) <= 38:
            return "BIGNUMERIC", notes
        notes.append(f"numeric({precision},{scale}) exceeds BIGNUMERIC; "
                     "mapped to STRING (WARNING)")
        return "STRING", notes
    if name in FLOAT_TYPES or udt in FLOAT_TYPES:
        return "FLOAT64", notes
    if name in BOOL_TYPES or udt in BOOL_TYPES:
        return "BOOL", notes
    if name in STRING_TYPES or udt in STRING_TYPES:
        return "STRING", notes
    if name == "bytea" or udt == "bytea":
        return "BYTES", notes + ["exported as base64"]
    if name == "date" or udt == "date":
        return "DATE", notes
    if name == "timestamp with time zone" or udt == "timestamptz":
        return "TIMESTAMP", notes
    if name in ("timestamp without time zone", "timestamp") \
            or udt == "timestamp":
        return "DATETIME", notes
    if name in ("time without time zone", "time") or udt == "time":
        return "TIME", notes
    if name == "time with time zone" or udt == "timetz":
        return "STRING", notes + ["time with time zone has no BigQuery "
                                  "equivalent; mapped to STRING (WARNING)"]
    if name in JSON_TYPES or udt in JSON_TYPES:
        if udt == "hstore" or name == "hstore":
            notes.append("hstore exported via hstore_to_json")
        return "JSON", notes
    if name in STRING_WITH_WARNING or udt in STRING_WITH_WARNING:
        notes.append(f"{udt or name} mapped to STRING (WARNING)")
        return "STRING", notes
    notes.append(f"unknown type {udt or name!r} mapped to STRING (WARNING); "
                 "enums and domains resolve to their underlying type on "
                 "the source, so check the column default and values")
    return "STRING", notes


def cast_type_name(pg_type):
    """BigQuery type name for a PostgreSQL cast target, or None."""
    key = pg_type.strip().lower()
    key = re.sub(r"\(.*\)$", "", key).strip()
    return CAST_NAMES.get(key)


def sanitize_identifier(name):
    """BigQuery datasets, tables, tags, and policies allow [A-Za-z0-9_]."""
    safe = IDENT_RE.sub("_", name)
    if not safe or safe[0].isdigit():
        safe = "_" + safe
    note = None
    if safe != name:
        note = f"identifier {name!r} renamed to {safe!r} for BigQuery"
    return safe, note


def dataset_for(schema, dataset_map, dbname):
    if schema in (dataset_map or {}):
        return sanitize_identifier(str(dataset_map[schema]))[0]
    if schema == "public":
        return sanitize_identifier(dbname)[0]
    return sanitize_identifier(schema)[0]


def qualified(project, dataset, table):
    return f"`{project}.{dataset}.{table}`"


def quote_pg(name):
    return '"' + name.replace('"', '""') + '"'


def export_expression(column):
    """SQL expression that renders the column as a JSON-friendly value."""
    col = quote_pg(column["name"])
    data_type = (column.get("data_type") or "").lower().strip()
    udt = (column.get("udt_name") or "").lower().strip()
    if data_type == "array" or udt.startswith("_"):
        return f"to_json({col})"
    if udt == "bytea":
        # encode(..., 'base64') follows RFC 2045 and breaks lines every 76
        # characters; BigQuery expects one unbroken base64 string.
        return f"translate(encode({col}, 'base64'), E'\\n', '')"
    if udt == "hstore":
        return f"hstore_to_json({col})"
    if udt in JSON_NATIVE_UDT:
        return col
    return f"({col})::text"

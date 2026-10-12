"""Engine-neutral fingerprints for PostgreSQL to BigQuery validation.

A checksum over rendered text cannot cross engines: PostgreSQL and
BigQuery print timestamps, numerics, and floats differently. Instead,
each table gets one aggregate query per engine built from the same
fingerprint spec, and the results are normalized in Python before they
are compared:

    class     metrics
    number    nonnull, sum, min, max        (INT64, NUMERIC, BIGNUMERIC, FLOAT64)
    string    nonnull, len_sum, min, max    (STRING; min and max in binary order)
    bool      nonnull, true_count
    temporal  nonnull, min, max             (DATE, DATETIME, TIMESTAMP, as UTC ISO text)
    other     nonnull, len_sum              (BYTES: octet_length on PostgreSQL,
                                             LENGTH on BigQuery, decoded base64
                                             length in Python)
    other     nonnull                       (TIME, JSON)
    other     nonempty                      (ARRAY<...>: BigQuery stores a NULL
                                             array as an empty array, so the
                                             non-empty count is the only one
                                             both engines agree on)

Plus the row count. Numbers become canonical Decimal strings ("1.50",
1.5, and "1.5E+0" all read "1.5"), temporal values become
YYYY-MM-DDTHH:MM:SS.ffffff in UTC (dates YYYY-MM-DD), strings are
compared verbatim. FLOAT64 sums, minima, and maxima compare within a
relative tolerance because the two engines add floats in different
orders.

Values at the edges follow PostgreSQL, which is what the export
carries. NaN sorts above every number there, so a column holding one
has sum NaN and max NaN while min ignores NaN unless every value is
NaN; the BigQuery query reproduces that ordering. An infinite date or
timestamp renders as the literal 'infinity' or '-infinity' on both
sides (BigQuery cannot store one, so a live load fails first; the
emulator loads the text and the mismatch is reported per column). A
JSON null value inside a json or jsonb column is exported as NDJSON
null, so the source counts it as null too.

The source query runs through psql over stdin, never as a -c argument:
Windows caps a command line at 32767 characters, and psql receives argv
in the ANSI code page there. A wide table is fingerprinted in batches
(chunk_spec) because PostgreSQL allows at most 1664 entries in one
target list; the batches must agree on the row count or the table was
changing under the query. PostgreSQL's JSON is parsed with Decimal so a
NUMERIC sum keeps every digit.

The emulated backend has no SQL engine; fingerprint_from_rows computes
the same metrics over the loaded NDJSON rows in pure Python, an
independent implementation from the PostgreSQL SQL, so an emulated run
still proves the export is complete and faithful. The emulator stores
the NDJSON lines as exported and reads their numbers as Decimal, so a
NUMERIC or BIGNUMERIC sum keeps every digit there too.
"""
import argparse
import base64
import decimal
import json
import math
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

from db_carry import bq_backend, bq_load, bq_types, config, pg

NUMBER_TYPES = {"INT64", "NUMERIC", "BIGNUMERIC", "FLOAT64"}
TEMPORAL_TYPES = {"DATE", "DATETIME", "TIMESTAMP"}
PG_TS_FORMAT = 'YYYY-MM-DD"T"HH24:MI:SS.US'
PG_DATE_FORMAT = "YYYY-MM-DD"
BQ_TS_FORMAT = "%Y-%m-%dT%H:%M:%E6S"
BQ_DATE_FORMAT = "%Y-%m-%d"
MISSING = "<missing>"

# Characters of SQL per source fingerprint query, and target list
# entries per query (PostgreSQL refuses more than 1664).
SQL_BUDGET = 20000
MAX_ENTRIES = 1000

# Wide enough for BIGNUMERIC sums; the default context (28 digits) would
# round a 38 digit NUMERIC.
_CTX = decimal.Context(prec=200)

# The zone may carry seconds: before 1883 a session zone is local mean
# time, and PostgreSQL renders the offset as -05:50:36.
TEMPORAL_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?)?"
    r"\s*(Z|UTC|[+-]\d{2}(?::?\d{2}(?::?\d{2})?)?)?$", re.IGNORECASE)
INFINITY_RE = re.compile(r"^(-?)infinity$", re.IGNORECASE)


class ValidateError(Exception):
    pass


# ------------------------------------------------------------------ spec

def _class_for(bq_type):
    if bq_type in NUMBER_TYPES:
        return "number"
    if bq_type == "STRING":
        return "string"
    if bq_type == "BOOL":
        return "bool"
    if bq_type in TEMPORAL_TYPES:
        return "temporal"
    return "other"


def fingerprint_spec(columns):
    """One entry per inventory column, in ordinal order:
    {"column", "class", "bq_type"} plus "udt_name" and "max_length" when
    the source needs them (char(n) pads on output, so the source pads
    before measuring). An entry may carry "bq_column" when the BigQuery
    column is named differently; both SQL builders honor it."""
    out = []
    for c in sorted(columns, key=lambda c: c.get("ordinal") or 0):
        bq_type, _notes = bq_types.map_type(c)
        entry = {"column": c["name"], "class": _class_for(bq_type),
                 "bq_type": bq_type}
        if c.get("udt_name"):
            entry["udt_name"] = c["udt_name"]
        if c.get("max_length") is not None:
            entry["max_length"] = int(c["max_length"])
        out.append(entry)
    return out


def _is_array(entry):
    return str(entry.get("bq_type") or "").startswith("ARRAY<")


def _udt(entry):
    return (entry.get("udt_name") or "").lower().strip()


def metrics_for(entry):
    cls = entry["class"]
    if cls == "number":
        return ["nonnull", "sum", "min", "max"]
    if cls == "string":
        return ["nonnull", "len_sum", "min", "max"]
    if cls == "bool":
        return ["nonnull", "true_count"]
    if cls == "temporal":
        return ["nonnull", "min", "max"]
    if _is_array(entry):
        return ["nonempty"]
    if _is_bytes(entry):
        return ["nonnull", "len_sum"]
    return ["nonnull"]


def _is_bytes(entry):
    return entry.get("bq_type") == "BYTES"


# ------------------------------------------------------------- SQL text

def _pg_string_expr(entry, col):
    text = f"({col})::text"
    if _udt(entry) == "bpchar" and entry.get("max_length"):
        return f"rpad({text}, {int(entry['max_length'])})"
    return text


def _pg_nonnull_expr(entry, col):
    """count(col), except that a JSON null value inside a json or jsonb
    column is exported as NDJSON null and so counts as null here too."""
    udt = _udt(entry)
    if udt in ("json", "jsonb"):
        typeof = "jsonb_typeof" if udt == "jsonb" else "json_typeof"
        return (f"count(*) FILTER (WHERE {col} IS NOT NULL AND "
                f"{typeof}({col}) <> 'null')")
    return f"count({col})"


def _pg_sum_expr(entry, col):
    """sum(col), with two source-specific casts. A float4 column sums in
    single precision on PostgreSQL, which drifts past the tolerance
    within a few thousand rows; the export renders each value as its
    shortest text, so the source sums the float8 that text denotes,
    which is what BigQuery and the emulator add up. sum(oid) does not
    exist, so oid sums as bigint."""
    udt = _udt(entry)
    if udt == "float4":
        return f"sum((({col})::text)::float8)"
    if udt == "oid":
        return f"sum(({col})::bigint)"
    return f"sum({col})"


def _pg_temporal_expr(agg, entry, col):
    """to_char of the aggregate in the canonical layout, or the text
    form ('infinity', '-infinity') when the value is not finite, since
    to_char renders infinity as an empty string."""
    inner = f"{agg}({col})"
    if entry["bq_type"] == "DATE":
        rendered = f"to_char({inner}, '{PG_DATE_FORMAT}')"
    elif entry["bq_type"] == "TIMESTAMP":
        rendered = f"to_char({inner} AT TIME ZONE 'UTC', '{PG_TS_FORMAT}')"
    else:
        rendered = f"to_char({inner}, '{PG_TS_FORMAT}')"
    return (f"CASE WHEN isfinite({inner}) THEN {rendered} "
            f"ELSE ({inner})::text END")


def pg_fingerprint_sql(schema, table, spec):
    """One row, one JSON cell: SELECT row_to_json(x) FROM (SELECT ...) x,
    on a single line. Aliases are positional (c<i>__<metric>, i the
    entry's index in spec) because PostgreSQL truncates an identifier to
    63 bytes silently, and <column>__<metric> would lose the metric for
    a long column name; expand_pg_aliases maps them back."""
    q = bq_types.quote_pg
    parts = [f'count(*) AS {q("rows")}']
    for i, e in enumerate(spec):
        col = q(e["column"])

        def alias(metric, i=i):
            return q(f"c{i}__{metric}")

        nonnull = f"{_pg_nonnull_expr(e, col)} AS {alias('nonnull')}"
        cls = e["class"]
        if cls == "number":
            parts += [nonnull, f"{_pg_sum_expr(e, col)} AS {alias('sum')}",
                      f"min({col}) AS {alias('min')}",
                      f"max({col}) AS {alias('max')}"]
        elif cls == "string":
            expr = _pg_string_expr(e, col)
            parts += [nonnull,
                      f"sum(length({expr})) AS {alias('len_sum')}",
                      f'min({expr} COLLATE "C") AS {alias("min")}',
                      f'max({expr} COLLATE "C") AS {alias("max")}']
        elif cls == "bool":
            parts += [nonnull,
                      f"count(*) FILTER (WHERE {col}) AS {alias('true_count')}"]
        elif cls == "temporal":
            parts += [nonnull,
                      f"{_pg_temporal_expr('min', e, col)} AS {alias('min')}",
                      f"{_pg_temporal_expr('max', e, col)} AS {alias('max')}"]
        elif _is_array(e):
            parts.append(f"count(*) FILTER (WHERE cardinality({col}) > 0) "
                         f"AS {alias('nonempty')}")
        elif _is_bytes(e):
            parts += [nonnull,
                      f"sum(octet_length({col})) AS {alias('len_sum')}"]
        else:
            parts.append(nonnull)
    return (f"SELECT row_to_json(x) FROM (SELECT {', '.join(parts)} "
            f"FROM {q(schema)}.{q(table)}) x")


def expand_pg_aliases(positional, spec):
    """The flat <column>__<metric> dict from a row keyed by the
    positional aliases pg_fingerprint_sql emits for spec. A key the row
    lacks is left out, never invented."""
    out = {}
    if "rows" in positional:
        out["rows"] = positional["rows"]
    for i, e in enumerate(spec):
        for metric in metrics_for(e):
            key = f"c{i}__{metric}"
            if key in positional:
                out[f"{e['column']}__{metric}"] = positional[key]
    return out


def chunk_spec(spec, budget=SQL_BUDGET, max_entries=MAX_ENTRIES,
               schema="x" * 63, table="x" * 63):
    """Split spec into runs whose pg_fingerprint_sql text stays within
    budget characters and max_entries target list entries (the row
    count included). A single entry always forms a run of its own when
    nothing else fits. Empty spec, empty list."""
    chunks = []
    current = []
    for entry in spec:
        candidate = current + [entry]
        entries = 1 + sum(len(metrics_for(e)) for e in candidate)
        sql = pg_fingerprint_sql(schema, table, candidate)
        if current and (len(sql) > budget or entries > max_entries):
            chunks.append(current)
            current = [entry]
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def _bq_ident(name):
    if "`" in str(name):
        raise ValueError(f"identifier {name!r} contains a backtick")
    return f"`{name}`"


def bq_fingerprint_sql(project, dataset, bq_name, spec):
    """One row of named columns for bq query --format=json."""
    for part in (project, dataset, bq_name):
        _bq_ident(part)
    parts = ["COUNT(*) AS `rows`"]
    for e in spec:
        name = e["column"]
        ref = _bq_ident(e.get("bq_column") or name)

        def alias(metric, name=name):
            return _bq_ident(f"{name}__{metric}")

        nonnull = f"COUNT({ref}) AS {alias('nonnull')}"
        cls = e["class"]
        if cls == "number":
            # INT64 sums overflow at 2^63; NUMERIC carries 38 digits and
            # PostgreSQL sums bigint into numeric as well.
            summed = (f"SUM(CAST({ref} AS NUMERIC))" if e["bq_type"] == "INT64"
                      else f"SUM({ref})")
            smallest = f"MIN({ref})"
            if e["bq_type"] == "FLOAT64":
                # BigQuery's MIN returns NaN when any input is NaN;
                # PostgreSQL's ignores NaN unless every value is NaN
                # (NaN sorts last there). MAX agrees on NaN already, so
                # it stands in for the all-NaN case.
                smallest = (f"IFNULL(MIN(IF(IS_NAN({ref}), NULL, {ref})), "
                            f"MAX({ref}))")
            parts += [nonnull, f"{summed} AS {alias('sum')}",
                      f"{smallest} AS {alias('min')}",
                      f"MAX({ref}) AS {alias('max')}"]
        elif cls == "string":
            parts += [nonnull, f"SUM(LENGTH({ref})) AS {alias('len_sum')}",
                      f"MIN({ref}) AS {alias('min')}",
                      f"MAX({ref}) AS {alias('max')}"]
        elif cls == "bool":
            parts += [nonnull, f"COUNTIF({ref}) AS {alias('true_count')}"]
        elif cls == "temporal":
            if e["bq_type"] == "DATE":
                fn, fmt = "FORMAT_DATE", BQ_DATE_FORMAT
            elif e["bq_type"] == "TIMESTAMP":
                fn, fmt = "FORMAT_TIMESTAMP", BQ_TS_FORMAT
            else:
                fn, fmt = "FORMAT_DATETIME", BQ_TS_FORMAT
            parts += [nonnull,
                      f"{fn}('{fmt}', MIN({ref})) AS {alias('min')}",
                      f"{fn}('{fmt}', MAX({ref})) AS {alias('max')}"]
        elif _is_array(e):
            parts.append(f"COUNTIF(ARRAY_LENGTH({ref}) > 0) "
                         f"AS {alias('nonempty')}")
        elif _is_bytes(e):
            # LENGTH over BYTES counts bytes, as octet_length does.
            parts += [nonnull, f"SUM(LENGTH({ref})) AS {alias('len_sum')}"]
        else:
            parts.append(nonnull)
    return (f"SELECT {', '.join(parts)} FROM "
            f"`{project}.{dataset}.{bq_name}`")


# ------------------------------------------------------- canonical forms

def canonical_number(value):
    """Decimal-normalized text: no exponent, no trailing zeros, no -0."""
    if value is None:
        return None
    if isinstance(value, bool):
        value = int(value)
    try:
        d = decimal.Decimal(str(value).strip())
    except (decimal.InvalidOperation, ValueError):
        raise ValueError(f"not a number: {value!r}")
    if d.is_nan():
        return "NaN"
    if d.is_infinite():
        return "Infinity" if d > 0 else "-Infinity"
    if d == 0:
        return "0"
    return format(d.normalize(context=_CTX), "f")


def infinite_temporal(text):
    """'infinity' or '-infinity' for PostgreSQL's infinite date and
    timestamp renderings (any case, surrounding space allowed), else
    None."""
    m = INFINITY_RE.match(str(text).strip())
    if not m:
        return None
    return f"{m.group(1)}infinity"


def parse_temporal(text):
    """(naive datetime, utc offset or None, had_time) for the renderings
    PostgreSQL, BigQuery, and NDJSON use: 2025-01-01T00:00:00+00:00,
    ...Z, 2025-01-01 00:00:00 UTC, ...+00, ...+0530, ...-05:50:36, a
    fraction of up to nine digits (kept to six), or a bare date."""
    m = TEMPORAL_RE.match(str(text).strip())
    if not m:
        raise ValueError(f"not a date or timestamp: {text!r}")
    year, month, day, hour, minute, second, frac, zone = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    dt = datetime(int(year), int(month), int(day), int(hour or 0),
                  int(minute or 0), int(second or 0), micro)
    offset = None
    if zone:
        z = zone.upper()
        if z in ("Z", "UTC"):
            offset = timedelta(0)
        else:
            digits = z[1:].replace(":", "")
            offset = timedelta(hours=int(digits[:2]),
                               minutes=int(digits[2:4] or 0),
                               seconds=int(digits[4:6] or 0))
            if z[0] == "-":
                offset = -offset
    return dt, offset, hour is not None


def utc_datetime(text):
    """The naive UTC datetime a rendering denotes."""
    dt, offset, _ = parse_temporal(text)
    if offset is None:
        return dt
    try:
        return dt - offset
    except OverflowError:
        raise ValueError(
            f"timestamp {text!r} is out of range once converted to UTC")


def canonical_temporal(value, bq_type):
    """YYYY-MM-DDTHH:MM:SS.ffffff in UTC, or YYYY-MM-DD for DATE;
    'infinity' and '-infinity' pass through as themselves."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"temporal value is not text: {value!r}")
    infinite = infinite_temporal(value)
    if infinite:
        return infinite
    return _render_temporal(utc_datetime(value), bq_type)


def _canonical(entry, metric, value):
    if value is None:
        return None
    if metric in ("nonnull", "nonempty", "len_sum", "true_count", "sum"):
        return canonical_number(value)
    cls = entry["class"]
    if cls == "number":
        return canonical_number(value)
    if cls == "temporal":
        return canonical_temporal(value, entry["bq_type"])
    return value if isinstance(value, str) else str(value)


def normalize(raw, spec):
    """{"rows": "N", "columns": {col: {metric: canonical}}} from the flat
    dict either engine returns. A metric the raw dict lacks is left out
    so compare() reports it rather than inventing a value."""
    out = {"rows": canonical_number(raw.get("rows")), "columns": {}}
    for e in spec:
        col = e["column"]
        metrics = {}
        for metric in metrics_for(e):
            key = f"{col}__{metric}"
            if key in raw:
                metrics[metric] = _canonical(e, metric, raw[key])
        out["columns"][col] = metrics
    return out


# ----------------------------------------------------- pure Python path

def _to_decimal(value):
    if isinstance(value, bool):
        value = int(value)
    return decimal.Decimal(str(value).strip())


def _add(total, d):
    """Decimal addition with PostgreSQL's float semantics for the edges:
    a NaN total stays NaN, and opposite infinities make NaN instead of
    signaling."""
    if total is None:
        return d
    if total.is_nan():
        return total
    if total.is_infinite() and d.is_infinite() and total != d:
        return decimal.Decimal("NaN")
    return total + d


def _accumulate(acc, entry, value):
    if value is None:
        return
    cls = entry["class"]
    if cls == "number":
        d = _to_decimal(value)
        acc["nonnull"] += 1
        if d.is_nan():
            acc["nan"] = True
            return
        acc["sum"] = _add(acc["sum"], d)
        acc["min"] = d if acc["min"] is None else min(acc["min"], d)
        acc["max"] = d if acc["max"] is None else max(acc["max"], d)
    elif cls == "string":
        s = value if isinstance(value, str) else str(value)
        acc["nonnull"] += 1
        acc["len_sum"] += len(s)
        key = s.encode("utf-8")
        if acc["min"] is None or key < acc["min"][0]:
            acc["min"] = (key, s)
        if acc["max"] is None or key > acc["max"][0]:
            acc["max"] = (key, s)
    elif cls == "bool":
        acc["nonnull"] += 1
        truth = value if isinstance(value, bool) else \
            str(value).strip().lower() == "true"
        if truth:
            acc["true_count"] += 1
    elif cls == "temporal":
        acc["nonnull"] += 1
        infinite = infinite_temporal(value)
        if infinite == "infinity":
            acc["pos_inf"] = True
            return
        if infinite == "-infinity":
            acc["neg_inf"] = True
            return
        dt = utc_datetime(value)
        acc["min"] = dt if acc["min"] is None else min(acc["min"], dt)
        acc["max"] = dt if acc["max"] is None else max(acc["max"], dt)
    elif _is_array(entry):
        if not isinstance(value, list) or value:
            acc["nonempty"] += 1
    elif _is_bytes(entry):
        # The export carries bytea as unbroken base64; the decoded
        # length is what octet_length and BigQuery's LENGTH report.
        acc["nonnull"] += 1
        text = value if isinstance(value, str) else str(value)
        acc["len_sum"] += len(base64.b64decode(text, validate=True))
    else:
        acc["nonnull"] += 1


def _render_temporal(dt, bq_type):
    if dt is None:
        return None
    date = f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
    if bq_type == "DATE":
        return date
    return (f"{date}T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
            f".{dt.microsecond:06d}")


def _render_number(acc, metric):
    """NaN sorts above every number on PostgreSQL: one NaN makes the sum
    and the maximum NaN, and the minimum only when nothing else is
    there."""
    if metric == "min":
        if acc["min"] is not None:
            return canonical_number(acc["min"])
        return "NaN" if acc["nan"] else None
    if acc["nan"]:
        return "NaN"
    return canonical_number(acc[metric])


def _render_temporal_metric(acc, metric, bq_type):
    if metric == "min":
        if acc["neg_inf"]:
            return "-infinity"
        if acc["min"] is not None:
            return _render_temporal(acc["min"], bq_type)
        return "infinity" if acc["pos_inf"] else None
    if acc["pos_inf"]:
        return "infinity"
    if acc["max"] is not None:
        return _render_temporal(acc["max"], bq_type)
    return "-infinity" if acc["neg_inf"] else None


def fingerprint_from_rows(rows, spec):
    """The flat metric dict over parsed NDJSON rows (numbers as int or
    float, temporal values as ISO text, booleans as bool). Sums use
    Decimal over the JSON text so they never drift; string order is by
    UTF-8 bytes, which matches COLLATE "C" and BigQuery's binary order;
    len_sum counts characters. Used by the emulated backend."""
    accs = {}
    for e in spec:
        accs[e["column"]] = {"nonnull": 0, "nonempty": 0, "len_sum": 0,
                             "true_count": 0, "sum": None, "min": None,
                             "max": None, "nan": False, "pos_inf": False,
                             "neg_inf": False}
    n = 0
    with decimal.localcontext(_CTX):
        for row in rows:
            n += 1
            for e in spec:
                value = row.get(e.get("bq_column") or e["column"])
                _accumulate(accs[e["column"]], e, value)
    raw = {"rows": n}
    for e in spec:
        col = e["column"]
        acc = accs[col]
        cls = e["class"]
        for metric in metrics_for(e):
            key = f"{col}__{metric}"
            if metric in ("nonnull", "nonempty", "true_count"):
                raw[key] = acc[metric]
            elif metric == "len_sum":
                raw[key] = acc["len_sum"] if acc["nonnull"] else None
            elif cls == "number":
                raw[key] = _render_number(acc, metric)
            elif cls == "string":
                raw[key] = None if acc[metric] is None else acc[metric][1]
            else:
                raw[key] = _render_temporal_metric(acc, metric, e["bq_type"])
    return raw


# --------------------------------------------------------------- compare

def _values_match(left, right, tolerant, rel_tol):
    if left == right:
        return True
    if left is None or right is None or MISSING in (left, right):
        return False
    if not tolerant:
        return False
    try:
        a, b = float(left), float(right)
    except (TypeError, ValueError):
        return False
    if math.isnan(a) and math.isnan(b):
        return True
    return math.isclose(a, b, rel_tol=rel_tol)


def compare(left, right, spec, float_rel_tol=1e-9):
    """{"match": bool, "mismatches": [{"column", "metric", "left",
    "right"}]} over two normalized fingerprints. FLOAT64 sums, minima,
    and maxima compare within float_rel_tol; everything else exactly.
    Without a spec every metric present on either side compares
    exactly. The row count is reported under column "*"."""
    mismatches = []
    lrows, rrows = left.get("rows"), right.get("rows")
    if not _values_match(lrows, rrows, False, 0):
        mismatches.append({"column": "*", "metric": "rows",
                           "left": lrows, "right": rrows})
    lcols = left.get("columns") or {}
    rcols = right.get("columns") or {}
    if spec is None:
        pairs = []
        for col in sorted(set(lcols) | set(rcols)):
            seen = list(lcols.get(col, {}))
            seen += [m for m in rcols.get(col, {}) if m not in seen]
            pairs += [(col, m, False) for m in seen]
    else:
        pairs = [(e["column"], m,
                  e.get("bq_type") == "FLOAT64" and m != "nonnull")
                 for e in spec for m in metrics_for(e)]
    for col, metric, tolerant in pairs:
        lv = lcols.get(col, {}).get(metric, MISSING)
        rv = rcols.get(col, {}).get(metric, MISSING)
        if not _values_match(lv, rv, tolerant, float_rel_tol):
            mismatches.append({"column": col, "metric": metric,
                               "left": lv, "right": rv})
    return {"match": not mismatches, "mismatches": mismatches}


# ---------------------------------------------- source fingerprint path

def run_source_sql(ci, sql):
    """psql's stdout for one read-only statement delivered over stdin
    (psql -f -). A -c argument would hit the 32767 character command
    line cap on Windows, where psql also receives argv in the ANSI code
    page; stdin carries UTF-8 of any length. Raises pg.PgError with the
    first 800 characters of psql's stderr (never the password)."""
    argv = ([pg.find_bin("psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1",
             "-A", "-t"] + pg.conn_argv(ci) + ["-f", "-"])
    try:
        proc = subprocess.run(argv, input=sql,
                              env=pg.build_env(ci, readonly=True),
                              capture_output=True, encoding="utf-8")
    except OSError as exc:
        raise pg.PgError(f"psql could not start: {exc}")
    if proc.returncode != 0:
        raise pg.PgError(f"psql failed ({proc.returncode}): "
                         f"{(proc.stderr or '').strip()[:800]}")
    return proc.stdout


def pg_table_fingerprint(ci, schema, table, spec):
    """The flat <column>__<metric> dict for one source table, batched
    through chunk_spec and parsed with Decimal so NUMERIC sums keep
    every digit. The single JSON row is parsed whole (str.splitlines
    would cut it at U+2028 and friends inside a string value). The
    batches must agree on the row count, otherwise the table was
    changing underneath and the fingerprint is refused."""
    raw = {}
    rows = None
    for chunk in chunk_spec(spec, schema=schema, table=table) or [[]]:
        sql = pg_fingerprint_sql(schema, table, chunk)
        out = (run_source_sql(ci, sql) or "").strip()
        try:
            positional = json.loads(out, parse_float=decimal.Decimal)
        except ValueError as exc:
            raise ValidateError(
                f"fingerprint query for {schema}.{table} returned no JSON "
                f"row: {exc}")
        if not isinstance(positional, dict):
            raise ValidateError(
                f"fingerprint query for {schema}.{table} returned no JSON "
                "row: not a JSON object")
        part = expand_pg_aliases(positional, chunk)
        if rows is None:
            rows = part.get("rows")
        elif part.get("rows") != rows:
            raise ValidateError(
                f"{schema}.{table} changed while it was being fingerprinted "
                f"({rows} rows, then {part.get('rows')}); rerun when the "
                "source is quiet")
        raw.update(part)
    return raw


# ------------------------------------------------------------------- CLI

def _load_json(path, what):
    path = Path(path)
    if not path.exists():
        raise ValidateError(f"no {what} at {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def table_fingerprints(side, targets, inventory, ci=None, backend=None):
    """{"schema.table": normalized fingerprint plus spec, side, mode}.
    Source fingerprints run pg_fingerprint_sql read-only; target
    fingerprints go through backend.query_fingerprint (the live backend
    runs bq_fingerprint_sql through bq query, the emulated backend
    computes fingerprint_from_rows over the loaded NDJSON)."""
    by_table = bq_load.columns_by_table(inventory)
    doc = {}
    for t in targets:
        key = f"{t['schema']}.{t['name']}"
        columns = by_table.get((t["schema"], t["name"]))
        if not columns:
            raise ValidateError(f"no columns in the inventory for {key}")
        columns = bq_load.alias_columns(columns, t.get("fields"))
        spec = fingerprint_spec(columns)
        aliases = {c["name"]: c.get("bq_name") for c in columns}
        for e in spec:
            alias = aliases.get(e["column"])
            if alias and alias != e["column"]:
                e["bq_column"] = alias
        if side == "source":
            raw = pg_table_fingerprint(ci, t["schema"], t["name"], spec)
            mode = "postgres"
        else:
            raw = backend.query_fingerprint(t["dataset"], t["bq_name"], spec)
            mode = backend.mode
        entry = normalize(raw, spec)
        entry["spec"] = spec
        entry["side"] = side
        entry["mode"] = mode
        doc[key] = entry
    return doc


def compare_documents(left, right):
    """Table by table comparison of two fingerprint files; a table
    present on one side only is listed as missing."""
    for label, doc in (("left", left), ("right", right)):
        if not isinstance(doc, dict):
            raise ValidateError(
                f"{label} file must be a JSON mapping of table names to "
                "fingerprints")
    report = {"match": True, "tables": {},
              "missing_in_left": sorted(set(right) - set(left)),
              "missing_in_right": sorted(set(left) - set(right))}
    for table in sorted(set(left) & set(right)):
        spec = left[table].get("spec") or right[table].get("spec")
        result = compare(left[table], right[table], spec)
        report["tables"][table] = result
        if not result["match"]:
            report["match"] = False
    if report["missing_in_left"] or report["missing_in_right"]:
        report["match"] = False
    return report


def _write_json(path, doc):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def main(argv):
    bq_load.tolerant_console()
    parser = argparse.ArgumentParser(prog="dbcarry.py bq-validate")
    parser.add_argument("--root", default=".",
                        help="project root holding migrations/")
    parser.add_argument("--migration", default=None)
    sub = parser.add_subparsers(dest="verb", required=True)
    fp = sub.add_parser("fingerprint",
                        help="fingerprint every table on one side")
    fp.add_argument("--side", choices=("source", "target"), required=True)
    fp.add_argument("--table", default=None,
                    help="schema.name; default every table")
    fp.add_argument("--out", required=True)
    fp.add_argument("--root", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    fp.add_argument("--migration", default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS)
    cp = sub.add_parser("compare", help="compare two fingerprint files")
    cp.add_argument("--left", required=True)
    cp.add_argument("--right", required=True)
    cp.add_argument("--out", default=None)
    args = parser.parse_args(argv[1:])
    try:
        if args.verb == "compare":
            report = compare_documents(_load_json(args.left, "left file"),
                                       _load_json(args.right, "right file"))
            # The file first, so a console that cannot encode a value
            # in a mismatch never loses the artifact; the console copy
            # escapes to ASCII for the same reason.
            if args.out:
                _write_json(args.out, report)
            print(json.dumps(report, indent=2, ensure_ascii=True))
            return 0 if report["match"] else 1
        if args.migration is None:
            parser.error("the following arguments are required: --migration")
        mig = config.load_migration(args.root, args.migration)
        bq_cfg = config.bigquery_config(mig, args.migration)
        ws = config.workspace(args.root, args.migration)
        inventory = _load_json(ws / "artifacts" / "inventory.json",
                               "inventory (run inventory first)")
        plan_path = ws / "artifacts" / "schema-plan.json"
        schema_plan = _load_json(plan_path, "schema plan") \
            if plan_path.exists() else None
        targets = bq_load.table_targets(schema_plan, inventory, bq_cfg)
        if args.table:
            targets = [t for t in targets
                       if f"{t['schema']}.{t['name']}" == args.table]
            if not targets:
                raise ValidateError(
                    f"table {args.table} is not in the schema plan or "
                    "inventory")
        if args.side == "source":
            doc = table_fingerprints("source", targets, inventory,
                                     ci=config.source_conn(mig))
        else:
            backend = bq_backend.make_backend(bq_cfg, args.migration, ws)
            doc = table_fingerprints("target", targets, inventory,
                                     backend=backend)
        _write_json(args.out, doc)
        for key, entry in doc.items():
            print(f"{key}: rows={entry['rows']} ({entry['mode']})")
        print(f"wrote {args.out} ({len(doc)} tables)")
        return 0
    except (ValidateError, config.ConfigError, pg.PgError,
            bq_backend.BackendError) as exc:
        print(f"BQ-VALIDATE ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError,
            ArithmeticError) as exc:
        print(f"BQ-VALIDATE ERROR: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(["bq-validate"] + sys.argv[1:]))

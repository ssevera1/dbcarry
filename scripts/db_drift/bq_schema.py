"""BigQuery schema translation, apply, and verification.

translate_schema turns the v0.2.0 inventory (columns, keys, view
definitions, view dependencies) into a plan: one CREATE TABLE per table,
a load schema per table, one view statement per view, and a findings
list for everything BigQuery cannot carry. The render functions turn the
plan into the apply scripts under artifacts/bq-apply/. apply_schema
drives a Backend (emulated or live) through the same steps, and
verify_schema reads the target back and compares it with the plan.

Rules (spec section 9.3):

- CREATE TABLE IF NOT EXISTS with NOT NULL preserved, primary and foreign
  keys as NOT ENFORCED constraints, CLUSTER BY on up to four primary key
  columns, and a description naming the source table.
- A primary key survives only when BigQuery accepts it: every column of
  a key type (KEY_TYPES), none repeated, at most MAX_KEY_COLUMNS columns.
  Otherwise it is dropped with a WARNING. CLUSTER BY uses the key columns
  BigQuery can cluster on (CLUSTER_TYPES), with a NOTE for the skipped
  ones, and stands even when the key constraint itself is dropped.
- A foreign key survives only when it points at the referenced table's
  surviving primary key (BigQuery has no other reference target); a key
  into a UNIQUE column set, into a table whose key was dropped, or into
  its own table is dropped with a WARNING.
- Tables are ordered so a referenced table exists before the foreign key
  that points at it. A cycle drops one constraint on the cycle, with a
  WARNING that says how to add it afterwards; tables outside the cycle
  keep their constraints.
- Indexes, sequences, and column defaults are dropped with findings. An
  identity column is reported when the inventory carries is_identity;
  information_schema reports no column_default for it, so an inventory
  without that field shows the identity only through its sequence.
  UNIQUE, CHECK, and EXCLUDE constraints are counted in one INFO.
- Views go through bq_predicate.translate with every table, view, and
  materialized view of the migration in the context, so a view over a
  view resolves. A bare name resolves first through the view's own
  dependency rows, then through the global map (public wins). A review
  result blocks apply until artifacts/translation-resolutions.json
  resolves it; a resolution must be one SELECT (or WITH) statement.
- Materialized views stay materialized only when the translation is auto
  and the body has none of ORDER BY, LIMIT, HAVING, a set operation,
  a window function or WINDOW clause, a non-deterministic function
  (CURRENT_TIMESTAMP, SESSION_USER, RAND, and the like), or a view
  reference; otherwise they become regular views with a WARNING.

Identifiers: datasets, tables, and columns are sanitized to
[A-Za-z0-9_] (a NOTE per rename, an error per collision; column
collisions are case-insensitive, as BigQuery column names are). A column
whose name is a BigQuery reserved keyword is backticked in DDL only; the
load schema keeps the bare name, which is what bq expects.
"""
import argparse
import json
import re
import sys
from pathlib import Path

from db_drift import bq_backend, bq_predicate, bq_types, config

MAX_CLUSTER_COLUMNS = 4
MAX_KEY_COLUMNS = 16
DESCRIPTION = "migrated from {source} by db-drift"

# Types BigQuery accepts in a primary or foreign key, and the types it
# can cluster on (a top-level, non-repeated column in either case).
KEY_TYPES = {"BIGNUMERIC", "BOOL", "BYTES", "DATE", "DATETIME", "INT64",
             "NUMERIC", "STRING", "TIMESTAMP"}
CLUSTER_TYPES = {"BIGNUMERIC", "BOOL", "DATE", "DATETIME", "GEOGRAPHY",
                 "INT64", "NUMERIC", "RANGE", "STRING", "TIMESTAMP"}

# Constructs a BigQuery materialized view body cannot hold. Set
# operations and named windows are keywords; the functions count only
# when called, so a column that happens to be named rand is fine.
MATVIEW_SET_OPERATIONS = {"UNION", "INTERSECT", "EXCEPT"}
MATVIEW_NONDETERMINISTIC = {"CURRENT_TIMESTAMP", "CURRENT_DATE",
                            "CURRENT_DATETIME", "CURRENT_TIME",
                            "SESSION_USER", "RAND", "GENERATE_UUID"}

PLAN_FILE = "schema-plan.json"
APPLIED_FILE = "schema-applied.json"
VERIFY_FILE = "schema-verify.json"
REVIEW_FILE = "translation-review.json"
RESOLUTIONS_FILE = "translation-resolutions.json"
APPLY_DIR = "bq-apply"
DATASETS_SCRIPT = "10-datasets.sh"
TABLES_SCRIPT = "20-tables.sql"

# BigQuery reserved keywords (GoogleSQL lexical structure). A column with
# one of these names needs backticks in DDL.
BQ_RESERVED = {
    "ALL", "AND", "ANY", "ARRAY", "AS", "ASC", "ASSERT_ROWS_MODIFIED", "AT",
    "BETWEEN", "BY", "CASE", "CAST", "COLLATE", "CONTAINS", "CREATE",
    "CROSS", "CUBE", "CURRENT", "DEFAULT", "DEFINE", "DESC", "DISTINCT",
    "ELSE", "END", "ENUM", "ESCAPE", "EXCEPT", "EXCLUDE", "EXISTS",
    "EXTRACT", "FALSE", "FETCH", "FOLLOWING", "FOR", "FROM", "FULL", "GROUP",
    "GROUPING", "GROUPS", "HASH", "HAVING", "IF", "IGNORE", "IN", "INNER",
    "INTERSECT", "INTERVAL", "INTO", "IS", "JOIN", "LATERAL", "LEFT", "LIKE",
    "LIMIT", "LOOKUP", "MERGE", "NATURAL", "NEW", "NO", "NOT", "NULL",
    "NULLS", "OF", "ON", "OR", "ORDER", "OUTER", "OVER", "PARTITION",
    "PRECEDING", "PROTO", "QUALIFY", "RANGE", "RECURSIVE", "RESPECT",
    "RIGHT", "ROLLUP", "ROWS", "SELECT", "SET", "SOME", "STRUCT",
    "TABLESAMPLE", "THEN", "TO", "TREAT", "TRUE", "UNBOUNDED", "UNION",
    "UNNEST", "USING", "WHEN", "WHERE", "WINDOW", "WITH", "WITHIN",
}

# Characters allowed in the values the datasets script interpolates.
_SHELL_SAFE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_TRAILING_SEMICOLONS_RE = re.compile(r"[\s;]+$")


class SchemaError(Exception):
    pass


# ------------------------------------------------------------- helpers

def _finding(severity, code, subject, message, action):
    return {"severity": severity, "code": code, "subject": subject,
            "message": message, "action": action}


def _ident(name):
    """A column name as DDL writes it: bare, or backticked when reserved."""
    return f"`{name}`" if name.upper() in BQ_RESERVED else name


def _strip_statement(text):
    """View body without leading whitespace or trailing semicolons."""
    return _TRAILING_SEMICOLONS_RE.sub("", (text or "").strip())


def _sql_string(text):
    """text as a BigQuery single-quoted string literal."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def field_for_column(column):
    """(load schema field, type notes) for one inventory column.

    The field carries the source column name; translate_schema replaces
    it with the sanitized BigQuery name. ARRAY<T> becomes type T with
    mode REPEATED, NOT NULL becomes REQUIRED, everything else NULLABLE.
    """
    bq_type, notes = bq_types.map_type(column)
    mode = "NULLABLE"
    if bq_type.startswith("ARRAY<") and bq_type.endswith(">"):
        bq_type = bq_type[len("ARRAY<"):-1]
        mode = "REPEATED"
    elif column.get("nullable") is False:
        mode = "REQUIRED"
    return {"name": column["name"], "type": bq_type, "mode": mode}, notes


def _column_ddl(field):
    type_text = field["type"]
    if field["mode"] == "REPEATED":
        type_text = f"ARRAY<{type_text}>"
    text = f"{_ident(field['name'])} {type_text}"
    if field["mode"] == "REQUIRED":
        text += " NOT NULL"
    return text


def _keys_for_table(source, pk, renamed, fields, findings):
    """(primary key columns, cluster columns) in BigQuery names.

    The key is kept whole or dropped whole: BigQuery wants every key
    column of a KEY_TYPES type, none repeated, and at most
    MAX_KEY_COLUMNS of them. Clustering takes the leading key columns
    of a CLUSTER_TYPES type, up to MAX_CLUSTER_COLUMNS, whether or not
    the key constraint survives.
    """
    if not pk:
        return [], []
    pk_cols = [renamed.get(c, c) for c in pk["columns"]]
    by_name = {f["name"]: f for f in fields}
    bad, cluster_by, skipped = [], [], []
    for name in pk_cols:
        f = by_name.get(name)
        if f is None:
            bad.append(f"{name} (not a column of the table)")
            skipped.append(name)
            continue
        repeated = f["mode"] == "REPEATED"
        shown = f"{name} ARRAY<{f['type']}>" if repeated else \
            f"{name} {f['type']}"
        if repeated or f["type"] not in KEY_TYPES:
            bad.append(shown)
        if repeated or f["type"] not in CLUSTER_TYPES:
            skipped.append(shown)
        elif len(cluster_by) < MAX_CLUSTER_COLUMNS:
            cluster_by.append(name)
    clustered = (f"the table is still clustered on {', '.join(cluster_by)}"
                 if cluster_by else "the table is not clustered")
    reason = None
    if len(pk_cols) > MAX_KEY_COLUMNS:
        reason = (f"BigQuery allows at most {MAX_KEY_COLUMNS} key columns "
                  f"and it has {len(pk_cols)}")
    elif bad:
        reason = (f"BigQuery key columns must be one of "
                  f"{', '.join(sorted(KEY_TYPES))}, and it has "
                  f"{', '.join(bad)}")
    if reason:
        findings.append(_finding(
            "WARNING", "primary_key_dropped", f"{source}.{pk['name']}",
            f"primary key {pk['name']} on ({', '.join(pk_cols)}) is not "
            f"migrated: {reason}; {clustered}",
            "none available; BigQuery keys are NOT ENFORCED anyway, so "
            "keep the uniqueness rule in the writer (foreign keys into "
            "this table are dropped too)"))
        return [], cluster_by
    if skipped:
        findings.append(_finding(
            "NOTE", "cluster_column_skipped", f"{source}.{pk['name']}",
            f"key columns {', '.join(skipped)} are not clustering columns "
            f"(BigQuery clusters on {', '.join(sorted(CLUSTER_TYPES))}); "
            + clustered.replace("still ", ""),
            "none needed"))
    return pk_cols, cluster_by


def _reaches(start, target, deps, done):
    """True when target is reachable from start along dependency edges
    through nodes that are not done yet."""
    stack, seen = [start], set()
    while stack:
        for dep in deps[stack.pop()]:
            if dep == target:
                return True
            if dep not in done and dep not in seen:
                seen.add(dep)
                stack.append(dep)
    return False


def _cycle_node(remaining, deps, done):
    """(name, back_edges) for the first remaining name that lies on a
    cycle; back_edges are its unmet dependencies that lead back to it.
    When nothing is ready every remaining name has an unmet dependency
    among the remaining names, so a finite graph must hold a cycle."""
    for name in remaining:
        back = [dep for dep in sorted(deps[name] - done)
                if dep == name or _reaches(dep, name, deps, done)]
        if back:
            return name, back
    first = remaining[0]
    return first, sorted(deps[first] - done)


def _topological(names, edges, on_cycle):
    """Order names so every (name, dependency) edge has the dependency
    first. Ties keep the input order. When nothing is ready (a cycle),
    the first remaining name on a cycle is picked and on_cycle(name,
    unmet) receives the dependencies that lead back to it; those edges
    are dropped and ordering goes on, so a name outside the cycle keeps
    every dependency and a cycle costs one edge per lap."""
    deps = {n: set() for n in names}
    for name, dep in edges:
        if name in deps and dep in deps:
            deps[name].add(dep)
    remaining = list(names)
    done = set()
    ordered = []
    while remaining:
        for candidate in remaining:
            if deps[candidate] <= done:
                ordered.append(candidate)
                done.add(candidate)
                remaining.remove(candidate)
                break
        else:
            pick, back = _cycle_node(remaining, deps, done)
            on_cycle(pick, list(back))
            deps[pick] -= set(back)
    return ordered


def _matview_blocker(sql, confidence, base_views):
    """Why a materialized view must become a regular view, or None."""
    if confidence != "auto":
        return (f"its translation has confidence {confidence}, and only an "
                "auto translation is trusted to satisfy BigQuery's "
                "materialized view restrictions")
    if base_views:
        return ("it reads the view " + ", ".join(base_views) + ", and a "
                "BigQuery materialized view can only read base tables")
    try:
        tokens = bq_backend.tokenize_sql(sql)
    except bq_backend.SqlSyntaxError:
        return "its body could not be tokenized for the construct check"
    words = [(t.text.upper() if t.kind == "word" else None, t) for t in tokens]
    for idx, (word, _) in enumerate(words):
        if word is None:
            continue
        prev = tokens[idx - 1] if idx else None
        if prev is not None and prev.kind == "punct" and prev.text == ".":
            continue  # a qualified column reference, whatever its name
        nxt_word, nxt = words[idx + 1] if idx + 1 < len(words) else (None, None)
        calls = nxt is not None and nxt.kind == "punct" and nxt.text == "("
        if word == "ORDER" and nxt_word == "BY":
            return "its body has ORDER BY"
        if word == "LIMIT":
            return "its body has LIMIT"
        if word == "HAVING":
            return "its body has HAVING"
        if word in MATVIEW_SET_OPERATIONS:
            return f"its body has a set operation ({word})"
        if word == "WINDOW":
            return "its body has a named window (WINDOW clause)"
        if word == "OVER" and (calls or nxt_word is not None):
            return "its body has a window function (OVER)"
        if word in MATVIEW_NONDETERMINISTIC and calls:
            return f"its body calls the non-deterministic function {word}()"
    return None


def _resolved_body(source, res):
    """The resolved body for a view from its translation-resolutions.json
    entry, or None when the entry carries no sql.

    Raises SchemaError for a malformed entry and for a body that is not
    exactly one SELECT (or WITH) statement: the live backend hands the
    text to bq query, which runs scripts, so a stray semicolon would
    execute whatever follows it.
    """
    where = f"{RESOLUTIONS_FILE} entry for {source}"
    if not isinstance(res, dict):
        raise SchemaError(f"{where} must be an object with sql and "
                          f"rationale, not {type(res).__name__}")
    sql = res.get("sql")
    if sql is None:
        return None
    if not isinstance(sql, str):
        raise SchemaError(f"{where}: sql must be a string, not "
                          f"{type(sql).__name__}")
    sql = _strip_statement(sql)
    if not sql:
        return None
    try:
        statements = bq_backend.split_statements(sql)
    except bq_backend.SqlSyntaxError as exc:
        raise SchemaError(f"{where}: the sql cannot be tokenized ({exc})")
    if len(statements) != 1:
        raise SchemaError(f"{where}: sql must be one SELECT statement, "
                          f"not {len(statements)} statements")
    tokens = statements[0][1]
    idx = 0
    while idx < len(tokens) and tokens[idx].kind == "punct" \
            and tokens[idx].text == "(":
        idx += 1
    if idx >= len(tokens) or tokens[idx].kind != "word" \
            or tokens[idx].text.upper() not in ("SELECT", "WITH"):
        raise SchemaError(f"{where}: sql must be a SELECT or WITH query "
                          f"body, not {sql[:40]!r}")
    return sql


def _normalize_ws(text):
    return " ".join(str(text or "").split())


def _resolution_problem(source, kind, res, rationale, source_sql):
    """Why a recorded view resolution cannot be applied, as (code,
    message, action), or None when it can. A resolution needs a
    rationale (Gate 1 shows it) and, when the sql-translator recorded
    the source_sql it worked from, that text must still be the view's
    definition up to whitespace; otherwise the view stays at review."""
    if not rationale:
        return ("view_resolution_unjustified",
                f"the resolution for {kind} {source} has no rationale; "
                "the view stays at review",
                "have the sql-translator state why the body keeps the "
                "source semantics")
    recorded = res.get("source_sql")
    if recorded is not None and _normalize_ws(_strip_statement(
            str(recorded))) != _normalize_ws(source_sql):
        return ("view_resolution_stale",
                f"the resolution for {kind} {source} was written against "
                f"the definition {_normalize_ws(recorded)}, but the source "
                f"now has {_normalize_ws(source_sql)}; the view stays at "
                "review",
                "re-run the sql-translator against the current review file")
    return None


def _view_ddl(qualified, sql, materialized):
    head = ("CREATE MATERIALIZED VIEW IF NOT EXISTS" if materialized
            else "CREATE OR REPLACE VIEW")
    return f"{head} {qualified} AS\n{sql};"


# --------------------------------------------------------- translation

def translate_schema(inventory, bq_cfg, resolutions=None):
    """Build the schema plan from an inventory and the bigquery config.

    Pure: writes nothing. resolutions is the parsed
    translation-resolutions.json ({"views": {"schema.name": {"sql",
    "rationale"}}, ...}); a view listed there takes the resolved body
    and confidence "resolved". Raises SchemaError when the inventory
    lacks the v0.2.0 sections, when sanitized names collide, or when
    views depend on each other in a cycle.
    """
    view_res = (resolutions or {}).get("views") or {}
    project = bq_cfg.get("project") or config.BQ_DEFAULTS["project"]
    location = bq_cfg.get("location") or config.BQ_DEFAULTS["location"]
    dataset_map = bq_cfg.get("dataset_map") or {}
    dbname = bq_cfg.get("dbname") or "public"
    findings = []

    # 1. Every relation gets a dataset and a sanitized target name.
    relations = [(t["schema"], t["name"], "table")
                 for t in inventory.get("tables", [])]
    for key, kind in (("views", "view"), ("matviews", "matview")):
        for full in inventory.get(key, []):
            schema, _, name = full.partition(".")
            relations.append((schema, name, kind))
    dataset_schemas = {}
    used = {}
    targets = {}
    for schema, name, kind in relations:
        raw_dataset = dataset_map[schema] if schema in dataset_map \
            else (dbname if schema == "public" else schema)
        dataset = bq_types.dataset_for(schema, dataset_map, dbname)
        if dataset != str(raw_dataset) and dataset not in dataset_schemas:
            findings.append(_finding(
                "NOTE", "identifier_renamed", schema,
                f"dataset {raw_dataset!r} renamed to {dataset!r} for "
                "BigQuery ([A-Za-z0-9_] only)",
                "none needed; the plan uses the renamed dataset"))
        schemas = dataset_schemas.setdefault(dataset, [])
        if schema not in schemas:
            schemas.append(schema)
        bq_name, note = bq_types.sanitize_identifier(name)
        source = f"{schema}.{name}"
        if note:
            findings.append(_finding(
                "NOTE", "identifier_renamed", source, note,
                "none needed; the plan and the load use the renamed "
                "table"))
        key = (dataset, bq_name)
        if key in used:
            raise SchemaError(
                f"{dataset}.{bq_name} would be created twice, from "
                f"{used[key]} and {source}; change dataset_map or rename "
                "one of them")
        used[key] = source
        targets[source] = {"schema": schema, "name": name, "kind": kind,
                           "dataset": dataset, "bq_name": bq_name,
                           "qualified": bq_types.qualified(
                               project, dataset, bq_name)}

    datasets = {}
    for dataset in sorted(dataset_schemas):
        schemas = dataset_schemas[dataset]
        entry = {"source_schema": schemas[0]}
        if len(schemas) > 1:
            entry["source_schemas"] = list(schemas)
        datasets[dataset] = entry

    # Table context for the translator: bare and schema-qualified names.
    # With a bare name in several schemas, public wins, then the first.
    context_tables = {}
    for source in sorted(targets, key=lambda s: (
            not s.startswith("public."), list(targets).index(s))):
        info = targets[source]
        context_tables[source] = info["qualified"]
        context_tables.setdefault(info["name"], info["qualified"])

    # 2. Columns and keys by table.
    columns_by_table = {}
    for c in inventory.get("columns", []):
        columns_by_table.setdefault(f"{c['schema']}.{c['table']}", []).append(c)
    for cols in columns_by_table.values():
        cols.sort(key=lambda c: c.get("ordinal", 0))
    pk_by_table = {f"{p['schema']}.{p['table']}": p
                   for p in inventory.get("primary_keys", [])}
    fks_by_table = {}
    for fk in inventory.get("foreign_keys", []):
        fks_by_table.setdefault(f"{fk['schema']}.{fk['table']}", []).append(fk)

    # 3. Tables: fields, renames, keys (rendering waits for the order).
    tables = {}
    has_column_rows = bool(inventory.get("columns"))
    for t in inventory.get("tables", []):
        source = f"{t['schema']}.{t['name']}"
        info = targets[source]
        cols = columns_by_table.get(source)
        if not cols and not has_column_rows:
            raise SchemaError(
                f"the inventory has no columns for {source}; re-run "
                "inventory with db-drift v0.2.0 or later (the columns, "
                "keys, and view sections are required)")
        if not cols:
            raise SchemaError(
                f"table {source} has no columns; BigQuery needs at least "
                "one column per table, so drop the empty table on the "
                "source or remove it from the inventory before translate")
        fields, renamed, seen = [], {}, {}
        for c in cols:
            field, type_notes = field_for_column(c)
            subject = f"{source}.{c['name']}"
            bq_col, note = bq_types.sanitize_identifier(c["name"])
            if note:
                renamed[c["name"]] = bq_col
                findings.append(_finding(
                    "NOTE", "identifier_renamed", subject, note,
                    "none needed; the export aliases the column to the "
                    "BigQuery name"))
            # BigQuery column names are case-insensitive.
            folded = bq_col.lower()
            if folded in seen:
                raise SchemaError(
                    f"column {bq_col} of {source} would be created twice, "
                    f"from {seen[folded]} and {c['name']} (BigQuery column "
                    "names are case-insensitive)")
            seen[folded] = c["name"]
            field["name"] = bq_col
            for text in type_notes:
                if "(WARNING)" in text:
                    findings.append(_finding(
                        "WARNING", "type_warning", subject, text,
                        "confirm the STRING mapping is acceptable or add "
                        "a cast in the export"))
                else:
                    findings.append(_finding(
                        "NOTE", "type_note", subject, text, "none needed"))
            if c.get("nullable") is False and field["mode"] == "REPEATED":
                findings.append(_finding(
                    "NOTE", "array_not_null_dropped", subject,
                    "BigQuery ARRAY columns cannot be NOT NULL; the "
                    "constraint is dropped (a missing array loads as "
                    "an empty one)",
                    "none needed"))
            default_action = ("generate the value in the writer (sequences "
                              "and identity columns have no BigQuery "
                              "equivalent)")
            # information_schema reports no column_default for an
            # identity column; an inventory that records is_identity
            # (YES or true) gets the finding through that field.
            identity = str(c.get("is_identity") or "").strip().upper()
            if identity in ("YES", "TRUE"):
                generation = str(c.get("identity_generation") or "").strip()
                findings.append(_finding(
                    "NOTE", "default_dropped", subject,
                    "the column is an identity column"
                    + (f" (GENERATED {generation} AS IDENTITY)"
                       if generation else "")
                    + "; the generator is not migrated, and BigQuery "
                    "tables are loaded with explicit values",
                    default_action))
            elif c.get("default"):
                findings.append(_finding(
                    "NOTE", "default_dropped", subject,
                    f"column default {c['default']} is not migrated; "
                    "BigQuery tables are loaded with explicit values",
                    default_action))
            fields.append(field)
        pk = pk_by_table.get(source)
        pk_cols, cluster_by = _keys_for_table(source, pk, renamed, fields,
                                              findings)
        if not pk:
            findings.append(_finding(
                "INFO", "no_primary_key", source,
                "the table has no primary key, so the BigQuery table has "
                "no key constraint and is not clustered",
                "none needed; add CLUSTER BY by hand if queries filter on "
                "a stable column"))
        tables[source] = {
            "schema": t["schema"], "name": t["name"], "source": source,
            "dataset": info["dataset"], "bq_name": info["bq_name"],
            "qualified": info["qualified"], "fields": fields,
            "renamed_columns": renamed, "primary_key": pk_cols,
            "cluster_by": cluster_by, "foreign_keys": [], "notes": []}

    # 4. Foreign keys: drop the unknown targets, then order the tables.
    edges = []
    kept_fks = {}
    for source, fks in fks_by_table.items():
        if source not in tables:
            continue
        for fk in fks:
            ref = f"{fk['ref_schema']}.{fk['ref_table']}"
            subject = f"{source}.{fk['name']}"
            if ref not in tables:
                findings.append(_finding(
                    "WARNING", "foreign_key_dropped", subject,
                    f"foreign key {fk['name']} references {ref}, which "
                    "is not a table in the migration inventory",
                    "add the referenced table to the migration or accept "
                    "the missing (unenforced) constraint"))
                continue
            if ref == source:
                findings.append(_finding(
                    "WARNING", "foreign_key_dropped", subject,
                    f"foreign key {fk['name']} references its own table, "
                    "and BigQuery does not allow a foreign key to "
                    "reference its own table",
                    "none available; the relationship is documented only"))
                continue
            # BigQuery foreign keys reference the primary key, nothing
            # else (a UNIQUE column set has no BigQuery counterpart).
            ref_entry = tables[ref]
            ref_cols = [ref_entry["renamed_columns"].get(c, c)
                        for c in fk["ref_columns"]]
            ref_pk = ref_entry["primary_key"]
            if not ref_pk or set(ref_cols) != set(ref_pk):
                if not ref_pk and pk_by_table.get(ref):
                    why = (f"whose primary key is not migrated (see "
                           f"primary_key_dropped for {ref})")
                elif not ref_pk:
                    why = "which has no primary key"
                else:
                    why = (f"on ({', '.join(ref_cols)}), which is not that "
                           f"table's primary key ({', '.join(ref_pk)})")
                findings.append(_finding(
                    "WARNING", "foreign_key_dropped", subject,
                    f"foreign key {fk['name']} references {ref} {why}; "
                    "BigQuery foreign keys reference the primary key of "
                    "the referenced table",
                    "none available; the relationship is documented only"))
                continue
            kept_fks.setdefault(source, []).append((fk, ref))
            edges.append((source, ref))
    dropped_edges = set()

    def on_table_cycle(name, unmet):
        for dep in unmet:
            dropped_edges.add((name, dep))

    table_order = _topological(list(tables), edges, on_table_cycle)
    for source in table_order:
        entry = tables[source]
        for fk, ref in kept_fks.get(source, []):
            ref_entry = tables[ref]
            cols = [entry["renamed_columns"].get(c, c) for c in fk["columns"]]
            ref_cols = [ref_entry["renamed_columns"].get(c, c)
                        for c in fk["ref_columns"]]
            if (source, ref) in dropped_edges:
                stmt = (f"ALTER TABLE {entry['qualified']} ADD CONSTRAINT "
                        f"{fk['name']} FOREIGN KEY "
                        f"({', '.join(_ident(c) for c in cols)}) REFERENCES "
                        f"{ref_entry['qualified']} "
                        f"({', '.join(_ident(c) for c in ref_cols)}) "
                        "NOT ENFORCED")
                findings.append(_finding(
                    "WARNING", "foreign_key_dropped", f"{source}.{fk['name']}",
                    f"foreign key {fk['name']} references {ref}, which "
                    "closes a reference cycle, so the referenced table "
                    "cannot exist first",
                    f"add it after both tables exist: {stmt}"))
                continue
            entry["foreign_keys"].append({
                "name": fk["name"], "columns": cols,
                "ref_table": ref_entry["qualified"], "ref_columns": ref_cols})
        entry["ddl"] = _table_ddl(entry)
    ordered_tables = [tables[s] for s in table_order]

    # 5. Views, in dependency order, through the translator.
    definitions = {f"{v['schema']}.{v['name']}": v
                   for v in inventory.get("view_definitions", [])}
    bases = {}
    for dep in inventory.get("view_dependencies", []):
        bases.setdefault(dep["view"], []).append(dep["base"])
    view_sources = [s for s, info in targets.items()
                    if info["kind"] in ("view", "matview")]
    view_edges = [(v, b) for v in view_sources for b in bases.get(v, [])
                  if b in targets and targets[b]["kind"] != "table"]

    def on_view_cycle(name, unmet):
        raise SchemaError(
            f"circular view dependency: {name} depends on "
            f"{', '.join(unmet)} and they depend back on it")

    view_order = _topological(view_sources, view_edges, on_view_cycle)
    all_columns = list(inventory.get("columns", []))

    def base_columns(source, visited):
        out = []
        for base in bases.get(source, []):
            if base in visited or base not in targets:
                continue
            visited.add(base)
            if targets[base]["kind"] == "table":
                out.extend(columns_by_table.get(base, []))
            else:
                out.extend(base_columns(base, visited))
        return out

    def view_context(source):
        """The translator's table map for one view: its own bases win
        the bare name (the dependency rows say what it reads), the
        global map covers the rest. A bare name that two of its bases
        share stays with the global map."""
        own = [targets[b] for b in bases.get(source, []) if b in targets]
        if not own:
            return context_tables
        counts = {}
        for info in own:
            counts[info["name"]] = counts.get(info["name"], 0) + 1
        ctx = dict(context_tables)
        for info in own:
            if counts[info["name"]] == 1:
                ctx[info["name"]] = info["qualified"]
        return ctx

    views = []
    for source in view_order:
        info = targets[source]
        definition = definitions.get(source)
        if definition is None:
            raise SchemaError(
                f"the inventory has no definition for {info['kind']} "
                f"{source}; re-run inventory with db-drift v0.2.0 or later")
        source_sql = _strip_statement(definition.get("definition"))
        columns = base_columns(source, {source}) if source in bases \
            else all_columns
        result = bq_predicate.translate(
            source_sql, {"tables": view_context(source), "columns": columns})
        sql, confidence = result["sql"], result["confidence"]
        notes = list(result["notes"])
        auto_sql = sql
        resolved = False
        resolved_sql = _resolved_body(source, view_res[source]) \
            if source in view_res else None
        if resolved_sql is not None and confidence != "review":
            # A resolution replaces only a review-flagged translation.
            findings.append(_finding(
                "WARNING", "view_resolution_ignored", source,
                f"translation-resolutions.json carries a resolution for "
                f"{info['kind']} {source}, but its body translated "
                "automatically; the automatic translation is kept and the "
                "recorded one is ignored",
                "remove the entry, or change the source view if the "
                "automatic translation is wrong"))
        elif resolved_sql is not None:
            res = view_res[source]
            rationale = str(res.get("rationale") or "").strip()
            problem = _resolution_problem(source, info["kind"], res,
                                          rationale, source_sql)
            if problem is not None:
                code, message, action = problem
                findings.append(_finding("WARNING", code, source, message,
                                         action))
            else:
                sql = resolved_sql
                confidence = "resolved"
                resolved = True
                notes.append(f"resolved by sql-translator: {rationale}")
                findings.append(_finding(
                    "NOTE", "view_resolved", source,
                    "the view body comes from translation-resolutions.json"
                    f": {rationale}",
                    "present the resolution at Gate 1"))
        materialized = False
        if info["kind"] == "matview":
            base_views = [b for b in bases.get(source, [])
                          if b in targets and targets[b]["kind"] != "table"]
            reason = _matview_blocker(sql, confidence, base_views)
            if reason is None:
                materialized = True
            else:
                findings.append(_finding(
                    "WARNING", "matview_as_view", source,
                    f"materialized view {source} becomes a regular view "
                    f"because {reason}",
                    "query cost is the same as the source view; convert "
                    "it to a materialized view by hand once the body "
                    "meets BigQuery's restrictions"))
        if confidence == "review":
            ddl = ""
            findings.append(_finding(
                "WARNING", "view_review", source,
                f"the translation of {info['kind']} {source} needs "
                "review: " + " ".join(notes),
                "dispatch the sql-translator agent; its resolution in "
                "translation-resolutions.json unblocks apply"))
        else:
            ddl = _view_ddl(info["qualified"], sql, materialized)
        views.append({
            "schema": info["schema"], "name": info["name"], "source": source,
            "kind": info["kind"], "dataset": info["dataset"],
            "bq_name": info["bq_name"], "qualified": info["qualified"],
            "ddl": ddl, "sql": sql, "auto_sql": auto_sql,
            "source_sql": source_sql, "confidence": confidence,
            "notes": notes, "resolved": resolved,
            "materialized": materialized})

    # 6. Inventory-level findings.
    indexes = (inventory.get("counts") or {}).get("indexes") or 0
    if indexes:
        findings.append(_finding(
            "INFO", "index_dropped", "all tables",
            f"{indexes} indexes on the source are not migrated; BigQuery "
            "has no indexes (clustering on the primary key stands in for "
            "them)",
            "none needed; add partitioning or clustering by hand for "
            "query patterns that relied on an index"))
    for seq in inventory.get("sequences", []):
        findings.append(_finding(
            "NOTE", "sequence_dropped", f"{seq['schema']}.{seq['name']}",
            "sequences have no BigQuery equivalent and are not migrated",
            "generate keys in the writer or with GENERATE_UUID()"))
    # The inventory counts every constraint; the keys are listed, so the
    # rest are UNIQUE, CHECK, or EXCLUDE constraints BigQuery cannot hold.
    constraints = (inventory.get("counts") or {}).get("constraints") or 0
    other = constraints - len(inventory.get("primary_keys", [])) \
        - len(inventory.get("foreign_keys", []))
    if other > 0:
        findings.append(_finding(
            "INFO", "constraints_dropped", "all tables",
            f"{_plural(other, 'constraint')} on the source (UNIQUE, CHECK, "
            "or EXCLUDE) are not migrated; BigQuery has no equivalent, and "
            "its keys are NOT ENFORCED",
            "none needed; enforce uniqueness and value rules in the writer "
            "or with a validation query"))

    return {"migration": str(bq_cfg.get("migration") or ""),
            "project": project, "location": location,
            "mode": str(bq_cfg.get("mode") or "emulated"),
            "datasets": datasets, "tables": ordered_tables, "views": views,
            "findings": findings, "context_tables": context_tables}


def _table_ddl(entry):
    lines = [_column_ddl(f) for f in entry["fields"]]
    if entry["primary_key"]:
        lines.append("PRIMARY KEY ("
                     + ", ".join(_ident(c) for c in entry["primary_key"])
                     + ") NOT ENFORCED")
    for fk in entry["foreign_keys"]:
        lines.append("FOREIGN KEY ("
                     + ", ".join(_ident(c) for c in fk["columns"])
                     + f") REFERENCES {fk['ref_table']} ("
                     + ", ".join(_ident(c) for c in fk["ref_columns"])
                     + ") NOT ENFORCED")
    body = ",\n".join("  " + line for line in lines)
    text = f"CREATE TABLE IF NOT EXISTS {entry['qualified']} (\n{body}\n)"
    if entry["cluster_by"]:
        text += "\nCLUSTER BY " + ", ".join(
            _ident(c) for c in entry["cluster_by"])
    description = _sql_string(DESCRIPTION.format(source=entry["source"]))
    text += f"\nOPTIONS (description = {description});"
    return text


def unresolved_views(plan):
    """Source names of views whose translation is review with no
    resolution, in plan order."""
    return [v["source"] for v in plan["views"] if v["confidence"] == "review"]


def review_items(plan):
    """The "views" section of translation-review.json: every review
    view with what the sql-translator agent needs."""
    items = {}
    for v in plan["views"]:
        if v["confidence"] != "review":
            continue
        items[v["source"]] = {
            "kind": v["kind"], "source_sql": v["source_sql"],
            "auto_sql": v["auto_sql"], "notes": list(v["notes"]),
            "context_tables": dict(plan.get("context_tables") or {})}
    return items


# ------------------------------------------------------------ rendering

def _shell_safe(label, value):
    if not _SHELL_SAFE_RE.match(str(value)):
        raise SchemaError(
            f"{label} {value!r} has characters the datasets script cannot "
            "quote safely; allowed: letters, digits, _ . : -")
    return str(value)


def render_datasets_script(plan):
    """10-datasets.sh: idempotent bq mk per dataset."""
    project = _shell_safe("project", plan["project"])
    location = _shell_safe("location", plan["location"])
    lines = [
        "#!/usr/bin/env bash",
        f"# {DATASETS_SCRIPT}: create the BigQuery datasets for migration "
        f"{plan.get('migration') or '(unnamed)'}.",
        "# Generated by db-drift bq-schema translate; re-run translate "
        "instead of editing.",
        "# Idempotent: an existing dataset is kept. In emulated mode the "
        "backend runs these",
        "# steps (bq-schema apply --datasets-only); in live mode it runs "
        "the same bq commands.",
        "set -euo pipefail",
        f'PROJECT="{project}"',
        f'LOCATION="{location}"',
        "",
    ]
    for dataset in sorted(plan["datasets"]):
        _shell_safe("dataset", dataset)
        info = plan["datasets"][dataset]
        schemas = info.get("source_schemas") or [info["source_schema"]]
        lines.append(f"# {dataset} (PostgreSQL schema {', '.join(schemas)})")
        lines.append(f'if ! bq --project_id="$PROJECT" show '
                     f'"$PROJECT:{dataset}" >/dev/null 2>&1; then')
        lines.append(f'  bq --project_id="$PROJECT" mk --dataset '
                     f'--location="$LOCATION" "$PROJECT:{dataset}"')
        lines.append("fi")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def render_tables_sql(plan):
    """20-tables.sql: tables in creation order, then views in dependency
    order. A review view is rendered as a comment block so the script
    stays runnable and honest."""
    parts = [
        f"-- {TABLES_SCRIPT}: BigQuery tables and views for migration "
        f"{plan.get('migration') or '(unnamed)'}.",
        "-- Generated by db-drift bq-schema translate; re-run translate "
        "instead of editing.",
        f"-- Run with: bq --project_id={plan['project']} query "
        f"--use_legacy_sql=false < {TABLES_SCRIPT}",
        "-- Tables come first, ordered so a referenced table exists before "
        "the foreign key",
        "-- that points at it; views follow in dependency order.",
        "",
    ]
    for t in plan["tables"]:
        parts.append(t["ddl"])
        parts.append("")
    if plan["views"]:
        parts.append("-- views (dependency order)")
        parts.append("")
    for v in plan["views"]:
        if v["ddl"]:
            parts.append(v["ddl"])
        else:
            parts.append(f"-- REVIEW {v['source']}: the translation needs "
                         "the sql-translator resolution; nothing is created "
                         "until translation-resolutions.json has it.")
            for note in v["notes"]:
                parts.append(f"-- note: {note}")
            parts.append("-- auto attempt:")
            for line in v["sql"].splitlines():
                parts.append(f"-- {line}")
        parts.append("")
    return "\n".join(parts).rstrip("\n") + "\n"


# --------------------------------------------------------- apply, verify

def apply_schema(plan, backend, log=None, datasets_only=False):
    """Create datasets, then tables, then views through the backend.

    log is an optional callable that receives one progress line per
    step. Refuses (SchemaError, before touching the backend) when the
    plan was written for another project or location than the backend
    serves, and when any view is review confidence and unresolved,
    unless datasets_only. Returns the list of operations performed.
    """
    def say(text):
        if log is not None:
            log(text)

    if plan.get("project") != backend.project or \
            str(plan.get("location") or "").lower() != \
            str(backend.location or "").lower():
        raise SchemaError(
            f"the schema plan targets {plan.get('project')} "
            f"({plan.get('location')}) but the backend serves "
            f"{backend.project} ({backend.location}); re-run bq-schema "
            "translate after changing the migration's bigquery config")
    if not datasets_only:
        pending = unresolved_views(plan)
        if pending:
            raise SchemaError(
                f"{len(pending)} view(s) have review-confidence "
                f"translations and no resolution: {', '.join(pending)}; "
                "dispatch the sql-translator agent to write artifacts/"
                f"{RESOLUTIONS_FILE}, then re-run bq-schema translate "
                "before apply")
    ops = []
    existing = set(backend.list_datasets())
    for dataset in sorted(plan["datasets"]):
        if dataset in existing:
            status = "exists"
        else:
            backend.create_dataset(dataset)
            status = "created"
        ops.append({"op": "create_dataset", "name": dataset, "status": status})
        say(f"dataset {dataset}: {status}")
    if datasets_only:
        return ops
    for t in plan["tables"]:
        backend.run_ddl(t["ddl"])
        ops.append({"op": "create_table", "name": t["qualified"],
                    "status": "applied"})
        say(f"table {t['qualified']}: applied")
    for v in plan["views"]:
        kind = "MATERIALIZED_VIEW" if v["materialized"] else "VIEW"
        backend.run_ddl(v["ddl"])
        ops.append({"op": "create_view", "name": v["qualified"],
                    "kind": kind, "status": "applied"})
        say(f"{kind.lower().replace('_', ' ')} {v['qualified']}: applied")
    return ops


def _field_shape(field):
    """(name, normalized type, mode) of a bq field; policy tags and any
    other decoration are not part of the comparison."""
    type_name = str(field.get("type") or "").upper()
    type_name = bq_backend.TYPE_ALIASES.get(type_name, type_name)
    mode = str(field.get("mode") or "NULLABLE").upper()
    return field.get("name"), type_name, mode


def _column_mismatches(entry, actual_fields):
    """Mismatch entries for one table: every planned column the target
    lacks or holds with another type or mode, and every extra column."""
    planned = {name: (type_name, mode) for name, type_name, mode
               in (_field_shape(f) for f in entry["fields"])}
    actual = {name: (type_name, mode) for name, type_name, mode
              in (_field_shape(f) for f in actual_fields)}
    out = []
    for name in sorted(set(planned) | set(actual)):
        want, got = planned.get(name), actual.get(name)
        if want == got:
            continue
        out.append({"name": entry["qualified"], "column": name,
                    "expected": " ".join(want) if want else "absent",
                    "actual": " ".join(got) if got else "missing"})
    return out


def verify_schema(plan, backend):
    """List the planned datasets and compare with the plan.

    expected and actual count tables and views (materialized views
    count as views; actual counts every object the datasets hold).
    missing lists planned objects the target lacks; mismatched lists
    objects present with another type, and for each planned table
    every column whose name, type, or mode differs from the plan
    (a missing column and an extra column both count; policy tags do
    not). Views are checked by name and type only. pass needs both
    lists empty; extra objects on the target are not a failure.
    """
    listed = {}
    for dataset in plan["datasets"]:
        try:
            listed[dataset] = {t["name"]: t["type"]
                               for t in backend.list_tables(dataset)}
        except bq_backend.BackendError:
            listed[dataset] = None
    actual = {"tables": 0, "views": 0}
    for names in listed.values():
        for type_name in (names or {}).values():
            if type_name == "TABLE":
                actual["tables"] += 1
            elif type_name in ("VIEW", "MATERIALIZED_VIEW"):
                actual["views"] += 1
    missing, mismatched = [], []

    def check(entry, want):
        names = listed.get(entry["dataset"]) or {}
        got = names.get(entry["bq_name"])
        if got is None:
            missing.append(entry["qualified"])
            return False
        if got != want:
            mismatched.append({"name": entry["qualified"], "expected": want,
                               "actual": got})
            return False
        return True

    for t in plan["tables"]:
        if not check(t, "TABLE"):
            continue
        try:
            fields = backend.get_table_schema(t["dataset"], t["bq_name"])
        except bq_backend.BackendError as exc:
            mismatched.append({"name": t["qualified"], "column": "*",
                               "expected": f"{len(t['fields'])} columns",
                               "actual": f"schema unreadable: {exc}"})
            continue
        mismatched.extend(_column_mismatches(t, fields))
    for v in plan["views"]:
        check(v, "MATERIALIZED_VIEW" if v["materialized"] else "VIEW")
    return {"expected": {"tables": len(plan["tables"]),
                         "views": len(plan["views"])},
            "actual": actual, "missing": missing, "mismatched": mismatched,
            "pass": not missing and not mismatched}


# ------------------------------------------------------------ artifacts

def load_resolutions(workspace):
    """artifacts/translation-resolutions.json as {"views", "policies"},
    or empty sections when the file does not exist."""
    path = Path(workspace) / "artifacts" / RESOLUTIONS_FILE
    if not path.exists():
        return {"views": {}, "policies": {}}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SchemaError(f"{RESOLUTIONS_FILE} is not JSON: {exc}")
    if not isinstance(doc, dict):
        raise SchemaError(
            f"{RESOLUTIONS_FILE} must be a JSON object with views and "
            "policies sections")
    out = {}
    for key in ("views", "policies"):
        section = doc.get(key) or {}
        if not isinstance(section, dict):
            raise SchemaError(f"{RESOLUTIONS_FILE}: {key} must be a mapping")
        out[key] = section
    return out


def write_translation_review(workspace, plan):
    """Write artifacts/translation-review.json for the sql-translator.

    The views section is replaced with this plan's review items; the
    policies section, which bq-security writes into the same file, is
    kept as it is.
    """
    path = Path(workspace) / "artifacts" / REVIEW_FILE
    doc = {"views": {}, "policies": {}}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            existing = None
        if isinstance(existing, dict) and isinstance(
                existing.get("policies"), dict):
            doc["policies"] = existing["policies"]
    doc["views"] = review_items(plan)
    _write_json(path, doc)
    return path


def _write_json(path, doc):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def _write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _load_plan(artifacts):
    path = Path(artifacts) / PLAN_FILE
    if not path.exists():
        raise SchemaError(
            f"no schema plan at {path}; run bq-schema translate first")
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SchemaError(f"{PLAN_FILE} is not JSON: {exc}")
    if not isinstance(plan, dict) or "tables" not in plan:
        raise SchemaError(f"{PLAN_FILE} is not a schema plan; re-run "
                          "bq-schema translate")
    return plan


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


# ------------------------------------------------------------------ CLI

def _translate(args, bq_cfg, ws):
    art = ws / "artifacts"
    inv_path = art / "inventory.json"
    if not inv_path.exists():
        raise SchemaError(
            f"no inventory at {inv_path}; run: python scripts/dbdrift.py "
            f"inventory <source flags> --out {inv_path}")
    inventory = json.loads(inv_path.read_text(encoding="utf-8"))
    plan = translate_schema(inventory, bq_cfg, load_resolutions(ws))
    plan_path = art / PLAN_FILE
    _write_json(plan_path, plan)
    datasets_path = art / APPLY_DIR / DATASETS_SCRIPT
    tables_path = art / APPLY_DIR / TABLES_SCRIPT
    _write_text(datasets_path, render_datasets_script(plan))
    _write_text(tables_path, render_tables_sql(plan))
    review_path = write_translation_review(ws, plan)
    pending = unresolved_views(plan)
    materialized = sum(1 for v in plan["views"] if v["materialized"])
    resolved = sum(1 for v in plan["views"] if v["resolved"])
    print(f"wrote {plan_path}: {_plural(len(plan['tables']), 'table')}, "
          f"{_plural(len(plan['views']), 'view')} ({materialized} "
          f"materialized, {resolved} resolved, {len(pending)} need review) "
          f"into {_plural(len(plan['datasets']), 'dataset')} of "
          f"{plan['project']} ({plan['location']})")
    print(f"wrote {datasets_path}")
    print(f"wrote {tables_path}")
    print(f"wrote {review_path}")
    counts = {"WARNING": 0, "INFO": 0, "NOTE": 0}
    for f in plan["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("findings: " + ", ".join(f"{n} {sev}" for sev, n in counts.items()))
    for f in plan["findings"]:
        if f["severity"] == "WARNING":
            print(f"  WARNING {f['code']} {f['subject']}: {f['message']}")
    if pending:
        print(f"{_plural(len(pending), 'view')} need review before apply: "
              + ", ".join(pending))
        print(f"dispatch the sql-translator agent on {review_path}, then "
              "re-run bq-schema translate")
    return 0


def _apply(args, bq_cfg, ws):
    art = ws / "artifacts"
    plan = _load_plan(art)
    backend = bq_backend.make_backend(bq_cfg, args.migration, ws)
    print(f"mode: {backend.mode}, project {plan['project']} "
          f"({plan['location']})")
    ops = apply_schema(plan, backend, log=print,
                       datasets_only=args.datasets_only)
    _write_json(art / APPLIED_FILE, {
        "migration": args.migration, "mode": backend.mode,
        "datasets_only": bool(args.datasets_only), "ops": ops})
    counts = {}
    for op in ops:
        counts[op["op"]] = counts.get(op["op"], 0) + 1
    summary = ", ".join(f"{n} {name.replace('_', ' ')}"
                        for name, n in counts.items())
    print(f"applied ({backend.mode}): {summary}; wrote {art / APPLIED_FILE}")
    return 0


def _verify(args, bq_cfg, ws):
    art = ws / "artifacts"
    plan = _load_plan(art)
    backend = bq_backend.make_backend(bq_cfg, args.migration, ws)
    report = verify_schema(plan, backend)
    report["mode"] = backend.mode
    _write_json(art / VERIFY_FILE, report)
    print(f"expected {report['expected']['tables']} tables and "
          f"{report['expected']['views']} views; found "
          f"{report['actual']['tables']} tables and "
          f"{report['actual']['views']} views ({backend.mode})")
    for name in report["missing"]:
        print(f"  missing: {name}")
    for item in report["mismatched"]:
        if "column" in item:
            print(f"  mismatched: {item['name']}: column {item['column']} "
                  f"expected {item['expected']}, actual {item['actual']}")
        else:
            print(f"  mismatched: {item['name']} is {item['actual']}, "
                  f"expected {item['expected']}")
    verdict = "PASSED" if report["pass"] else "FAILED"
    print(f"SCHEMA VERIFY {verdict} ({backend.mode}); wrote "
          f"{art / VERIFY_FILE}")
    return 0 if report["pass"] else 1


def main(argv):
    parser = argparse.ArgumentParser(prog="dbdrift.py bq-schema")
    parser.add_argument("--root", default=".",
                        help="project root holding migrations/")
    parser.add_argument("--migration", default=None)
    sub = parser.add_subparsers(dest="verb", required=True)
    translate_p = sub.add_parser(
        "translate", help="write artifacts/schema-plan.json, bq-apply/"
                          "10-datasets.sh, bq-apply/20-tables.sql, and "
                          "translation-review.json from the inventory")
    apply_p = sub.add_parser(
        "apply", help="create datasets, tables, and views through the "
                      "backend; refuses while any view needs review")
    apply_p.add_argument("--datasets-only", action="store_true",
                         help="create only the datasets (provision phase)")
    verify_p = sub.add_parser(
        "verify", help="list the target and compare with the plan; exit 1 "
                       "when anything is missing")
    # --root and --migration are accepted before or after the verb.
    for p in (translate_p, apply_p, verify_p):
        p.add_argument("--root", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
        p.add_argument("--migration", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    args = parser.parse_args(argv[1:])
    if args.migration is None:
        parser.error("the following arguments are required: --migration")
    try:
        mig = config.load_migration(args.root, args.migration)
        bq_cfg = config.bigquery_config(mig, args.migration)
        ws = config.workspace(args.root, args.migration)
        if args.verb == "translate":
            return _translate(args, bq_cfg, ws)
        if args.verb == "apply":
            return _apply(args, bq_cfg, ws)
        return _verify(args, bq_cfg, ws)
    except (SchemaError, config.ConfigError, bq_backend.BackendError) as exc:
        print(f"BQ-SCHEMA ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"BQ-SCHEMA ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(["bq-schema"] + sys.argv[1:]))

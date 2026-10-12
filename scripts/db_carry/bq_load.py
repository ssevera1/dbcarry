"""NDJSON export from PostgreSQL and bulk load into BigQuery.

Export is read-only and streams: psql runs

    \\copy (SELECT row_to_json(r) FROM (SELECT <expressions> FROM t) r)
      TO STDOUT WITH (FORMAT csv, QUOTE E'\\x01', DELIMITER E'\\x02')

and every stdout line is written into a gzip file as it arrives, so a
large table never sits in memory. The CSV options matter: COPY's
default text format doubles every backslash on output, which turns the
JSON escapes row_to_json emits (\\" and \\\\ and \\n) into invalid JSON.
CSV mode with a quote and delimiter character that cannot occur in JSON
text (row_to_json escapes control characters as \\u0001) passes each
line through verbatim. Column expressions come from bq_types (base64
for bytea, with the line breaks encode() adds every 76 characters
stripped there, hstore_to_json for hstore, ::text for interval and the
unknown types, to_json for arrays).

The session runs with TimeZone=UTC. row_to_json renders timestamptz in
the session zone, and before 1883 that zone is local mean time with an
offset carrying seconds (-05:50:36 for America/Chicago), which BigQuery
cannot load; in UTC every value renders as +00:00.

Load hands the file to the backend (bq load for the live backend, a
validated copy for the emulated one) with the table's schema as the
backend reads it back, not the schema plan: bq-security apply attaches
policy tags to the live table only, and a load schema without them
would be the wrong statement of the table. The row count is read back;
a count that differs from the export line count fails the table. A
table that already holds rows is never loaded again, because both
backends append: the report says so and the phase fails until the
target is reset.

The export files (and the GCS copies in live mode) hold every row in
plain text, restricted columns and RLS-protected rows included. They
are staging, not a product: the report names them, the object prefix
carries the migration name so two migrations sharing a bucket never
overwrite each other, and --cleanup removes each table's copies once
its counts match. In live mode, load and run refuse to start until
artifacts/security-verify.json records a passing verification, so the
controls exist before the data does (--force overrides, and the report
records that it did).

Identifiers travel inside a psql -c argument. On Windows psql receives
argv in the ANSI code page, so a table or column name with characters
outside ASCII cannot be exported this way; every psql -c call in the
pipeline shares that limit.
"""
import argparse
import gzip
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from db_carry import bq_backend, bq_types, config, pg

COPY_OPTIONS = "WITH (FORMAT csv, QUOTE E'\\x01', DELIMITER E'\\x02')"
EXPORT_TZ_OPTS = "-c TimeZone=UTC"
GCS_PREFIX = "dbcarry"
REPORT_NAME = "load-report.json"
EXPORT_DIR = "export"
SECURITY_VERIFY_NAME = "security-verify.json"
RETENTION_NOTE = (
    "export files hold every row in plain text, restricted columns and "
    "RLS-protected rows included; they are staging for the load, so remove "
    "them once validation passes (bq-load --cleanup deletes each table's "
    "local and GCS copies after its counts match)")


class LoadError(Exception):
    pass


def tolerant_console():
    """Make stdout and stderr replace characters the console cannot
    encode instead of raising. Under a pipe on Windows Python picks the
    ANSI code page, and a psql message or a table value outside it
    would otherwise turn a report into a UnicodeEncodeError."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


# ---------------------------------------------------------------- export

def export_sql(schema, table, columns):
    """SELECT row_to_json(r) FROM (SELECT <expr> AS "name", ... FROM
    "schema"."table") r, on one line. A column dict may carry "bq_name";
    the JSON key then takes that name so the load schema matches."""
    if not columns:
        raise ValueError(f"no columns to export for {schema}.{table}")
    q = bq_types.quote_pg
    selects = [f"{bq_types.export_expression(c)} AS "
               f"{q(c.get('bq_name') or c['name'])}" for c in columns]
    return (f"SELECT row_to_json(r) FROM (SELECT {', '.join(selects)} "
            f"FROM {q(schema)}.{q(table)}) r")


def copy_command(sql):
    if "\n" in sql or "\r" in sql:
        raise ValueError("\\copy takes a single line of SQL")
    return f"\\copy ({sql}) TO STDOUT {COPY_OPTIONS}"


def export_env(ci):
    """The read-only psql environment with the session zone pinned to
    UTC, so timestamptz renders with a +00:00 offset for every year."""
    env = pg.build_env(ci, readonly=True)
    env["PGOPTIONS"] = f"{env['PGOPTIONS']} {EXPORT_TZ_OPTS}"
    return env


def export_table(ci, schema, table, columns, out_path):
    """Stream one table to a gzip NDJSON file; {"rows": n, "bytes": n}.
    Raises pg.PgError with the first 800 characters of psql's stderr
    when psql fails; the partial file is removed."""
    command = copy_command(export_sql(schema, table, columns))
    argv = ([pg.find_bin("psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1",
             "-A", "-t"] + pg.conn_argv(ci) + ["-c", command])
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.Popen(argv, env=export_env(ci),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, encoding="utf-8")
    except OSError as exc:
        raise pg.PgError(f"psql could not start: {exc}")
    stderr_chunks = []
    drain = threading.Thread(
        target=lambda: stderr_chunks.append(proc.stderr.read()), daemon=True)
    drain.start()
    rows = 0
    try:
        with gzip.open(out_path, "wb") as gz:
            for line in proc.stdout:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                gz.write(line.encode("utf-8"))
                gz.write(b"\n")
                rows += 1
    except BaseException:
        proc.kill()
        proc.wait()
        drain.join()
        out_path.unlink(missing_ok=True)
        raise
    rc = proc.wait()
    drain.join()
    if rc != 0:
        out_path.unlink(missing_ok=True)
        stderr = "".join(chunk or "" for chunk in stderr_chunks)
        raise pg.PgError(f"psql failed ({rc}): {stderr.strip()[:800]}")
    return {"rows": rows, "bytes": out_path.stat().st_size}


def count_ndjson_lines(path):
    path = Path(path)
    with open(path, "rb") as fh:
        magic = fh.read(2)
    opener = gzip.open if magic == b"\x1f\x8b" else open
    n = 0
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n


# ------------------------------------------------------------------ load

def load_table(backend, dataset, bq_name, path, fields):
    """Rows the table holds after the load, as the backend reports it."""
    return backend.load_ndjson(dataset, bq_name, str(path), fields)


def load_schema(backend, dataset, bq_name, plan_fields):
    """The load schema: the table as the backend reads it back, which
    carries the policy tags bq-security apply attached (the plan fields
    never do), falling back to the plan fields when the read-back is
    empty."""
    fields = backend.get_table_schema(dataset, bq_name)
    return fields if fields else list(plan_fields)


def tagged_columns(fields):
    return [f["name"] for f in fields
            if (f.get("policyTags") or {}).get("names")]


def _gcs_command(backend, argv, op, uri):
    """One gcloud storage command through the backend's runner (so tests
    can fake it), recorded in the backend's operation log."""
    runner = getattr(backend, "runner", None) or bq_backend.default_runner
    rc, out, err = runner(argv, None)
    log = getattr(backend, "log", None) or bq_backend.OperationLog(None)
    entry = {"argv": argv, "rc": rc, "uri": uri}
    if rc != 0:
        entry["stderr"] = (err or "").strip()[:800]
    log.record(op, **entry)
    if rc != 0:
        raise LoadError(
            f"{' '.join(argv[:3])} failed ({rc}): {(err or out).strip()[:800]}")


def upload_to_gcs(backend, path, bucket, object_name):
    uri = f"gs://{bucket}/{object_name}"
    _gcs_command(backend, ["gcloud", "storage", "cp", str(path), uri],
                 "gcs_upload", uri)
    return uri


def delete_from_gcs(backend, uri):
    _gcs_command(backend, ["gcloud", "storage", "rm", uri], "gcs_delete", uri)


def remove_staged(backend, path, gcs_uri, notes):
    """Delete a table's plaintext staging copies after a passing load:
    {"local": bool, "gcs": bool | None}. A copy that could not be
    removed is a note, not a failure: the data landed and the counts
    matched."""
    path = Path(path)
    path.unlink(missing_ok=True)
    result = {"local": not path.exists(), "gcs": None}
    if gcs_uri:
        try:
            delete_from_gcs(backend, gcs_uri)
            result["gcs"] = True
        except LoadError as exc:
            result["gcs"] = False
            notes.append(f"staged copy {gcs_uri} was not removed: {exc}")
    return result


# ----------------------------------------------------------- table plan

def columns_by_table(inventory):
    """{(schema, table): [column dicts in ordinal order]}."""
    out = {}
    for c in inventory.get("columns", []):
        out.setdefault((c["schema"], c["table"]), []).append(c)
    for cols in out.values():
        cols.sort(key=lambda c: c.get("ordinal") or 0)
    return out


def alias_columns(columns, fields):
    """Copies of the column dicts with "bq_name" set to the load schema
    field each one feeds: the same name when the plan kept it, else the
    sanitized identifier when the plan renamed it that way. Without a
    load schema the PostgreSQL names are used as they are."""
    if fields is None:
        return [dict(c) for c in columns]
    names = {f.get("name") for f in fields}
    out = []
    for c in columns:
        alias = c["name"]
        if alias not in names:
            safe = bq_types.sanitize_identifier(c["name"])[0]
            if safe in names:
                alias = safe
        out.append(dict(c, bq_name=alias))
    return out


def table_targets(schema_plan, inventory, bq_cfg):
    """[{"schema", "name", "dataset", "bq_name", "fields"}] from the
    schema plan, or derived from the inventory and the dataset map when
    no plan exists yet (fields None: enough to export, not to load)."""
    if schema_plan is not None and "tables" in schema_plan:
        return [{"schema": t["schema"], "name": t["name"],
                 "dataset": t["dataset"], "bq_name": t["bq_name"],
                 "fields": t.get("fields")} for t in schema_plan["tables"]]
    dataset_map = bq_cfg.get("dataset_map") or {}
    dbname = bq_cfg.get("dbname") or ""
    return [{"schema": t["schema"], "name": t["name"],
             "dataset": bq_types.dataset_for(t["schema"], dataset_map, dbname),
             "bq_name": bq_types.sanitize_identifier(t["name"])[0],
             "fields": None} for t in inventory.get("tables", [])]


# --------------------------------------------------------------- run_all

def run_all(schema_plan, inventory, ci, backend, export_dir, gcs_bucket="",
            only=None, steps=("export", "load"), exporter=None,
            gcs_prefix=GCS_PREFIX, cleanup=False):
    """Export and load every table in schema_plan["tables"] (or the
    "schema.name" keys in only). steps selects the halves: ("export",)
    writes files only, ("load",) loads files an earlier export left
    under export_dir. Returns {"tables": [{"table", "dataset",
    "bq_name", "path", "exported", "loaded", "seconds", "pass", ...}],
    "pass": bool}; a failure in one table is recorded and the others
    still run. exporter defaults to export_table. GCS objects go under
    gcs_prefix/<dataset>/; cleanup removes a table's staging copies
    after its load passes (never on an export-only run)."""
    exporter = exporter or export_table
    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    by_table = columns_by_table(inventory)
    do_export = "export" in steps
    do_load = "load" in steps
    results = []
    for target in schema_plan["tables"]:
        schema, name = target["schema"], target["name"]
        key = f"{schema}.{name}"
        if only is not None and key not in only:
            continue
        started = time.monotonic()
        path = export_dir / f"{schema}.{name}.ndjson.gz"
        rec = {"table": key, "dataset": target.get("dataset"),
               "bq_name": target.get("bq_name"), "path": str(path),
               "exported": 0, "loaded": 0, "seconds": 0.0, "pass": False,
               "notes": []}
        try:
            dataset, bq_name = target["dataset"], target["bq_name"]
            columns = by_table.get((schema, name))
            if not columns:
                raise LoadError(f"no columns in the inventory for {key}")
            columns = alias_columns(columns, target.get("fields"))
            if do_load:
                before = backend.count_rows(dataset, bq_name)
                if before:
                    rec["loaded"] = before
                    raise LoadError(
                        f"{dataset}.{bq_name} already holds {before} rows; "
                        "both backends append, so reset the target before "
                        "loading again")
            if do_export:
                info = exporter(ci, schema, name, columns, path)
                rec["exported"] = int(info["rows"])
                rec["bytes"] = int(info.get("bytes", 0))
            elif do_load:
                if not path.exists():
                    raise LoadError(
                        f"no export file at {path}; run bq-load export first")
                rec["exported"] = count_ndjson_lines(path)
                rec["bytes"] = path.stat().st_size
            if do_load:
                plan_fields = target.get("fields")
                if not plan_fields:
                    raise LoadError(
                        f"no load schema for {key} in the schema plan; run "
                        "bq-schema translate first")
                fields = load_schema(backend, dataset, bq_name, plan_fields)
                rec["policy_tagged_columns"] = tagged_columns(fields)
                source = path
                if gcs_bucket:
                    if backend.mode == "live":
                        source = upload_to_gcs(
                            backend, path, gcs_bucket,
                            f"{gcs_prefix}/{dataset}/{path.name}")
                        rec["gcs_uri"] = source
                    else:
                        rec["notes"].append(
                            f"gcs_bucket {gcs_bucket!r} ignored in "
                            f"{backend.mode} mode; loaded from the local file")
                rec["loaded"] = load_table(backend, dataset, bq_name, source,
                                           fields)
                if rec["loaded"] == rec["exported"]:
                    rec["pass"] = True
                    if cleanup:
                        rec["cleanup"] = remove_staged(
                            backend, path, rec.get("gcs_uri"), rec["notes"])
                else:
                    rec["reason"] = (f"row count mismatch: exported "
                                     f"{rec['exported']} rows, loaded "
                                     f"{rec['loaded']} rows")
            else:
                rec["pass"] = True
        except LoadError as exc:
            rec["pass"] = False
            rec["reason"] = str(exc)
        except (pg.PgError, bq_backend.BackendError, OSError, ValueError,
                KeyError) as exc:
            rec["pass"] = False
            rec["reason"] = f"{type(exc).__name__}: {exc}"
        rec["seconds"] = round(time.monotonic() - started, 3)
        results.append(rec)
    return {"tables": results,
            "pass": bool(results) and all(r["pass"] for r in results)}


# ------------------------------------------------------------------- CLI

STEPS = {"export": ("export",), "load": ("load",), "run": ("export", "load")}


def _load_json(path, what):
    path = Path(path)
    if not path.exists():
        raise LoadError(f"no {what} at {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def security_verified(artifacts):
    """(verified, reason): whether artifacts/security-verify.json records
    a passing bq-security verify run."""
    path = Path(artifacts) / SECURITY_VERIFY_NAME
    if not path.exists():
        return False, f"no {path}; run bq-security verify first"
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except ValueError as exc:
        return False, f"{path} is not valid JSON: {exc}"
    if not isinstance(doc, dict) or doc.get("pass") is not True:
        return False, f"{path} records a failed verification"
    return True, ""


def main(argv):
    tolerant_console()
    parser = argparse.ArgumentParser(prog="dbcarry.py bq-load")
    parser.add_argument("--root", default=".",
                        help="project root holding migrations/")
    parser.add_argument("--migration", default=None)
    sub = parser.add_subparsers(dest="verb", required=True)
    helps = {"export": "export tables to artifacts/export/*.ndjson.gz",
             "load": "load previously exported files into BigQuery",
             "run": "export and load every table, then compare counts"}
    for verb, text in helps.items():
        p = sub.add_parser(verb, help=text)
        p.add_argument("--table", default=None,
                       help="schema.name; default every table in the plan")
        if verb != "export":
            p.add_argument("--cleanup", action="store_true",
                           help="delete each table's local and GCS staging "
                                "copies once its counts match")
            p.add_argument("--force", action="store_true",
                           help="load in live mode even when artifacts/"
                                "security-verify.json is missing or failed "
                                "(controls are applied before data; the "
                                "report records the override)")
        # --root and --migration are accepted before or after the verb.
        p.add_argument("--root", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
        p.add_argument("--migration", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    args = parser.parse_args(argv[1:])
    if args.migration is None:
        parser.error("the following arguments are required: --migration")
    cleanup = bool(getattr(args, "cleanup", False))
    force = bool(getattr(args, "force", False))
    try:
        mig = config.load_migration(args.root, args.migration)
        bq_cfg = config.bigquery_config(mig, args.migration)
        ws = config.workspace(args.root, args.migration)
        artifacts = ws / "artifacts"
        inventory = _load_json(artifacts / "inventory.json",
                               "inventory (run inventory first)")
        plan_path = artifacts / "schema-plan.json"
        schema_plan = _load_json(plan_path, "schema plan") \
            if plan_path.exists() else None
        targets = table_targets(schema_plan, inventory, bq_cfg)
        only = None
        if args.table:
            if args.table not in {f"{t['schema']}.{t['name']}"
                                  for t in targets}:
                raise LoadError(
                    f"table {args.table} is not in the schema plan or "
                    "inventory")
            only = {args.table}
        ci = config.source_conn(mig)
        backend = bq_backend.make_backend(bq_cfg, args.migration, ws)
        steps = STEPS[args.verb]
        verified, reason = security_verified(artifacts)
        enforced = backend.mode == "live" and "load" in steps
        forced = bool(enforced and not verified and force)
        if enforced and not verified and not force:
            raise LoadError(
                f"refusing to load in live mode before the security phase "
                f"verified: {reason} (controls are applied before data; "
                "pass --force to load anyway)")
        if forced:
            print(f"WARNING: loading in live mode before the security phase "
                  f"verified ({reason}); --force given, and the report "
                  "records it", file=sys.stderr)
        result = run_all({"tables": targets}, inventory, ci, backend,
                         artifacts / EXPORT_DIR,
                         gcs_bucket=bq_cfg.get("gcs_bucket") or "",
                         only=only, steps=steps,
                         gcs_prefix=f"{GCS_PREFIX}/{args.migration}",
                         cleanup=cleanup)
        report = {"verb": args.verb, "mode": backend.mode,
                  "security_verify": {"enforced": enforced,
                                      "verified": verified,
                                      "forced": forced},
                  "staging": {"export_dir": str(artifacts / EXPORT_DIR),
                              "gcs_bucket": bq_cfg.get("gcs_bucket") or "",
                              "gcs_prefix": f"{GCS_PREFIX}/{args.migration}",
                              "cleanup": cleanup,
                              "retention": RETENTION_NOTE},
                  "tables": result["tables"], "pass": result["pass"]}
        report_path = artifacts / REPORT_NAME
        artifacts.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(report, indent=2) + "\n")
        for t in report["tables"]:
            verdict = "PASS" if t["pass"] else f"FAIL: {t.get('reason', '')}"
            print(f"{t['table']}: exported={t['exported']} "
                  f"loaded={t['loaded']} seconds={t['seconds']} {verdict}")
        print(f"wrote {report_path} ({len(report['tables'])} tables, "
              f"{'pass' if report['pass'] else 'FAIL'})")
        return 0 if report["pass"] else 1
    except (LoadError, config.ConfigError, pg.PgError,
            bq_backend.BackendError) as exc:
        print(f"BQ-LOAD ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"BQ-LOAD ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(["bq-load"] + sys.argv[1:]))

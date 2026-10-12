"""Sectioned dump and restore plus object counts.

Flow: schema dump (-Fc --schema-only) restored as pre-data first and
post-data after the data load; data dump (-Fc --data-only) restored in
between with parallel jobs. Dumps run read-only via PGOPTIONS.
"""
import argparse
import json
import sys
import time
from pathlib import Path

from db_carry import pg

SYSTEM_SCHEMAS = "('pg_catalog', 'information_schema')"

OBJCOUNT_QUERIES = {
    "tables": ("SELECT count(*) FROM pg_class c JOIN pg_namespace n "
               "ON n.oid = c.relnamespace WHERE c.relkind = 'r' "
               f"AND n.nspname NOT IN {SYSTEM_SCHEMAS}"),
    "views": (f"SELECT count(*) FROM pg_views WHERE schemaname NOT IN "
              f"{SYSTEM_SCHEMAS}"),
    "matviews": "SELECT count(*) FROM pg_matviews",
    "sequences": "SELECT count(*) FROM pg_sequences",
    "indexes": (f"SELECT count(*) FROM pg_indexes WHERE schemaname NOT IN "
                f"{SYSTEM_SCHEMAS}"),
    "constraints": ("SELECT count(*) FROM pg_constraint c JOIN pg_namespace "
                    "n ON n.oid = c.connamespace WHERE n.nspname NOT IN "
                    f"{SYSTEM_SCHEMAS}"),
}


def _report(step, seconds, path=None):
    record = {"step": step, "seconds": round(seconds, 1)}
    if path:
        record["bytes"] = Path(path).stat().st_size
    print(json.dumps(record))


def do_dump(kind, ci, out):
    argv = [pg.find_bin("pg_dump"), "-Fc", "--no-owner",
            "--schema-only" if kind == "schema" else "--data-only"] \
        + pg.conn_argv(ci) + ["-f", out]
    start = time.monotonic()
    pg.run_tool(argv, ci, readonly=True)
    _report(f"dump-{kind}", time.monotonic() - start, out)
    return 0


def do_restore(section, ci, dump_path, jobs, disable_triggers):
    argv = [pg.find_bin("pg_restore"), "--no-owner", "--exit-on-error",
            "--section", section] + pg.conn_argv(ci)
    if jobs > 1:
        argv += ["-j", str(jobs)]
    if disable_triggers:
        argv += ["--disable-triggers"]
    argv.append(dump_path)
    start = time.monotonic()
    pg.run_tool(argv, ci)
    _report(f"restore-{section}", time.monotonic() - start, dump_path)
    return 0


def do_objcount(ci):
    counts = {key: int(pg.query_rows(ci, sql, readonly=True)[0][0])
              for key, sql in OBJCOUNT_QUERIES.items()}
    print(json.dumps(counts))
    return 0


def main(argv):
    verb = argv[0]
    parser = argparse.ArgumentParser(prog=f"dbcarry.py {verb}")
    if verb == "dump":
        parser.add_argument("kind", choices=["schema", "data"])
        parser.add_argument("--out", required=True)
    elif verb == "restore":
        parser.add_argument("section",
                            choices=["pre-data", "data", "post-data"])
        parser.add_argument("--dump", required=True, dest="dump_path")
        parser.add_argument("--jobs", type=int, default=1)
        parser.add_argument("--disable-triggers", action="store_true")
    pg.add_conn_args(parser)
    args = parser.parse_args(argv[1:])
    ci = pg.conn_from_args(args)
    try:
        if verb == "dump":
            return do_dump(args.kind, ci, args.out)
        if verb == "restore":
            return do_restore(args.section, ci, args.dump_path,
                              args.jobs, args.disable_triggers)
        if verb == "objcount":
            return do_objcount(ci)
        raise pg.PgError(f"unknown verb {verb}")
    except pg.PgError as exc:
        print(f"{verb.upper()} ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"{verb.upper()} ERROR: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(sys.argv[1:])

"""Locate PostgreSQL binaries and run SQL via psql.

Secrets policy: passwords come from env vars named by password_env and are
passed to child processes via PGPASSWORD. Nothing here ever prints a
password or a full connection URL. Source sessions are forced read-only
via PGOPTIONS.
"""
import os
import shutil
import subprocess
from pathlib import Path

TOOLS_ROOT = Path(os.environ.get("DBDRIFT_HOME", str(Path.home() / ".db-drift")))
PORTABLE_BIN = TOOLS_ROOT / "pg" / "pgsql" / "bin"
READONLY_OPTS = "-c default_transaction_read_only=on"


class PgError(Exception):
    pass


def find_bin(name):
    exe = shutil.which(name)
    if exe:
        return exe
    candidate = PORTABLE_BIN / (name + (".exe" if os.name == "nt" else ""))
    if candidate.exists():
        return str(candidate)
    raise PgError(
        f"{name} not found on PATH or in {PORTABLE_BIN}. "
        "Run: python scripts/dbdrift.py pg ensure-tools")


def add_conn_args(parser, prefix=""):
    dash = f"--{prefix}-" if prefix else "--"
    parser.add_argument(dash + "host", default="127.0.0.1")
    parser.add_argument(dash + "port", type=int, required=True)
    parser.add_argument(dash + "dbname", required=True)
    parser.add_argument(dash + "user", default="postgres")
    parser.add_argument(dash + "password-env", default=None)


def conn_from_args(args, prefix=""):
    pre = f"{prefix}_" if prefix else ""

    def get(key):
        return getattr(args, pre + key)

    return {"host": get("host"), "port": get("port"), "dbname": get("dbname"),
            "user": get("user"), "password_env": get("password_env")}


def build_env(ci, readonly=False):
    env = dict(os.environ)
    env["PGCLIENTENCODING"] = "UTF8"
    env.pop("PGOPTIONS", None)
    if readonly:
        env["PGOPTIONS"] = READONLY_OPTS
    password_env = ci.get("password_env")
    if password_env and password_env in os.environ:
        env["PGPASSWORD"] = os.environ[password_env]
    return env


def conn_argv(ci):
    return ["-h", ci["host"], "-p", str(ci["port"]),
            "-U", ci["user"], "-d", ci["dbname"]]


def run_tool(argv, ci, readonly=False):
    """Run a pg tool (psql, pg_dump, ...) with connection env prepared."""
    proc = subprocess.run(argv, env=build_env(ci, readonly),
                          capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        tool = Path(argv[0]).stem
        raise PgError(f"{tool} failed ({proc.returncode}): "
                      f"{proc.stderr.strip()[:800]}")
    return proc


def run_sql(ci, sql, readonly=False):
    argv = [find_bin("psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-A", "-t", "-F", "\t"] + conn_argv(ci) + ["-c", sql]
    return run_tool(argv, ci, readonly).stdout


def query_rows(ci, sql, readonly=False):
    out = run_sql(ci, sql, readonly)
    return [line.split("\t") for line in out.splitlines() if line]

"""Portable PostgreSQL bootstrap and local instance lifecycle.

Downloads the pinned EDB binaries zip on Windows when no tools are on
PATH. Instances are plain data directories under ~/.db-drift/instances,
listening on 127.0.0.1 only, auth=trust (local demo instances hold only
generated demo data). initdb and pg_ctl self-drop admin privileges on
Windows via restricted tokens.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from db_drift import pg

PG_VERSION = "17.5-1"
PG_URL = ("https://get.enterprisedb.com/postgresql/"
          f"postgresql-{PG_VERSION}-windows-x64-binaries.zip")
# Pinned after first verified download (Task 2 Step 4 records the value).
PG_SHA256 = "795196df1b2855fd0c7fb52629c6cc16acaa85819912e732bd4c46863e77eb30"
INSTANCES = pg.TOOLS_ROOT / "instances"


def _tools_on_path():
    return all(shutil.which(n) for n in ("initdb", "pg_ctl", "psql", "pg_dump"))


def ensure_tools():
    if _tools_on_path():
        print("tools: PATH")
        return 0
    if pg.PORTABLE_BIN.joinpath("psql.exe" if os.name == "nt" else "psql").exists():
        print(f"tools: {pg.PORTABLE_BIN}")
        return 0
    if os.name != "nt":
        raise pg.PgError(
            "No PostgreSQL tools on PATH. Install them with your package "
            "manager (e.g. apt install postgresql postgresql-client).")
    dest = pg.TOOLS_ROOT / "pg"
    dest.mkdir(parents=True, exist_ok=True)
    zip_path = dest / "download.zip"
    print(f"downloading {PG_URL}")
    with urllib.request.urlopen(PG_URL) as resp, open(zip_path, "wb") as out:
        copied = 0
        while chunk := resp.read(1 << 20):
            out.write(chunk)
            copied += len(chunk)
            if copied % (50 << 20) < (1 << 20):
                print(f"  {copied >> 20} MB")
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    if PG_SHA256 and digest != PG_SHA256:
        zip_path.unlink()
        raise pg.PgError(
            f"SHA256 mismatch: expected {PG_SHA256}, got {digest}. "
            "Refusing to unpack; download the binaries manually from "
            "enterprisedb.com and unzip into " + str(dest))
    import zipfile
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    zip_path.unlink()
    (dest / "manifest.json").write_text(json.dumps(
        {"url": PG_URL, "sha256": digest, "version": PG_VERSION}, indent=2),
        encoding="utf-8")
    if not pg.PORTABLE_BIN.joinpath("psql.exe").exists():
        raise pg.PgError(f"unzip did not produce {pg.PORTABLE_BIN}")
    print(f"tools: {pg.PORTABLE_BIN} (sha256 {digest})")
    return 0


def _inst(name):
    return INSTANCES / name


def _meta(name):
    meta_path = _inst(name) / "meta.json"
    if not meta_path.exists():
        raise pg.PgError(f"no such instance: {name}")
    return json.loads(meta_path.read_text(encoding="utf-8"))


def _run(argv):
    proc = subprocess.run(argv, capture_output=True, text=True,
                          encoding="utf-8")
    if proc.returncode != 0:
        raise pg.PgError(f"{Path(argv[0]).stem} failed: "
                         f"{(proc.stderr or proc.stdout).strip()[:800]}")
    return proc


def create(name, port, wal_level):
    inst = _inst(name)
    if inst.exists():
        raise pg.PgError(f"instance {name} already exists at {inst}")
    data = inst / "data"
    data.parent.mkdir(parents=True, exist_ok=True)
    _run([pg.find_bin("initdb"), "-D", str(data), "-U", "postgres",
          "-A", "trust", "-E", "UTF8", "--locale=C"])
    with (data / "postgresql.conf").open("a", encoding="utf-8") as fh:
        fh.write(f"\n# db-drift\nport = {port}\n"
                 "listen_addresses = '127.0.0.1'\n"
                 f"wal_level = {wal_level}\n")
    (inst / "meta.json").write_text(
        json.dumps({"port": port, "wal_level": wal_level}, indent=2),
        encoding="utf-8")
    print(f"created {name} (port {port}, wal_level {wal_level})")
    return 0


def start(name):
    meta = _meta(name)
    inst = _inst(name)
    # Not _run(): pg_ctl start leaves a detached postgres.exe running, and
    # on Windows that grandchild inherits our captured stdout/stderr pipe
    # handles, so capture_output=True never sees EOF and hangs forever
    # once the server is actually up. Discard instead; the real startup
    # log is already captured by pg_ctl's own -l file.
    proc = subprocess.run([pg.find_bin("pg_ctl"), "-D", str(inst / "data"),
                           "-l", str(inst / "pg.log"), "-w", "start"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if proc.returncode != 0:
        raise pg.PgError(f"pg_ctl start failed ({proc.returncode}); "
                         f"see {inst / 'pg.log'}")
    ready = [pg.find_bin("pg_isready"), "-h", "127.0.0.1",
             "-p", str(meta["port"])]
    for _ in range(30):
        if subprocess.run(ready, capture_output=True).returncode == 0:
            print(f"started {name} on 127.0.0.1:{meta['port']}")
            return 0
        time.sleep(1)
    raise pg.PgError(f"{name} did not become ready; see {inst / 'pg.log'}")


def stop(name):
    _meta(name)
    _run([pg.find_bin("pg_ctl"), "-D", str(_inst(name) / "data"),
          "-m", "fast", "-w", "stop"])
    print(f"stopped {name}")
    return 0


def status(name):
    meta = _meta(name)
    ready = subprocess.run(
        [pg.find_bin("pg_isready"), "-h", "127.0.0.1", "-p", str(meta["port"])],
        capture_output=True)
    print(json.dumps({"name": name, "port": meta["port"],
                      "wal_level": meta["wal_level"],
                      "running": ready.returncode == 0}))
    return 0


def destroy(name, yes):
    meta = _meta(name)
    if not yes:
        raise pg.PgError(
            f"destroy is irreversible; re-run with --yes to delete "
            f"instance {name} and its data directory")
    ready = subprocess.run(
        [pg.find_bin("pg_isready"), "-h", "127.0.0.1", "-p", str(meta["port"])],
        capture_output=True)
    if ready.returncode == 0:
        raise pg.PgError(f"{name} is running; stop it first")
    shutil.rmtree(_inst(name))
    print(f"destroyed {name}")
    return 0


def set_conf(name, setting):
    key, _, value = setting.partition("=")
    if not value:
        raise pg.PgError("expected --set key=value")
    data = _inst(name) / "data"
    _meta(name)
    with (data / "postgresql.conf").open("a", encoding="utf-8") as fh:
        fh.write(f"{key.strip()} = {value.strip()}\n")
    meta = _meta(name)
    if key.strip() == "wal_level":
        meta["wal_level"] = value.strip()
        (_inst(name) / "meta.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8")
    print(f"set {key.strip()} = {value.strip()} on {name}; restart required")
    return 0


def list_instances():
    if not INSTANCES.exists():
        print("[]")
        return 0
    print(json.dumps(sorted(p.name for p in INSTANCES.iterdir() if p.is_dir())))
    return 0


def main(argv):
    parser = argparse.ArgumentParser(prog="dbdrift.py pg")
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("ensure-tools")
    p = sub.add_parser("create")
    p.add_argument("--name", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--wal-level", default="replica",
                   choices=["replica", "logical"])
    for verb in ("start", "stop", "status"):
        sub.add_parser(verb).add_argument("--name", required=True)
    p = sub.add_parser("destroy")
    p.add_argument("--name", required=True)
    p.add_argument("--yes", action="store_true")
    p = sub.add_parser("set-conf")
    p.add_argument("--name", required=True)
    p.add_argument("--set", dest="setting", required=True)
    sub.add_parser("list")
    args = parser.parse_args(argv[1:])
    try:
        if args.verb == "ensure-tools":
            return ensure_tools()
        if args.verb == "create":
            return create(args.name, args.port, args.wal_level)
        if args.verb == "start":
            return start(args.name)
        if args.verb == "stop":
            return stop(args.name)
        if args.verb == "status":
            return status(args.name)
        if args.verb == "destroy":
            return destroy(args.name, args.yes)
        if args.verb == "set-conf":
            return set_conf(args.name, args.setting)
        if args.verb == "list":
            return list_instances()
    except pg.PgError as exc:
        print(f"PG ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(["pg"] + sys.argv[1:])

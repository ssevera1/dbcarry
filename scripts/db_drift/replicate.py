"""Logical replication lifecycle: publication, subscription, lag.

The subscription connection string is built without a password: v1
supports trust or .pgpass auth for the subscriber-to-source link,
because a password in CREATE SUBSCRIPTION lands in the target catalog.
The create-publication call is the pipeline's one approved source
write (Gate 1 lists it).
"""
import argparse
import json
import sys
import time

from db_drift import pg

READY_SQL = ("SELECT count(*) FILTER (WHERE srsubstate <> 'r'), count(*) "
             "FROM pg_subscription_rel")
LAG_SQL = ("SELECT coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), "
           "confirmed_flush_lsn), 0)::bigint FROM pg_replication_slots "
           "WHERE slot_name = %s")


def create_publication(ci, name):
    pg.run_sql(ci, f'CREATE PUBLICATION "{name}" FOR ALL TABLES')
    print(f"created publication {name}")
    return 0


def create_subscription(ci, name, publication, src):
    conn = (f"host={src['host']} port={src['port']} "
            f"dbname={src['dbname']} user={src['user']}")
    pg.run_sql(ci, f"CREATE SUBSCRIPTION \"{name}\" CONNECTION '{conn}' "
                   f"PUBLICATION \"{publication}\"")
    print(f"created subscription {name}")
    return 0


def status(ci):
    unready = pg.query_rows(ci, READY_SQL)[0]
    print(json.dumps({"tables_total": int(unready[1]),
                      "tables_not_ready": int(unready[0])}))
    return 0


def wait_synced(target_ci, source_ci, slot, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        unready, total = pg.query_rows(target_ci, READY_SQL)[0]
        lag_sql = LAG_SQL.replace("%s", f"'{slot}'")
        lag_rows = pg.query_rows(source_ci, lag_sql, readonly=True)
        lag = int(lag_rows[0][0]) if lag_rows else -1
        print(json.dumps({"tables_not_ready": int(unready),
                          "tables_total": int(total), "lag_bytes": lag}))
        if int(unready) == 0 and 0 <= lag < 16384:
            print("synced")
            return 0
        time.sleep(5)
    print("TIMEOUT: not synced", file=sys.stderr)
    return 1


def drop_subscription(ci, name):
    pg.run_sql(ci, f'DROP SUBSCRIPTION IF EXISTS "{name}"')
    print(f"dropped subscription {name}")
    return 0


def drop_publication(ci, name):
    pg.run_sql(ci, f'DROP PUBLICATION IF EXISTS "{name}"')
    slots = pg.query_rows(
        ci, "SELECT slot_name FROM pg_replication_slots "
            "WHERE NOT active AND slot_name LIKE 'dbdrift%'")
    for (slot,) in slots:
        pg.run_sql(ci, f"SELECT pg_drop_replication_slot('{slot}')")
        print(f"dropped orphan slot {slot}")
    print(f"dropped publication {name}")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(prog="dbdrift.py replicate")
    sub = parser.add_subparsers(dest="verb", required=True)
    p = sub.add_parser("create-publication")
    pg.add_conn_args(p)
    p.add_argument("--name", default="dbdrift_pub")
    p = sub.add_parser("create-subscription")
    pg.add_conn_args(p)
    pg.add_conn_args(p, "source")
    p.add_argument("--name", default="dbdrift_sub")
    p.add_argument("--publication", default="dbdrift_pub")
    p = sub.add_parser("status")
    pg.add_conn_args(p)
    p = sub.add_parser("wait-synced")
    pg.add_conn_args(p)
    pg.add_conn_args(p, "source")
    p.add_argument("--slot", default="dbdrift_sub")
    p.add_argument("--timeout", type=int, default=600)
    p = sub.add_parser("drop-subscription")
    pg.add_conn_args(p)
    p.add_argument("--name", default="dbdrift_sub")
    p = sub.add_parser("drop-publication")
    pg.add_conn_args(p)
    p.add_argument("--name", default="dbdrift_pub")
    args = parser.parse_args(argv[1:])
    ci = pg.conn_from_args(args)
    try:
        if args.verb == "create-publication":
            return create_publication(ci, args.name)
        if args.verb == "create-subscription":
            if getattr(args, "source_password_env", None):
                raise pg.PgError(
                    "v1 subscriptions support trust/.pgpass auth only; a "
                    "password here would persist in the target catalog")
            return create_subscription(ci, args.name, args.publication,
                                      pg.conn_from_args(args, "source"))
        if args.verb == "status":
            return status(ci)
        if args.verb == "wait-synced":
            return wait_synced(ci, pg.conn_from_args(args, "source"),
                               args.slot, args.timeout)
        if args.verb == "drop-subscription":
            return drop_subscription(ci, args.name)
        if args.verb == "drop-publication":
            return drop_publication(ci, args.name)
    except pg.PgError as exc:
        print(f"REPLICATE ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(["replicate"] + sys.argv[1:])

"""Dispatch a top-level verb to its implementing module."""
import importlib

SUBCOMMANDS = {
    "state": "db_drift.state",
    "pg": "db_drift.portable_pg",
    "seed": "db_drift.seed_demo",
    "inventory": "db_drift.inventory",
    "dump": "db_drift.dump_restore",
    "restore": "db_drift.dump_restore",
    "objcount": "db_drift.dump_restore",
    "checksum": "db_drift.checksum",
    "replicate": "db_drift.replicate",
    "security": "db_drift.security",
    "bq-schema": "db_drift.bq_schema",
    "bq-security": "db_drift.bq_security",
    "bq-load": "db_drift.bq_load",
    "bq-validate": "db_drift.bq_validate",
    "bq-backend": "db_drift.bq_backend",
}


def main(argv):
    if not argv or argv[0] in ("-h", "--help") or argv[0] not in SUBCOMMANDS:
        verbs = ", ".join(sorted(set(SUBCOMMANDS)))
        print(f"usage: dbdrift.py <verb> [args]\nverbs: {verbs}")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    module = importlib.import_module(SUBCOMMANDS[argv[0]])
    return module.main(argv)

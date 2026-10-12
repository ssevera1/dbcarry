"""Dispatch a top-level verb to its implementing module."""
import importlib

SUBCOMMANDS = {
    "state": "db_carry.state",
    "pg": "db_carry.portable_pg",
    "seed": "db_carry.seed_demo",
    "inventory": "db_carry.inventory",
    "dump": "db_carry.dump_restore",
    "restore": "db_carry.dump_restore",
    "objcount": "db_carry.dump_restore",
    "checksum": "db_carry.checksum",
    "replicate": "db_carry.replicate",
    "security": "db_carry.security",
    "bq-schema": "db_carry.bq_schema",
    "bq-security": "db_carry.bq_security",
    "bq-load": "db_carry.bq_load",
    "bq-validate": "db_carry.bq_validate",
    "bq-backend": "db_carry.bq_backend",
}


def main(argv):
    if not argv or argv[0] in ("-h", "--help") or argv[0] not in SUBCOMMANDS:
        verbs = ", ".join(sorted(set(SUBCOMMANDS)))
        print(f"usage: dbcarry.py <verb> [args]\nverbs: {verbs}")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    module = importlib.import_module(SUBCOMMANDS[argv[0]])
    return module.main(argv)

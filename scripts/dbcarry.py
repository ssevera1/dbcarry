"""dbcarry CLI entrypoint. Usage: python scripts/dbcarry.py <verb> [args]."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from db_carry import cli  # noqa: E402

if __name__ == "__main__":
    sys.exit(cli.main(sys.argv[1:]))

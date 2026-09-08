"""Read migration.yaml and the principal map without a YAML dependency.

The pipeline writes these files in a small, regular shape (nested
mappings by indentation, scalar values, short lists), so a subset parser
covers them. Anything fancier (anchors, multi-line scalars, flow
collections) is out of scope and raises ConfigError.
"""
import json
from pathlib import Path


class ConfigError(Exception):
    pass


BQ_DEFAULTS = {
    "mode": "emulated",
    "project": "emulated-project",
    "location": "US",
    "dataset_map": {},
    "principal_map": "security/principal-map.yaml",
    "admin_principal": "",
    "public_principal": "",
    "column_security": "policy_tags",
    "binding_granularity": "auto",
    "gcs_bucket": "",
}


def _strip_comment(line):
    out = []
    quote = None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _scalar(text):
    text = text.strip()
    if text == "":
        return ""
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        inner = text[1:-1]
        if text[0] == '"':
            try:
                return json.loads(text)
            except ValueError:
                return inner
        return inner.replace("''", "'")
    low = text.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    if text.lstrip("-").isdigit():
        return int(text)
    if text in ("{}", "[]"):
        return {} if text == "{}" else []
    return text


def _split_key(content):
    """Split 'key: value' at the first colon outside quotes."""
    quote = None
    for i, ch in enumerate(content):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == ":" and (i + 1 == len(content) or content[i + 1] in " \t"):
            return content[:i].strip(), content[i + 1:].strip()
    return None, None


def parse_yaml_subset(text):
    lines = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))
    root = {}
    pos = [0]

    def parse_block(indent):
        """Parse a mapping or a list at exactly this indent."""
        if pos[0] >= len(lines):
            return {}
        if lines[pos[0]][1].startswith("- "):
            items = []
            while pos[0] < len(lines) and lines[pos[0]][0] == indent \
                    and lines[pos[0]][1].startswith("- "):
                items.append(_scalar(lines[pos[0]][1][2:]))
                pos[0] += 1
            return items
        mapping = {}
        while pos[0] < len(lines) and lines[pos[0]][0] == indent:
            content = lines[pos[0]][1]
            key, value = _split_key(content)
            if key is None:
                raise ConfigError(f"cannot parse line: {content!r}")
            key = _scalar(key) if key[:1] in ("'", '"') else key
            pos[0] += 1
            if value == "":
                if pos[0] < len(lines) and lines[pos[0]][0] > indent:
                    mapping[key] = parse_block(lines[pos[0]][0])
                else:
                    mapping[key] = ""
            else:
                mapping[key] = _scalar(value)
        if pos[0] < len(lines) and lines[pos[0]][0] > indent:
            raise ConfigError(
                f"unexpected indentation at: {lines[pos[0]][1]!r}")
        return mapping

    if lines:
        root = parse_block(lines[0][0])
    if pos[0] < len(lines):
        raise ConfigError(f"unparsed trailing content: {lines[pos[0]][1]!r}")
    return root


def workspace(root, migration):
    return Path(root) / "migrations" / migration


def load_migration(root, migration):
    path = workspace(root, migration) / "migration.yaml"
    if not path.exists():
        raise ConfigError(f"no migration.yaml at {path}; run init first")
    cfg = parse_yaml_subset(path.read_text(encoding="utf-8"))
    for key in ("migration", "provider", "source"):
        if key not in cfg:
            raise ConfigError(f"migration.yaml missing key: {key}")
    return cfg


def source_conn(mig):
    src = mig["source"]
    if not isinstance(src, dict):
        raise ConfigError("migration.yaml source must be a mapping")
    return {
        "host": str(src.get("host", "127.0.0.1")),
        "port": int(src.get("port", 5432)),
        "dbname": str(src["dbname"]),
        "user": str(src.get("user", "postgres")),
        "password_env": (str(src.get("password_env") or "") or None),
    }


def bigquery_config(mig, migration):
    block = mig.get("bigquery") or {}
    if not isinstance(block, dict):
        raise ConfigError("migration.yaml bigquery must be a mapping")
    cfg = dict(BQ_DEFAULTS)
    cfg["dataset_map"] = dict(BQ_DEFAULTS["dataset_map"])
    for key, value in block.items():
        if key == "dataset_map":
            cfg["dataset_map"] = dict(value or {})
        else:
            cfg[key] = "" if value is None else value
    if cfg["mode"] not in ("emulated", "live"):
        raise ConfigError(f"bigquery.mode must be emulated or live, "
                          f"got {cfg['mode']!r}")
    cfg["migration"] = migration
    cfg["dbname"] = str(mig["source"]["dbname"])
    return cfg


def load_principal_map(path):
    p = Path(path)
    if not p.exists():
        return {"roles": {}}
    cfg = parse_yaml_subset(p.read_text(encoding="utf-8"))
    roles = cfg.get("roles") or {}
    if not isinstance(roles, dict):
        raise ConfigError("principal map: roles must be a mapping")
    out = {}
    for name, entry in roles.items():
        entry = entry if isinstance(entry, dict) else {}
        out[name] = {
            "principal": str(entry.get("principal") or ""),
            "probe_service_account":
                str(entry.get("probe_service_account") or ""),
        }
    return {"roles": out}

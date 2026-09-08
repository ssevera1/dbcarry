import pytest

from db_drift import config

SAMPLE = """# comment
migration: demo-run
engine: postgres
provider: bigquery
downtime_tolerance: flexible   # inline comment
source:
  host: 127.0.0.1
  port: 55432
  dbname: retail
  user: postgres
  password_env: ""
bigquery:
  mode: emulated
  project: my-sandbox
  dataset_map:
    public: retail
  admin_principal: "user:op@example.com"
notes: "Acceptance run: v0.2.0 # not a comment"
"""


def test_parse_nested_mappings_and_scalars():
    cfg = config.parse_yaml_subset(SAMPLE)
    assert cfg["source"]["port"] == 55432
    assert cfg["source"]["password_env"] == ""
    assert cfg["downtime_tolerance"] == "flexible"
    assert cfg["bigquery"]["dataset_map"] == {"public": "retail"}
    assert cfg["bigquery"]["admin_principal"] == "user:op@example.com"
    assert cfg["notes"] == "Acceptance run: v0.2.0 # not a comment"


def test_bigquery_defaults_and_overrides():
    cfg = config.parse_yaml_subset(SAMPLE)
    bq = config.bigquery_config(cfg, "demo-run")
    assert bq["mode"] == "emulated" and bq["location"] == "US"
    assert bq["project"] == "my-sandbox"
    assert bq["column_security"] == "policy_tags"
    assert bq["binding_granularity"] == "auto"
    assert bq["dbname"] == "retail" and bq["migration"] == "demo-run"
    assert bq["principal_map"] == "security/principal-map.yaml"


def test_bigquery_block_absent_gives_defaults():
    cfg = config.parse_yaml_subset(
        "migration: x\nprovider: local\nsource:\n  dbname: d\n")
    bq = config.bigquery_config(cfg, "x")
    assert bq["project"] == "emulated-project"
    assert bq["dataset_map"] == {}


def test_bad_mode_rejected():
    cfg = config.parse_yaml_subset(
        "migration: x\nsource:\n  dbname: d\nbigquery:\n  mode: sideways\n")
    with pytest.raises(config.ConfigError, match="mode"):
        config.bigquery_config(cfg, "x")


def test_lists_and_booleans():
    cfg = config.parse_yaml_subset(
        "flags:\n  - a\n  - b\nenabled: true\noff: false\n")
    assert cfg["flags"] == ["a", "b"]
    assert cfg["enabled"] is True and cfg["off"] is False


def test_source_conn():
    cfg = config.parse_yaml_subset(SAMPLE)
    ci = config.source_conn(cfg)
    assert ci == {"host": "127.0.0.1", "port": 55432, "dbname": "retail",
                  "user": "postgres", "password_env": None}


def test_principal_map(tmp_path):
    p = tmp_path / "pm.yaml"
    p.write_text(
        'roles:\n  app_ro:\n    principal: "group:ro@example.com"\n'
        '  app_rw:\n    principal: ""\n    probe_service_account: sa@x.iam\n',
        encoding="utf-8")
    pm = config.load_principal_map(str(p))
    assert pm["roles"]["app_ro"]["principal"] == "group:ro@example.com"
    assert pm["roles"]["app_ro"]["probe_service_account"] == ""
    assert pm["roles"]["app_rw"]["principal"] == ""
    assert pm["roles"]["app_rw"]["probe_service_account"] == "sa@x.iam"
    assert config.load_principal_map(str(tmp_path / "missing.yaml")) == {
        "roles": {}}


def test_load_migration_requires_file(tmp_path):
    with pytest.raises(config.ConfigError, match="run init"):
        config.load_migration(str(tmp_path), "nope")
    ws = tmp_path / "migrations" / "m"
    ws.mkdir(parents=True)
    (ws / "migration.yaml").write_text(SAMPLE, encoding="utf-8")
    mig = config.load_migration(str(tmp_path), "m")
    assert mig["provider"] == "bigquery"


def test_unparseable_line_raises():
    with pytest.raises(config.ConfigError):
        config.parse_yaml_subset("just some words\n")

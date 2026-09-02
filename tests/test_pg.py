from db_drift import pg

CI = {"host": "127.0.0.1", "port": 5432, "dbname": "demo", "user": "postgres",
      "password_env": None}


def test_build_env_no_flags_does_not_set_pgoptions():
    env = pg.build_env(CI)
    assert "PGOPTIONS" not in env


def test_build_env_no_flags_strips_inherited_pgoptions(monkeypatch):
    monkeypatch.setenv("PGOPTIONS", "-c some_pre_existing_option=on")
    env = pg.build_env(CI)
    assert "PGOPTIONS" not in env


def test_build_env_readonly_sets_readonly_opts():
    env = pg.build_env(CI, readonly=True)
    assert env["PGOPTIONS"] == pg.READONLY_OPTS


def test_build_env_writable_sets_writable_opts():
    env = pg.build_env(CI, writable=True)
    assert env["PGOPTIONS"] == pg.WRITABLE_OPTS


def test_build_env_writable_takes_precedence_over_readonly():
    env = pg.build_env(CI, readonly=True, writable=True)
    assert env["PGOPTIONS"] == pg.WRITABLE_OPTS

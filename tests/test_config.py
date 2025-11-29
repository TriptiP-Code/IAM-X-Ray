import os
import tempfile
import pytest
import importlib
from unittest.mock import patch, MagicMock


def reload_config_with_secrets(fake_secrets, extra_env=None):
    # Optional ENV overrides
    if extra_env:
        for k, v in extra_env.items():
            os.environ[k] = v

    # Patch full streamlit module
    fake_st = MagicMock()
    fake_st.secrets = fake_secrets

    with patch.dict("sys.modules", {"streamlit": fake_st}):
        import core.config as cfg
        importlib.reload(cfg)
        return cfg


# ----- SECRET LOOKUP -----
def test_secret_nested_lookup():
    cfg = reload_config_with_secrets({"APP": {"KEY": "VALUE"}})
    assert cfg._secret("APP", "KEY") == "VALUE"


def test_secret_missing_returns_default():
    cfg = reload_config_with_secrets({})
    assert cfg._secret("APP", "NO", default=123) == 123


# ----- INT PARSER -----
def test_int_parser_valid(monkeypatch):
    import core.config as cfg
    monkeypatch.setenv("MY_VAL", "42")
    assert cfg._int("MY_VAL", 5) == 42


def test_int_parser_invalid(monkeypatch):
    import core.config as cfg
    monkeypatch.setenv("MY_VAL", "no")
    assert cfg._int("MY_VAL", 5) == 5


# ----- PATHS -----
def test_data_dir_env_override(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("IAM_XRAY_DATA_DIR", tmp)
        cfg = reload_config_with_secrets({})
        assert cfg.DATA_DIR == tmp


def test_snapshot_path_env(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "a.json")
        monkeypatch.setenv("IAM_XRAY_SNAPSHOT_PATH", snap)
        cfg = reload_config_with_secrets({})
        assert cfg.SNAPSHOT_PATH == snap


# ----- KEEP_DAYS -----
def test_keep_days_secret_priority():
    cfg = reload_config_with_secrets({"APP": {"KEEP_DAYS": 9}})
    assert cfg.KEEP_DAYS == 9


def test_keep_days_env(monkeypatch):
    monkeypatch.setenv("KEEP_DAYS", "7")
    cfg = reload_config_with_secrets({})
    assert cfg.KEEP_DAYS == 7


# ----- FERNET KEY -----
def test_fernet_key_from_app_secret():
    cfg = reload_config_with_secrets({"APP": {"FERNET_KEY": "AAA"}})
    assert cfg.FERNET_KEY == "AAA"


def test_fernet_key_from_root_secret():
    cfg = reload_config_with_secrets({"FERNET_KEY": "BBB"})
    assert cfg.FERNET_KEY == "BBB"


def test_fernet_key_from_env(monkeypatch):
    monkeypatch.setenv("IAM_XRAY_FERNET_KEY", "CCC")
    cfg = reload_config_with_secrets({})
    assert cfg.FERNET_KEY == "CCC"


def test_fernet_key_local_fallback(monkeypatch):
    monkeypatch.delenv("IAM_XRAY_FERNET_KEY", raising=False)
    cfg = reload_config_with_secrets({})
    assert cfg.FERNET_KEY == "0" * 32


# ----- RERUN -----
def test_rerun_prefers_st_rerun():
    fake_st = MagicMock()
    fake_st.rerun = MagicMock()

    with patch.dict("sys.modules", {"streamlit": fake_st}):
        import core.config as cfg
        importlib.reload(cfg)
        cfg.rerun()

    fake_st.rerun.assert_called_once()


def test_rerun_uses_experimental():
    fake_st = MagicMock()
    fake_st.rerun = None
    fake_st.experimental_rerun = MagicMock()

    with patch.dict("sys.modules", {"streamlit": fake_st}):
        import core.config as cfg
        importlib.reload(cfg)
        cfg.rerun()

    fake_st.experimental_rerun.assert_called_once()

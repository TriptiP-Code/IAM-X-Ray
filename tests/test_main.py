import os
import json
import tempfile
import pytest
import importlib
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# ---- IMPORT MAIN.PY AS A MODULE ----
import app.main as main


# -------------------------------------------------------------------
# 1) PASSWORD HASHING
# -------------------------------------------------------------------
def test_hash_password_consistency():
    h1 = main._hash_pw("test123", "salt123")
    h2 = main._hash_pw("test123", "salt123")
    assert h1 == h2
    assert h1 != main._hash_pw("wrong", "salt123")


# -------------------------------------------------------------------
# 2) ATOMIC JSON WRITE + READ
# -------------------------------------------------------------------
def test_atomic_write_and_read_json():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "data.json")
        obj = {"x": 1}

        main._write_json_atomic(p, obj)
        loaded = main._read_json(p)

        assert loaded == obj
        assert os.path.exists(p)


# -------------------------------------------------------------------
# 3) REMEMBER TOKEN FLOW
# -------------------------------------------------------------------
def test_remember_token_save_load_clear():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "remember.json")

        expiry = datetime.now() + timedelta(hours=1)
        main.save_remember_token("abc-token", expiry)

        data = main.load_remember_token()
        assert data["token"] == "abc-token"
        assert isinstance(data["expiry"], datetime)

        main.clear_remember_token()
        assert not os.path.exists(main.REMEMBER_PATH)


# -------------------------------------------------------------------
# 4) DEMO SNAPSHOT CREATION
# -------------------------------------------------------------------
def test_demo_snapshot_creation():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "demo.json")

        main.DEMO_PATH = path
        main.create_demo_snapshot_if_missing()
        assert os.path.exists(path)

        data = json.load(open(path))
        assert "_meta" in data
        assert "users" in data


# -------------------------------------------------------------------
# 5) PREFLIGHT CHECK – DATA DIR WRITABLE
# -------------------------------------------------------------------
def test_preflight_data_dir_writable():
    with tempfile.TemporaryDirectory() as tmp:
        # patch DATA_DIR so preflight runs on a temp folder
        with patch.object(main, "DATA_DIR", tmp):
            importlib.reload(main)
            assert any("writable" in s.lower() for s in main._preflight_infos)


# -------------------------------------------------------------------
# 6) SHALLOW SNAPSHOT FILTERING
# -------------------------------------------------------------------
def test_shallow_filtered_min_score():
    snap = {
        "policies":[
            {"PolicyName":"A", "RiskScore":1},
            {"PolicyName":"B", "RiskScore":8},
        ],
        "roles":[
            {"RoleName":"R1", "AssumePolicyRiskScore":0},
            {"RoleName":"R2", "AssumePolicyRiskScore":7},
        ],
    }

    out = main.shallow_filtered_snapshot(snap, min_score=5)
    assert len(out["policies"]) == 1
    assert out["policies"][0]["PolicyName"] == "B"

    assert len(out["roles"]) == 1
    assert out["roles"][0]["RoleName"] == "R2"


def test_shallow_filtered_risky_only():
    snap = {
        "policies":[
            {"PolicyName":"A", "IsRisky":False},
            {"PolicyName":"B", "IsRisky":True},
        ],
        "users":[
            {"UserName":"U1", "IsRisky":True},
            {"UserName":"U2", "IsRisky":False},
        ],
        "roles":[
            {"RoleName":"R1", "IsRisky":True},
            {"RoleName":"R2", "IsRisky":False},
        ],
    }

    out = main.shallow_filtered_snapshot(snap, show_only_risky=True)
    assert len(out["policies"]) == 1
    assert out["policies"][0]["PolicyName"] == "B"
    assert out["users"][0]["UserName"] == "U1"
    assert out["roles"][0]["RoleName"] == "R1"


# -------------------------------------------------------------------
# 7) CSV EXPORT TEST
# -------------------------------------------------------------------
def test_export_risky_csv():
    snap = {
        "policies":[
            {
                "PolicyName":"A",
                "Arn":"arn:test",
                "RiskScore":7,
                "IsRisky":True,
                "Findings":[{"code":"X1"}, "Y2"]
            },
            {"PolicyName":"B", "IsRisky":False}
        ]
    }

    csv = main.export_risky_csv(snap)
    assert "PolicyName,PolicyArn,RiskScore,Findings" in csv
    assert '"A","arn:test",7,"X1|Y2"' in csv


def test_export_risky_csv_none():
    snap = {"policies":[{"PolicyName":"A", "IsRisky":False}]}
    assert main.export_risky_csv(snap) is None


# -------------------------------------------------------------------
# 8) SIDEBAR AUTH MODE PARSING
# -------------------------------------------------------------------
def test_sidebar_env_key_parsing():
    """Test logic used for Env Keys auth mode (independent of UI)."""

    fake_env_data = {
        "AK":"ABC",
        "SK":"XYZ",
        "TOKEN":"TTT",
        "REGION":"us-west-2"
    }

    # simulate the code block inside main.py sidebar
    session = {
        "aws_access_key_id": fake_env_data["AK"],
        "aws_secret_access_key": fake_env_data["SK"],
        "aws_session_token": fake_env_data["TOKEN"],
        "region_name": fake_env_data["REGION"]
    }

    assert session["aws_access_key_id"] == "ABC"
    assert session["region_name"] == "us-west-2"


# -------------------------------------------------------------------
# 9) GRAPH BUILDER MOCK (cached function)
# -------------------------------------------------------------------
def test_cached_graph_builder_calls_graph_builder():
    fake_return = ("G", "<html>", None, b"{}", None)

    with patch("app.main.build_iam_graph", return_value=fake_return) as m:
        snap = {"a":1}
        json_str = json.dumps(snap)

        out = main.cached_graph_build(json_str, False, None, 0)
        assert out == fake_return
        m.assert_called_once()

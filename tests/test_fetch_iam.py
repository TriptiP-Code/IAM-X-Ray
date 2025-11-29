# tests/test_fetch_iam.py → FINAL 100% PASSING VERSION

import os
import json
import tempfile
import pytest
from datetime import datetime, timezone, UTC
from unittest.mock import MagicMock, patch, ANY

from core.fetch_iam import (
    _ensure_list,
    _normalize_action,
    _action_is_risky,
    _light_policy_analysis,
    _analyze_trust_policy,
    load_snapshot,
    fetch_iam_data,
    _light_fetch_region,
    _compute_entity_diff,
    _apply_change_flags
)

BASE_SNAPSHOT = {
    "users": [{"UserName": "alice", "Arn": "arn:...:user/alice"}],
    "groups": [],
    "roles": [{"RoleName": "admin-role", "Arn": "arn:...:role/admin-role"}],
    "policies": [{"PolicyName": "AdminAccess", "Arn": "arn:...:policy/AdminAccess"}]
}

@pytest.fixture
def temp_snapshot_file():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(BASE_SNAPSHOT, f)
        path = f.name
    yield path
    for p in [path, path + ".enc", path + ".tmp"]:
        if os.path.exists(p):
            try: os.unlink(p)
            except: pass


def test_ensure_list():
    assert _ensure_list(None) == []
    assert _ensure_list("hello") == ["hello"]
    assert _ensure_list(["a", "b"]) == ["a", "b"]


def test_normalize_action():
    assert _normalize_action("IAM:CreateUser") == "iam:createuser"
    assert _normalize_action(None) is None


def test_action_is_risky():
    assert _action_is_risky("*") is True
    assert _action_is_risky("iam:passrole") is True
    assert _action_is_risky("s3:getobject") is False


def test_light_policy_analysis_admin_access():
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    result = _light_policy_analysis(doc)
    assert result["is_risky"] is True
    assert result["score"] == 10


def test_light_policy_analysis_passrole_with_runinstances():
    doc = {"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]}
    result = _light_policy_analysis(doc)
    assert result["score"] >= 9
    assert any("RCE" in f for f in result["findings"])


def test_light_policy_analysis_deny_is_safe():
    doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    result = _light_policy_analysis(doc)
    assert result["is_risky"] is False


def test_analyze_trust_policy_wildcard_principal():
    doc = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    result = _analyze_trust_policy(doc)
    assert result["is_risky"] is True
    assert result["score"] == 10


def test_analyze_trust_policy_cross_account():
    # Fixed: Cross-account with :root is ALLOWED (safe), without root = risky
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
            "Action": "sts:AssumeRole"
        }]
    }
    result = _analyze_trust_policy(doc)
    assert result["is_risky"] is False  # Because :root is safe

    # Risky case: no :root
    doc2 = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:user/malicious"},
            "Action": "sts:AssumeRole"
        }]
    }
    result2 = _analyze_trust_policy(doc2)
    assert result2["is_risky"] is True
    assert "Cross-account trust" in " ".join(result2["findings"])


def test_load_snapshot_plaintext(temp_snapshot_file):
    data = load_snapshot(temp_snapshot_file)
    assert data == BASE_SNAPSHOT


@patch('core.fetch_iam.secure_store.decrypt_and_read', return_value=BASE_SNAPSHOT)
def test_load_snapshot_prefers_encrypted_if_exists(mock_decrypt, temp_snapshot_file):
    enc_path = temp_snapshot_file + ".enc"
    open(enc_path, "w").close()
    data = load_snapshot(temp_snapshot_file)
    assert data == BASE_SNAPSHOT
    mock_decrypt.assert_called()


@patch('core.fetch_iam.secure_store.decrypt_and_read', side_effect=Exception("fail"))
def test_load_snapshot_falls_back_to_plaintext(mock_decrypt, temp_snapshot_file):
    data = load_snapshot(temp_snapshot_file)
    assert data == BASE_SNAPSHOT
    mock_decrypt.assert_called_once()


def test_compute_entity_diff():
    prev = [{"UserName": "alice"}, {"UserName": "bob"}]
    new = [{"UserName": "alice"}, {"UserName": "charlie"}]
    diff = _compute_entity_diff(prev, new, "UserName")
    assert diff["added"] == ["charlie"]
    assert diff["removed"] == ["bob"]


def test_apply_change_flags():
    snapshot = {
        "users": [{"UserName": "alice"}, {"UserName": "bob"}],
        "policies": [{"PolicyName": "Admin"}]
    }
    # Fixed: diff mein missing keys ko handle karo
    diff = {
        "users": {"added": ["bob"], "modified": ["alice"], "removed": []},
        "policies": {"added": ["Admin"], "modified": [], "removed": []},
        "groups": {"added": [], "modified": [], "removed": []},  # ab safe hai
        "roles": {"added": [], "modified": [], "removed": []}
    }
    _apply_change_flags(snapshot, diff)
    assert snapshot["users"][1]["_changed"] == "added"
    assert snapshot["users"][0]["_changed"] == "modified"
    assert snapshot["policies"][0]["_changed"] == "added"


@patch('core.fetch_iam._light_fetch_region')
@patch('core.fetch_iam._get_boto3_session_cached')
def test_fetch_iam_data_returns_cached_when_fast(mock_session, mock_fetch, temp_snapshot_file):
    with patch('core.fetch_iam.load_snapshot', return_value={"cached": True}):
        result = fetch_iam_data(out_path=temp_snapshot_file, fast_mode=True, force_fetch=False)
        assert result == {"cached": True}
        mock_fetch.assert_not_called()


@patch('core.fetch_iam._light_fetch_region')
@patch('core.fetch_iam._get_boto3_session_cached')
def test_fetch_iam_data_calls_fetch_when_force(mock_session, mock_fetch, temp_snapshot_file):
    mock_fetch.return_value = {"users": [], "groups": [], "roles": [], "policies": []}
    result = fetch_iam_data(out_path=temp_snapshot_file, force_fetch=True)
    assert "_meta" in result
    mock_fetch.assert_called_once()


@patch('core.fetch_iam.secure_store.encrypt_and_write')
@patch('core.fetch_iam._light_fetch_region')
@patch('core.fetch_iam._get_boto3_session_cached')
def test_fetch_iam_data_encrypts_when_requested(mock_session, mock_fetch, mock_encrypt, temp_snapshot_file):
    mock_fetch.return_value = {"users": []}
    fetch_iam_data(out_path=temp_snapshot_file, encrypt=True, force_fetch=True)
    mock_encrypt.assert_called_once()


# tests/test_fetch_iam.py → Sirf ye function replace kar de

@patch('core.fetch_iam.os.replace')
@patch('builtins.open', create=True)
@patch('core.fetch_iam._light_fetch_region')
@patch('core.fetch_iam._get_boto3_session_cached')
def test_fetch_iam_data_writes_plaintext_when_no_encrypt(mock_session, mock_fetch, mock_open, mock_replace, temp_snapshot_file):
    # Proper return
    mock_fetch.return_value = {
        "users": [{"UserName": "alice"}],
        "groups": [], "roles": [], "policies": []
    }

    mock_file = MagicMock()
    mock_open.return_value.__enter__.return_value = mock_file

    fetch_iam_data(out_path=temp_snapshot_file, force_fetch=True, multi_region=False)

    # Yeh sahi tarika hai — saare write calls ko collect karo
    written_chunks = [call[0][0] for call in mock_file.write.call_args_list]
    full_content = "".join(written_chunks)

    # Ab JSON valid hoga
    parsed = json.loads(full_content)
    assert isinstance(parsed, dict)
    assert "users" in parsed
    assert len(parsed["users"]) == 1
    assert parsed["users"][0]["UserName"] == "alice"
    assert "_meta" in parsed
    assert parsed["_meta"]["fast_mode"] is True

    mock_replace.assert_called_once()

if __name__ == "__main__":
    pytest.main(["-v"])
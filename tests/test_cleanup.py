# tests/test_cleanup.py
import os
import json
import shutil
import tempfile
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest

from core import cleanup
from core.cleanup import (
    _list_snapshot_files,
    _group_snapshot_files,
    purge_old_snapshots,
    reset_app,
)


# -------------------------------------------------------------------
# FIXTURE: temporary isolated data directory
# -------------------------------------------------------------------
@pytest.fixture
def temp_data_dir(monkeypatch):
    """Patch DATA_DIR, SNAPSHOT_DIR, SNAPSHOT_PATH to a temp dir."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # Patch config.DATA_DIR and SNAPSHOT_PATH
        monkeypatch.setattr(cleanup.config, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(cleanup.config, "SNAPSHOT_PATH", str(tmp_path / "snapshots" / "current.json"))
        monkeypatch.setattr(cleanup, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(cleanup, "SNAPSHOT_DIR", str(tmp_path / "snapshots"))
        monkeypatch.setattr(cleanup, "CURRENT_SNAPSHOT_NAME", "current.json")

        # ensure snapshot dir exists
        os.makedirs(str(tmp_path / "snapshots"), exist_ok=True)

        yield tmp_path


# -------------------------------------------------------------------
# TEST: listing snapshot files
# -------------------------------------------------------------------
def test_list_snapshot_files(temp_data_dir):
    snapdir = temp_data_dir / "snapshots"

    (snapdir / "a.json").write_text("{}")
    (snapdir / "b.json.enc").write_text("x")
    (snapdir / "c.enc").write_text("y")
    (snapdir / "ignore.txt").write_text("no")

    files = _list_snapshot_files()
    names = sorted([f.name for f in files])

    assert names == ["a.json", "b.json.enc", "c.enc"]


# -------------------------------------------------------------------
# TEST: grouping snapshot files
# -------------------------------------------------------------------
def test_group_snapshot_files(temp_data_dir):
    snapdir = temp_data_dir / "snapshots"

    paths = []
    for name in ["abc.json", "abc.json.enc", "abc.enc", "xyz.json"]:
        p = snapdir / name
        p.write_text("x")
        paths.append(p)

    groups = _group_snapshot_files(paths)

    assert set(groups.keys()) == {"abc", "xyz"}
    assert len(groups["abc"]) == 3
    assert len(groups["xyz"]) == 1


# -------------------------------------------------------------------
# TEST: purge_old_snapshots - deletes only OLD ones
# -------------------------------------------------------------------
def test_purge_old_snapshots_deletes_old(temp_data_dir):
    snapdir = temp_data_dir / "snapshots"

    # old file (2 days old)
    old = snapdir / "old.json"
    old.write_text("x")
    old_mtime = time.time() - (60 * 60 * 24 * 2)
    os.utime(old, (old_mtime, old_mtime))

    # recent file (1 hour old)
    recent = snapdir / "recent.json"
    recent.write_text("y")
    r_mtime = time.time() - 3600
    os.utime(recent, (r_mtime, r_mtime))

    removed, total = purge_old_snapshots(keep_days=1)

    assert total == 2
    assert removed == 1
    assert not old.exists()
    assert recent.exists()


# -------------------------------------------------------------------
# TEST: purge_old_snapshots does not delete active snapshot
# -------------------------------------------------------------------
def test_purge_does_not_delete_current_snapshot(temp_data_dir):
    snapdir = temp_data_dir / "snapshots"

    current = snapdir / "current.json"
    current.write_text("{}")
    recent = snapdir / "data.json"
    recent.write_text("{}")

    removed, total = purge_old_snapshots(keep_days=0)

    # current.json must never be removed
    assert current.exists()
    assert recent.exists()  # because it's recent


# -------------------------------------------------------------------
# TEST: multi-variant handling (a.json + a.json.enc)
# oldest gets deleted
# -------------------------------------------------------------------
def test_purge_multivariant_only_oldest_removed(temp_data_dir):
    snapdir = temp_data_dir / "snapshots"

    # older plaintext
    p1 = snapdir / "a.json"
    p1.write_text("{}")
    old_m = time.time() - (60 * 60 * 24 * 5)
    os.utime(p1, (old_m, old_m))

    # newer encrypted
    p2 = snapdir / "a.json.enc"
    p2.write_text("x")
    new_m = time.time() - 100
    os.utime(p2, (new_m, new_m))

    removed, total = purge_old_snapshots(keep_days=1)

    assert total == 2
    assert removed == 1
    assert not p1.exists()  # oldest deleted
    assert p2.exists()      # newest retained


# -------------------------------------------------------------------
# TEST: reset_app backs up and deletes everything
# -------------------------------------------------------------------
def test_reset_app_creates_backup_and_deletes(temp_data_dir):
    tmp = temp_data_dir
    auth = tmp / "auth.json"
    lock = tmp / "setup.lock"
    remember = tmp / "iamxray_remember.json"
    snapdir = tmp / "snapshots"

    # create all files
    auth.write_text("auth")
    lock.write_text("lock")
    remember.write_text("remember")

    (snapdir / "a.json").write_text("snap1")
    (snapdir / "b.json.enc").write_text("snap2")

    backup_folder = reset_app()

    # verify folder created
    assert os.path.exists(backup_folder)

    # all original files deleted
    assert not auth.exists()
    assert not lock.exists()
    assert not remember.exists()
    assert list(snapdir.glob("*")) == []

    # all backed up
    backed_files = [p.name for p in Path(backup_folder).glob("*")]
    assert set(backed_files) == {"auth.json", "setup.lock", "iamxray_remember.json", "a.json", "b.json.enc"}

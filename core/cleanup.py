# import os
# from datetime import datetime, timedelta

# def purge_old_snapshots(dirpath="data/snapshots", keep_days=30):
#     """Delete snapshot files older than keep_days."""
#     if not os.path.exists(dirpath):
#         return 0
#     cutoff = datetime.utcnow() - timedelta(days=keep_days)
#     removed = 0
#     for fname in os.listdir(dirpath):
#         path = os.path.join(dirpath, fname)
#         try:
#             mtime = datetime.utcfromtimestamp(os.path.getmtime(path))
#             if mtime < cutoff:
#                 os.remove(path)
#                 removed += 1
#         except Exception:
#             continue
#     return removed

# import os
# from datetime import datetime, timedelta
# import streamlit as st  # For potential UI integration, but conditional

# def purge_old_snapshots(dirpath="data/snapshots", keep_days=None):
#     """Delete snapshot files older than keep_days."""
#     if keep_days is None:
#         keep_days = int(os.getenv("KEEP_DAYS", 30))  # Configurable via env var
#     if not os.path.exists(dirpath):
#         return 0
#     cutoff = datetime.utcnow() - timedelta(days=keep_days)
#     removed = 0
#     for fname in os.listdir(dirpath):
#         path = os.path.join(dirpath, fname)
#         try:
#             mtime = datetime.utcfromtimestamp(os.path.getmtime(path))
#             if mtime < cutoff:
#                 os.remove(path)
#                 removed += 1
#         except Exception:
#             continue
#     return removed

# # For UI button in main.py (this can be called from main.py)
# def ui_purge_button():
#     keep_days = int(os.getenv("KEEP_DAYS", 30))
#     if st.button(f"Purge snapshots older than {keep_days} days"):
#         removed = purge_old_snapshots()
#         st.success(f"Purged {removed} old snapshots.")


# core/cleanup.py
# import os
# import logging
# from datetime import datetime, timedelta
# import streamlit as st  # Optional, used only when UI is active
# from config import KEEP_DAYS, DATA_DIR

# logger = logging.getLogger("cleanup")
# logger.setLevel(logging.INFO)
# if not logger.handlers:
#     ch = logging.StreamHandler()
#     ch.setLevel(logging.INFO)
#     logger.addHandler(ch)

# SNAPSHOT_DIR = os.path.join(DATA_DIR, "snapshots")
# os.makedirs(SNAPSHOT_DIR, exist_ok=True)


# def purge_old_snapshots(dirpath: str = SNAPSHOT_DIR, keep_days: int = KEEP_DAYS) -> int:
#     """
#     Delete snapshot files older than keep_days.
#     Returns the number of removed files.
#     """
#     if not os.path.exists(dirpath):
#         return 0

#     cutoff = datetime.utcnow() - timedelta(days=keep_days)
#     removed = 0

#     for fname in os.listdir(dirpath):
#         path = os.path.join(dirpath, fname)
#         try:
#             mtime = datetime.utcfromtimestamp(os.path.getmtime(path))
#             if mtime < cutoff:
#                 os.remove(path)
#                 removed += 1
#                 logger.info(f"🗑 Deleted old snapshot: {fname}")
#         except Exception as e:
#             logger.warning(f"⚠️ Failed to process {fname}: {e}")

#     if removed > 0:
#         logger.info(f"✅ Purged {removed} snapshots older than {keep_days} days")
#     else:
#         logger.info("No old snapshots found to purge")

#     return removed


# def ui_purge_button():
#     """
#     Streamlit UI button for manual snapshot purge.
#     Allows dynamic selection of retention days.
#     """
#     days = st.slider("Retention (days)", 7, 180, KEEP_DAYS, step=1)
#     if st.button(f"🧹 Purge snapshots older than {days} days"):
#         removed = purge_old_snapshots(keep_days=days)
#         if removed > 0:
#             st.success(f"✅ Purged {removed} old snapshots (>{days} days)")
#         else:
#             st.info(f"No snapshots older than {days} days found.")


import os
from datetime import datetime, timedelta
import streamlit as st
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import time
from core import config  # For SNAPSHOT_DIR, KEEP_DAYS

def purge_old_snapshots(dirpath=config.DATA_DIR + "/snapshots", keep_days=None):
    """Delete snapshot files older than keep_days with batching and backup."""
    if keep_days is None:
        try:
            keep_days = config.KEEP_DAYS
        except ValueError:
            st.warning("Invalid KEEP_DAYS env var, defaulting to 30 days")
            keep_days = 30
    if not os.path.exists(dirpath):
        os.makedirs(dirpath, exist_ok=True)
        return 0, 0  # (removed, total)

    cutoff = datetime.utcnow() - timedelta(days=keep_days)
    files = list(Path(dirpath).glob("*.json"))
    total_files = len(files)
    removed = 0
    backup_dir = os.path.join(dirpath, "backup")
    os.makedirs(backup_dir, exist_ok=True)
    current_snapshot = os.path.basename(config.SNAPSHOT_PATH)  # Exclude current

    batch_size = 10
    for i in range(0, total_files, batch_size):
        batch = files[i:i + batch_size]
        for path in batch:
            if path.name == current_snapshot:
                continue  # Skip current snapshot
            try:
                mtime = datetime.utcfromtimestamp(path.stat().st_mtime)
                enc_path = str(path) + ".enc"
                if os.path.exists(enc_path):
                    if mtime < cutoff:
                        # Backup before deletion
                        shutil.copy2(enc_path, os.path.join(backup_dir, path.name + ".bak"))
                        os.remove(enc_path)
                        removed += 1
                else:
                    st.warning(f"Unencrypted snapshot skipped: {path}")
            except PermissionError as e:
                st.warning(f"Permission denied for {path}: {e}, skipping")
                continue
            except Exception as e:
                st.warning(f"Failed to purge {path}: {e}, retrying...")
                time.sleep(1)  # Retry delay
                try:
                    if os.path.exists(enc_path) and mtime < cutoff:
                        shutil.copy2(enc_path, os.path.join(backup_dir, path.name + ".bak"))
                        os.remove(enc_path)
                        removed += 1
                except Exception as e2:
                    st.error(f"Retry failed for {path}: {e2}")
                    continue
    return removed, total_files

# Run purge in background thread with progress
def run_purge_in_background(dirpath=config.DATA_DIR + "/snapshots", keep_days=None):
    progress = st.progress(0.0)
    with ThreadPoolExecutor() as executor:
        result = executor.submit(purge_old_snapshots, dirpath, keep_days).result()
    return result

def ui_purge_button():
    keep_days = config.KEEP_DAYS
    if st.button(f"Purge snapshots older than {keep_days} days"):
        if st.button("Confirm purge"):
            with st.spinner("Purging old snapshots..."):
                removed, total = run_purge_in_background(keep_days=keep_days)
                if total == 0:
                    st.info("No snapshots to purge.")
                else:
                    st.success(f"Purged {removed} out of {total} old snapshots. Backups saved in {os.path.join('data/snapshots', 'backup')}.")
        else:
            st.warning("Purge cancelled.")

# # Example usage (for testing)
# if __name__ == "__main__":
#     st.title("Snapshot Purge Test")
#     ui_purge_button()

# Integrate with main.py to call ui_purge_button() in the sidebar.
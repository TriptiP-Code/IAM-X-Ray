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

def purge_old_snapshots(dirpath="data/snapshots", keep_days=None):
    """Delete snapshot files older than keep_days."""
    if keep_days is None:
        keep_days = int(os.getenv("KEEP_DAYS", 30))  # Configurable via env var
    if not os.path.exists(dirpath):
        os.makedirs(dirpath, exist_ok=True)
        return 0
    cutoff = datetime.utcnow() - timedelta(days=keep_days)
    removed = 0
    for path in Path(dirpath).glob("*.json"):  # Use glob for pattern matching
        try:
            mtime = datetime.utcfromtimestamp(path.stat().st_mtime)
            enc_path = str(path) + ".enc"
            if os.path.exists(enc_path):
                if mtime < cutoff:
                    os.remove(enc_path)
                    removed += 1
            else:
                raise Exception("Unencrypted snapshot detected")
        except Exception as e:
            st.warning(f"Failed to purge {path}: {e}")
            continue
    return removed

# Run purge in background thread
def run_purge_in_background(dirpath="data/snapshots", keep_days=None):
    with ThreadPoolExecutor() as executor:
        return executor.submit(purge_old_snapshots, dirpath, keep_days).result()

def ui_purge_button():
    keep_days = int(os.getenv("KEEP_DAYS", 30))
    if st.button(f"Purge snapshots older than {keep_days} days"):
        if st.button("Confirm purge"):
            with st.spinner("Purging old snapshots..."):
                removed = run_purge_in_background()
                st.success(f"Purged {removed} old snapshots.")
        else:
            st.warning("Purge cancelled.")
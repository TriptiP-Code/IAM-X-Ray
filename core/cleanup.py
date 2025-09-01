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

import os
from datetime import datetime, timedelta
import streamlit as st  # For potential UI integration, but conditional

def purge_old_snapshots(dirpath="data/snapshots", keep_days=None):
    """Delete snapshot files older than keep_days."""
    if keep_days is None:
        keep_days = int(os.getenv("KEEP_DAYS", 30))  # Configurable via env var
    if not os.path.exists(dirpath):
        return 0
    cutoff = datetime.utcnow() - timedelta(days=keep_days)
    removed = 0
    for fname in os.listdir(dirpath):
        path = os.path.join(dirpath, fname)
        try:
            mtime = datetime.utcfromtimestamp(os.path.getmtime(path))
            if mtime < cutoff:
                os.remove(path)
                removed += 1
        except Exception:
            continue
    return removed

# For UI button in main.py (this can be called from main.py)
def ui_purge_button():
    keep_days = int(os.getenv("KEEP_DAYS", 30))
    if st.button(f"Purge snapshots older than {keep_days} days"):
        removed = purge_old_snapshots()
        st.success(f"Purged {removed} old snapshots.")
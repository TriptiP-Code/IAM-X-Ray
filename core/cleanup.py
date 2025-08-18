import os
from datetime import datetime, timedelta

def purge_old_snapshots(dirpath="data/snapshots", keep_days=30):
    """Delete snapshot files older than keep_days."""
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

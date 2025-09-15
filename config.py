# # # app/config.py
# # import os
# # from pathlib import Path
# # from dotenv import load_dotenv

# # # 🔧 Load .env file if present
# # load_dotenv()

# # # 📦 App metadata
# # APP_NAME = "IAM X-Ray"
# # APP_VERSION = os.getenv("APP_VERSION", "1.0.0")

# # # 📂 Directories
# # BASE_DIR = Path(__file__).resolve().parent.parent
# # DATA_DIR = BASE_DIR / "data"
# # LOG_DIR = BASE_DIR / "logs"

# # # Ensure dirs exist
# # DATA_DIR.mkdir(parents=True, exist_ok=True)
# # LOG_DIR.mkdir(parents=True, exist_ok=True)

# # # 🔑 Auth & Lock files
# # AUTH_FILE = str(DATA_DIR / "auth.json")
# # LOCK_FILE = str(DATA_DIR / "setup.lock")

# # # 📦 Snapshot files
# # SNAPSHOT_PATH = str(DATA_DIR / "iam_snapshot.json")
# # DEMO_PATH = str(DATA_DIR / "sample_snapshot.json")

# # # ⚙️ Configurable defaults (with env override)
# # KEEP_DAYS = int(os.getenv("KEEP_DAYS", "30"))       # Retain snapshots (days)
# # MAX_NODES = int(os.getenv("MAX_NODES", "500"))      # Max nodes before subgraph
# # THREADS = int(os.getenv("THREADS", "8"))            # Thread pool size
# # DEFAULT_REGION = os.getenv("AWS_REGION", "us-east-1")
# # FAST_MODE_DEFAULT = os.getenv("FAST_MODE", "true").lower() in ("1", "true", "yes")

# # # 🔒 Security
# # FERNET_KEY = os.getenv("IAM_XRAY_FERNET_KEY", None)   # Encryption key (must be set in prod)
# # PEPPER = os.getenv("IAM_XRAY_PEPPER", None)           # Extra pepper for password hashing

# # # 🛠 Logging
# # LOG_FILE = str(LOG_DIR / "app.log")

# # # ⚠️ Warnings if missing critical vars
# # if not FERNET_KEY:
# #     print("⚠️ Warning: IAM_XRAY_FERNET_KEY not set. Encryption will not work properly.")
# # if not PEPPER:
# #     print("⚠️ Warning: IAM_XRAY_PEPPER not set. Password hashing less secure.")



# # app/config.py
# import os
# from pathlib import Path
# import logging
# from dotenv import load_dotenv
# import streamlit as st  # 👈 For compat wrappers
# logger = logging.getLogger(__name__)

# # 🔧 Load .env file if present
# load_dotenv()

# # 📦 App metadata
# APP_NAME = "IAM X-Ray"
# APP_VERSION = os.getenv("APP_VERSION", "1.0.0")

# # 📂 Directories
# BASE_DIR = Path(__file__).resolve().parent.parent
# DATA_DIR = BASE_DIR / "data"
# LOG_DIR = BASE_DIR / "logs"

# # Ensure dirs exist
# DATA_DIR.mkdir(parents=True, exist_ok=True)
# LOG_DIR.mkdir(parents=True, exist_ok=True)

# # 🔑 Auth & Lock files
# AUTH_FILE = str(DATA_DIR / "auth.json")
# LOCK_FILE = str(DATA_DIR / "setup.lock")

# # 📦 Snapshot files
# SNAPSHOT_PATH = str(DATA_DIR / "iam_snapshot.json")
# DEMO_PATH = str(DATA_DIR / "sample_snapshot.json")

# # ⚙️ Configurable defaults (with env override) 👈 Centralized all vars
# KEEP_DAYS = int(os.getenv("KEEP_DAYS", "30"))       # Retain snapshots (days)
# MAX_NODES = int(os.getenv("MAX_NODES", "500"))      # Max nodes before subgraph
# THREADS = int(os.getenv("THREADS", "8"))            # Thread pool size
# DEFAULT_REGION = os.getenv("AWS_REGION", "us-east-1")
# FAST_MODE_DEFAULT = os.getenv("FAST_MODE", "true").lower() in ("1", "true", "yes")

# # 🔒 Security
# FERNET_KEY = os.getenv("IAM_XRAY_FERNET_KEY", None)   # Encryption key (must be set in prod)
# PEPPER = os.getenv("IAM_XRAY_PEPPER", None)           # Extra pepper for password hashing

# # 🛠 Logging
# LOG_FILE = str(LOG_DIR / "app.log")

# # ⚠️ Warnings if missing critical vars 👈 Enhanced: Use st.warning if in Streamlit context
# if not FERNET_KEY:
#     if 'st' in globals():
#         st.warning("⚠️ IAM_XRAY_FERNET_KEY not set. Encryption will not work properly.")
#     else:
#         print("⚠️ Warning: IAM_XRAY_FERNET_KEY not set. Encryption will not work properly.")
# if not PEPPER:
#     if 'st' in globals():
#         st.warning("⚠️ IAM_XRAY_PEPPER not set. Password hashing less secure.")
#     else:
#         print("⚠️ Warning: IAM_XRAY_PEPPER not set. Password hashing less secure.")

# # 👈 Compat wrappers for Streamlit caching (backward compat for old versions)
# def cache_data_compat(func=None, ttl=0, max_entries=None, show_spinner=True, persist=None):
#     """
#     Backward compatible wrapper for st.cache_data.
#     - For Streamlit >=1.18: Uses st.cache_data.
#     - For older: Falls back to st.cache (deprecated but works) or experimental.
#     """
#     if hasattr(st, "cache_data"):
#         return st.cache_data(ttl=ttl, max_entries=max_entries, experimental_allow_widgets=True)(func)
#     elif hasattr(st, "experimental_memo"):
#         # Fallback for very old (pre-1.0)
#         return st.experimental_memo(ttl=ttl)(func)
#     else:
#         logger.warning("Streamlit version too old; no caching available.")
#         return func

# # Example usage: @cache_data_compat
# # def my_func(): ...



import os

AWS_REGION = "us-east-1"  # Or your preferred AWS region

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Cache TTL in seconds (default 1 hour)
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))

# Security: Mandatory FERNET_KEY for encryption
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise ValueError("FERNET_KEY is required for secure encryption")

# Nice-to-have: Email alert threshold (default 5)
EMAIL_ALERT_THRESHOLD = int(os.getenv("EMAIL_THRESHOLD", "5"))
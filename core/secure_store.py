# import os, json
# from cryptography.fernet import Fernet

# DEFAULT_KEY_ENV = "IAM_XRAY_FERNET_KEY"
# DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
# os.makedirs(DATA_DIR, exist_ok=True)
# KEYS_FILE = os.path.join(DATA_DIR, "fernet-keys.json")

# def _load_or_create_keys():
#     keys = []

#     # 1) ENV var highest priority
#     env_key = os.getenv(DEFAULT_KEY_ENV)
#     if env_key:
#         keys.append(env_key.encode())

#     # 2) Existing keys file
#     if os.path.exists(KEYS_FILE):
#         try:
#             with open(KEYS_FILE, "r") as f:
#                 raw = json.load(f)
#             for k in raw.get("keys", []):
#                 if isinstance(k, str):
#                     keys.append(k.encode())
#         except Exception:
#             pass

#     # 3) If no keys → generate new
#     if not keys:
#         k = Fernet.generate_key()
#         keys = [k]
#         with open(KEYS_FILE, "w") as f:
#             json.dump({"keys": [k.decode()]}, f, indent=2)

#     return keys

# FERNET_KEYS = _load_or_create_keys()
# PRIMARY_KEY = FERNET_KEYS[0]
# fernet_primary = Fernet(PRIMARY_KEY)
# FERNET_INSTANCES = [Fernet(k) for k in FERNET_KEYS]

# def encrypt_and_write(obj, path: str):
#     raw = json.dumps(obj, indent=2).encode()
#     enc = fernet_primary.encrypt(raw)
#     with open(path, "wb") as f:
#         f.write(enc)

# def decrypt_and_read(path: str):
#     import json
#     with open(path, "rb") as f:
#         raw = f.read()
#     for fernet in FERNET_INSTANCES:
#         try:
#             dec = fernet.decrypt(raw)
#             return json.loads(dec.decode())
#         except Exception:
#             continue
#     # fallback plain json
#     try:
#         return json.loads(raw.decode())
#     except Exception:
#         raise RuntimeError("Unable to decrypt snapshot with available keys")

import os, json
from cryptography.fernet import Fernet
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("secure_store")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

DEFAULT_KEY_ENV = "IAM_XRAY_FERNET_KEY"
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)
KEYS_FILE = os.path.join(DATA_DIR, "fernet-keys.json")

def _load_or_create_keys():
    keys = []

    # 1) ENV var highest priority
    env_key = os.getenv(DEFAULT_KEY_ENV)
    if env_key:
        keys.append(env_key.encode())

    # 2) Existing keys file
    created_at = None
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r") as f:
                raw = json.load(f)
            for k in raw.get("keys", []):
                if isinstance(k, str):
                    keys.append(k.encode())
            created_at = raw.get("created_at")
        except Exception:
            pass

    # 3) If no keys → generate new
    if not keys:
        k = Fernet.generate_key()
        keys = [k]
        created_at = datetime.utcnow().isoformat()
        with open(KEYS_FILE, "w") as f:
            json.dump({"keys": [k.decode()], "created_at": created_at}, f, indent=2)

    # Auto-rotate if >90 days
    if created_at:
        try:
            created_dt = datetime.fromisoformat(created_at)
            if datetime.utcnow() - created_dt > timedelta(days=90):
                logger.info("Rotating encryption key (older than 90 days)")
                new_k = Fernet.generate_key()
                keys.append(new_k)  # Append new key
                with open(KEYS_FILE, "w") as f:
                    json.dump({"keys": [k.decode() for k in keys], "created_at": datetime.utcnow().isoformat()}, f, indent=2)
        except Exception as e:
            logger.warning(f"Key rotation check failed: {e}")

    return keys

FERNET_KEYS = _load_or_create_keys()
PRIMARY_KEY = FERNET_KEYS[-1] if FERNET_KEYS else None  # Use latest key for encryption
fernet_primary = Fernet(PRIMARY_KEY) if PRIMARY_KEY else None
FERNET_INSTANCES = [Fernet(k) for k in FERNET_KEYS] if FERNET_KEYS else []

def encrypt_and_write(obj, path: str):
    if not fernet_primary:
        logger.warning("No encryption key available; writing plaintext")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        logger.info("Snapshot written in plaintext (no key)")
        return

    raw = json.dumps(obj, indent=2).encode()
    enc = fernet_primary.encrypt(raw)
    with open(path, "wb") as f:
        f.write(enc)
    logger.info("Snapshot encrypted and written successfully")

def decrypt_and_read(path: str):
    import json
    with open(path, "rb") as f:
        raw = f.read()
    for idx, fernet in enumerate(FERNET_INSTANCES):
        try:
            dec = fernet.decrypt(raw)
            logger.info(f"Decrypted snapshot using key index {idx}")
            return json.loads(dec.decode())
        except Exception:
            continue
    # fallback plain json
    try:
        logger.warning("Decryption failed; falling back to plaintext read")
        return json.loads(raw.decode())
    except Exception:
        raise RuntimeError("Unable to decrypt or read snapshot as plaintext")
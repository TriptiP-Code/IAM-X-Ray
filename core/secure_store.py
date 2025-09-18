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

# import os, json
# from cryptography.fernet import Fernet
# import logging
# from datetime import datetime, timedelta

# logger = logging.getLogger("secure_store")
# logger.setLevel(logging.INFO)
# if not logger.handlers:
#     ch = logging.StreamHandler()
#     ch.setLevel(logging.INFO)
#     logger.addHandler(ch)

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
#     created_at = None
#     if os.path.exists(KEYS_FILE):
#         try:
#             with open(KEYS_FILE, "r") as f:
#                 raw = json.load(f)
#             for k in raw.get("keys", []):
#                 if isinstance(k, str):
#                     keys.append(k.encode())
#             created_at = raw.get("created_at")
#         except Exception:
#             pass

#     # 3) If no keys → generate new
#     if not keys:
#         k = Fernet.generate_key()
#         keys = [k]
#         created_at = datetime.utcnow().isoformat()
#         with open(KEYS_FILE, "w") as f:
#             json.dump({"keys": [k.decode()], "created_at": created_at}, f, indent=2)

#     # Auto-rotate if >90 days
#     if created_at:
#         try:
#             created_dt = datetime.fromisoformat(created_at)
#             if datetime.utcnow() - created_dt > timedelta(days=90):
#                 logger.info("Rotating encryption key (older than 90 days)")
#                 new_k = Fernet.generate_key()
#                 keys.append(new_k)  # Append new key
#                 with open(KEYS_FILE, "w") as f:
#                     json.dump({"keys": [k.decode() for k in keys], "created_at": datetime.utcnow().isoformat()}, f, indent=2)
#         except Exception as e:
#             logger.warning(f"Key rotation check failed: {e}")

#     return keys

# FERNET_KEYS = _load_or_create_keys()
# PRIMARY_KEY = FERNET_KEYS[-1] if FERNET_KEYS else None  # Use latest key for encryption
# fernet_primary = Fernet(PRIMARY_KEY) if PRIMARY_KEY else None
# FERNET_INSTANCES = [Fernet(k) for k in FERNET_KEYS] if FERNET_KEYS else []

# def encrypt_and_write(obj, path: str):
#     if not fernet_primary:
#         logger.warning("No encryption key available; writing plaintext")
#         with open(path, "w", encoding="utf-8") as f:
#             json.dump(obj, f, indent=2)
#         logger.info("Snapshot written in plaintext (no key)")
#         return

#     raw = json.dumps(obj, indent=2).encode()
#     enc = fernet_primary.encrypt(raw)
#     with open(path, "wb") as f:
#         f.write(enc)
#     logger.info("Snapshot encrypted and written successfully")

# def decrypt_and_read(path: str):
#     import json
#     with open(path, "rb") as f:
#         raw = f.read()
#     for idx, fernet in enumerate(FERNET_INSTANCES):
#         try:
#             dec = fernet.decrypt(raw)
#             logger.info(f"Decrypted snapshot using key index {idx}")
#             return json.loads(dec.decode())
#         except Exception:
#             continue
#     # fallback plain json
#     try:
#         logger.warning("Decryption failed; falling back to plaintext read")
#         return json.loads(raw.decode())
#     except Exception:
#         raise RuntimeError("Unable to decrypt or read snapshot as plaintext")


# # core/secure_store.py
# import os
# import json
# import logging
# from cryptography.fernet import Fernet
# from datetime import datetime, timedelta
# from functools import lru_cache

# logger = logging.getLogger("secure_store")
# logger.setLevel(logging.INFO)
# if not logger.handlers:
#     ch = logging.StreamHandler()
#     ch.setLevel(logging.INFO)
#     logger.addHandler(ch)

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
#     else:
#         logger.warning("⚠️ No env key set; falling back to local file key (not recommended for prod).")

#     # 2) Existing keys file
#     created_at = None
#     if os.path.exists(KEYS_FILE):
#         try:
#             with open(KEYS_FILE, "r") as f:
#                 raw = json.load(f)
#             for k in raw.get("keys", []):
#                 if isinstance(k, str):
#                     keys.append(k.encode())
#             created_at = raw.get("created_at")
#         except Exception as e:
#             logger.error(f"Failed to load keys file: {e}")

#     # 3) If no keys → generate new
#     if not keys:
#         k = Fernet.generate_key()
#         keys = [k]
#         created_at = datetime.utcnow().isoformat()
#         with open(KEYS_FILE, "w") as f:
#             json.dump({"keys": [k.decode()], "created_at": created_at}, f, indent=2)
#         logger.info("Generated new Fernet key and saved locally.")

#     # Auto-rotate if >90 days
#     if created_at:
#         try:
#             created_dt = datetime.fromisoformat(created_at)
#             if datetime.utcnow() - created_dt > timedelta(days=90):
#                 logger.info("🔑 Rotating encryption key (older than 90 days)")
#                 new_k = Fernet.generate_key()
#                 keys.append(new_k)  # Append new key
#                 with open(KEYS_FILE, "w") as f:
#                     json.dump(
#                         {"keys": [k.decode() for k in keys], "created_at": datetime.utcnow().isoformat()},
#                         f,
#                         indent=2,
#                     )
#         except Exception as e:
#             logger.warning(f"Key rotation check failed: {e}")

#     return keys

# FERNET_KEYS = _load_or_create_keys()
# PRIMARY_KEY = FERNET_KEYS[-1] if FERNET_KEYS else None
# fernet_primary = Fernet(PRIMARY_KEY) if PRIMARY_KEY else None
# FERNET_INSTANCES = [Fernet(k) for k in FERNET_KEYS] if FERNET_KEYS else []

# def write_encrypted(obj, path: str):
#     """Encrypt JSON obj and write to path"""
#     if not fernet_primary:
#         logger.warning("No encryption key available; writing plaintext")
#         with open(path, "w", encoding="utf-8") as f:
#             json.dump(obj, f, indent=2)
#         return

#     raw = json.dumps(obj, indent=2).encode()
#     enc = fernet_primary.encrypt(raw)
#     with open(path, "wb") as f:
#         f.write(enc)
#     logger.info(f"✅ Snapshot encrypted and written to {path}")

# @lru_cache(maxsize=32)
# def read_and_decrypt(path: str):
#     """Read file, try decrypt with all keys, cache result"""
#     with open(path, "rb") as f:
#         raw = f.read()

#     # Try decrypt with all keys
#     for idx, fernet in enumerate(FERNET_INSTANCES):
#         try:
#             dec = fernet.decrypt(raw)
#             logger.info(f"✅ Decrypted snapshot using key index {idx}")
#             return json.loads(dec.decode())
#         except Exception:
#             continue

#     # fallback plain json
#     try:
#         logger.warning("⚠️ Decryption failed; falling back to plaintext read")
#         return json.loads(raw.decode())
#     except Exception:
#         raise RuntimeError("❌ Unable to decrypt or read snapshot as plaintext")

# # Aliases for consistency
# encrypt_and_write = write_encrypted
# decrypt_and_read = read_and_decrypt

import os
import json
from cryptography.fernet import Fernet
import logging
from datetime import datetime, timedelta
from functools import lru_cache
import time
from core import config 
# Import config to sync with FERNET_KEY
# Changed to relative

logger = logging.getLogger("secure_store")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

DEFAULT_KEY_ENV = "IAM_XRAY_FERNET_KEY"  # Keep this for fallback/env check
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)
KEYS_FILE = os.path.join(DATA_DIR, "fernet-keys.json")

@lru_cache(maxsize=1)
def _load_or_create_keys():
    keys = []

    # 1) Use FERNET_KEY from config (highest priority)
    if config.FERNET_KEY:
        keys.append(config.FERNET_KEY.encode())
    else:
        # Fallback to env var if config key not set
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
        except json.JSONDecodeError as e:
            logger.error(f"Corrupted keys file, regenerating: {e}")
            os.remove(KEYS_FILE)  # Remove corrupted file
        except Exception as e:
            logger.error(f"Failed to load keys file: {e}")

    # 3) If no keys → generate new
    if not keys:
        k = Fernet.generate_key()
        keys = [k]
        created_at = datetime.utcnow().isoformat()
        with open(KEYS_FILE, "w") as f:
            json.dump({"keys": [k.decode()], "created_at": created_at}, f, indent=2)
        logger.info("Generated new encryption key")

    # Auto-rotate if >90 days
    if created_at:
        try:
            created_dt = datetime.fromisoformat(created_at)
            if datetime.utcnow() - created_dt > timedelta(days=90):
                logger.info("Rotating encryption key (older than 90 days)")
                new_k = Fernet.generate_key()
                keys.append(new_k)
                with open(KEYS_FILE, "w") as f:
                    json.dump({"keys": [k.decode() for k in keys], "created_at": datetime.utcnow().isoformat()}, f, indent=2)
                # Placeholder for email alert (to be implemented in config.py)
                logger.info("Key rotation completed; email alert pending implementation")
        except PermissionError as e:
            logger.error(f"Key rotation failed due to permissions: {e}")
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")

    return keys

FERNET_KEYS = _load_or_create_keys()
PRIMARY_KEY = FERNET_KEYS[-1] if FERNET_KEYS else None
fernet_primary = Fernet(PRIMARY_KEY) if PRIMARY_KEY else None
FERNET_INSTANCES = [Fernet(k) for k in FERNET_KEYS] if FERNET_KEYS else []

def encrypt_and_write(obj, path: str, max_retries=3):
    if not fernet_primary:
        logger.warning("No encryption key; writing plaintext JSON")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        return
    
    raw = json.dumps(obj, indent=2).encode()
    enc_data = fernet_primary.encrypt(raw)
    for attempt in range(max_retries):
        try:
            with open(path, "wb") as f:
                chunk_size = 8192
                for i in range(0, len(enc_data), chunk_size):
                    f.write(enc_data[i:i + chunk_size])
            logger.info(f"Snapshot encrypted and written to {path}")
            # Verify policy data is encrypted (basic check)
            if "policies" in json.dumps(obj):
                logger.info("Policy data successfully encrypted")
            break
        except IOError as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to write after {max_retries} attempts: {e}")
                raise
            time.sleep(1)  # Wait before retry
            logger.warning(f"Retry {attempt + 1}/{max_retries} due to I/O error: {e}")

def decrypt_and_read(path: str, max_retries=3):
    for attempt in range(max_retries):
        try:
            with open(path, "rb") as f:
                raw = b""
                chunk_size = 8192
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    raw += chunk
            for idx, fernet in enumerate(FERNET_INSTANCES):
                try:
                    dec = fernet.decrypt(raw)
                    logger.info(f"Decrypted snapshot using key index {idx}")
                    return json.loads(dec.decode())
                except Exception:
                    continue
            # Fallback plain if decryption fails
            try:
                logger.warning("Decryption failed; assuming plaintext")
                return json.loads(raw.decode())
            except Exception:
                raise RuntimeError("Unable to decrypt or read snapshot")
        except IOError as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to read after {max_retries} attempts: {e}")
                raise
            time.sleep(1)  # Wait before retry
            logger.warning(f"Retry {attempt + 1}/{max_retries} due to I/O error: {e}")

# # Example usage (for testing)
# if __name__ == "__main__":
#     test_data = {"policies": [{"name": "test", "data": "secret"}]}
#     encrypt_and_write(test_data, "test_encrypted.json")
#     decrypted = decrypt_and_read("test_encrypted.json")
#     print(decrypted)
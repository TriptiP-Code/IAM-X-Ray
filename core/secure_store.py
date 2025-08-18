import os, json
from cryptography.fernet import Fernet

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
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r") as f:
                raw = json.load(f)
            for k in raw.get("keys", []):
                if isinstance(k, str):
                    keys.append(k.encode())
        except Exception:
            pass

    # 3) If no keys → generate new
    if not keys:
        k = Fernet.generate_key()
        keys = [k]
        with open(KEYS_FILE, "w") as f:
            json.dump({"keys": [k.decode()]}, f, indent=2)

    return keys

FERNET_KEYS = _load_or_create_keys()
PRIMARY_KEY = FERNET_KEYS[0]
fernet_primary = Fernet(PRIMARY_KEY)
FERNET_INSTANCES = [Fernet(k) for k in FERNET_KEYS]

def encrypt_and_write(obj, path: str):
    raw = json.dumps(obj, indent=2).encode()
    enc = fernet_primary.encrypt(raw)
    with open(path, "wb") as f:
        f.write(enc)

def decrypt_and_read(path: str):
    import json
    with open(path, "rb") as f:
        raw = f.read()
    for fernet in FERNET_INSTANCES:
        try:
            dec = fernet.decrypt(raw)
            return json.loads(dec.decode())
        except Exception:
            continue
    # fallback plain json
    try:
        return json.loads(raw.decode())
    except Exception:
        raise RuntimeError("Unable to decrypt snapshot with available keys")

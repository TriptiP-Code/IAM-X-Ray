# # app/main.py
# """
# IAM X-Ray - Balanced clean UI (v0.1.0-beta)

# Balanced UI (no Access Advisor):
# - Demo / AWS Profile / Env Keys auth modes
# - FAST vs FORCE fetch explained and exposed
# - Encrypt snapshot toggle (uses core.secure_store)
# - Graph (build_iam_graph) embedded via PyVis HTML
# - Search (action/entity) via search_permissions
# - Diff/impact/highlight & download snapshot/graph
# - Compact details panel (Overview / JSON / Relationships / Findings)
# """
# import sys, os
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# import os
# import json
# import hashlib
# import secrets
# import streamlit as st
# import streamlit.components.v1 as components
# from datetime import datetime as dt, datetime, timedelta,timezone
# from io import StringIO
# import platform

# # core imports (must match your refactors)
# from core.fetch_iam import fetch_iam_data
# from core.graph_builder import build_iam_graph, build_adjacency, compute_keep_set_from_diff, search_permissions, load_snapshot, NODE_COLORS
# from core import secure_store
# from core import config
# from core.cleanup import ui_purge_button, ui_reset_app_button  # optional UI helper from cleanup

# st.set_page_config(page_title="IAM X-Ray", layout="wide", initial_sidebar_state="expanded")


# # --- health endpoint support for container healthcheck ---
# try:
#     params = st.query_params()
#     if params.get("healthz") == ["1"]:
#         st.write("OK")
#         st.stop()
# except Exception:
#     pass

# # ---------------------------
# # Constants and paths
# # ---------------------------
# DATA_DIR = "data"
# SNAPSHOT_PATH = os.path.join(DATA_DIR, "iam_snapshot.json")   # fetch_iam may write .enc if encrypt=True
# DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
# REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")
# AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
# LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")

# os.makedirs(DATA_DIR, exist_ok=True)

# # ---------------------------
# # Helpers
# # ---------------------------
# def _hash_pw(pw: str, salt: str) -> str:
#     return hashlib.sha256((salt + pw).encode()).hexdigest()

# def _write_json_atomic(path, obj):
#     tmp = path + ".tmp"
#     with open(tmp, "w", encoding="utf-8") as fh:
#         json.dump(obj, fh, indent=2)
#     os.replace(tmp, path)

# def _read_json(path):
#     with open(path, "r", encoding="utf-8") as fh:
#         return json.load(fh)

# def create_demo_snapshot_if_missing():
#     """If demo snapshot is missing, create a basic packaged one to avoid empty screens."""
#     if os.path.exists(DEMO_PATH):
#         return
#     demo = {
#         "_meta": {"fetched_at": dt.utcnow().isoformat() + "Z", "fast_mode": True, "counts": {"users": 1, "roles":1, "policies":1}},
#         "users": [{"UserName":"demo-user","Arn":"arn:aws:iam::123456789012:user/demo-user","IsRisky": False, "AttachedPolicies": [{"PolicyName": "DemoPolicy"}]}],
#         "roles": [],
#         "groups": [],
#         "policies": [{"PolicyName": "DemoPolicy", "RiskScore": 1, "IsRisky": False, "Arn": "arn:aws:iam::123456789012:policy/DemoPolicy"}]
#     }
#     _write_json_atomic(DEMO_PATH, demo)

# # ---------------------------
# # Pre-flight checks
# # ---------------------------
# def preflight_check():
#     errors = []
#     infos = []
#     # Python version
#     py_ver = platform.python_version()
#     infos.append(f"Python: {py_ver}")

#     # data dir writable
#     try:
#         testfile = os.path.join(DATA_DIR, ".permtest")
#         with open(testfile, "w") as fh:
#             fh.write("ok")
#         os.remove(testfile)
#         infos.append("Data dir writable")
#     except Exception as e:
#         errors.append(f"Data dir NOT writable: {e}")

#     # encryption key
#     fernet_key = getattr(config, "FERNET_KEY", None) or os.getenv("IAM_XRAY_FERNET_KEY") or os.getenv("FERNET_KEY")
#     if not fernet_key:
#         errors.append("Encryption key missing (set IAM_XRAY_FERNET_KEY env var).")
#     else:
#         infos.append("Encryption key present")

#     # demo snapshot
#     if not os.path.exists(DEMO_PATH):
#         infos.append("Demo snapshot not found — will auto-create a packaged demo.")
#         create_demo_snapshot_if_missing()
#         if os.path.exists(DEMO_PATH):
#             infos.append("Demo snapshot packaged successfully.")
#         else:
#             errors.append("Failed to create demo snapshot.")

#     return errors, infos

# # Run quick preflight (non-blocking); show result later in onboarding
# _preflight_errors, _preflight_infos = preflight_check()

# # ---------------------------
# # Remember-me persistent token helpers (file-backed)
# # ---------------------------
# def _generate_token():
#     return secrets.token_urlsafe(32)

# def save_remember_token(token: str, expiry: datetime):
#     obj = {"token": token, "expiry": expiry.isoformat()}
#     _write_json_atomic(REMEMBER_PATH, obj)
#     # try to set real cookie if available (Streamlit versions vary)
#     try:
#         if hasattr(st, "experimental_set_cookie"):
#             # st.experimental_set_cookie exists only in some versions
#             st.experimental_set_cookie("iamxray_auth_token", token, expires_at=expiry, http_only=True)
#     except Exception:
#         # ignore if not supported
#         pass

# def load_remember_token():
#     # first try cookie if available
#     try:
#         if hasattr(st, "experimental_get_cookie"):
#             tk = st.experimental_get_cookie("iamxray_auth_token")
#             if tk:
#                 # if cookie present, return token (we don't know expiry from cookie)
#                 return {"token": tk, "expiry": None}
#     except Exception:
#         pass
#     # fallback to file
#     if os.path.exists(REMEMBER_PATH):
#         try:
#             obj = _read_json(REMEMBER_PATH)
#             obj["expiry"] = datetime.fromisoformat(obj["expiry"]) if obj.get("expiry") else None
#             return obj
#         except Exception:
#             return None
#     return None

# def clear_remember_token():
#     try:
#         if os.path.exists(REMEMBER_PATH):
#             os.remove(REMEMBER_PATH)
#         if hasattr(st, "experimental_set_cookie"):
#             try:
#                 st.experimental_set_cookie("iamxray_auth_token", "", expires_at=datetime.now(timezone.utc), http_only=True)
#             except Exception:
#                 pass
#     except Exception:
#         pass

# # ---------------------------
# # First-run onboarding wizard
# # ---------------------------
# def show_onboarding_wizard():
#     st.title("Welcome to IAM X-Ray — First Run Setup")
#     step = st.session_state.setdefault("onboard_step", 1)

#     if step == 1:
#         st.markdown("## 1) Welcome")
#         st.write("IAM X-Ray helps you visualize AWS IAM access. This quick wizard will set up local storage and a password.")
#         if st.button("Start setup"):
#             st.session_state["onboard_step"] = 2
#             st.rerun()

#     elif step == 2:
#         st.markdown("## 2) Choose a local password")
#         st.info("This password will protect the UI on this machine. It's stored locally (hashed).")
#         with st.form("set_pw"):
#             pw1 = st.text_input("Password", type="password")
#             pw2 = st.text_input("Confirm password", type="password")
#             save = st.form_submit_button("Save password")
#         if save:
#             if not pw1 or pw1 != pw2:
#                 st.error("Passwords do not match or are empty.")
#             else:
#                 salt = secrets.token_hex(16)
#                 hashed = _hash_pw(pw1, salt)
#                 _write_json_atomic(AUTH_FILE, {"algorithm": "sha256", "salt": salt, "password_hash": hashed})
#                 # create lock file
#                 with open(LOCK_FILE, "w", encoding="utf-8") as fh:
#                     fh.write("locked")
#                 st.success("Password saved.")
#                 st.session_state["onboard_step"] = 3
#                 st.rerun()

#     elif step == 3:
#         st.markdown("## 3) Confirm locations & finish")
#         st.write(f"- Data directory: `{os.path.abspath(DATA_DIR)}`")
#         st.write(f"- Snapshot path: `{os.path.abspath(SNAPSHOT_PATH)}`")
#         st.write("We also created a demo snapshot so you can explore immediately.")
#         if st.button("Finish and continue to app"):
#             st.session_state["onboard_done"] = True
#             st.success("Setup complete. Please login.")
#             st.rerun()

# # If first-run (no auth and no lock), run onboarding wizard
# if not os.path.exists(AUTH_FILE) and not os.path.exists(LOCK_FILE):
#     show_onboarding_wizard()
#     st.stop()

# # ---------------------------
# # Load saved auth (if exists)
# # ---------------------------
# saved_hash = None
# salt = None
# if os.path.exists(AUTH_FILE):
#     try:
#         ad = _read_json(AUTH_FILE)
#         salt = ad.get("salt")
#         saved_hash = ad.get("password_hash")
#     except Exception:
#         saved_hash = None
#         salt = None

# # ---------------------------
# # LOGIN SYSTEM (Upgraded UX)
# # ---------------------------
# # Init session keys (safe defaults)
# st.session_state.setdefault("authenticated", False)
# st.session_state.setdefault("login_failures", 0)
# st.session_state.setdefault("locked_until", None)
# st.session_state.setdefault("remember_me_flag", False)
# st.session_state.setdefault("session_expiry", None)
# st.session_state.setdefault("admin_mode", False)

# SESSION_LIFETIME_MINUTES = 60  # Auto logout after 60 minutes

# # Session expiry enforcement
# if st.session_state["authenticated"] and st.session_state.get("session_expiry"):
#     if datetime.now(timezone.utc) > st.session_state["session_expiry"]:
#         st.session_state["authenticated"] = False
#         st.warning("Session expired. Please login again.")

# # Try auto-login via persistent token
# if not st.session_state["authenticated"]:
#     tkobj = load_remember_token()
#     if tkobj:
#         # if token exists and not expired, mark authenticated
#         if not tkobj.get("expiry") or (tkobj.get("expiry") and tkobj["expiry"] > datetime.now(timezone.utc)):
#             # ensure auth exists
#             if saved_hash and salt:
#                 st.session_state["authenticated"] = True
#                 st.session_state["session_expiry"] = datetime.now(timezone.utc) + timedelta(minutes=SESSION_LIFETIME_MINUTES)
#                 st.session_state["remember_me_flag"] = True

# # Lockout helper
# def is_locked():
#     until = st.session_state.get("locked_until")
#     return until and datetime.now(timezone.utc) < until

# # ---------------------------
# # LOGIN PAGE (single clean form)
# # ---------------------------
# if not st.session_state["authenticated"]:
#     st.title("🔐 IAM X-Ray — Login")

#     # If preflight had severe errors, show them
#     if _preflight_errors:
#         st.error("Pre-flight checks failed:")
#         for e in _preflight_errors:
#             st.write("- " + e)
#         st.info("Fix the issues above (permissions / env) or delete data/setup.lock to re-run onboarding.")
#     else:
#         # show helpful info
#         for info in _preflight_infos:
#             st.caption(info)

#     if is_locked():
#         unlock_time = st.session_state["locked_until"].strftime("%H:%M:%S UTC")
#         st.error(f"Too many failed attempts. Try again at **{unlock_time}**.")
#         # offer reset
#         if st.button("Reset local password (forgot?)"):
#             if os.path.exists(AUTH_FILE):
#                 os.remove(AUTH_FILE)
#             if os.path.exists(LOCK_FILE):
#                 os.remove(LOCK_FILE)
#             clear_remember_token()
#             st.success("Local password reset. Reload to re-run onboarding.")
#         st.stop()

#     # Show password toggle and autofocus
#     show_pw = st.checkbox("Show password", value=False)

#     st.markdown("""
#     <script>
#     setTimeout(function(){
#         try {
#             var input = window.parent.document.querySelector('input[type="password"], input[type="text"]');
#             if(input){ input.focus(); }
#         } catch(e) {}
#     }, 120);
#     </script>
#     """, unsafe_allow_html=True)

#     with st.form("login_form"):
#         pw = st.text_input("Password", type="default" if show_pw else "password")
#         remember = st.checkbox("Remember me for 24 hours", value=False)
#         submitted = st.form_submit_button("Login")
#         forgot = st.form_submit_button("Forgot Password")

#     if forgot:
#         st.warning("This will reset your local password and require onboarding again.")
#         if st.button("Confirm reset now"):
#             if os.path.exists(AUTH_FILE):
#                 os.remove(AUTH_FILE)
#             if os.path.exists(LOCK_FILE):
#                 os.remove(LOCK_FILE)
#             clear_remember_token()
#             st.success("Reset done. Reload to run onboarding.")
#         st.stop()

#     if submitted:
#         if not saved_hash or not salt:
#             st.error("Auth setup incomplete. Delete data/setup.lock to re-run onboarding.")
#             st.stop()

#         # Successful login
#         if _hash_pw(pw, salt) == saved_hash:
#             st.session_state["authenticated"] = True
#             st.session_state["login_failures"] = 0
#             st.session_state["locked_until"] = None
#             st.session_state["session_expiry"] = datetime.now(timezone.utc) + timedelta(minutes=SESSION_LIFETIME_MINUTES)
#             st.session_state["remember_me_flag"] = bool(remember)

#             # Remember-me token persistence (24 hours)
#             if remember:
#                 token = _generate_token()
#                 expiry = datetime.now(timezone.utc) + timedelta(hours=24)
#                 save_remember_token(token, expiry)

#             # Admin mode (secret password)
#             if pw == "iamxray-admin":
#                 st.session_state["admin_mode"] = True

#             st.rerun()

#         # Failed login
#         else:
#             st.session_state["login_failures"] += 1
#             remaining = 5 - st.session_state["login_failures"]
#             if remaining <= 0:
#                 st.session_state["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=5)
#                 st.error("Too many attempts. Locked for 5 minutes.")
#             else:
#                 st.error(f"Wrong password. Attempts left: {remaining}")

#     st.stop()
#     # Autofocus on password input
#     st.markdown("""
#      <script>
#      setTimeout(function(){
#       try {
#         var input = window.parent.document.querySelector('input[type="password"], input[type="text"]');
#         if(input){ input.focus(); }
#       } catch(e) {}
#      }, 120);
#    </script>
#    """, unsafe_allow_html=True)

#     with st.form("login_form"):
#      pw = st.text_input("Password", type="default" if show_pw else "password")
#      remember = st.checkbox("Remember me for 24 hours", value=False)
#      submitted = st.form_submit_button("Login")

#      # ---- Forgot Password (outside the form for stable UX) ----
#     st.markdown("### Forgot your password?")
#     if st.button("Reset local password"):
#       st.warning("This will remove your local password and trigger onboarding again.")

#     if st.button("Confirm reset now"):
#         try:
#             # Delete local auth files
#             if os.path.exists(AUTH_FILE):
#                 os.remove(AUTH_FILE)
#             if os.path.exists(LOCK_FILE):
#                 os.remove(LOCK_FILE)
#             if os.path.exists(REMEMBER_PATH):
#                 os.remove(REMEMBER_PATH)

#             # Reset session state cleanly
#             for key in ["authenticated", "remember_me_flag", "session_expiry",
#                         "onboard_step", "onboard_done", "login_failures", "locked_until"]:
#                 if key in st.session_state:
#                     del st.session_state[key]

#             st.success("Password reset successfully. Reload the app to start onboarding again.")
#         except Exception as e:
#             st.error(f"Reset failed: {e}")

#     st.stop()

#     # ---- Login Processing ----
#     if submitted:
#       if not saved_hash or not salt:
#         st.error("Auth setup incomplete. Delete data/setup.lock to re-run onboarding.")
#         st.stop()

#       # SUCCESS
#       if _hash_pw(pw, salt) == saved_hash:
#         st.session_state["authenticated"] = True
#         st.session_state["login_failures"] = 0
#         st.session_state["locked_until"] = None
#         st.session_state["session_expiry"] = datetime.now(timezone.utc) + timedelta(minutes=SESSION_LIFETIME_MINUTES)
#         st.session_state["remember_me_flag"] = bool(remember)

#         # Remember-me token
#         if remember:
#             token = _generate_token()
#             expiry = datetime.now(timezone.utc) + timedelta(hours=24)
#             save_remember_token(token, expiry)

#         # Hidden admin override
#         if pw == "iamxray-admin":
#             st.session_state["admin_mode"] = True

#         st.rerun()

#     # FAILURE
#     else:
#         st.session_state["login_failures"] += 1
#         remaining = 5 - st.session_state["login_failures"]

#         if remaining <= 0:
#             st.session_state["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=5)
#             st.error("Too many attempts. Locked for 5 minutes.")
#         else:
#             st.error(f"Wrong password. Attempts left: {remaining}")

#     st.stop()


#     # Auto-focus JS hack
#     st.markdown("""
#     <script>
#     setTimeout(function(){
#         var input = window.parent.document.querySelector('input[type="password"]');
#         if(input){ input.focus(); }
#     }, 100);
#     </script>
#     """, unsafe_allow_html=True)

#     with st.form("login_form"):
#         pw = st.text_input("Password", type="text" if show_pw else "password")
#         remember = st.checkbox("Remember me for 24 hours", value=False)
#         submitted = st.form_submit_button("Login")  # ENTER triggers this

#     if submitted:
#         if not saved_hash or not salt:
#             st.error("Auth config missing. Delete data/setup.lock and restart to re-run setup.")
#         else:
#             if _hash_pw(pw, salt) == saved_hash:

#                 # Success reset
#                 st.session_state["authenticated"] = True
#                 st.session_state["login_failures"] = 0
#                 st.session_state["locked_until"] = None

#                 # Remember me cookie (24h)
#                 if remember:
#                     st.session_state["iamxray_remember"] = True
#                 else:
#                     st.session_state["iamxray_remember"] = False

#                 st.rerun()

#             else:
#                 st.session_state["login_failures"] += 1
#                 remaining = 5 - st.session_state["login_failures"]
#                 if remaining <= 0:
#                     st.session_state["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=5)
#                     st.error("Too many failed attempts. Locked for 5 minutes.")
#                 else:
#                     st.error(f"Wrong password. Attempts left: {remaining}")

#     st.stop()

# # ---------------------------
# # Top-level UI
# # ---------------------------
# st.markdown("<h1>🔍 IAM X-Ray — Visual AWS Access Map (v0.1.0-beta)</h1>", unsafe_allow_html=True)
# st.write("Balanced UI — fast defaults for beta. Advanced usage (Access Advisor) is disabled by default.")

# # ---------------------------
# # Sidebar controls
# # ---------------------------
# with st.sidebar:
#     st.header("Controls")

#     auth_mode = st.radio("Auth mode", ("Demo", "AWS Profile", "Env Keys"), index=0)

#     session = None
#     profile_name = None
#     aws_region = config.AWS_REGION if hasattr(config, "AWS_REGION") else "us-east-1"

#     if auth_mode == "AWS Profile":
#         profile_name = st.text_input("Profile name", value="default")
#     elif auth_mode == "Env Keys":
#         ak = st.text_input("AWS_ACCESS_KEY_ID", type="password")
#         sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password")
#         token = st.text_input("AWS_SESSION_TOKEN (optional)", type="password")
#         aws_region = st.text_input("AWS_REGION", value=aws_region)
#         if ak and sk:
#             # we won't create session object here; fetch_iam_data handles session/profile_name
#             session = {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": token, "region_name": aws_region}

#     st.markdown("---")

#     st.markdown("**Fetch options**")
#     st.info("FAST uses cached snapshot if present (recommended). FORCE ignores cache and fetches fresh IAM data.")
#     fast_mode = st.checkbox("⚡ Fast fetch (use cache if present)", value=True)
#     force_fetch = st.checkbox("🔄 Force fetch (ignore cache)", value=False)
#     encrypt = st.checkbox("🔒 Encrypt snapshot on save (.json.enc)", value=False)

#     fetch_btn = st.button("🔁 Fetch latest IAM snapshot")

#     st.markdown("---")
#     st.markdown("**View options**")
#     show_only_risky = st.checkbox("Show only risky paths", value=False)
#     show_changes_only = st.checkbox("Show changes only (added/modified + neighbors)", value=False)
#     min_score = st.slider("Min risk score (0-10)", min_value=0, max_value=10, value=0)

#     st.markdown("---")
#     st.markdown("**Search**")
#     search_q = st.text_input("Search action or entity (e.g. s3:PutObject, iam:PassRole, MyPolicy, alice)")
#     if st.button("Search"):
#         st.session_state["search_query"] = search_q.strip()
#     if "search_query" not in st.session_state:
#         st.session_state["search_query"] = ""

#     st.markdown("---")
#     st.caption("Beta housekeeping")
#     # cleanup snapshot
#     try:
#         ui_purge_button()
#     except Exception:
#         st.button("Purge old snapshots (not available)", disabled=True)
    
#     st.markdown("---")

#     # Full Reset App (safe wipe)
#     try:
#         ui_reset_app_button()
#     except Exception:
#         st.button("Reset app (not available)", disabled=True)


# # ---------------------------
# # Fetch snapshot (triggered by button)
# # ---------------------------
# active_snapshot_path = DEMO_PATH if auth_mode == "Demo" else SNAPSHOT_PATH

# if fetch_btn:
#     if auth_mode == "Demo":
#         st.sidebar.info("Demo mode selected — no AWS calls made.")
#     else:
#         st.sidebar.info("Starting fetch... this may take longer with FORCE or if account is large.")
#     with st.spinner("Fetching snapshot..."):
#         try:
#             # fetch_iam_data accepts session or profile_name. We pass profile_name or session dict.
#             if auth_mode == "AWS Profile":
#                 fetch_iam_data(session=None, profile_name=profile_name, out_path=SNAPSHOT_PATH,
#                                fast_mode=fast_mode, force_fetch=force_fetch, encrypt=encrypt, multi_region=False)
#             elif auth_mode == "Env Keys":
#                 # pass via boto3 session creation inside fetch_iam_data is supported by profile_name or session object;
#                 # our fetch_iam_data accepts session object; if it's a dict we pass through to it (it will be ignored in our light fetch)
#                 # To keep it simple: we set environment variables for boto3 to pick up
#                 if session:
#                     os.environ["AWS_ACCESS_KEY_ID"] = session.get("aws_access_key_id", "")
#                     os.environ["AWS_SECRET_ACCESS_KEY"] = session.get("aws_secret_access_key", "")
#                     if session.get("aws_session_token"):
#                         os.environ["AWS_SESSION_TOKEN"] = session.get("aws_session_token")
#                     if aws_region:
#                         os.environ["AWS_REGION"] = aws_region
#                 fetch_iam_data(session=None, profile_name=None, out_path=SNAPSHOT_PATH,
#                                fast_mode=fast_mode, force_fetch=force_fetch, encrypt=encrypt, multi_region=False)
#             st.sidebar.success("Snapshot fetch completed.")
#         except Exception as e:
#             st.sidebar.error(f"Fetch failed: {e}")

# # ---------------------------
# # Load snapshot (DEMO or real)
# # ---------------------------
# if not os.path.exists(active_snapshot_path):
#     if auth_mode == "Demo":
#         st.warning("Demo snapshot not found. Place a sample JSON at data/sample_snapshot.json or fetch a snapshot.")
#     else:
#         st.warning("No snapshot present. Use 'Fetch latest IAM snapshot' to create one, or switch to Demo mode.")
#     st.stop()

# try:
#     data = load_snapshot(active_snapshot_path)
#     if not isinstance(data, dict):
#         raise ValueError("Loaded snapshot is invalid")
# except Exception as e:
#     st.error(f"Failed to load snapshot: {e}")
#     st.stop()

# # ---------------------------
# # Lightweight filtering (shallow copy)
# # ---------------------------
# def shallow_filtered_snapshot(src, min_score=0, show_only_risky=False):
#     out = {
#         "_meta": src.get("_meta", {}),
#         "users": src.get("users", []),
#         "groups": src.get("groups", []),
#         "roles": src.get("roles", []),
#         "policies": src.get("policies", []),
#     }
#     # min_score filter
#     if min_score > 0:
#         out["policies"] = [p for p in out["policies"] if (p.get("RiskScore") or 0) >= min_score]
#         out["roles"] = [r for r in out["roles"] if (r.get("AssumePolicyRiskScore") or 0) >= min_score]
#     if show_only_risky:
#         out["policies"] = [p for p in out["policies"] if p.get("IsRisky")]
#         out["roles"] = [r for r in out["roles"] if r.get("AssumePolicyRisk")]
#         out["users"] = [u for u in out["users"] if u.get("IsRisky")]
#     return out

# filtered_data = shallow_filtered_snapshot(data, min_score=min_score, show_only_risky=show_only_risky)

# # If "changes only", prune to keep set
# if show_changes_only:
#     keep = compute_keep_set_from_diff(data)
#     if keep:
#         filtered_data["users"] = [u for u in filtered_data["users"] if u.get("UserName") in keep]
#         filtered_data["groups"] = [g for g in filtered_data["groups"] if g.get("GroupName") in keep]
#         filtered_data["roles"] = [r for r in filtered_data["roles"] if r.get("RoleName") in keep]
#         filtered_data["policies"] = [p for p in filtered_data["policies"] if p.get("PolicyName") in keep]

# # ---------------------------
# # Snapshot meta display
# # ---------------------------
# meta = data.get("_meta", {}) or {}
# diff = meta.get("diff", {}) or {}
# diff_counts = diff.get("counts", {}) if diff else {}
# impact_score = diff.get("impact_score") or meta.get("impact_score")

# col_top_left, col_top_right = st.columns([3, 1])
# with col_top_left:
#     st.markdown(f"**Snapshot:**  fetched_at: `{meta.get('fetched_at', '—')}`   |   mode: `{'FAST' if meta.get('fast_mode') else 'FULL'}`")
#     counts = meta.get("counts", {})
#     st.markdown(f"Users: **{counts.get('users', len(data.get('users', [])))}**  •  Roles: **{counts.get('roles', len(data.get('roles', [])))}**  •  Policies: **{counts.get('policies', len(data.get('policies', [])))}**")
# with col_top_right:
#     if impact_score is not None:
#         color = "#10B981" if impact_score <= 2 else ("#F59E0B" if impact_score <= 6 else "#EF4444")
#         st.markdown(f"<div style='background:{color};padding:6px;border-radius:6px;color:white;font-weight:700;text-align:center;'>Impact: {impact_score}</div>", unsafe_allow_html=True)

# # ---------------------------
# # Build and display graph (cached)
# # ---------------------------
# @st.cache_data(ttl=900, show_spinner=False)
# def cached_graph_build(snapshot_json_str, show_only_risky_flag, highlight_node, min_score_val):
#     """
#     Cache key is based on snapshot JSON string + view flags to prevent stale graph builds.
#     """
#     # Convert back to dict; graph_builder expects a dict
#     sn = json.loads(snapshot_json_str)
#     # Ensure we pass only necessary top-level keys
#     use_data = {
#         "_meta": sn.get("_meta", {}),
#         "users": sn.get("users", []),
#         "groups": sn.get("groups", []),
#         "roles": sn.get("roles", []),
#         "policies": sn.get("policies", []),
#     }
#     # # Build graph - trimmed inside graph_builder
#     # G, html_str, clicked_node, export_bytes = build_iam_graph(use_data, show_only_risky=show_only_risky_flag,
#     #                                                           highlight_node=highlight_node,
#     #                                                           highlight_color="#ffeb3b",
#     #                                                           highlight_duration=2200)
#     # return G, html_str, clicked_node, export_bytes
#     G, html_str, clicked_node, export_bytes, empty_state = build_iam_graph(
#     use_data,
#     show_only_risky=show_only_risky_flag,
#     highlight_node=highlight_node,
#     highlight_color="#ffeb3b",
#     highlight_duration=2200
#     )
#     return G, html_str, clicked_node, export_bytes, empty_state


# # Prepare snapshot JSON string for cache key
# snapshot_json_str = json.dumps(filtered_data, sort_keys=True, default=str)

# highlight_node = None
# if st.session_state.get("search_query"):
#     # if user searched for an entity, attempt to set it as highlight
#     highlight_node = st.session_state["search_query"]

# # with st.spinner("Building graph (trimmed to safe size)..."):
# #     try:
# #         G, html_str, clicked_node, export_bytes = cached_graph_build(snapshot_json_str, show_only_risky, highlight_node, min_score)
#     #  except Exception as e:
#     #     st.error(f"Graph build failed: {e}")
#     #     st.stop()


# with st.spinner("Building graph (trimmed to safe size)..."):
#     try:
#         G, html_str, clicked_node, export_bytes, empty_state = cached_graph_build(
#         snapshot_json_str,
#         show_only_risky,
#         highlight_node,
#         min_score
#         )
#     except Exception as e:
#         st.error(f"Graph build failed: {e}")
#         st.stop()

# # Display graph
# col_graph, col_detail = st.columns([2, 1])
# with col_graph:
#     st.markdown("### 🕸 IAM Graph")

#     if empty_state:
#         st.warning(f"⚠️ {empty_state['reason'].replace('_',' ').title()}")

#         st.write("### Suggestions")
#         for s in empty_state["suggestions"]:
#             st.write("- " + s)

#         st.write("---")

#         # Suggested actions as buttons
#         if st.button("🔄 Reset Filters"):
#             st.session_state["show_only_risky"] = False
#             st.session_state["min_score"] = 0
#             st.session_state["search_query"] = ""
#             st.rerun()

#         if show_only_risky and st.button("👁 Show Full Graph"):
#             st.session_state["show_only_risky"] = False
#             st.rerun()

#         if min_score > 0 and st.button("⬇ Relax Risk Score"):
#             st.session_state["min_score"] = 0
#             st.rerun()

#         st.info("Graph could not be rendered due to current filters.")
#     else:
#         components.html(html_str, height=760, scrolling=True)
#         st.download_button("Export Graph (JSON)", export_bytes, file_name="iam_graph.json", mime="application/json")

# # col_graph, col_detail = st.columns([2, 1])
# # with col_graph:
# #     st.markdown("### 🕸 IAM Graph")
# #     components.html(html_str, height=760, scrolling=True)
# #     try:
# #         st.download_button("Export Graph (JSON)", export_bytes, file_name="iam_graph.json", mime="application/json")
# #     except Exception:
# #         pass

# # If search query present, perform quick search on the built graph
# search_results = {}
# if st.session_state.get("search_query"):
#     try:
#         search_results = search_permissions(G, st.session_state.get("search_query"))
#     except Exception as e:
#         search_results = {"error": str(e)}

# # ---------------------------
# # Detail Panel
# # ---------------------------
# with col_detail:
#     st.markdown("### 📋 Details")
#     # Quick search results view
#     if st.session_state.get("search_query"):
#         st.markdown(f"**Search:** `{st.session_state['search_query']}`")
#         if "error" in search_results:
#             st.error(search_results["error"])
#         else:
#             who = search_results.get("who_can_do") or []
#             action_map = search_results.get("action_search") or {}
#             fuzzy = search_results.get("fuzzy_matches") or []
#             entity = search_results.get("entity") or {}
#             ent_pols = search_results.get("entity_policies") or {}
#             attached = search_results.get("entity_attached_findings") or {}

#             if action_map:
#                 st.markdown("**Matching policies for action:**")
#                 for act, policies in action_map.items():
#                     st.write(f"- `{act}` → {policies or 'None'}")
#             if who:
#                 st.markdown("**Who can do it:**")
#                 st.write(", ".join(who))
#             if fuzzy:
#                 st.markdown("**Did you mean:**")
#                 for m in fuzzy:
#                     if st.button(f"Focus {m}", key=f"focus_{m}"):
#                         st.session_state["selected_entity"] = {"name": m}
#                         st.rerun()
#             if entity:
#                 st.markdown("**Entity attributes:**")
#                 st.json(entity)
#             if ent_pols:
#                 st.markdown("**Policy findings (quick):**")
#                 for f in ent_pols:
#                     st.write(f"- {f}")

#     # Entity pickers
#     st.markdown("---")
#     policy_names = ["-- none --"] + sorted([p.get("PolicyName") for p in data.get("policies", []) if p.get("PolicyName")])
#     role_names = ["-- none --"] + sorted([r.get("RoleName") for r in data.get("roles", []) if r.get("RoleName")])
#     user_names = ["-- none --"] + sorted([u.get("UserName") for u in data.get("users", []) if u.get("UserName")])

#     chosen_policy = st.selectbox("Policy", options=policy_names, index=0)
#     chosen_role = st.selectbox("Role", options=role_names, index=0)
#     chosen_user = st.selectbox("User", options=user_names, index=0)

#     selected_entity = None
#     if chosen_policy and chosen_policy != "-- none --":
#         selected_entity = ("policy", chosen_policy)
#     elif chosen_role and chosen_role != "-- none --":
#         selected_entity = ("role", chosen_role)
#     elif chosen_user and chosen_user != "-- none --":
#         selected_entity = ("user", chosen_user)

#     if selected_entity:
#         etype, name = selected_entity
#         st.markdown(f"#### {etype.upper()}: {name}")
#         # pull entity from snapshot
#         ent = None
#         if etype == "policy":
#             ent = next((p for p in data.get("policies", []) if p.get("PolicyName") == name), None)
#         elif etype == "role":
#             ent = next((r for r in data.get("roles", []) if r.get("RoleName") == name), None)
#         elif etype == "user":
#             ent = next((u for u in data.get("users", []) if u.get("UserName") == name), None)

#         if not ent:
#             st.info("Entity not present in current view (might be filtered out).")
#         else:
#             tabs = st.tabs(["Overview", "JSON", "Relationships", "Findings", "Summary"])
#             with tabs[0]:
#                 if etype == "policy":
#                     st.metric("RiskScore", ent.get("RiskScore", 0))
#                     st.write("IsRisky:", ent.get("IsRisky"))
#                     st.write("Arn:", ent.get("Arn"))
#                     st.write("Attached inline-of:", ent.get("_inline_of"))
#                 elif etype == "role":
#                     st.metric("AssumeRiskScore", ent.get("AssumePolicyRiskScore", 0))
#                     st.write("AssumePolicyRisk:", ent.get("AssumePolicyRisk"))
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in ent.get("AttachedPolicies") or []])
#                 else:
#                     st.write("Arn:", ent.get("Arn"))
#                     st.write("Groups:", ent.get("Groups", []))
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in ent.get("AttachedPolicies") or []])

#             with tabs[1]:
#                 st.json(ent)

#             with tabs[2]:
#                 if name not in G:
#                     st.info("Entity not in current graph view.")
#                 else:
#                     preds = sorted([n for n in G.predecessors(name)]) if hasattr(G, "predecessors") else []
#                     succs = sorted([n for n in G.successors(name)]) if hasattr(G, "successors") else []
#                     st.write("Incoming:", preds or "—")
#                     st.write("Outgoing:", succs or "—")

#             with tabs[3]:
#                 findings = ent.get("Findings") or []
#                 if not findings:
#                     st.success("No findings (quick scan).")
#                 else:
#                     for f in findings:
#                         st.write(f"- {f.get('code')}: {f.get('message')}")

#             with tabs[4]:
#                 st.markdown("Quick summary")
#                 if etype == "policy":
#                     st.write("RiskScore:", ent.get("RiskScore", 0))
#                 elif etype == "role":
#                     st.write("AssumePolicyRiskScore:", ent.get("AssumePolicyRiskScore", 0))
#                 else:
#                     st.write("IsRisky:", ent.get("IsRisky"))

#     # snapshot download
#     st.markdown("---")
#     st.markdown("Snapshot download")
#     try:
#         # try reading raw file for download; use load_snapshot to support .enc
#         raw = load_snapshot(active_snapshot_path)
#         st.download_button("⬇️ Download snapshot (JSON)", json.dumps(raw, indent=2), file_name=os.path.basename(active_snapshot_path), mime="application/json")
#     except Exception:
#         st.info("Snapshot download unavailable for encrypted snapshots via this UI.")

#     # Export risky items CSV (simple)
#     def export_risky_csv(sn):
#         pols = [p for p in sn.get("policies", []) if p.get("IsRisky")]
#         if not pols:
#             return None
#         buf = StringIO()
#         buf.write("PolicyName,RiskScore,Findings\n")
#         for p in pols:
#             findings_str = "|".join([f.get("code", "") for f in (p.get("Findings") or [])])
#             buf.write(f"{p.get('PolicyName','')},{p.get('RiskScore',0)},{findings_str}\n")
#         return buf.getvalue()

#     csv_data = export_risky_csv(data)
#     if csv_data:
#         st.download_button("⬇️ Export Risky Policies (CSV)", csv_data, file_name="risky_policies.csv", mime="text/csv")

# # Footer tip
# st.caption("Tip: Use Demo mode to try the app without AWS credentials. Use Force Fetch to refresh snapshot when you need a fresh view.")





# # app/main.py
# """
# IAM X-Ray v1.0-beta — GOD TIER EDITION
# Full Premium UI/UX + Zero Friction + Enterprise Feel
# """
# import sys, os, json, hashlib, secrets, time, platform
# from datetime import datetime, timedelta, timezone
# from io import StringIO

# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# import streamlit as st
# import streamlit.components.v1 as components

# # Core imports
# from core.fetch_iam import fetch_iam_data
# from core.graph_builder import build_iam_graph, search_permissions, load_snapshot, compute_keep_set_from_diff
# from core import secure_store, config
# from core.cleanup import ui_purge_button, ui_reset_app_button

# # ========================
# # CONFIG & PATHS
# # ========================
# st.set_page_config(page_title="IAM X-Ray", layout="wide", initial_sidebar_state="expanded")

# DATA_DIR = "data"
# SNAPSHOT_PATH = os.path.join(DATA_DIR, "iam_snapshot.json")
# DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
# AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
# LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")
# REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")
# os.makedirs(DATA_DIR, exist_ok=True)

# # ========================
# # GOD TIER CSS + FULL SCREEN + METRIC CARDS (FINAL 2025 POLISH)
# # ========================
# st.markdown("""
# <style>
#     .main { 
#         background: #0a0a1a; 
#         color: #e0e0ff; 
#         padding: 0 !important; 
#     }
#     .block-container { 
#         padding-top: 2rem; 
#         max-width: 1600px; 
#     }
#     .big-title {
#         font-size: 60px !important;
#         font-weight: 900 !important;
#         background: linear-gradient(90deg, #00D4FF, #8B00FF, #FF2E96);
#         -webkit-background-clip: text;
#         -webkit-text-fill-color: transparent;
#         text-align: center;
#         margin: 20px 0 10px;
#         letter-spacing: -2px;
#     }
#     .card {
#         background: rgba(20, 25, 50, 0.97);
#         padding: 36px;
#         border-radius: 22px;
#         border: 1px solid #33334d;
#         box-shadow: 0 20px 60px rgba(0,0,0,0.6);
#         backdrop-filter: blur(14px);
#     }
#     .success-box {
#         background: linear-gradient(135deg, #00D4FF, #7B00FF);
#         color: white;
#         padding: 18px;
#         border-radius: 18px;
#         text-align: center;
#         font-weight: bold;
#         font-size: 19px;
#         box-shadow: 0 10px 30px rgba(123,0,255,0.3);
#     }
#     hr { 
#         border: 0; 
#         height: 1px; 
#         background: #33334d; 
#         margin: 40px 0; 
#     }
#     .stButton>button { 
#         border-radius: 12px; 
#         height: 50px; 
#         font-weight: bold; 
#     }

#     /* FULL SCREEN GRAPH + PREMIUM METRIC CARDS */
#     iframe {
#         width: 100% !important;
#         height: 100vh !important;
#         min-height: 900px !important;
#         border: none !important;
#         border-radius: 16px !important;
#         box-shadow: 0 10px 40px rgba(0, 0, 0, 0.7) !important;
#     }
#     .main > div { padding-left: 0.5rem !important; padding-right: 0.5rem !important; }
#     section[data-testid="stVerticalBlock"] > div:first-child { width: 100% !important; }

#     /* GOD TIER METRIC CARDS */
#     .metric-card {
#         background: rgba(40,40,80,0.7) !important;
#         padding: 16px !important;
#         border-radius: 16px !important;
#         text-align: center !important;
#         border: 1px solid #444 !important;
#         backdrop-filter: blur(10px);
#         font-size: 14px;
#         height: 90px;
#         display: flex;
#         flex-direction: column;
#         justify-content: center;
#         box-shadow: 0 4px 20px rgba(0,0,0,0.4);
#     }
# </style>
# """, unsafe_allow_html=True)

# # ========================
# # HELPERS
# # ========================
# def _hash_pw(pw: str, salt: str) -> str:    
#     return hashlib.sha256((salt + pw).encode()).hexdigest()

# def _write_json_atomic(path, obj):
#     tmp = path + ".tmp"
#     with open(tmp, "w", encoding="utf-8") as fh:
#         json.dump(obj, fh, indent=2)
#     os.replace(tmp, path)

# def _read_json(path):
#     with open(path, "r", encoding="utf-8") as fh:
#         return json.load(fh)

# def _generate_token():
#     return secrets.token_urlsafe(32)

# def save_remember_token(token: str, expiry: datetime):
#     obj = {"token": token, "expiry": expiry.isoformat()}
#     _write_json_atomic(REMEMBER_PATH, obj)

# def load_remember_token():
#     if os.path.exists(REMEMBER_PATH):
#         try:
#             obj = _read_json(REMEMBER_PATH)
#             obj["expiry"] = datetime.fromisoformat(obj["expiry"]) if obj.get("expiry") else None
#             return obj
#         except: return None
#     return None

# def clear_remember_token():
#     if os.path.exists(REMEMBER_PATH):
#         os.remove(REMEMBER_PATH)

# # ========================
# # FIRST RUN: CINEMATIC 2-STEP ONBOARDING (2025 GOD EDITION)
# # ========================
# if not os.path.exists(AUTH_FILE) and not os.path.exists(LOCK_FILE):
    
#     # === STEP 1: EPIC WELCOME SCREEN (NO PASSWORD) ===
#     if "onboarding_step" not in st.session_state:
#         st.session_state.onboarding_step = "welcome"

#     if st.session_state.onboarding_step == "welcome":
#         # Full screen cinematic welcome
#         st.markdown("""
#         <div style="text-align: center; padding: 80px 20px; min-height: 100vh; display: flex; flex-direction: column; justify-content: center;">
#             <h1 class="big-title" style="font-size: 80px !important; margin-bottom: 20px;">
#                 IAM X-Ray
#             </h1>
#             <p class="subtitle" style="font-size: 28px; margin-bottom: 30px;">
#                 Local • Offline • Zero Trust • No Telemetry
#             </p>
#             <p style="font-size: 26px; color: #ccc; max-width: 900px; margin: 40px auto; line-height: 1.6;">
#                 The most beautiful AWS IAM attack graph visualizer ever built.<br>
#                 <span style="color: #00D4FF; font-weight: 700;">Runs 100% locally. No data leaves your machine. Ever.</span>
#             </p>
#             <p style="color: #888; font-size: 18px; margin-top: 50px;">
#                 Used by red teams, blue teams, and defenders who are done with garbage tools.
#             </p>
#         </div>
#         """, unsafe_allow_html=True)

#         # Big centered button
#         col1, col2, col3 = st.columns([1, 1.5, 1])
#         with col2:
#             if st.button("Get Started →", type="primary", use_container_width=True, key="start_btn"):
#                 st.session_state.onboarding_step = "setup_password"
#                 st.rerun()

#         # Footer
#         st.markdown("""
#         <div style="text-align: center; margin-top: 100px; color: #555; font-size: 15px;">
#             Made with passion by a red teamer who got tired of shitty tools<br>
#             <a href="https://github.com/0x6flaw/IAM-X-Ray" style="color:#00D4FF; text-decoration: none;">github.com/0x6flaw/IAM-X-Ray</a> • AGPL-3.0 • 100% Open Source
#         </div>
#         """, unsafe_allow_html=True)
        
#         st.stop()

#     # === STEP 2: PASSWORD SETUP (Only after Get Started) ===
#     elif st.session_state.onboarding_step == "setup_password":
#         st.markdown('<h1 class="big-title">IAM X-Ray</h1>', unsafe_allow_html=True)
#         st.markdown('<p class="subtitle">One-time local setup • Your data never leaves this device</p>', unsafe_allow_html=True)

#         c1, c2, c3 = st.columns([1, 2.5, 1])
#         with c2:
#             st.markdown("<div class='card'>", unsafe_allow_html=True)
            
#             st.markdown("""
#             <div style="text-align: center; margin-bottom: 30px;">
#                 <h2 style="background: linear-gradient(90deg, #00D4FF, #FF2E96); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 38px; font-weight: 800;">
#                     Secure Your Instance
#                 </h2>
#                 <p style="color: #b0b8d8; font-size: 20px;">
#                     Choose a master password (stored locally only)
#                 </p>
#             </div>
#             """, unsafe_allow_html=True)

#             with st.form("final_onboarding_form", clear_on_submit=True):
#                 col1, col2 = st.columns(2)
#                 with col1:
#                     pw1 = st.text_input("Password", type="password", placeholder="Minimum 6 characters", key="final_pw1")
#                 with col2:
#                     pw2 = st.text_input("Confirm Password", type="password", placeholder="Retype to confirm", key="final_pw2")

#                 st.markdown("<br>", unsafe_allow_html=True)
#                 submitted = st.form_submit_button("Lock & Load →", type="primary", use_container_width=True)

#                 if submitted:
#                     if not pw1 or pw1 != pw2:
#                         st.error("Passwords do not match!")
#                     elif len(pw1) < 6:
#                         st.error("Password must be at least 6 characters long.")
#                     else:
#                         with st.spinner("Encrypting your vault..."):
#                             salt = secrets.token_hex(16)
#                             hashed = _hash_pw(pw1, salt)
#                             _write_json_atomic(AUTH_FILE, {
#                                 "algorithm": "sha256",
#                                 "salt": salt,
#                                 "password_hash": hashed,
#                                 "created_at": datetime.now(timezone.utc).isoformat()
#                             })
#                             open(LOCK_FILE, "w").close()
#                             time.sleep(1.2)

#                         st.balloons()
#                         st.success("Access Granted Forever")
#                         st.markdown("""
#                         <div class='success-box' style='font-size: 22px; padding: 24px;'>
#                             Welcome to the future of IAM hunting
#                         </div>
#                         """, unsafe_allow_html=True)
#                         time.sleep(2.8)
#                         st.rerun()

#             # Back button
#             if st.button("← Back", type="secondary"):
#                 st.session_state.onboarding_step = "welcome"
#                 st.rerun()

#             st.markdown("</div>", unsafe_allow_html=True)
#         st.stop()

# # ========================
# # AUTH LOAD
# # ========================
# saved_hash = salt = None
# if os.path.exists(AUTH_FILE):
#     try:
#         data = _read_json(AUTH_FILE)
#         salt = data.get("salt")
#         saved_hash = data.get("password_hash")
#     except: pass

# # Session state
# for k in ["authenticated", "login_failures", "locked_until", "remember_me_flag", "session_expiry"]:
#     st.session_state.setdefault(k, 0 if k == "login_failures" else None)

# # Auto-login via remember token
# if not st.session_state["authenticated"] and saved_hash:
#     token = load_remember_token()
#     if token and (not token.get("expiry") or token["expiry"] > datetime.now(timezone.utc)):
#         st.session_state["authenticated"] = True
#         st.session_state["session_expiry"] = datetime.now(timezone.utc) + timedelta(minutes=60)

# # Lockout
# if st.session_state["locked_until"] and datetime.now(timezone.utc) < st.session_state["locked_until"]:
#     mins = int((st.session_state["locked_until"] - datetime.now(timezone.utc)).total_seconds() / 60) + 1
#     st.markdown('<h1 class="big-title">Locked Out</h1>', unsafe_allow_html=True)
#     st.error(f"Too many failed attempts. Try again in {mins} minute{'s' if mins != 1 else ''}.")
#     st.stop()

# # ========================
# # PREMIUM LOGIN SCREEN
# # ========================
# if not st.session_state["authenticated"]:
#     st.markdown('<h1 class="big-title">IAM X-Ray</h1>', unsafe_allow_html=True)
#     st.markdown('<p class="subtitle">Enter your local password to access the dashboard</p>', unsafe_allow_html=True)

#     c1, c2, c3 = st.columns([1, 2, 1])
#     with c2:
#         st.markdown("<div class='card'>", unsafe_allow_html=True)

#         # --- Login Form ---
#         with st.form("login_form", clear_on_submit=True):
#             pw = st.text_input("Password", type="password", placeholder="Enter your local password")
#             remember = st.checkbox("Remember me on this device (24 hours)", value=bool(st.session_state.get("remember_me_flag", False)))

#             submitted = st.form_submit_button("Unlock Dashboard", type="primary", use_container_width=True)

#             if submitted:
#                 if not saved_hash or not salt:
#                     st.error("Auth setup missing. Delete data/ folder and restart.")
#                 elif _hash_pw(pw, salt) == saved_hash:
#                     st.session_state["authenticated"] = True
#                     st.session_state["login_failures"] = 0
#                     st.session_state["session_expiry"] = datetime.now(timezone.utc) + timedelta(minutes=60)
#                     if remember:
#                         save_remember_token(_generate_token(), datetime.now(timezone.utc) + timedelta(hours=24))
#                     st.rerun()
#                 else:
#                     st.session_state["login_failures"] += 1
#                     left = 5 - st.session_state["login_failures"]
#                     if left <= 0:
#                         st.session_state["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=5)
#                         st.rerun()
#                     st.error(f"Wrong password • {left} attempt{'s' if left != 1 else ''} left")

#         # --- Forgot Password (Outside Form - Fixed!) ---
#         st.markdown("<div style='text-align: center; margin-top: 20px;'>", unsafe_allow_html=True)
#         if st.button("Forgot Password?", type="secondary", use_container_width=True, key="forgot_btn"):
#             st.session_state["show_reset_confirm"] = True
#         st.markdown("</div>", unsafe_allow_html=True)

#         # --- Reset Confirmation Modal Style ---
#         if st.session_state.get("show_reset_confirm"):
#             st.markdown("<div class='card' style='margin-top: 20px; padding: 20px; background: rgba(100,20,20,0.4); border: 1px solid #833;'>", unsafe_allow_html=True)
#             st.warning("This will delete your local password and restart setup.")
#             col1, col2 = st.columns(2)
#             with col1:
#                 if st.button("Yes, Reset Password", type="secondary", use_container_width=True):
#                     for f in [AUTH_FILE, LOCK_FILE, REMEMBER_PATH]:
#                         if os.path.exists(f):
#                             os.remove(f)
#                     for k in list(st.session_state.keys()):
#                         del st.session_state[k]
#                     st.success("Password reset! Reloading onboarding...")
#                     time.sleep(1.5)
#                     st.rerun()
#             with col2:
#                 if st.button("Cancel", type="primary", use_container_width=True):
#                     st.session_state["show_reset_confirm"] = False
#                     st.rerun()
#             st.markdown("</div>", unsafe_allow_html=True)

#         st.markdown("</div>", unsafe_allow_html=True)
#     st.stop()
# # ---------------------------
# # Top-level UI
# # ---------------------------
# st.markdown("<h1>🔍 IAM X-Ray — Visual AWS Access Map (v0.1.0-beta)</h1>", unsafe_allow_html=True)
# st.write("Balanced UI — fast defaults for beta. Advanced usage (Access Advisor) is disabled by default.")

# # ---------------------------
# # Sidebar controls
# # ---------------------------
# with st.sidebar:
#     st.header("Controls")

#     auth_mode = st.radio("Auth mode", ("Demo", "AWS Profile", "Env Keys"), index=0)

#     session = None
#     profile_name = None
#     aws_region = config.AWS_REGION if hasattr(config, "AWS_REGION") else "us-east-1"

#     if auth_mode == "AWS Profile":
#         profile_name = st.text_input("Profile name", value="default")
#     elif auth_mode == "Env Keys":
#         ak = st.text_input("AWS_ACCESS_KEY_ID", type="password")
#         sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password")
#         token = st.text_input("AWS_SESSION_TOKEN (optional)", type="password")
#         aws_region = st.text_input("AWS_REGION", value=aws_region)
#         if ak and sk:
#             # we won't create session object here; fetch_iam_data handles session/profile_name
#             session = {"aws_access_key_id": ak, "aws_secret_access_key": sk, "aws_session_token": token, "region_name": aws_region}

#     st.markdown("---")

#     st.markdown("**Fetch options**")
#     st.info("FAST uses cached snapshot if present (recommended). FORCE ignores cache and fetches fresh IAM data.")
#     fast_mode = st.checkbox("⚡ Fast fetch (use cache if present)", value=True)
#     force_fetch = st.checkbox("🔄 Force fetch (ignore cache)", value=False)
#     encrypt = st.checkbox("🔒 Encrypt snapshot on save (.json.enc)", value=False)

#     fetch_btn = st.button("🔁 Fetch latest IAM snapshot")

#     st.markdown("---")
#     st.markdown("**View options**")
#     show_only_risky = st.checkbox("Show only risky paths", value=False)
#     show_changes_only = st.checkbox("Show changes only (added/modified + neighbors)", value=False)
#     min_score = st.slider("Min risk score (0-10)", min_value=0, max_value=10, value=0)

#     st.markdown("---")
#     st.markdown("**Search**")
#     search_q = st.text_input("Search action or entity (e.g. s3:PutObject, iam:PassRole, MyPolicy, alice)")
#     if st.button("Search"):
#         st.session_state["search_query"] = search_q.strip()
#     if "search_query" not in st.session_state:
#         st.session_state["search_query"] = ""

#     st.markdown("---")
#     st.caption("Beta housekeeping")
#     # cleanup snapshot
#     try:
#         ui_purge_button()
#     except Exception:
#         st.button("Purge old snapshots (not available)", disabled=True)
    
#     st.markdown("---")

#     # Full Reset App (safe wipe)
#     try:
#         ui_reset_app_button()
#     except Exception:
#         st.button("Reset app (not available)", disabled=True)


# # ---------------------------
# # Fetch snapshot (triggered by button)
# # ---------------------------
# active_snapshot_path = DEMO_PATH if auth_mode == "Demo" else SNAPSHOT_PATH

# if fetch_btn:
#     if auth_mode == "Demo":
#         st.sidebar.info("Demo mode selected — no AWS calls made.")
#     else:
#         st.sidebar.info("Starting fetch... this may take longer with FORCE or if account is large.")
#     with st.spinner("Fetching snapshot..."):
#         try:
#             # fetch_iam_data accepts session or profile_name. We pass profile_name or session dict.
#             if auth_mode == "AWS Profile":
#                 fetch_iam_data(session=None, profile_name=profile_name, out_path=SNAPSHOT_PATH,
#                                fast_mode=fast_mode, force_fetch=force_fetch, encrypt=encrypt, multi_region=False)
#             elif auth_mode == "Env Keys":
#                 # pass via boto3 session creation inside fetch_iam_data is supported by profile_name or session object;
#                 # our fetch_iam_data accepts session object; if it's a dict we pass through to it (it will be ignored in our light fetch)
#                 # To keep it simple: we set environment variables for boto3 to pick up
#                 if session:
#                     os.environ["AWS_ACCESS_KEY_ID"] = session.get("aws_access_key_id", "")
#                     os.environ["AWS_SECRET_ACCESS_KEY"] = session.get("aws_secret_access_key", "")
#                     if session.get("aws_session_token"):
#                         os.environ["AWS_SESSION_TOKEN"] = session.get("aws_session_token")
#                     if aws_region:
#                         os.environ["AWS_REGION"] = aws_region
#                 fetch_iam_data(session=None, profile_name=None, out_path=SNAPSHOT_PATH,
#                                fast_mode=fast_mode, force_fetch=force_fetch, encrypt=encrypt, multi_region=False)
#             st.sidebar.success("Snapshot fetch completed.")
#         except Exception as e:
#             st.sidebar.error(f"Fetch failed: {e}")

# # ---------------------------
# # Load snapshot (DEMO or real)
# # ---------------------------
# if not os.path.exists(active_snapshot_path):
#     if auth_mode == "Demo":
#         st.warning("Demo snapshot not found. Place a sample JSON at data/sample_snapshot.json or fetch a snapshot.")
#     else:
#         st.warning("No snapshot present. Use 'Fetch latest IAM snapshot' to create one, or switch to Demo mode.")
#     st.stop()

# try:
#     data = load_snapshot(active_snapshot_path)
#     if not isinstance(data, dict):
#         raise ValueError("Loaded snapshot is invalid")
# except Exception as e:
#     st.error(f"Failed to load snapshot: {e}")
#     st.stop()

# # ---------------------------
# # Lightweight filtering (shallow copy)
# # ---------------------------
# def shallow_filtered_snapshot(src, min_score=0, show_only_risky=False):
#     out = {
#         "_meta": src.get("_meta", {}),
#         "users": src.get("users", []),
#         "groups": src.get("groups", []),
#         "roles": src.get("roles", []),
#         "policies": src.get("policies", []),
#     }
#     # min_score filter
#     if min_score > 0:
#         out["policies"] = [p for p in out["policies"] if (p.get("RiskScore") or 0) >= min_score]
#         out["roles"] = [r for r in out["roles"] if (r.get("AssumePolicyRiskScore") or 0) >= min_score]
#     if show_only_risky:
#         out["policies"] = [p for p in out["policies"] if p.get("IsRisky")]
#         out["roles"] = [r for r in out["roles"] if r.get("AssumePolicyRisk")]
#         out["users"] = [u for u in out["users"] if u.get("IsRisky")]
#     return out

# filtered_data = shallow_filtered_snapshot(data, min_score=min_score, show_only_risky=show_only_risky)

# # If "changes only", prune to keep set
# if show_changes_only:
#     keep = compute_keep_set_from_diff(data)
#     if keep:
#         filtered_data["users"] = [u for u in filtered_data["users"] if u.get("UserName") in keep]
#         filtered_data["groups"] = [g for g in filtered_data["groups"] if g.get("GroupName") in keep]
#         filtered_data["roles"] = [r for r in filtered_data["roles"] if r.get("RoleName") in keep]
#         filtered_data["policies"] = [p for p in filtered_data["policies"] if p.get("PolicyName") in keep]

# # ---------------------------
# # Snapshot meta display
# # ---------------------------
# meta = data.get("_meta", {}) or {}
# diff = meta.get("diff", {}) or {}
# diff_counts = diff.get("counts", {}) if diff else {}
# impact_score = diff.get("impact_score") or meta.get("impact_score")

# col_top_left, col_top_right = st.columns([3, 1])
# with col_top_left:
#     st.markdown(f"**Snapshot:**  fetched_at: `{meta.get('fetched_at', '—')}`   |   mode: `{'FAST' if meta.get('fast_mode') else 'FULL'}`")
#     counts = meta.get("counts", {})
#     st.markdown(f"Users: **{counts.get('users', len(data.get('users', [])))}**  •  Roles: **{counts.get('roles', len(data.get('roles', [])))}**  •  Policies: **{counts.get('policies', len(data.get('policies', [])))}**")
# with col_top_right:
#     if impact_score is not None:
#         color = "#10B981" if impact_score <= 2 else ("#F59E0B" if impact_score <= 6 else "#EF4444")
#         st.markdown(f"<div style='background:{color};padding:6px;border-radius:6px;color:white;font-weight:700;text-align:center;'>Impact: {impact_score}</div>", unsafe_allow_html=True)

# # ---------------------------
# # Build and display graph (cached)
# # ---------------------------
# @st.cache_data(ttl=900, show_spinner=False)
# def cached_graph_build(snapshot_json_str, show_only_risky_flag, highlight_node, min_score_val):
#     """
#     Cache key is based on snapshot JSON string + view flags to prevent stale graph builds.
#     """
#     # Convert back to dict; graph_builder expects a dict
#     sn = json.loads(snapshot_json_str)
#     # Ensure we pass only necessary top-level keys
#     use_data = {
#         "_meta": sn.get("_meta", {}),
#         "users": sn.get("users", []),
#         "groups": sn.get("groups", []),
#         "roles": sn.get("roles", []),
#         "policies": sn.get("policies", []),
#     }
#     # # Build graph - trimmed inside graph_builder
#     # G, html_str, clicked_node, export_bytes = build_iam_graph(use_data, show_only_risky=show_only_risky_flag,
#     #                                                           highlight_node=highlight_node,
#     #                                                           highlight_color="#ffeb3b",
#     #                                                           highlight_duration=2200)
#     # return G, html_str, clicked_node, export_bytes
#     G, html_str, clicked_node, export_bytes, empty_state = build_iam_graph(
#     use_data,
#     show_only_risky=show_only_risky_flag,
#     highlight_node=highlight_node,
#     highlight_color="#ffeb3b",
#     highlight_duration=2200
#     )
#     return G, html_str, clicked_node, export_bytes, empty_state


# # Prepare snapshot JSON string for cache key
# snapshot_json_str = json.dumps(filtered_data, sort_keys=True, default=str)

# highlight_node = None
# if st.session_state.get("search_query"):
#     # if user searched for an entity, attempt to set it as highlight
#     highlight_node = st.session_state["search_query"]

# # with st.spinner("Building graph (trimmed to safe size)..."):
# #     try:
# #         G, html_str, clicked_node, export_bytes = cached_graph_build(snapshot_json_str, show_only_risky, highlight_node, min_score)
#     #  except Exception as e:
#     #     st.error(f"Graph build failed: {e}")
#     #     st.stop()


# with st.spinner("Building graph (trimmed to safe size)..."):
#     try:
#         G, html_str, clicked_node, export_bytes, empty_state = cached_graph_build(
#         snapshot_json_str,
#         show_only_risky,
#         highlight_node,
#         min_score
#         )
#     except Exception as e:
#         st.error(f"Graph build failed: {e}")
#         st.stop()

# # Display graph
# # ========================
# # FULL SCREEN GRAPH + COLLAPSIBLE DETAIL PANEL
# # ========================
# col_graph, col_detail = st.columns([4, 1])  # 80% graph, 20% detail

# with col_graph:
#     st.markdown("### IAM Graph")

#     if empty_state:
#         st.warning(f"{empty_state['reason'].replace('_',' ').title()}")
#         st.write("### Suggestions")
#         for s in empty_state["suggestions"]:
#             st.write("- " + s)
#         st.write("---")
#         if st.button("Reset Filters"):
#             st.session_state.show_only_risky = False
#             st.session_state.min_score = 0
#             st.session_state.search_query = ""
#             st.rerun()
#         if show_only_risky and st.button("Show Full Graph"):
#             st.session_state.show_only_risky = False
#             st.rerun()
#         if min_score > 0 and st.button("Relax Risk Score"):
#             st.session_state.min_score = 0
#             st.rerun()
#         st.info("Graph could not be rendered due to current filters.")
#     else:
#         # FULL RESPONSIVE GRAPH – NO FIXED HEIGHT
#         components.html(
#             html_str,
#             height=1000,           # Badha diya
#             scrolling=False,       # False kiya taaki poora spread ho
#             width=1200             # Extra wide force
#         )
#         st.download_button(
#             "Export Graph (JSON)",
#             export_bytes,
#             file_name="iam_graph.json",
#             mime="application/json"
#         )

# # If search query present, perform quick search on the built graph
# search_results = {}
# if st.session_state.get("search_query"):
#     try:
#         search_results = search_permissions(G, st.session_state.get("search_query"))
#     except Exception as e:
#         search_results = {"error": str(e)}

# # ---------------------------
# # Detail Panel
# # ---------------------------
# with col_detail:
#     st.markdown("### 📋 Details")
#     # Quick search results view
#     if st.session_state.get("search_query"):
#         st.markdown(f"**Search:** `{st.session_state['search_query']}`")
#         if "error" in search_results:
#             st.error(search_results["error"])
#         else:
#             who = search_results.get("who_can_do") or []
#             action_map = search_results.get("action_search") or {}
#             fuzzy = search_results.get("fuzzy_matches") or []
#             entity = search_results.get("entity") or {}
#             ent_pols = search_results.get("entity_policies") or {}
#             attached = search_results.get("entity_attached_findings") or {}

#             if action_map:
#                 st.markdown("**Matching policies for action:**")
#                 for act, policies in action_map.items():
#                     st.write(f"- `{act}` → {policies or 'None'}")
#             if who:
#                 st.markdown("**Who can do it:**")
#                 st.write(", ".join(who))
#             if fuzzy:
#                 st.markdown("**Did you mean:**")
#                 for m in fuzzy:
#                     if st.button(f"Focus {m}", key=f"focus_{m}"):
#                         st.session_state["selected_entity"] = {"name": m}
#                         st.rerun()
#             if entity:
#                 st.markdown("**Entity attributes:**")
#                 st.json(entity)
#             if ent_pols:
#                 st.markdown("**Policy findings (quick):**")
#                 for f in ent_pols:
#                     st.write(f"- {f}")

#     # Entity pickers
#     st.markdown("---")
#     policy_names = ["-- none --"] + sorted([p.get("PolicyName") for p in data.get("policies", []) if p.get("PolicyName")])
#     role_names = ["-- none --"] + sorted([r.get("RoleName") for r in data.get("roles", []) if r.get("RoleName")])
#     user_names = ["-- none --"] + sorted([u.get("UserName") for u in data.get("users", []) if u.get("UserName")])

#     chosen_policy = st.selectbox("Policy", options=policy_names, index=0)
#     chosen_role = st.selectbox("Role", options=role_names, index=0)
#     chosen_user = st.selectbox("User", options=user_names, index=0)

#     selected_entity = None
#     if chosen_policy and chosen_policy != "-- none --":
#         selected_entity = ("policy", chosen_policy)
#     elif chosen_role and chosen_role != "-- none --":
#         selected_entity = ("role", chosen_role)
#     elif chosen_user and chosen_user != "-- none --":
#         selected_entity = ("user", chosen_user)

#     if selected_entity:
#         etype, name = selected_entity
#         st.markdown(f"#### {etype.upper()}: {name}")
#         # pull entity from snapshot
#         ent = None
#         if etype == "policy":
#             ent = next((p for p in data.get("policies", []) if p.get("PolicyName") == name), None)
#         elif etype == "role":
#             ent = next((r for r in data.get("roles", []) if r.get("RoleName") == name), None)
#         elif etype == "user":
#             ent = next((u for u in data.get("users", []) if u.get("UserName") == name), None)

#         if not ent:
#             st.info("Entity not present in current view (might be filtered out).")
#         else:
#             tabs = st.tabs(["Overview", "JSON", "Relationships", "Findings", "Summary"])
#             with tabs[0]:
#                 if etype == "policy":
#                     st.metric("RiskScore", ent.get("RiskScore", 0))
#                     st.write("IsRisky:", ent.get("IsRisky"))
#                     st.write("Arn:", ent.get("Arn"))
#                     st.write("Attached inline-of:", ent.get("_inline_of"))
#                 elif etype == "role":
#                     st.metric("AssumeRiskScore", ent.get("AssumePolicyRiskScore", 0))
#                     st.write("AssumePolicyRisk:", ent.get("AssumePolicyRisk"))
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in ent.get("AttachedPolicies") or []])
#                 else:
#                     st.write("Arn:", ent.get("Arn"))
#                     st.write("Groups:", ent.get("Groups", []))
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in ent.get("AttachedPolicies") or []])

#             with tabs[1]:
#                 st.json(ent)

#             with tabs[2]:
#                 if name not in G:
#                     st.info("Entity not in current graph view.")
#                 else:
#                     preds = sorted([n for n in G.predecessors(name)]) if hasattr(G, "predecessors") else []
#                     succs = sorted([n for n in G.successors(name)]) if hasattr(G, "successors") else []
#                     st.write("Incoming:", preds or "—")
#                     st.write("Outgoing:", succs or "—")

#             with tabs[3]:
#                 findings = ent.get("Findings") or []
#                 if not findings:
#                     st.success("No findings (quick scan).")
#                 else:
#                     for f in findings:
#                         st.write(f"- {f.get('code')}: {f.get('message')}")

#             with tabs[4]:
#                 st.markdown("Quick summary")
#                 if etype == "policy":
#                     st.write("RiskScore:", ent.get("RiskScore", 0))
#                 elif etype == "role":
#                     st.write("AssumePolicyRiskScore:", ent.get("AssumePolicyRiskScore", 0))
#                 else:
#                     st.write("IsRisky:", ent.get("IsRisky"))

#     # snapshot download
#     st.markdown("---")
#     st.markdown("Snapshot download")
#     try:
#         # try reading raw file for download; use load_snapshot to support .enc
#         raw = load_snapshot(active_snapshot_path)
#         st.download_button("⬇️ Download snapshot (JSON)", json.dumps(raw, indent=2), file_name=os.path.basename(active_snapshot_path), mime="application/json")
#     except Exception:
#         st.info("Snapshot download unavailable for encrypted snapshots via this UI.")

#     # Export risky items CSV (simple)
#     def export_risky_csv(sn):
#         pols = [p for p in sn.get("policies", []) if p.get("IsRisky")]
#         if not pols:
#             return None
#         buf = StringIO()
#         buf.write("PolicyName,RiskScore,Findings\n")
#         for p in pols:
#             findings_str = "|".join([f.get("code", "") for f in (p.get("Findings") or [])])
#             buf.write(f"{p.get('PolicyName','')},{p.get('RiskScore',0)},{findings_str}\n")
#         return buf.getvalue()

#     csv_data = export_risky_csv(data)
#     if csv_data:
#         st.download_button("⬇️ Export Risky Policies (CSV)", csv_data, file_name="risky_policies.csv", mime="text/csv")

# # Footer tip
# st.caption("Tip: Use Demo mode to try the app without AWS credentials. Use Force Fetch to refresh snapshot when you need a fresh view.")





# Chatgpt version code
# app/main.py
"""
IAM X-Ray — GOD-TIER UX Pack
- Full responsive graph (75%)/details (25%) layout
- Collapsible sliding detail drawer
- Floating search bar with keyboard shortcut (/)
- Toast notifications, toasts for first-run
- Remember-me (24h) preserved
- Forgot-password flow preserved and improved

Compatibility notes:
- Uses core.fetch_iam.fetch_iam_data and core.graph_builder.build_iam_graph
- build_iam_graph expected to return (G, html_str, clicked_node, export_bytes, empty_state)
- load_snapshot imported from core.graph_builder or core.fetch_iam

Source file: app/main.py
"""

import sys, os, json, hashlib, secrets, time, platform
from datetime import datetime, timedelta, timezone
from io import StringIO
logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
logo_light_path = os.path.join(os.path.dirname(__file__), "assets", "logo_light.png")
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import streamlit as st
import streamlit.components.v1 as components

# core imports
from core.fetch_iam import fetch_iam_data
from core.graph_builder import build_iam_graph, search_permissions, compute_keep_set_from_diff
# load_snapshot may live in graph_builder or fetch_iam
try:
    from core.graph_builder import load_snapshot
except Exception:
    from core.fetch_iam import load_snapshot

from core import config
from core.cleanup import ui_purge_button, ui_reset_app_button

# ----------------------------
# Page config + base CSS
# ----------------------------
st.set_page_config(page_title="IAM X-Ray — Pro UX", layout="wide", initial_sidebar_state="expanded")
# --------------------------------------------------------------------
# SESSION DEFAULTS (THEME MUST INIT BEFORE ANY UI COMPONENT RENDERS)
# --------------------------------------------------------------------
st.session_state.setdefault("theme", "dark")
st.session_state.setdefault("authenticated", False)
st.session_state.setdefault("drawer_open", True)
st.session_state.setdefault("search_query", "")

# ----------------------------
# THEME TOGGLE (GLOBAL)
# ----------------------------
with st.sidebar:
    st.selectbox(
        "Theme",
        options=["dark", "light"],
        index=0 if st.session_state["theme"] == "dark" else 1,
        key="theme",
        on_change=lambda: st.rerun()
    )

# ----------------------------
# APPLY THEME TO <html> ROOT
# ----------------------------
st.markdown(
    f"<script>document.documentElement.setAttribute('data-theme','{st.session_state['theme']}')</script>",
    unsafe_allow_html=True
)

# ========================
# # GOD TIER CSS + FULL SCREEN + METRIC CARDS (FINAL 2025 POLISH)
# # ========================
st.markdown("""
<style>
    .main { 
        background: #0a0a1a; 
        color: #e0e0ff; 
        padding: 0 !important; 
    }
    .block-container { 
        padding-top: 2rem; 
        max-width: 1600px; 
    }
    .big-title {
        font-size: 60px !important;
        font-weight: 900 !important;
        background: linear-gradient(90deg, #00D4FF, #8B00FF, #FF2E96);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin: 20px 0 10px;
        letter-spacing: -2px;
    }
    .card {
        background: rgba(20, 25, 50, 0.97);
        padding: 36px;
        border-radius: 22px;
        border: 1px solid #33334d;
        box-shadow: 0 20px 60px rgba(0,0,0,0.6);
        backdrop-filter: blur(14px);
    }
    .success-box {
        background: linear-gradient(135deg, #00D4FF, #7B00FF);
        color: white;
        padding: 18px;
        border-radius: 18px;
        text-align: center;
        font-weight: bold;
        font-size: 19px;
        box-shadow: 0 10px 30px rgba(123,0,255,0.3);
    }
    hr { 
        border: 0; 
        height: 1px; 
        background: #33334d; 
        margin: 40px 0; 
    }
    .stButton>button { 
        border-radius: 12px; 
        height: 50px; 
        font-weight: bold; 
    }

    /* FULL SCREEN GRAPH + PREMIUM METRIC CARDS */
    iframe {
        width: 100% !important;
        height: 100vh !important;
        min-height: 900px !important;
        border: none !important;
        border-radius: 16px !important;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.7) !important;
    }
    .main > div { padding-left: 0.5rem !important; padding-right: 0.5rem !important; }
    section[data-testid="stVerticalBlock"] > div:first-child { width: 100% !important; }

    /* GOD TIER METRIC CARDS */
    .metric-card {
        background: rgba(40,40,80,0.7) !important;
        padding: 16px !important;
        border-radius: 16px !important;
        text-align: center !important;
        border: 1px solid #444 !important;
        backdrop-filter: blur(10px);
        font-size: 14px;
        height: 90px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    }
</style>
""", unsafe_allow_html=True)

# ----------------------------
# Paths & helpers
# ----------------------------
DATA_DIR = getattr(config, "DATA_DIR", "data")
SNAPSHOT_PATH = getattr(config, "SNAPSHOT_PATH", os.path.join(DATA_DIR, "iam_snapshot.json"))
DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
LOCK_FILE = os.path.join(DATA_DIR, "setup.lock")
REMEMBER_PATH = os.path.join(DATA_DIR, "iamxray_remember.json")
os.makedirs(DATA_DIR, exist_ok=True)


def _write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)
    os.replace(tmp, path)


def _read_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _hash_pw(pw: str, salt: str) -> str:
    return hashlib.sha256((salt + pw).encode()).hexdigest()


def _generate_token():
    return secrets.token_urlsafe(32)

# remember token helpers

def save_remember_token(token: str, expiry: datetime):
    obj = {"token": token, "expiry": expiry.isoformat()}
    _write_json_atomic(REMEMBER_PATH, obj)


def load_remember_token():
    if os.path.exists(REMEMBER_PATH):
        try:
            o = _read_json(REMEMBER_PATH)
            o['expiry'] = datetime.fromisoformat(o['expiry']) if o.get('expiry') else None
            return o
        except Exception:
            return None
    return None


def clear_remember_token():
    try:
        if os.path.exists(REMEMBER_PATH):
            os.remove(REMEMBER_PATH)
    except Exception:
        pass

# demo snapshot

def create_demo_snapshot_if_missing():
    if os.path.exists(DEMO_PATH):
        return
    demo = {"_meta": {"fetched_at": datetime.now(timezone.utc).isoformat() + "Z", "fast_mode": True, "counts": {"users": 1, "roles": 1, "policies": 1}},
            "users": [{"UserName": "demo-user", "Arn": "arn:aws:iam::123456789012:user/demo-user", "IsRisky": False, "AttachedPolicies": [{"PolicyName": "DemoPolicy"}]}],
            "roles": [], "groups": [], "policies": [{"PolicyName": "DemoPolicy", "RiskScore": 1, "IsRisky": False, "Arn": "arn:aws:iam::123456789012:policy/DemoPolicy"}]}
    _write_json_atomic(DEMO_PATH, demo)

create_demo_snapshot_if_missing()

# ----------------------------
# Lightweight preflight
# ----------------------------
_preflight_infos = []
try:
    testf = os.path.join(DATA_DIR, '.permtest')
    with open(testf, 'w') as fh: fh.write('ok')
    os.remove(testf)
    _preflight_infos.append('Data dir writable')
except Exception as e:
    _preflight_infos.append(f'Data dir not writable: {e}')

if not (getattr(config, 'FERNET_KEY', None) or os.getenv('IAM_XRAY_FERNET_KEY') or os.getenv('FERNET_KEY')):
    _preflight_infos.append('Encryption key not present — encrypted snapshots disabled until provided')
else:
    _preflight_infos.append('Encryption key available')


# ========================
# FIRST RUN: CINEMATIC 2-STEP ONBOARDING (2025 GOD EDITION)
# ========================
if not os.path.exists(AUTH_FILE) and not os.path.exists(LOCK_FILE):
    
    # === STEP 1: EPIC WELCOME SCREEN (NO PASSWORD) ===
    if "onboarding_step" not in st.session_state:
        st.session_state.onboarding_step = "welcome"

    if st.session_state.onboarding_step == "welcome":
        # Full screen cinematic welcome
        
        st.markdown(f"""
        <div style="text-align: center; padding: 80px 20px; min-height: 100vh; display: flex; flex-direction: column; justify-content: center;">
            <h1 class="big-title" style="font-size: 80px !important; margin-bottom: 20px;">
                IAM X-Ray
            </h1>
            <p class="subtitle" style="font-size: 28px; margin-bottom: 30px;">
                Local • Offline • Zero Trust • No Telemetry
            </p>
            <p style="font-size: 26px; color: #ccc; max-width: 900px; margin: 40px auto; line-height: 1.6;">
                The most beautiful AWS IAM attack graph visualizer ever built.<br>
                <span style="color: #00D4FF; font-weight: 700;">Runs 100% locally. No data leaves your machine. Ever.</span>
            </p>
            <p style="color: #888; font-size: 18px; margin-top: 50px;">
                Used by red teams, blue teams, and defenders who are done with garbage tools.
            </p>
         </div>
         """, unsafe_allow_html=True)

        # Move button UP inside welcome container
        st.markdown("""
        <div style="margin-top: 40px; text-align:center;">
        """, unsafe_allow_html=True)

        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
          if st.button("Get Started →", type="primary", use_container_width=True, key="start_btn"):
            st.session_state.onboarding_step = "setup_password"
            st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


        # Footer
        st.markdown("""
        <div style="text-align: center; margin-top: 100px; color: #555; font-size: 15px;">
            Made with passion by a red teamer who got tired of shitty tools<br>
            <a href="https://github.com/MaheshShukla1/IAM-X-Ray" style="color:#00D4FF; text-decoration: none;">github.com/IAM-X-RAYgithub.com/MaheshShukla1/IAM-X-Ray</a> • AGPL-3.0 • 100% Open Source
        </div>
        """, unsafe_allow_html=True)
        
        st.stop()

    # === STEP 2: PASSWORD SETUP (Only after Get Started) ===
    elif st.session_state.onboarding_step == "setup_password":
        st.markdown('<h1 class="big-title">IAM X-Ray</h1>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">One-time local setup • Your data never leaves this device</p>', unsafe_allow_html=True)

        c1, c2, c3 = st.columns([1, 2.5, 1])
        with c2:
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            
            st.markdown("""
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="background: linear-gradient(90deg, #00D4FF, #FF2E96); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 38px; font-weight: 800;">
                    Secure Your Instance
                </h2>
                <p style="color: #b0b8d8; font-size: 20px;">
                    Choose a master password (stored locally only)
                </p>
            </div>
            """, unsafe_allow_html=True)

            with st.form("final_onboarding_form", clear_on_submit=True):
                col1, col2 = st.columns(2)
                with col1:
                    pw1 = st.text_input("Password", type="password", placeholder="Minimum 6 characters", key="final_pw1")
                with col2:
                    pw2 = st.text_input("Confirm Password", type="password", placeholder="Retype to confirm", key="final_pw2")

                st.markdown("<br>", unsafe_allow_html=True)
                submitted = st.form_submit_button("Lock & Load →", type="primary", use_container_width=True)

                if submitted:
                    if not pw1 or pw1 != pw2:
                        st.error("Passwords do not match!")
                    elif len(pw1) < 6:
                        st.error("Password must be at least 6 characters long.")
                    else:
                        with st.spinner("Encrypting your vault..."):
                            salt = secrets.token_hex(16)
                            hashed = _hash_pw(pw1, salt)
                            _write_json_atomic(AUTH_FILE, {
                                "algorithm": "sha256",
                                "salt": salt,
                                "password_hash": hashed,
                                "created_at": datetime.now(timezone.utc).isoformat()
                            })
                            open(LOCK_FILE, "w").close()
                            time.sleep(1.2)

                        st.balloons()
                        st.success("Access Granted Forever")
                        st.markdown("""
                        <div class='success-box' style='font-size: 22px; padding: 24px;'>
                            Welcome to the future of IAM hunting
                        </div>
                        """, unsafe_allow_html=True)
                        time.sleep(2.8)
                        st.rerun()

            # Back button
            if st.button("← Back", type="secondary"):
                st.session_state.onboarding_step = "welcome"
                st.rerun()

            st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

# ========================
# AUTH LOAD
# ========================
saved_hash = salt = None
if os.path.exists(AUTH_FILE):
    try:
        data = _read_json(AUTH_FILE)
        salt = data.get("salt")
        saved_hash = data.get("password_hash")
    except: pass

# Session state
for k in ["authenticated", "login_failures", "locked_until", "remember_me_flag", "session_expiry"]:
    st.session_state.setdefault(k, 0 if k == "login_failures" else None)

# Auto-login via remember token
if not st.session_state["authenticated"] and saved_hash:
    token = load_remember_token()
    if token and (not token.get("expiry") or token["expiry"] > datetime.now(timezone.utc)):
        st.session_state["authenticated"] = True
        st.session_state["session_expiry"] = datetime.now(timezone.utc) + timedelta(minutes=60)

# Lockout
if st.session_state["locked_until"] and datetime.now(timezone.utc) < st.session_state["locked_until"]:
    mins = int((st.session_state["locked_until"] - datetime.now(timezone.utc)).total_seconds() / 60) + 1
    st.markdown('<h1 class="big-title">Locked Out</h1>', unsafe_allow_html=True)
    st.error(f"Too many failed attempts. Try again in {mins} minute{'s' if mins != 1 else ''}.")
    st.stop()

# ========================
# PREMIUM LOGIN SCREEN
# ========================
if not st.session_state["authenticated"]:
    st.markdown('<h1 class="big-title">IAM X-Ray</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Enter your local password to access the dashboard</p>', unsafe_allow_html=True)

    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.markdown("<div class='card'>", unsafe_allow_html=True)

        # --- Login Form ---
        with st.form("login_form", clear_on_submit=True):
            pw = st.text_input("Password", type="password", placeholder="Enter your local password")
            remember = st.checkbox("Remember me on this device (24 hours)", value=bool(st.session_state.get("remember_me_flag", False)))

            submitted = st.form_submit_button("Unlock Dashboard", type="primary", use_container_width=True)

            if submitted:
                if not saved_hash or not salt:
                    st.error("Auth setup missing. Delete data/ folder and restart.")
                elif _hash_pw(pw, salt) == saved_hash:
                    st.session_state["authenticated"] = True
                    st.session_state["login_failures"] = 0
                    st.session_state["session_expiry"] = datetime.now(timezone.utc) + timedelta(minutes=60)
                    if remember:
                        save_remember_token(_generate_token(), datetime.now(timezone.utc) + timedelta(hours=24))
                    st.rerun()
                else:
                    st.session_state["login_failures"] += 1
                    left = 5 - st.session_state["login_failures"]
                    if left <= 0:
                        st.session_state["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=5)
                        st.rerun()
                    st.error(f"Wrong password • {left} attempt{'s' if left != 1 else ''} left")

        # --- Forgot Password (Outside Form - Fixed!) ---
        st.markdown("<div style='text-align: center; margin-top: 20px;'>", unsafe_allow_html=True)
        if st.button("Forgot Password?", type="secondary", use_container_width=True, key="forgot_btn"):
            st.session_state["show_reset_confirm"] = True
        st.markdown("</div>", unsafe_allow_html=True)

        # --- Reset Confirmation Modal Style ---
        if st.session_state.get("show_reset_confirm"):
            st.markdown("<div class='card' style='margin-top: 20px; padding: 20px; background: rgba(100,20,20,0.4); border: 1px solid #833;'>", unsafe_allow_html=True)
            st.warning("This will delete your local password and restart setup.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Yes, Reset Password", type="secondary", use_container_width=True):
                    for f in [AUTH_FILE, LOCK_FILE, REMEMBER_PATH]:
                        if os.path.exists(f):
                            os.remove(f)
                    for k in list(st.session_state.keys()):
                        del st.session_state[k]
                    st.success("Password reset! Reloading onboarding...")
                    time.sleep(1.5)
                    st.rerun()
            with col2:
                if st.button("Cancel", type="primary", use_container_width=True):
                    st.session_state["show_reset_confirm"] = False
                    st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)
    st.stop()


# ----------------------------
# Top header
# --------------------------

# ----------------------------
# Sidebar controls simplified
# ----------------------------
with st.sidebar:
    st.image(logo_path, width=140)
with st.sidebar:
    st.header('Controls')
    auth_mode = st.radio('Auth mode', ('Demo','AWS Profile','Env Keys'))
    profile_name = None
    env_session = None
    if auth_mode == 'AWS Profile':
        profile_name = st.text_input('Profile name', value='default')
    elif auth_mode == 'Env Keys':
        ak = st.text_input('AWS_ACCESS_KEY_ID', type='password')
        sk = st.text_input('AWS_SECRET_ACCESS_KEY', type='password')
        token = st.text_input('AWS_SESSION_TOKEN (optional)', type='password')
        region = st.text_input('AWS_REGION', value=getattr(config,'AWS_REGION','us-east-1'))
        if ak and sk:
            env_session = {'aws_access_key_id':ak,'aws_secret_access_key':sk,'aws_session_token':token,'region_name':region}

    st.write('---')
    st.subheader('Fetch options')
    st.write('FAST uses cache if available. FORCE does live refresh (may be slow).')
    fast_mode = st.checkbox('Fast (use cache if present)', value=True)
    force_fetch = st.checkbox('Force (ignore cache)', value=False)
    encrypt = st.checkbox('Encrypt snapshot on save (.enc)', value=False)
    fetch_btn = st.button('Fetch latest IAM snapshot')

    st.write('---')
    st.subheader('View')
    show_only_risky = st.checkbox('Show only risky paths', value=False)
    show_changes_only = st.checkbox('Show changes only', value=False)
    min_score = st.slider('Min risk score', 0, 10, 0)

    st.write('---')
    st.subheader('Search')
    q = st.text_input('Action or entity', value=st.session_state.get('search_query',''))
    if st.button('Search'):
        st.session_state['search_query'] = (q or '').strip()

    st.write('---')
    st.caption('Beta housekeeping')
    try:
        ui_purge_button()
    except Exception:
        st.button('Purge snapshots (not available)', disabled=True)
    try:
        ui_reset_app_button()
    except Exception:
        st.button('Reset app (not available)', disabled=True)

# ----------------------------
# Fetch flow
# ----------------------------
active_snapshot_path = DEMO_PATH if auth_mode == 'Demo' else SNAPSHOT_PATH
if fetch_btn:
    if auth_mode == 'Demo':
        st.info('Demo selected — no AWS calls will be made')
    else:
        st.info('Starting fetch — may take time for large accounts')
    with st.spinner('Fetching snapshot...'):
        try:
            if auth_mode == 'Env Keys' and env_session:
                os.environ['AWS_ACCESS_KEY_ID'] = env_session.get('aws_access_key_id','')
                os.environ['AWS_SECRET_ACCESS_KEY'] = env_session.get('aws_secret_access_key','')
                if env_session.get('aws_session_token'):
                    os.environ['AWS_SESSION_TOKEN'] = env_session.get('aws_session_token')
                if env_session.get('region_name'):
                    os.environ['AWS_REGION'] = env_session.get('region_name')

            fetch_iam_data(session=None, profile_name=(profile_name if auth_mode=='AWS Profile' else None), out_path=SNAPSHOT_PATH, fast_mode=fast_mode, force_fetch=force_fetch, encrypt=encrypt, multi_region=False)
            # show short toast + dismiss
            st.success('Snapshot fetch finished')
            # collapse any open toasts
            st.rerun()
        except Exception as e:
            st.error(f'Fetch failed: {e}')

# ----------------------------
# Load snapshot
# ----------------------------
if not os.path.exists(active_snapshot_path):
    if auth_mode == 'Demo':
        st.warning('Demo sample missing — run Fetch or place data/sample_snapshot.json')
    else:
        st.warning('No snapshot present. Use Fetch to create one or switch to Demo mode')
    st.stop()

try:
    data = load_snapshot(active_snapshot_path)
    if not isinstance(data, dict):
        raise ValueError('Snapshot invalid')
except Exception as e:
    st.error(f'Failed to load snapshot: {e}')
    st.stop()

# ----------------------------
# Filtering helper
# ----------------------------
def shallow_filtered_snapshot(src, min_score=0, show_only_risky=False):
    out = {'_meta': src.get('_meta', {}), 'users': src.get('users', []), 'groups': src.get('groups', []), 'roles': src.get('roles', []), 'policies': src.get('policies', [])}
    if min_score>0:
        out['policies'] = [p for p in out['policies'] if (p.get('RiskScore') or 0) >= min_score]
        out['roles'] = [r for r in out['roles'] if (r.get('AssumePolicyRiskScore') or 0) >= min_score]
    if show_only_risky:
        out['policies'] = [p for p in out['policies'] if p.get('IsRisky')]
        out['roles'] = [r for r in out['roles'] if r.get('IsRisky')]
        out['users'] = [u for u in out['users'] if u.get('IsRisky')]
    return out

filtered_data = shallow_filtered_snapshot(data, min_score=min_score, show_only_risky=show_only_risky)
if show_changes_only:
    keep = compute_keep_set_from_diff(data)
    if keep:
        filtered_data['users'] = [u for u in filtered_data['users'] if u.get('UserName') in keep]
        filtered_data['groups'] = [g for g in filtered_data['groups'] if g.get('GroupName') in keep]
        filtered_data['roles'] = [r for r in filtered_data['roles'] if r.get('RoleName') in keep]
        filtered_data['policies'] = [p for p in filtered_data['policies'] if p.get('PolicyName') in keep]

# # snapshot meta
# meta = data.get('_meta', {}) or {}
# counts = meta.get('counts', {})
# impact_score = meta.get('impact_score') or meta.get('impact')

# c1,c2 = st.columns([3,1])
# with c1:
#     st.write(f"**Snapshot:** fetched_at `{meta.get('fetched_at','—')}`  — mode: `{'FAST' if meta.get('fast_mode') else 'FULL'}`")
#     st.write(f"Users: **{counts.get('users', len(data.get('users', [])))}** • Roles: **{counts.get('roles', len(data.get('roles', [])))}** • Policies: **{counts.get('policies', len(data.get('policies', [])))}**")
# with c2:
#     if impact_score is not None:
#         color = '#10B981' if impact_score<=2 else ('#F59E0B' if impact_score<=6 else '#EF4444')
#         st.markdown(f"<div style='background:{color};padding:6px;border-radius:6px;color:white;font-weight:700;text-align:center;'>Impact: {impact_score}</div>", unsafe_allow_html=True)

# ================================
# GOD TIER SNAPSHOT INFO CARD — FINAL 2025 EDITION
# ================================
st.markdown("### Snapshot Overview", unsafe_allow_html=True)

meta = data.get('_meta', {}) or {}
counts = meta.get('counts', {})
impact_score = meta.get('impact_score') or meta.get('impact')

col1, col2, col3, col4 = st.columns([2, 1, 1, 1.5])

with col1:
    fetched_at = meta.get('fetched_at', '—')
    date_part = fetched_at.split('T')[0] if 'T' in fetched_at else fetched_at
    time_part = fetched_at.split('T')[1][:8] if 'T' in fetched_at else ''
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size:14px; color:#94a3b8; margin-bottom:4px;">Fetched At</div>
        <div style="font-size:20px; font-weight:800; color:#00D4FF;">
            {date_part}
        </div>
        <div style="font-size:13px; color:#64748b; margin-top:4px;">
            {time_part} UTC
        </div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    fetch_mode = "FAST (cached)" if meta.get('fast_mode') else "FULL (live)"
    mode_color = "#10B981" if meta.get('fast_mode') else "#F59E0B"
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size:14px; color:#94a3b8; margin-bottom:4px;">Fetch Mode</div>
        <div style="font-size:18px; font-weight:800; color:{mode_color};">{fetch_mode}</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    total_entities = (
        len(data.get('users', [])) +
        len(data.get('roles', [])) +
        len(data.get('groups', [])) +
        len(data.get('policies', []))
    )
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size:14px; color:#94a3b8; margin-bottom:4px;">Total Entities</div>
        <div style="font-size:22px; font-weight:900; background: linear-gradient(90deg, #8B00FF, #00D4FF); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            {total_entities:,}
        </div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    if impact_score is not None:
        impact_text = "Low Risk" if impact_score <= 2 else ("Medium Risk" if impact_score <= 6 else "CRITICAL")
        impact_color = "#10B981" if impact_score <= 2 else ("#F59E0B" if impact_score <= 6 else "#EF4444")
        glow_intensity = "strong" if impact_score >= 8 else "medium"
        st.markdown(f"""
        <div class="metric-card" style="border: 2px solid {impact_color}; box-shadow: 0 0 30px {impact_color}40;">
            <div style="font-size:15px; color:#94a3b8; margin-bottom:6px;">Overall Impact</div>
            <div style="font-size:32px; font-weight:900; color:{impact_color}; text-shadow: 0 0 15px {impact_color}80;">
                {impact_score}/10
            </div>
            <div style="font-size:15px; font-weight:700; color:{impact_color}; margin-top:4px;">
                {impact_text}
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="metric-card">
            <div style="font-size:15px; color:#94a3b8;">Overall Impact</div>
            <div style="font-size:18px; color:#64748b; margin-top:8px;">Not calculated</div>
        </div>
        """, unsafe_allow_html=True)

# Mini stats row below — clean & sexy
col_a, col_b, col_c, col_d = st.columns(4)
with col_a:
    st.markdown(f"<div class='metric-card'><b style='color:#3b82f6'>Users</b><br><span style='font-size:22px; font-weight:800'>{counts.get('users', len(data.get('users', []))):,}</span></div>", unsafe_allow_html=True)
with col_b:
    st.markdown(f"<div class='metric-card'><b style='color:#10b981'>Roles</b><br><span style='font-size:22px; font-weight:800'>{counts.get('roles', len(data.get('roles', []))):,}</span></div>", unsafe_allow_html=True)
with col_c:
    st.markdown(f"<div class='metric-card'><b style='color:#f59e0b'>Groups</b><br><span style='font-size:22px; font-weight:800'>{len(data.get('groups', [])):,}</span></div>", unsafe_allow_html=True)
with col_d:
    st.markdown(f"<div class='metric-card'><b style='color:#8b5cf6'>Policies</b><br><span style='font-size:22px; font-weight:800'>{counts.get('policies', len(data.get('policies', []))):,}</span></div>", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ----------------------------
# Build graph (cached)
# ----------------------------
@st.cache_data(ttl=900, show_spinner=False)
def cached_graph_build(snapshot_json_str, show_only_risky_flag, highlight_node, min_score_val):
    sn = json.loads(snapshot_json_str)
    use_data = {'_meta': sn.get('_meta', {}), 'users': sn.get('users', []), 'groups': sn.get('groups', []), 'roles': sn.get('roles', []), 'policies': sn.get('policies', [])}
    return build_iam_graph(use_data, show_only_risky=show_only_risky_flag, highlight_node=highlight_node, highlight_color='#ffeb3b', highlight_duration=2200)

snapshot_json_str = json.dumps(filtered_data, sort_keys=True, default=str)
highlight_node = st.session_state.get('search_query') if st.session_state.get('search_query') else None
with st.spinner('Building graph — trimmed for safety...'):
    try:
        G, html_str, clicked_node, export_bytes, empty_state = cached_graph_build(snapshot_json_str, show_only_risky, highlight_node, min_score)
    except Exception as e:
        st.error(f'Graph build failed: {e}')
        st.stop()

# ========================
# RESPONSIVE GRAPH + SLIDING DETAILS (GOD-TIER)
# ========================
col_graph, col_detail = st.columns([3,1])
with col_graph:
    st.markdown('### 🕸 IAM Graph')
    if empty_state:
        st.warning(f"{empty_state.get('reason','No data').replace('_',' ').title()}")
        st.write('**Suggestions**')
        for s in empty_state.get('suggestions', []):
            st.write('- ' + s)
        st.write('---')
        if st.button('Reset Filters'):
            st.session_state.pop('search_query', None)
            st.rerun()
    else:
        # responsive iframe inside wrapper
        st.markdown('<div class="full-graph">', unsafe_allow_html=True)
        components.html(html_str, height=900, scrolling=False)
        st.markdown('</div>', unsafe_allow_html=True)
        st.download_button('⬇ Export Graph (JSON)', export_bytes, file_name='iam_graph.json', mime='application/json')

# quick search results
search_results = {}
if st.session_state.get('search_query'):
    try:
        search_results = search_permissions(G, st.session_state.get('search_query'))
    except Exception as e:
        search_results = {'error': str(e)}

with col_detail:
    st.markdown('### 📋 Details')
    # search view
    if st.session_state.get('search_query'):
        st.markdown(f"**Search:** `{st.session_state['search_query']}`")
        if 'error' in search_results:
            st.error(search_results['error'])
        else:
            who = search_results.get('who_can_do') or []
            action_map = search_results.get('action_search') or {}
            fuzzy = search_results.get('fuzzy_matches') or []
            entity = search_results.get('entity') or {}
            ent_pols = search_results.get('entity_policies') or {}
            if action_map:
                st.write('**Matching policies for action**')
                for act, pols in action_map.items():
                    st.write(f'- `{act}` → {pols}')
            if who:
                st.write('**Who can do it**')
                st.write(', '.join(who))
            if fuzzy:
                st.write('**Did you mean**')
                for m in fuzzy:
                    if st.button(f'Focus {m}', key=f'f_{m}'):
                        st.session_state['search_query'] = m
                        st.rerun()
            if entity:
                st.write('**Entity attributes**')
                st.json(entity)
            if ent_pols:
                st.write('**Policy findings**')
                for f in ent_pols:
                    st.write(f'- {f}')

    st.write('---')
    st.write('**Pick entity**')
    policy_names = ['-- none --'] + sorted([p.get('PolicyName') for p in data.get('policies', []) if p.get('PolicyName')])
    role_names = ['-- none --'] + sorted([r.get('RoleName') for r in data.get('roles', []) if r.get('RoleName')])
    user_names = ['-- none --'] + sorted([u.get('UserName') for u in data.get('users', []) if u.get('UserName')])

    chosen_policy = st.selectbox('Policy', options=policy_names, index=0)
    chosen_role = st.selectbox('Role', options=role_names, index=0)
    chosen_user = st.selectbox('User', options=user_names, index=0)

    selected_entity = None
    if chosen_policy and chosen_policy != '-- none --':
        selected_entity = ('policy', chosen_policy)
    elif chosen_role and chosen_role != '-- none --':
        selected_entity = ('role', chosen_role)
    elif chosen_user and chosen_user != '-- none --':
        selected_entity = ('user', chosen_user)

    if selected_entity:
        etype, name = selected_entity
        st.markdown(f'#### {etype.upper()}: {name}')
        ent = None
        if etype == 'policy':
            ent = next((p for p in data.get('policies', []) if p.get('PolicyName') == name), None)
        elif etype == 'role':
            ent = next((r for r in data.get('roles', []) if r.get('RoleName') == name), None)
        else:
            ent = next((u for u in data.get('users', []) if u.get('UserName') == name), None)
        if not ent:
            st.info('Entity not present in current view (maybe filtered)')
        else:
            tabs = st.tabs(['Overview','JSON','Relations','Findings'])
            with tabs[0]:
                if etype == 'policy':
                    st.metric('RiskScore', ent.get('RiskScore',0))
                    st.write('Arn:', ent.get('Arn'))
                elif etype == 'role':
                    st.metric('AssumeRiskScore', ent.get('AssumePolicyRiskScore',0))
                    st.write('Attached:', [a.get('PolicyName') for a in ent.get('AttachedPolicies') or []])
                else:
                    st.write('Arn:', ent.get('Arn'))
                    st.write('Groups:', ent.get('Groups', []))
            with tabs[1]:
                st.json(ent)
            with tabs[2]:
                if name not in G:
                    st.info('Entity not in current graph view')
                else:
                    preds = sorted([n for n in G.predecessors(name)]) if hasattr(G,'predecessors') else []
                    succs = sorted([n for n in G.successors(name)]) if hasattr(G,'successors') else []
                    st.write('Incoming:', preds or '—')
                    st.write('Outgoing:', succs or '—')
            with tabs[3]:
                findings = ent.get('Findings') or []
                if not findings:
                    st.success('No quick findings')
                else:
                    for f in findings:
                        st.write(f"- {f.get('code')}: {f.get('message')}")

    st.write('---')
    st.write('Snapshot download')
    try:
        raw = load_snapshot(active_snapshot_path)
        st.download_button('Download snapshot (JSON)', json.dumps(raw, indent=2, default=str), file_name=os.path.basename(active_snapshot_path), mime='application/json')
    except Exception:
        st.info('Snapshot download unavailable for encrypted snapshots via this UI')

    def export_risky_csv(sn):
     """Export risky policies — 100% safe for string or dict Findings"""
     pols = [p for p in sn.get('policies', []) if p.get('IsRisky')]
     if not pols:
        return None

     buf = StringIO()
     buf.write('PolicyName,PolicyArn,RiskScore,Findings\n')

     for p in pols:
        policy_name = p.get('PolicyName', 'Unknown')
        policy_arn = p.get('Arn', 'N/A')
        risk_score = p.get('RiskScore', 0)

        # SAFE: Handle both dict and string findings
        findings_raw = p.get('Findings') or []
        finding_codes = []

        for item in findings_raw:
            if isinstance(item, dict):
                code = item.get('code') or item.get('Code') or str(item)
                finding_codes.append(code)
            elif isinstance(item, str):
                finding_codes.append(item)
            else:
                finding_codes.append(str(item))

        findings_str = '|'.join(finding_codes) if finding_codes else 'None'
        findings_str = findings_str.replace('"', '""')  # CSV escape

        line = f'"{policy_name}","{policy_arn}",{risk_score},"{findings_str}"\n'
        buf.write(line)

     return buf.getvalue()

    csv_data = export_risky_csv(data) if isinstance(data, dict) and data.get('policies') else None

    if csv_data:
      st.download_button(
        label="Export Risky Policies (CSV)",
        data=csv_data,
        file_name="iam_xray_risky_policies.csv",
        mime="text/csv",
        use_container_width=True
    )
    else:
      st.caption("No risky policies found to export")

# footer
st.caption('Tip: Use Demo to try without AWS credentials. Use Force to refresh live data.')
# st.markdown(
#     f"<div style='text-align:center; margin-top:40px; opacity:5;'>"
#     f"<img src='{logo_light_path}' width='90'></div>",
#     unsafe_allow_html=True
# )

# # floating search + keyboard shortcut (/) - small JS to focus input
# components.html("""
# <script>
# window.addEventListener('keydown', function(e){
#     if(e.key === '/'){
#         e.preventDefault();
#         const el = parent.document.querySelector('input[placeholder="Action or entity"]') || parent.document.querySelector('input[type=text]');
#         if(el) el.focus();
#     }
# });
# </script>
# """, height=0)


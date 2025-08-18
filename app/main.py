# # app/main.py

# import sys, os
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# import json
# import streamlit as st
# import streamlit.components.v1 as components
# from copy import deepcopy

# from core.fetch_iam import fetch_iam_data
# from core.graph_builder import (
#     build_iam_graph,
#     NODE_COLORS,
#     compute_keep_set_from_diff,
#     build_adjacency,
# )
# # ⬇️ Phase-3: permission search helper
# from core.graph_builder import search_permissions

# st.set_page_config(page_title="IAM X-Ray", layout="wide", initial_sidebar_state="expanded")

# # ---- CSS
# st.markdown("""
# <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
# <style>
# html, body, [data-testid="stAppViewContainer"] { font-family: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, Arial; }
# h1 { font-size: 28px; font-weight: 700; margin-bottom: 2px; }
# .graph-card { border-radius: 12px; padding: 10px; background: #0b0f19; box-shadow: 0 8px 24px rgba(0,0,0,.35); }
# .detail-card { border-radius: 12px; padding: 14px; background: #0b0f19; box-shadow: 0 8px 24px rgba(0,0,0,.35); }
# .tip { color:#97a0af; font-size: 13px; }
# .badge { display:inline-block; padding:6px 10px; border-radius:8px; font-weight:600; color:#fff; }
# </style>
# """, unsafe_allow_html=True)

# st.markdown("<h1>🔐 IAM X-Ray — Visual AWS Access Map</h1>", unsafe_allow_html=True)

# SNAPSHOT_PATH = "data/iam_snapshot.json"

# # ---- SIDEBAR
# if "sidebar_collapsed" not in st.session_state:
#     st.session_state["sidebar_collapsed"] = False

# with st.sidebar:
#     if st.checkbox("Collapse sidebar (show minimal)", value=st.session_state["sidebar_collapsed"]):
#         st.session_state["sidebar_collapsed"] = True
#     else:
#         st.session_state["sidebar_collapsed"] = False

#     controls_expanded = not st.session_state["sidebar_collapsed"]
#     with st.expander("Controls", expanded=controls_expanded):
#         st.header("Controls")
#         profile = st.text_input("AWS profile (optional)", value="")
#         fast_mode = st.checkbox("⚡ Fast fetch (seconds)", value=True)
#         force = st.checkbox("Force fetch (ignore cache)", value=False)
#         fetch_btn = st.button("🔁 Fetch latest IAM snapshot")
#         show_only_risky = st.checkbox("Show only risky paths", value=False)
#         show_only_changes = st.checkbox("Show only changes (added/modified + neighbors)", value=False)
#         min_score = st.slider("Min risk score (0-10)", 0, 10, 0)

#     # 🔎 Phase-3: Search box (action / entity)
#     with st.expander("Search", expanded=True):
#         q_default = st.session_state.get("search_query", "")
#         q = st.text_input("Search action or entity", value=q_default,
#                           placeholder="e.g. s3:PutObject  •  iam:PassRole  •  MyPolicy  •  alice")
#         run_search = st.button("Search")
#         if run_search:
#             st.session_state["search_query"] = q or ""
#             # results will be computed after graph is built (need G)

#     with st.expander("Risky items / Changes", expanded=False):
#         st.write("Loading snapshot to populate...")

# # ---- Fetch action
# if 'fetch_btn' in locals() and fetch_btn:
#     with st.spinner("Fetching IAM data from AWS..."):
#         try:
#             fetch_iam_data(
#                 profile_name=(profile or None),
#                 out_path=SNAPSHOT_PATH,
#                 fast_mode=fast_mode,
#                 force_fetch=force,
#             )
#             st.sidebar.success("Snapshot saved.")
#         except Exception as e:
#             st.sidebar.error(f"Fetch failed: {e}")
#             st.stop()

# # ---- Load snapshot
# if not os.path.exists(SNAPSHOT_PATH):
#     st.info("No snapshot found. Use the sidebar to fetch from AWS.")
#     st.stop()

# try:
#     with open(SNAPSHOT_PATH, "r", encoding="utf-8") as f:
#         data = json.load(f)
# except Exception as e:
#     st.error(f"Failed to load snapshot: {e}")
#     st.stop()

# # ---- Min-score filter
# if min_score > 0:
#     data = deepcopy(data)
#     data["policies"] = [p for p in data.get("policies", []) if (p.get("RiskScore") or 0) >= min_score]
#     data["roles"] = [r for r in data.get("roles", []) if (r.get("AssumePolicyRiskScore") or 0) >= min_score]

# # ---- Snapshot meta
# meta = data.get("_meta", {})
# diff = meta.get("diff", {}) or {}
# diff_counts = diff.get("counts", {}) if diff else {}
# impact_score = diff.get("impact_score") if diff else None

# # ---- Sidebar risky items
# with st.sidebar:
#     with st.expander("Risky items / Changes", expanded=True):
#         if meta.get("fast_mode"):
#             st.warning("FAST MODE: Some relationships/policies may be missing.")
#         if diff:
#             st.markdown("**Changes (since previous snapshot):**")
#             st.write(f"➕ Added: {diff_counts.get('added', 0)}")
#             st.write(f"🔄 Modified: {diff_counts.get('modified', 0)}")
#             st.write(f"➖ Removed: {diff_counts.get('removed', 0)}")
#             if impact_score is not None:
#                 color = "#10B981" if impact_score <= 2 else ("#F59E0B" if impact_score <= 6 else "#EF4444")
#                 st.markdown(f"<span class='badge' style='background:{color}'>Impact Score: {impact_score}</span>", unsafe_allow_html=True)
#         counts = meta.get("counts", {})
#         st.write(f"Users: {counts.get('users', len(data.get('users', [])))}")
#         st.write(f"Roles: {counts.get('roles', len(data.get('roles', [])))}")
#         st.write(f"Policies: {counts.get('policies', len(data.get('policies', [])))}")

#         risky_choices = []
#         for p in data.get("policies", []):
#             if p.get("IsRisky") or p.get("_changed"):
#                 risky_choices.append(("policy", p.get("PolicyName")))
#         for r in data.get("roles", []):
#             if r.get("AssumePolicyRisk") or r.get("_changed"):
#                 risky_choices.append(("role", r.get("RoleName")))
#         for u in data.get("users", []):
#             if u.get("IsRisky") or u.get("_changed"):
#                 risky_choices.append(("user", u.get("UserName")))

#         if risky_choices:
#             option_display = [f"{t.UPPER() if hasattr(t,'UPPER') else t.upper()}: {n}" for (t, n) in risky_choices]
#             sel = st.selectbox("Risky / changed items", options=["-- none --"] + option_display)
#             if sel and sel != "-- none --":
#                 if st.button("Jump to selected"):
#                     _, chosen = sel.split(": ", 1)
#                     typ = sel.split(":")[0].lower()
#                     st.session_state["selected_entity"] = {"type": typ, "name": chosen}
#         else:
#             st.write("No risky/changed items found.")

# # ---- Layout
# col1, col2 = st.columns([2, 1])

# # ===================== GRAPH (col1) =====================
# with col1:
#     st.header("🕸️ IAM Graph — Interactive")

#     # 📦 Snapshot Info
#     st.markdown(
#         f"""
#         <div style="background:#111;padding:10px;border-radius:8px;margin-bottom:10px;">
#         <b>📦 Snapshot Info</b><br>
#         <span style="color:#bbb;">Fetched:</span> {meta.get("fetched_at", "—")}<br>
#         <span style="color:#bbb;">Profile:</span> {profile or "default"}<br>
#         <span style="color:#bbb;">Mode:</span> {"Fast" if meta.get("fast_mode") else "Full"}<br>
#         <span style="color:#bbb;">Entities:</span> Users: {meta.get("counts",{}).get("users",0)}, 
#         Roles: {meta.get("counts",{}).get("roles",0)}, 
#         Policies: {meta.get("counts",{}).get("policies",0)}
#         </div>
#         """, unsafe_allow_html=True
#     )

#     highlight = (st.session_state.get("selected_entity") or {}).get("name")

#     try:
#         use_data = data
#         if 'show_only_changes' in locals() and show_only_changes:
#             keep = compute_keep_set_from_diff(data)
#             if keep:
#                 filtered = deepcopy(data)
#                 filtered["users"] = [u for u in data.get("users", []) if u.get("UserName") in keep]
#                 filtered["groups"] = [g for g in data.get("groups", []) if g.get("GroupName") in keep]
#                 filtered["roles"] = [r for r in data.get("roles", []) if r.get("RoleName") in keep]
#                 filtered["policies"] = [p for p in data.get("policies", []) if p.get("PolicyName") in keep]
#                 filtered["_meta"] = deepcopy(data.get("_meta", {}))
#                 use_data = filtered

#         G, html_str, clicked_node = build_iam_graph(
#             use_data,
#             show_only_risky=show_only_risky,
#             highlight_node=highlight,
#             highlight_color="orange",
#             highlight_duration=2500
#         )

#         # 🔎 Phase-3: compute search results after G is ready
#         if "search_query" in st.session_state and st.session_state["search_query"]:
#             try:
#                 st.session_state["search_results"] = search_permissions(G, st.session_state["search_query"])
#             except Exception as _e:
#                 st.session_state["search_results"] = {"error": str(_e)}

#         if clicked_node:
#             node_type = G.nodes[clicked_node].get("type", "policy")
#             st.session_state["selected_entity"] = {"type": node_type, "name": clicked_node}

#         st.markdown('<div class="graph-card">', unsafe_allow_html=True)
#         components.html(f"<div style='width:100%;'>{html_str}</div>", height=760, scrolling=True)
#         st.markdown('</div>', unsafe_allow_html=True)

#         with st.expander("Legend", expanded=False):
#             st.markdown(f"""
#             **Legend:**
#             - <span style="color:{NODE_COLORS['user']}">■</span> User
#             - <span style="color:{NODE_COLORS['group']}">■</span> Group
#             - <span style="color:{NODE_COLORS['role']}">■</span> Role
#             - <span style="color:{NODE_COLORS['policy']}">■</span> Policy
#             - <span style="color:#FF6B6B">■</span> Risky
#             """, unsafe_allow_html=True)

#     except Exception as e:
#         st.error(f"Failed to render interactive graph: {e}")

# # ===================== DETAILS (col2) =====================
# with col2:
#     st.header("📋 Details")

#     # 🔎 Phase-3: Show search results (if any)
#     if st.session_state.get("search_query"):
#         st.subheader(f"🔎 Results for: `{st.session_state['search_query']}`")
#         sr = st.session_state.get("search_results") or {}
#         if "error" in sr:
#             st.error(sr["error"])
#         else:
#             # Action search matches -> policies
#             action_map = sr.get("action_search") or {}
#             for action, policies in action_map.items():
#                 st.markdown(f"**Action:** `{action}`")
#                 if not policies:
#                     st.info("No matching customer-managed policies found.")
#                 else:
#                     for pname in sorted(set(policies)):
#                         cols = st.columns([1, 1])
#                         with cols[0]:
#                             st.write(f"Policy: **{pname}**")
#                         with cols[1]:
#                             if st.button(f"Focus {pname}", key=f"focus_policy_{pname}"):
#                                 st.session_state["selected_entity"] = {"type": "policy", "name": pname}
#                                 # trigger highlight on next render
#                                 st.experimental_rerun()

#             # Entity search info
#             ent = sr.get("entity")
#             if ent:
#                 st.markdown("**Entity attributes:**")
#                 st.json(ent)

#             ent_pols = sr.get("entity_policies")
#             if ent_pols:
#                 st.markdown("**Policy Findings (quick scan):**")
#                 for f in ent_pols:
#                     st.write(f"- `{f.get('action')}` (pattern: `{f.get('pattern')}` | effect: {f.get('effect')})")

#         st.divider()

#     policy_names = ["-- none --"] + sorted([p.get("PolicyName") for p in data.get("policies", []) if p.get("PolicyName")])
#     role_names = ["-- none --"] + sorted([r.get("RoleName") for r in data.get("roles", []) if r.get("RoleName")])
#     user_names = ["-- none --"] + sorted([u.get("UserName") for u in data.get("users", []) if u.get("UserName")])

#     selected = st.session_state.get("selected_entity")

#     chosen_policy = st.selectbox("Select policy", options=policy_names, index=0)
#     chosen_role = st.selectbox("Select role", options=role_names, index=0)
#     chosen_user = st.selectbox("Select user", options=user_names, index=0)

#     if not selected:
#         if chosen_policy != "-- none --":
#             selected = {"type": "policy", "name": chosen_policy}
#         elif chosen_role != "-- none --":
#             selected = {"type": "role", "name": chosen_role}
#         elif chosen_user != "-- none --":
#             selected = {"type": "user", "name": chosen_user}

#     st.markdown('<div class="detail-card">', unsafe_allow_html=True)

#     tab_overview, tab_json, tab_rels, tab_hints = st.tabs(["Overview", "Policy JSON", "Relationships", "Least-Privilege Hints"])

#     def _render_findings(findings):
#         if not findings:
#             st.success("No findings.")
#             return
#         sever_map = {"high": "🔴 High", "medium": "🟠 Medium", "low": "🟡 Low"}
#         for f in findings:
#             sev = sever_map.get((f.get("severity") or "").lower(), "ℹ️ Info")
#             with st.container():
#                 st.markdown(f"**{sev}** — `{f.get('code')}`")
#                 st.write(f.get("message") or "")
#                 if f.get("hint"):
#                     st.caption(f"Hint: {f['hint']}")
#                 if f.get("path"):
#                     st.caption(f"Path: {f['path']}")
#                 st.divider()

#     if selected:
#         etype, name = selected["type"], selected["name"]

#         with tab_overview:
#             st.markdown(f"### {etype.upper()} — {name}")
#             if etype == "policy":
#                 p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
#                 if p:
#                     st.metric("RiskScore", p.get("RiskScore", 0))
#                     st.write("IsRisky:", p.get("IsRisky"))
#                     st.write("RiskActions:", p.get("RiskActions"))
#                     st.write("Arn:", p.get("Arn"))
#             elif etype == "role":
#                 r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
#                 if r:
#                     st.metric("AssumeRiskScore", r.get("AssumePolicyRiskScore", 0))
#                     st.write("AssumePolicyRisk:", r.get("AssumePolicyRisk"))
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in (r.get("AttachedPolicies") or [])])
#                     st.write("Arn:", r.get("Arn"))
#             elif etype == "user":
#                 u = next((x for x in data.get("users", []) if x.get("UserName") == name), None)
#                 if u:
#                     st.write("Arn:", u.get("Arn"))
#                     st.write("Groups:", u.get("Groups", []))
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in (u.get("AttachedPolicies") or [])])

#         with tab_json:
#             if etype == "policy":
#                 p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
#                 if p:
#                     st.json(p.get("Document") or {})
#                 else:
#                     st.info("No policy JSON available.")
#             elif etype == "role":
#                 r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
#                 if r:
#                     st.json(r.get("AssumeRolePolicyDocument") or {})
#                 else:
#                     st.info("No assume role policy document available.")
#             else:
#                 st.info("JSON view is available for policies and roles only.")

#         with tab_rels:
#             if 'G' in locals():
#                 if name not in G:
#                     st.info("Selected entity not present in the current graph view.")
#                 else:
#                     preds = sorted([n for n in G.predecessors(name)]) if hasattr(G, "predecessors") else []
#                     succs = sorted([n for n in G.successors(name)]) if hasattr(G, "successors") else []
#                     st.write("Incoming:", preds or "—")
#                     st.write("Outgoing:", succs or "—")
#             else:
#                 st.info("Graph not built - relationships unavailable.")

#         with tab_hints:
#             if etype == "policy":
#                 p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
#                 if p:
#                     _render_findings(p.get("Findings") or [])
#                 else:
#                     st.info("No findings.")
#             elif etype == "role":
#                 r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
#                 if r:
#                     # trust findings + attached policy findings
#                     trust = r.get("AssumePolicyFindings") or []
#                     st.subheader("Trust policy")
#                     _render_findings(trust)
#                     if r.get("AttachedPolicies"):
#                         st.subheader("Attached customer-managed policies")
#                         # map attached names to findings available in snapshot["policies"]
#                         attached_names = [a.get("PolicyName") for a in (r.get("AttachedPolicies") or [])]
#                         for pname in attached_names:
#                             pol = next((x for x in data.get("policies", []) if x.get("PolicyName") == pname), None)
#                             if pol:
#                                 st.markdown(f"**Policy:** {pname}")
#                                 _render_findings(pol.get("Findings") or [])
#                 else:
#                     st.info("No findings.")
#             elif etype == "user":
#                 u = next((x for x in data.get("users", []) if x.get("UserName") == name), None)
#                 if u:
#                     st.subheader("Attached customer-managed policies")
#                     for ap in (u.get("AttachedPolicies") or []):
#                         pname = ap.get("PolicyName")
#                         pol = next((x for x in data.get("policies", []) if x.get("PolicyName") == pname), None)
#                         if pol:
#                             st.markdown(f"**Policy:** {pname}")
#                             _render_findings(pol.get("Findings") or [])
#                     # inline user policy findings (if fetched in non-fast mode)
#                     inline_prefix = f"{name}::INLINE::"
#                     inlines = [p for p in data.get("policies", []) if p.get("PolicyName","").startswith(inline_prefix)]
#                     if inlines:
#                         st.subheader("Inline policies")
#                         for pol in inlines:
#                             st.markdown(f"**Policy:** {pol.get('PolicyName')}")
#                             _render_findings(pol.get("Findings") or [])
#                 else:
#                     st.info("No findings.")

#     st.markdown('</div>', unsafe_allow_html=True)

#     st.markdown("---")
#     if st.button("Download snapshot (JSON)"):
#         with open(SNAPSHOT_PATH, "r", encoding="utf-8") as f:
#             st.download_button(
#                 "Click to download snapshot.json",
#                 f.read(),
#                 file_name="iam_snapshot.json",
#                 mime="application/json"
#             )

# st.caption("Tip: Click on a node in the graph or use the sidebar to explore IAM entities.")




# # app/main.py
# import sys, os
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# import json
# import boto3
# import streamlit as st
# import streamlit.components.v1 as components
# from copy import deepcopy
# from datetime import datetime as dt, timedelta
# from core.graph_builder import load_snapshot

# from core.fetch_iam import fetch_iam_data
# from core.graph_builder import (
#     build_iam_graph,
#     NODE_COLORS,
#     compute_keep_set_from_diff,
#     build_adjacency,
# )
# # ⬇️ Phase-3: permission search helper
# from core.graph_builder import search_permissions

# st.set_page_config(page_title="IAM X-Ray", layout="wide", initial_sidebar_state="expanded")

# # ---- CSS
# st.markdown("""
# <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
# <style>
# html, body, [data-testid="stAppViewContainer"] { font-family: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, Arial; }
# h1 { font-size: 28px; font-weight: 700; margin-bottom: 2px; }
# .graph-card { border-radius: 12px; padding: 10px; background: #0b0f19; box-shadow: 0 8px 24px rgba(0,0,0,.35); }
# .detail-card { border-radius: 12px; padding: 14px; background: #0b0f19; box-shadow: 0 8px 24px rgba(0,0,0,.35); }
# .tip { color:#97a0af; font-size: 13px; }
# .badge { display:inline-block; padding:6px 10px; border-radius:8px; font-weight:600; color:#fff; }
# </style>
# """, unsafe_allow_html=True)

# st.markdown("<h1>🔐 IAM X-Ray — Visual AWS Access Map</h1>", unsafe_allow_html=True)

# SNAPSHOT_PATH = "data/iam_snapshot.json"
# DEMO_PATH = "data/sample_snapshot.json"

# # ---- SIDEBAR
# if "sidebar_collapsed" not in st.session_state:
#     st.session_state["sidebar_collapsed"] = False

# with st.sidebar:
#     if st.checkbox("Collapse sidebar (show minimal)", value=st.session_state["sidebar_collapsed"]):
#         st.session_state["sidebar_collapsed"] = True
#     else:
#         st.session_state["sidebar_collapsed"] = False

#     controls_expanded = not st.session_state["sidebar_collapsed"]
#     with st.expander("Controls", expanded=controls_expanded):
#         st.header("Controls")

#         # --- Auth block ---
#         auth_mode = st.radio("Auth mode", ["Demo", "AWS Profile", "Env Keys"], index=0)
#         session = None
#         profile = None

#         if auth_mode == "AWS Profile":
#             profile = st.text_input("AWS profile name", value="default")
#             if profile:
#                 try:
#                     session = boto3.Session(profile_name=profile)
#                 except Exception as e:
#                     st.error(f"Failed to init AWS profile: {e}")
#         elif auth_mode == "Env Keys":
#             ak = st.text_input("AWS_ACCESS_KEY_ID", type="password")
#             sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password")
#             token = st.text_input("AWS_SESSION_TOKEN (optional)", type="password")
#             region = st.text_input("AWS_REGION (optional)", value="us-east-1")
#             if ak and sk:
#                 try:
#                     session = boto3.Session(
#                         aws_access_key_id=ak,
#                         aws_secret_access_key=sk,
#                         aws_session_token=token or None,
#                         region_name=region or None,
#                     )
#                 except Exception as e:
#                     st.error(f"Failed to init AWS session: {e}")

#         # --- Fetch options ---
#         fast_mode = st.checkbox("⚡ Fast fetch (seconds)", value=True)
#         force = st.checkbox("Force fetch (ignore cache)", value=False)
#         encrypt = st.checkbox("🔒 Encrypt snapshot", value=False)

#         fetch_btn = st.button("🔁 Fetch latest IAM snapshot")
#         show_only_risky = st.checkbox("Show only risky paths", value=False)
#         show_only_changes = st.checkbox("Show only changes (added/modified + neighbors)", value=False)
#         min_score = st.slider("Min risk score (0-10)", 0, 10, 0)

#     # 🔎 Phase-3: Search box (action / entity)
#     with st.expander("Search", expanded=True):
#         q_default = st.session_state.get("search_query", "")
#         q = st.text_input("Search action or entity", value=q_default,
#                           placeholder="e.g. s3:PutObject  •  iam:PassRole  •  MyPolicy  •  alice")
#         run_search = st.button("Search")
#         if run_search:
#             st.session_state["search_query"] = q or ""
#             # results will be computed after graph is built (need G)

#     with st.expander("Risky items / Changes", expanded=False):
#         st.write("Loading snapshot to populate...")

# # ---- Fetch / Load Snapshot
# if fetch_btn:
#     if auth_mode == "Demo":
#         st.sidebar.info("Demo mode selected — loading sample snapshot.")
#         SNAPSHOT_PATH = DEMO_PATH
#     else:
#         with st.spinner("Fetching IAM data from AWS..."):
#             try:
#                 fetch_iam_data(
#                     session=session,
#                     profile_name=(profile or None),
#                     out_path=SNAPSHOT_PATH,
#                     fast_mode=fast_mode,
#                     force_fetch=force,
#                     encrypt=encrypt,
#                 )
#                 st.sidebar.success("Snapshot saved.")
#             except Exception as e:
#                 st.sidebar.error(f"Fetch failed: {e}")
#                 st.stop()

# # ---- Load snapshot
# if not os.path.exists(SNAPSHOT_PATH):
#     st.info("No snapshot found. Use the sidebar to fetch from AWS or run Demo mode.")
#     st.stop()

# try:
#     data = load_snapshot(SNAPSHOT_PATH)
# except Exception as e:
#     st.error(f"Failed to load snapshot: {e}")
#     st.stop()

# # ---- Min-score filter
# if min_score > 0:
#     data = deepcopy(data)
#     data["policies"] = [p for p in data.get("policies", []) if (p.get("RiskScore") or 0) >= min_score]
#     data["roles"] = [r for r in data.get("roles", []) if (r.get("AssumePolicyRiskScore") or 0) >= min_score]

# # ---- Snapshot meta
# meta = data.get("_meta", {})
# diff = meta.get("diff", {}) or {}
# diff_counts = diff.get("counts", {}) if diff else {}
# impact_score = diff.get("impact_score") if diff else None

# # ---- Sidebar risky items
# with st.sidebar:
#     with st.expander("Risky items / Changes", expanded=True):
#         if meta.get("fast_mode"):
#             st.warning("FAST MODE: Some relationships/policies may be missing.")
#         if diff:
#             st.markdown("**Changes (since previous snapshot):**")
#             st.write(f"➕ Added: {diff_counts.get('added', 0)}")
#             st.write(f"🔄 Modified: {diff_counts.get('modified', 0)}")
#             st.write(f"➖ Removed: {diff_counts.get('removed', 0)}")
#             if impact_score is not None:
#                 color = "#10B981" if impact_score <= 2 else ("#F59E0B" if impact_score <= 6 else "#EF4444")
#                 st.markdown(f"<span class='badge' style='background:{color}'>Impact Score: {impact_score}</span>", unsafe_allow_html=True)
#         counts = meta.get("counts", {})
#         st.write(f"Users: {counts.get('users', len(data.get('users', [])))}")
#         st.write(f"Roles: {counts.get('roles', len(data.get('roles', [])))}")
#         st.write(f"Policies: {counts.get('policies', len(data.get('policies', [])))}")

#         risky_choices = []
#         for p in data.get("policies", []):
#             if p.get("IsRisky") or p.get("_changed"):
#                 risky_choices.append(("policy", p.get("PolicyName")))
#         for r in data.get("roles", []):
#             if r.get("AssumePolicyRisk") or r.get("_changed"):
#                 risky_choices.append(("role", r.get("RoleName")))
#         for u in data.get("users", []):
#             if u.get("IsRisky") or u.get("_changed"):
#                 risky_choices.append(("user", u.get("UserName")))

#         if risky_choices:
#             option_display = [f"{t.UPPER() if hasattr(t,'UPPER') else t.upper()}: {n}" for (t, n) in risky_choices]
#             sel = st.selectbox("Risky / changed items", options=["-- none --"] + option_display)
#             if sel and sel != "-- none --":
#                 if st.button("Jump to selected"):
#                     _, chosen = sel.split(": ", 1)
#                     typ = sel.split(":")[0].lower()
#                     st.session_state["selected_entity"] = {"type": typ, "name": chosen}
#         else:
#             st.write("No risky/changed items found.")

# # ---- Layout
# col1, col2 = st.columns([2, 1])

# # ===================== GRAPH (col1) =====================
# with col1:
#     st.header("🕸️ IAM Graph — Interactive")

#     # 📦 Snapshot Info
#     st.markdown(
#         f"""
#         <div style="background:#111;padding:10px;border-radius:8px;margin-bottom:10px;">
#         <b>📦 Snapshot Info</b><br>
#         <span style="color:#bbb;">Fetched:</span> {meta.get("fetched_at", "—")}<br>
#         <span style="color:#bbb;">Profile:</span> {profile or "default"}<br>
#         <span style="color:#bbb;">Mode:</span> {"Fast" if meta.get("fast_mode") else "Full"}<br>
#         <span style="color:#bbb;">Entities:</span> Users: {meta.get("counts",{}).get("users",0)}, 
#         Roles: {meta.get("counts",{}).get("roles",0)}, 
#         Policies: {meta.get("counts",{}).get("policies",0)}
#         </div>
#         """, unsafe_allow_html=True
#     )

#     highlight = (st.session_state.get("selected_entity") or {}).get("name")

#     try:
#         use_data = data
#         if 'show_only_changes' in locals() and show_only_changes:
#             keep = compute_keep_set_from_diff(data)
#             if keep:
#                 filtered = deepcopy(data)
#                 filtered["users"] = [u for u in data.get("users", []) if u.get("UserName") in keep]
#                 filtered["groups"] = [g for g in data.get("groups", []) if g.get("GroupName") in keep]
#                 filtered["roles"] = [r for r in data.get("roles", []) if r.get("RoleName") in keep]
#                 filtered["policies"] = [p for p in data.get("policies", []) if p.get("PolicyName") in keep]
#                 filtered["_meta"] = deepcopy(data.get("_meta", {}))
#                 use_data = filtered

#         G, html_str, clicked_node = build_iam_graph(
#             use_data,
#             show_only_risky=show_only_risky,
#             highlight_node=highlight,
#             highlight_color="orange",
#             highlight_duration=2500
#         )

#         # 🔎 Phase-3: compute search results after G is ready
#         if "search_query" in st.session_state and st.session_state["search_query"]:
#             try:
#                 st.session_state["search_results"] = search_permissions(G, st.session_state["search_query"])
#             except Exception as _e:
#                 st.session_state["search_results"] = {"error": str(_e)}

#         if clicked_node:
#             node_type = G.nodes[clicked_node].get("type", "policy")
#             st.session_state["selected_entity"] = {"type": node_type, "name": clicked_node}

#         st.markdown('<div class="graph-card">', unsafe_allow_html=True)
#         components.html(f"<div style='width:100%;'>{html_str}</div>", height=760, scrolling=True)
#         st.markdown('</div>', unsafe_allow_html=True)

#         with st.expander("Legend", expanded=False):
#             st.markdown(f"""
#             **Legend:**
#             - <span style="color:{NODE_COLORS['user']}">■</span> User
#             - <span style="color:{NODE_COLORS['group']}">■</span> Group
#             - <span style="color:{NODE_COLORS['role']}">■</span> Role
#             - <span style="color:{NODE_COLORS['policy']}">■</span> Policy
#             - <span style="color:#FF6B6B">■</span> Risky
#             """, unsafe_allow_html=True)

#     except Exception as e:
#         st.error(f"Failed to render interactive graph: {e}")

# # ===================== DETAILS (col2) =====================
# with col2:
#     st.header("📋 Details")

#     # 🔎 Phase-3: Show search results (if any)
#     if st.session_state.get("search_query"):
#         st.subheader(f"🔎 Results for: `{st.session_state['search_query']}`")
#         sr = st.session_state.get("search_results") or {}
#         if "error" in sr:
#             st.error(sr["error"])
#         else:
#             action_map = sr.get("action_search") or {}
#             for action, policies in action_map.items():
#                 st.markdown(f"**Action:** `{action}`")
#                 if not policies:
#                     st.info("No matching customer-managed policies found.")
#                 else:
#                     for pname in sorted(set(policies)):
#                         cols = st.columns([1, 1])
#                         with cols[0]:
#                             st.write(f"Policy: **{pname}**")
#                         with cols[1]:
#                             if st.button(f"Focus {pname}", key=f"focus_policy_{pname}"):
#                                 st.session_state["selected_entity"] = {"type": "policy", "name": pname}
#                                 st.experimental_rerun()

#             ent = sr.get("entity")
#             if ent:
#                 st.markdown("**Entity attributes:**")
#                 st.json(ent)
#                 if st.button(f"Focus on {st.session_state['search_query']} in Graph"):
#                     etype = ent.get("type", "policy")
#                     st.session_state["selected_entity"] = {"type": etype, "name": st.session_state['search_query']}
#                     st.experimental_rerun()

#             ent_pols = sr.get("entity_policies")
#             if ent_pols:
#                 st.markdown("**Policy Findings (quick scan):**")
#                 for f in ent_pols:
#                     st.write(f"- `{f.get('action')}` (pattern: `{f.get('pattern')}` | effect: {f.get('effect')})")

#         st.divider()

#     policy_names = ["-- none --"] + sorted([p.get("PolicyName") for p in data.get("policies", []) if p.get("PolicyName")])
#     role_names = ["-- none --"] + sorted([r.get("RoleName") for r in data.get("roles", []) if r.get("RoleName")])
#     user_names = ["-- none --"] + sorted([u.get("UserName") for u in data.get("users", []) if u.get("UserName")])

#     selected = st.session_state.get("selected_entity")

#     chosen_policy = st.selectbox("Select policy", options=policy_names, index=0)
#     chosen_role = st.selectbox("Select role", options=role_names, index=0)
#     chosen_user = st.selectbox("Select user", options=user_names, index=0)

#     if not selected:
#         if chosen_policy != "-- none --":
#             selected = {"type": "policy", "name": chosen_policy}
#         elif chosen_role != "-- none --":
#             selected = {"type": "role", "name": chosen_role}
#         elif chosen_user != "-- none --":
#             selected = {"type": "user", "name": chosen_user}

#     st.markdown('<div class="detail-card">', unsafe_allow_html=True)

#     tab_overview, tab_json, tab_rels, tab_hints = st.tabs(["Overview", "Policy JSON", "Relationships", "Least-Privilege Hints"])

#     def _render_findings(findings):
#         if not findings:
#             st.success("No findings.")
#             return
#         sever_map = {"high": "🔴 High", "medium": "🟠 Medium", "low": "🟡 Low"}
#         for f in findings:
#             sev = sever_map.get((f.get("severity") or "").lower(), "ℹ️ Info")
#             with st.container():
#                 st.markdown(f"**{sev}** — `{f.get('code')}`")
#                 st.write(f.get("message") or "")
#                 if f.get("hint"):
#                     st.caption(f"Hint: {f['hint']}")
#                 if f.get("path"):
#                     st.caption(f"Path: {f['path']}")
#                 st.divider()

#     if selected:
#         etype, name = selected["type"], selected["name"]

#         with tab_overview:
#             st.markdown(f"### {etype.upper()} — {name}")
#             if etype == "policy":
#                 p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
#                 if p:
#                     st.metric("RiskScore", p.get("RiskScore", 0))
#                     st.write("IsRisky:", p.get("IsRisky"))
#                     st.write("RiskActions:", p.get("RiskActions"))
#                     st.write("Arn:", p.get("Arn"))
#             elif etype == "role":
#                 r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
#                 if r:
#                     st.metric("AssumeRiskScore", r.get("AssumePolicyRiskScore", 0))
#                     st.write("AssumePolicyRisk:", r.get("AssumePolicyRisk"))
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in (r.get("AttachedPolicies") or [])])
#                     st.write("Arn:", r.get("Arn"))
#                     # Service Last Used
#                     slu = r.get("ServiceLastUsed", {})
#                     services = slu.get("services", [])
#                     if services:
#                         st.subheader("Service Last Used")
#                         st.table([{"Service": s.get("service"), "LastAccessed": s.get("last_accessed")} for s in services])
#                     else:
#                         st.info("No usage data (enable CloudTrail).")
#             elif etype == "user":
#                 u = next((x for x in data.get("users", []) if x.get("UserName") == name), None)
#                 if u:
#                     st.write("Arn:", u.get("Arn"))
#                     st.write("Groups:", u.get("Groups", []))
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in (u.get("AttachedPolicies") or [])])
#                     # Service Last Used
#                     slu = u.get("ServiceLastUsed", {})
#                     services = slu.get("services", [])
#                     if services:
#                         st.subheader("Service Last Used")
#                         st.table([{"Service": s.get("service"), "LastAccessed": s.get("last_accessed")} for s in services])
#                     else:
#                         st.info("No usage data (enable CloudTrail).")
#             elif etype == "group":
#                 g = next((x for x in data.get("groups", []) if x.get("GroupName") == name), None)
#                 if g:
#                     st.write("AttachedPolicies:", [a.get("PolicyName") for a in (g.get("AttachedPolicies") or [])])
#                     # Service Last Used
#                     slu = g.get("ServiceLastUsed", {})
#                     services = slu.get("services", [])
#                     if services:
#                         st.subheader("Service Last Used")
#                         st.table([{"Service": s.get("service"), "LastAccessed": s.get("last_accessed")} for s in services])
#                     else:
#                         st.info("No usage data (enable CloudTrail).")

#         with tab_json:
#             if etype == "policy":
#                 p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
#                 if p:
#                     st.json(p.get("Document") or {})
#                 else:
#                     st.info("No policy JSON available.")
#             elif etype == "role":
#                 r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
#                 if r:
#                     st.json(r.get("AssumeRolePolicyDocument") or {})
#                 else:
#                     st.info("No assume role policy document available.")
#             else:
#                 st.info("JSON view is available for policies and roles only.")

#         with tab_rels:
#             if 'G' in locals():
#                 if name not in G:
#                     st.info("Selected entity not present in the current graph view.")
#                 else:
#                     preds = sorted([n for n in G.predecessors(name)]) if hasattr(G, "predecessors") else []
#                     succs = sorted([n for n in G.successors(name)]) if hasattr(G, "successors") else []
#                     st.write("Incoming:", preds or "—")
#                     st.write("Outgoing:", succs or "—")
#             else:
#                 st.info("Graph not built - relationships unavailable.")

#         with tab_hints:
#             if etype == "policy":
#                 p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
#                 if p:
#                     _render_findings(p.get("Findings") or [])
#                 else:
#                     st.info("No findings.")
#             elif etype == "role":
#                 r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
#                 if r:
#                     trust = r.get("AssumePolicyFindings") or []
#                     st.subheader("Trust policy")
#                     _render_findings(trust)
#                     if r.get("AttachedPolicies"):
#                         st.subheader("Attached customer-managed policies")
#                         attached_names = [a.get("PolicyName") for a in (r.get("AttachedPolicies") or [])]
#                         for pname in attached_names:
#                             pol = next((x for x in data.get("policies", []) if x.get("PolicyName") == pname), None)
#                             if pol:
#                                 st.markdown(f"**Policy:** {pname}")
#                                 _render_findings(pol.get("Findings") or [])

#                     # usage-based hints
#                     slu = r.get("ServiceLastUsed", {})
#                     services = slu.get("services", [])
#                     unused = []
#                     for s in services:
#                         last = s.get("last_accessed")
#                         if last:
#                             try:
#                                 last_dt = dt.fromisoformat(last.replace("Z", "+00:00"))
#                                 if dt.utcnow() - last_dt > timedelta(days=90):
#                                     unused.append(s.get("service"))
#                             except Exception:
#                                 pass
#                     if unused:
#                         st.subheader("Usage-based Hints")
#                         for svc in unused:
#                             st.warning(f"Unused service: **{svc}** – consider removing.")
#                 else:
#                     st.info("No findings.")
#             elif etype == "user":
#                 u = next((x for x in data.get("users", []) if x.get("UserName") == name), None)
#                 if u:
#                     st.subheader("Attached customer-managed policies")
#                     for ap in (u.get("AttachedPolicies") or []):
#                         pname = ap.get("PolicyName")
#                         pol = next((x for x in data.get("policies", []) if x.get("PolicyName") == pname), None)
#                         if pol:
#                             st.markdown(f"**Policy:** {pname}")
#                             _render_findings(pol.get("Findings") or [])

#                     inline_prefix = f"{name}::INLINE::"
#                     inlines = [p for p in data.get("policies", []) if p.get("PolicyName","").startswith(inline_prefix)]
#                     if inlines:
#                         st.subheader("Inline policies")
#                         for pol in inlines:
#                             st.markdown(f"**Policy:** {pol.get('PolicyName')}")
#                             _render_findings(pol.get("Findings") or [])

#                     # usage-based hints
#                     slu = u.get("ServiceLastUsed", {})
#                     services = slu.get("services", [])
#                     unused = []
#                     for s in services:
#                         last = s.get("last_accessed")
#                         if last:
#                             try:
#                                 last_dt = dt.fromisoformat(last.replace("Z", "+00:00"))
#                                 if dt.utcnow() - last_dt > timedelta(days=90):
#                                     unused.append(s.get("service"))
#                             except Exception:
#                                 pass
#                     if unused:
#                         st.subheader("Usage-based Hints")
#                         for svc in unused:
#                             st.warning(f"Unused service: **{svc}** – consider removing.")
#                 else:
#                     st.info("No findings.")
#             elif etype == "group":
#                 g = next((x for x in data.get("groups", []) if x.get("GroupName") == name), None)
#                 if g:
#                     # usage-based hints
#                     slu = g.get("ServiceLastUsed", {})
#                     services = slu.get("services", [])
#                     unused = []
#                     for s in services:
#                         last = s.get("last_accessed")
#                         if last:
#                             try:
#                                 last_dt = dt.fromisoformat(last.replace("Z", "+00:00"))
#                                 if dt.utcnow() - last_dt > timedelta(days=90):
#                                     unused.append(s.get("service"))
#                             except Exception:
#                                 pass
#                     if unused:
#                         st.subheader("Usage-based Hints")
#                         for svc in unused:
#                             st.warning(f"Unused service: **{svc}** – consider removing.")
#                 else:
#                     st.info("No findings.")

#     st.markdown('</div>', unsafe_allow_html=True)

#     st.markdown("---")
#     if st.button("Download snapshot (JSON)"):
#         with open(SNAPSHOT_PATH, "r", encoding="utf-8") as f:
#             st.download_button(
#                 "Click to download snapshot.json",
#                 f.read(),
#                 file_name="iam_snapshot.json",
#                 mime="application/json"
#             )

# st.caption("Tip: Click on a node in the graph or use the sidebar to explore IAM entities.")

# app/main.py
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import os, json, hashlib, secrets, streamlit as st
import json
import boto3
import streamlit as st
import streamlit.components.v1 as components
from copy import deepcopy
from datetime import datetime as dt, timedelta
from core.compat import rerun
from core.fetch_iam import fetch_iam_data
from core.graph_builder import (
    build_iam_graph,
    NODE_COLORS,
    compute_keep_set_from_diff,
    build_adjacency,
    search_permissions,
    load_snapshot,  # 👈 encrypted/plain snapshot loader
)

AUTH_FILE = "data/auth.json"
LOCK_FILE = "data/setup.lock"   # 👈 lock file

def hash_pw(pw: str, salt: str) -> str:
    return hashlib.sha256((salt + pw).encode()).hexdigest()

os.makedirs("data", exist_ok=True)

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# --------- SETUP PHASE (first time run) ---------
if not os.path.exists(AUTH_FILE) and not os.path.exists(LOCK_FILE):
    st.title("🔐 IAM X-Ray — Setup")
    pw1 = st.text_input("Set a new password", type="password")
    pw2 = st.text_input("Confirm password", type="password")
    if st.button("Save password"):
        if pw1 and pw1 == pw2:
            salt = secrets.token_hex(16)
            hashed = hash_pw(pw1, salt)
            with open(AUTH_FILE, "w") as f:
                json.dump({
                    "algorithm": "sha256",
                    "salt": salt,
                    "password_hash": hashed
                }, f, indent=2)
            # 👇 create lock file so reset needs manual deletion
            with open(LOCK_FILE, "w") as f:
                f.write("locked")
            st.success("✅ Password set! Restart app and login.")
        else:
            st.error("❌ Passwords do not match")
    st.stop()

# --------- RESET BLOCK (auth.json missing but lock exists) ---------
if not os.path.exists(AUTH_FILE) and os.path.exists(LOCK_FILE):
    st.error("⚠️ Auth reset disabled. Delete auth.json + setup.lock manually to reset.")
    st.stop()

# --------- LOGIN PHASE ---------
with open(AUTH_FILE, "r") as f:
    auth_data = json.load(f)

salt = auth_data["salt"]
saved_hash = auth_data["password_hash"]

if not st.session_state["authenticated"]:
    st.title("🔐 IAM X-Ray Login")
    pw = st.text_input("Password", type="password")
    if pw:
        if hash_pw(pw, salt) == saved_hash:
            st.session_state["authenticated"] = True
            rerun()
        else:
            st.error("❌ Wrong password")
    st.stop()


st.set_page_config(page_title="IAM X-Ray", layout="wide", initial_sidebar_state="expanded")

# ---- CSS
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
html, body, [data-testid="stAppViewContainer"] { font-family: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, Arial; }
h1 { font-size: 28px; font-weight: 700; margin-bottom: 2px; }
.graph-card { border-radius: 12px; padding: 10px; background: #0b0f19; box-shadow: 0 8px 24px rgba(0,0,0,.35); }
.detail-card { border-radius: 12px; padding: 14px; background: #0b0f19; box-shadow: 0 8px 24px rgba(0,0,0,.35); }
.tip { color:#97a0af; font-size: 13px; }
.badge { display:inline-block; padding:6px 10px; border-radius:8px; font-weight:600; color:#fff; }
</style>
""", unsafe_allow_html=True)

st.markdown("<h1>🔐 IAM X-Ray — Visual AWS Access Map</h1>", unsafe_allow_html=True)

DATA_DIR = "data"
SNAPSHOT_PATH = os.path.join(DATA_DIR, "iam_snapshot.json")
DEMO_PATH = os.path.join(DATA_DIR, "sample_snapshot.json")

# ensure data dir exists
os.makedirs(DATA_DIR, exist_ok=True)

# ---- SIDEBAR
if "sidebar_collapsed" not in st.session_state:
    st.session_state["sidebar_collapsed"] = False

with st.sidebar:
    if st.checkbox("Collapse sidebar (show minimal)", value=st.session_state["sidebar_collapsed"]):
        st.session_state["sidebar_collapsed"] = True
    else:
        st.session_state["sidebar_collapsed"] = False

    controls_expanded = not st.session_state["sidebar_collapsed"]
    with st.expander("Controls", expanded=controls_expanded):
        st.header("Controls")

        # --- Auth block ---
        auth_mode = st.radio("Auth mode", ["Demo", "AWS Profile", "Env Keys"], index=0)
        session = None
        profile = None

        if auth_mode == "AWS Profile":
            profile = st.text_input("AWS profile name", value="default")
            if profile:
                try:
                    session = boto3.Session(profile_name=profile)
                except Exception as e:
                    st.error(f"Failed to init AWS profile: {e}")
        elif auth_mode == "Env Keys":
            ak = st.text_input("AWS_ACCESS_KEY_ID", type="password")
            sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password")
            token = st.text_input("AWS_SESSION_TOKEN (optional)", type="password")
            region = st.text_input("AWS_REGION (optional)", value="us-east-1")
            if ak and sk:
                try:
                    session = boto3.Session(
                        aws_access_key_id=ak,
                        aws_secret_access_key=sk,
                        aws_session_token=token or None,
                        region_name=region or None,
                    )
                except Exception as e:
                    st.error(f"Failed to init AWS session: {e}")

        # --- Fetch options ---
        fast_mode = st.checkbox("⚡ Fast fetch (seconds)", value=True)
        force = st.checkbox("Force fetch (ignore cache)", value=False)
        encrypt = st.checkbox("🔒 Encrypt snapshot", value=False)

        fetch_btn = st.button("🔁 Fetch latest IAM snapshot")
        show_only_risky = st.checkbox("Show only risky paths", value=False)
        show_only_changes = st.checkbox("Show only changes (added/modified + neighbors)", value=False)
        min_score = st.slider("Min risk score (0-10)", 0, 10, 0)

    # 🔎 Search box (action / entity)
    with st.expander("Search", expanded=True):
        q_default = st.session_state.get("search_query", "")
        q = st.text_input("Search action or entity", value=q_default,
                          placeholder="e.g. s3:PutObject  •  iam:PassRole  •  MyPolicy  •  alice")
        run_search = st.button("Search")
        if run_search:
            st.session_state["search_query"] = q or ""

    with st.expander("Risky items / Changes", expanded=False):
        st.write("Loading snapshot to populate...")

# ---- Fetch / Load Snapshot
# Auto-select DEMO_PATH when Demo mode is active (no need to click fetch)
active_snapshot_path = DEMO_PATH if auth_mode == "Demo" else SNAPSHOT_PATH

if fetch_btn and auth_mode != "Demo":
    with st.spinner("Fetching IAM data from AWS..."):
        try:
            fetch_iam_data(
                session=session,
                profile_name=(profile or None),
                out_path=SNAPSHOT_PATH,
                fast_mode=fast_mode,
                force_fetch=force,
                encrypt=encrypt,
            )
            st.sidebar.success("Snapshot saved.")
        except Exception as e:
            st.sidebar.error(f"Fetch failed: {e}")
            st.stop()
elif fetch_btn and auth_mode == "Demo":
    st.sidebar.info("Demo mode: using sample snapshot (no AWS calls).")

# ---- Load snapshot
if not os.path.exists(active_snapshot_path):
    # Helpful guidance
    if auth_mode == "Demo":
        st.info("Demo mode selected but 'data/sample_snapshot.json' not found. Please add the file.")
    else:
        st.info("No snapshot found. Use the sidebar to fetch from AWS, or switch to Demo mode.")
    st.stop()

try:
    data = load_snapshot(active_snapshot_path)
except Exception as e:
    st.error(f"Failed to load snapshot: {e}")
    st.stop()

# ---- Min-score filter
if min_score > 0:
    data = deepcopy(data)
    data["policies"] = [p for p in data.get("policies", []) if (p.get("RiskScore") or 0) >= min_score]
    data["roles"] = [r for r in data.get("roles", []) if (r.get("AssumePolicyRiskScore") or 0) >= min_score]

# ---- Snapshot meta
meta = data.get("_meta", {}) or {}
diff = meta.get("diff", {}) or {}
diff_counts = diff.get("counts", {}) if diff else {}
impact_score = diff.get("impact_score") if diff else None

# ---- Sidebar risky items
with st.sidebar:
    with st.expander("Risky items / Changes", expanded=True):
        if meta.get("fast_mode"):
            st.warning("FAST MODE: Some relationships/policies may be missing.")
        if diff:
            st.markdown("**Changes (since previous snapshot):**")
            st.write(f"➕ Added: {diff_counts.get('added', 0)}")
            st.write(f"🔄 Modified: {diff_counts.get('modified', 0)}")
            st.write(f"➖ Removed: {diff_counts.get('removed', 0)}")
            if impact_score is not None:
                color = "#10B981" if impact_score <= 2 else ("#F59E0B" if impact_score <= 6 else "#EF4444")
                st.markdown(f"<span class='badge' style='background:{color}'>Impact Score: {impact_score}</span>", unsafe_allow_html=True)
        counts = meta.get("counts", {})
        st.write(f"Users: {counts.get('users', len(data.get('users', [])))}")
        st.write(f"Roles: {counts.get('roles', len(data.get('roles', [])))}")
        st.write(f"Policies: {counts.get('policies', len(data.get('policies', [])))}")

        risky_choices = []
        for p in data.get("policies", []):
            if p.get("IsRisky") or p.get("_changed"):
                risky_choices.append(("policy", p.get("PolicyName")))
        for r in data.get("roles", []):
            if r.get("AssumePolicyRisk") or r.get("_changed"):
                risky_choices.append(("role", r.get("RoleName")))
        for u in data.get("users", []):
            if u.get("IsRisky") or u.get("_changed"):
                risky_choices.append(("user", u.get("UserName")))

        if risky_choices:
            option_display = [f"{t.upper()}: {n}" for (t, n) in risky_choices]
            sel = st.selectbox("Risky / changed items", options=["-- none --"] + option_display)
            if sel and sel != "-- none --":
                if st.button("Jump to selected"):
                    _, chosen = sel.split(": ", 1)
                    typ = sel.split(":")[0].lower()
                    st.session_state["selected_entity"] = {"type": typ, "name": chosen}
        else:
            st.write("No risky/changed items found.")

# ---- Layout
col1, col2 = st.columns([2, 1])

# ===================== GRAPH (col1) =====================
with col1:
    st.header("🕸️ IAM Graph — Interactive")

    # 📦 Snapshot Info
    auth_label = auth_mode if auth_mode == "Demo" else (f"Profile: {profile or 'env/default'}")
    st.markdown(
        f"""
        <div style="background:#111;padding:10px;border-radius:8px;margin-bottom:10px;">
        <b>📦 Snapshot Info</b><br>
        <span style="color:#bbb;">Fetched:</span> {meta.get("fetched_at", "—")}<br>
        <span style="color:#bbb;">Auth:</span> {auth_label}<br>
        <span style="color:#bbb;">Mode:</span> {"Fast" if meta.get("fast_mode") else "Full"}<br>
        <span style="color:#bbb;">Entities:</span> Users: {meta.get("counts",{}).get("users",0)}, 
        Roles: {meta.get("counts",{}).get("roles",0)}, 
        Policies: {meta.get("counts",{}).get("policies",0)}
        </div>
        """, unsafe_allow_html=True
    )

    highlight = (st.session_state.get("selected_entity") or {}).get("name")

    try:
        use_data = data
        if show_only_changes:
            keep = compute_keep_set_from_diff(data)
            if keep:
                filtered = deepcopy(data)
                filtered["users"] = [u for u in data.get("users", []) if u.get("UserName") in keep]
                filtered["groups"] = [g for g in data.get("groups", []) if g.get("GroupName") in keep]
                filtered["roles"] = [r for r in data.get("roles", []) if r.get("RoleName") in keep]
                filtered["policies"] = [p for p in data.get("policies", []) if p.get("PolicyName") in keep]
                filtered["_meta"] = deepcopy(data.get("_meta", {}))
                use_data = filtered

        G, html_str, clicked_node = build_iam_graph(
            use_data,
            show_only_risky=show_only_risky,
            highlight_node=highlight,
            highlight_color="orange",
            highlight_duration=2500
        )

        # 🔎 Search results after G is ready
        if st.session_state.get("search_query"):
            try:
                st.session_state["search_results"] = search_permissions(G, st.session_state["search_query"])
            except Exception as _e:
                st.session_state["search_results"] = {"error": str(_e)}

        if clicked_node:
            node_type = G.nodes[clicked_node].get("type", "policy")
            st.session_state["selected_entity"] = {"type": node_type, "name": clicked_node}

        st.markdown('<div class="graph-card">', unsafe_allow_html=True)
        components.html(f"<div style='width:100%;'>{html_str}</div>", height=760, scrolling=True)
        st.markdown('</div>', unsafe_allow_html=True)

        with st.expander("Legend", expanded=False):
            st.markdown(f"""
            **Legend:**
            - <span style="color:{NODE_COLORS['user']}">■</span> User
            - <span style="color:{NODE_COLORS['group']}">■</span> Group
            - <span style="color:{NODE_COLORS['role']}">■</span> Role
            - <span style="color:{NODE_COLORS['policy']}">■</span> Policy
            - <span style="color:#FF6B6B">■</span> Risky
            """, unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Failed to render interactive graph: {e}")

# ===================== DETAILS (col2) =====================
with col2:
    st.header("📋 Details")

    # 🔎 Show search results (if any)
    if st.session_state.get("search_query"):
        st.subheader(f"🔎 Results for: `{st.session_state['search_query']}`")
        sr = st.session_state.get("search_results") or {}
        if "error" in sr:
            st.error(sr["error"])
        else:
            action_map = sr.get("action_search") or {}
            for action, policies in action_map.items():
                st.markdown(f"**Action:** `{action}`")
                if not policies:
                    st.info("No matching customer-managed policies found.")
                else:
                    for pname in sorted(set(policies)):
                        cols = st.columns([1, 1])
                        with cols[0]:
                            st.write(f"Policy: **{pname}**")
                        with cols[1]:
                            if st.button(f"Focus {pname}", key=f"focus_policy_{pname}"):
                                st.session_state["selected_entity"] = {"type": "policy", "name": pname}
                                st.experimental_rerun()

            ent = sr.get("entity")
            if ent:
                st.markdown("**Entity attributes:**")
                st.json(ent)
                if st.button(f"Focus on {st.session_state['search_query']} in Graph"):
                    etype = ent.get("type", "policy")
                    st.session_state["selected_entity"] = {"type": etype, "name": st.session_state['search_query']}
                    st.experimental_rerun()

            ent_pols = sr.get("entity_policies")
            if ent_pols:
                st.markdown("**Policy Findings (quick scan):**")
                for f in ent_pols:
                    st.write(f"- `{f.get('action')}` (pattern: `{f.get('pattern')}` | effect: {f.get('effect')})")

            attached = sr.get("entity_attached_findings")
            if attached:
                st.markdown("**Attached Policy Findings:**")
                for pname, findings in attached.items():
                    st.markdown(f"- **{pname}**")
                    if isinstance(findings, list) and findings and isinstance(findings[0], dict) and "action" in findings[0]:
                        for f in findings:
                            st.write(f"  • `{f.get('action')}` (pattern `{f.get('pattern')}`, effect {f.get('effect')})")
                    else:
                        st.write("  • ✅ No risky actions")

        st.divider()

    policy_names = ["-- none --"] + sorted([p.get("PolicyName") for p in data.get("policies", []) if p.get("PolicyName")])
    role_names = ["-- none --"] + sorted([r.get("RoleName") for r in data.get("roles", []) if r.get("RoleName")])
    user_names = ["-- none --"] + sorted([u.get("UserName") for u in data.get("users", []) if u.get("UserName")])

    selected = st.session_state.get("selected_entity")

    chosen_policy = st.selectbox("Select policy", options=policy_names, index=0)
    chosen_role = st.selectbox("Select role", options=role_names, index=0)
    chosen_user = st.selectbox("Select user", options=user_names, index=0)

    if not selected:
        if chosen_policy != "-- none --":
            selected = {"type": "policy", "name": chosen_policy}
        elif chosen_role != "-- none --":
            selected = {"type": "role", "name": chosen_role}
        elif chosen_user != "-- none --":
            selected = {"type": "user", "name": chosen_user}

    st.markdown('<div class="detail-card">', unsafe_allow_html=True)

    tab_overview, tab_json, tab_rels, tab_hints = st.tabs(["Overview", "Policy JSON", "Relationships", "Least-Privilege Hints"])

    def _render_findings(findings):
        if not findings:
            st.success("No findings.")
            return
        sever_map = {"high": "🔴 High", "medium": "🟠 Medium", "low": "🟡 Low"}
        for f in findings:
            sev = sever_map.get((f.get("severity") or "").lower(), "ℹ️ Info")
            with st.container():
                st.markdown(f"**{sev}** — `{f.get('code')}`")
                st.write(f.get("message") or "")
                if f.get("hint"):
                    st.caption(f"Hint: {f['hint']}")
                if f.get("path"):
                    st.caption(f"Path: {f['path']}")
                st.divider()

    if selected:
        etype, name = selected["type"], selected["name"]

        with tab_overview:
            st.markdown(f"### {etype.upper()} — {name}")
            if etype == "policy":
                p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
                if p:
                    st.metric("RiskScore", p.get("RiskScore", 0))
                    st.write("IsRisky:", p.get("IsRisky"))
                    st.write("RiskActions:", p.get("RiskActions"))
                    st.write("Arn:", p.get("Arn"))
            elif etype == "role":
                r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
                if r:
                    st.metric("AssumeRiskScore", r.get("AssumePolicyRiskScore", 0))
                    st.write("AssumePolicyRisk:", r.get("AssumePolicyRisk"))
                    st.write("AttachedPolicies:", [a.get("PolicyName") for a in (r.get("AttachedPolicies") or [])])
                    st.write("Arn:", r.get("Arn"))
                    # Service Last Used
                    slu = r.get("ServiceLastUsed", {})
                    services = slu.get("services", [])
                    if services:
                        st.subheader("Service Last Used")
                        st.table([{"Service": s.get("service"), "LastAccessed": s.get("last_accessed")} for s in services])
                    else:
                        st.info("No usage data (enable CloudTrail).")
            elif etype == "user":
                u = next((x for x in data.get("users", []) if x.get("UserName") == name), None)
                if u:
                    st.write("Arn:", u.get("Arn"))
                    st.write("Groups:", u.get("Groups", []))
                    st.write("AttachedPolicies:", [a.get("PolicyName") for a in (u.get("AttachedPolicies") or [])])
                    # Service Last Used
                    slu = u.get("ServiceLastUsed", {})
                    services = slu.get("services", [])
                    if services:
                        st.subheader("Service Last Used")
                        st.table([{"Service": s.get("service"), "LastAccessed": s.get("last_accessed")} for s in services])
                    else:
                        st.info("No usage data (enable CloudTrail).")
            elif etype == "group":
                g = next((x for x in data.get("groups", []) if x.get("GroupName") == name), None)
                if g:
                    st.write("AttachedPolicies:", [a.get("PolicyName") for a in (g.get("AttachedPolicies") or [])])
                    # Service Last Used
                    slu = g.get("ServiceLastUsed", {})
                    services = slu.get("services", [])
                    if services:
                        st.subheader("Service Last Used")
                        st.table([{"Service": s.get("service"), "LastAccessed": s.get("last_accessed")} for s in services])
                    else:
                        st.info("No usage data (enable CloudTrail).")

        with tab_json:
            if etype == "policy":
                p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
                if p:
                    st.json(p.get("Document") or {})
                else:
                    st.info("No policy JSON available.")
            elif etype == "role":
                r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
                if r:
                    st.json(r.get("AssumeRolePolicyDocument") or {})
                else:
                    st.info("No assume role policy document available.")
            else:
                st.info("JSON view is available for policies and roles only.")

        with tab_rels:
            if 'G' in locals():
                if name not in G:
                    st.info("Selected entity not present in the current graph view.")
                else:
                    preds = sorted([n for n in G.predecessors(name)]) if hasattr(G, "predecessors") else []
                    succs = sorted([n for n in G.successors(name)]) if hasattr(G, "successors") else []
                    st.write("Incoming:", preds or "—")
                    st.write("Outgoing:", succs or "—")
            else:
                st.info("Graph not built - relationships unavailable.")

        with tab_hints:
            if etype == "policy":
                p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
                if p:
                    _render_findings(p.get("Findings") or [])
                else:
                    st.info("No findings.")
            elif etype == "role":
                r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
                if r:
                    trust = r.get("AssumePolicyFindings") or []
                    st.subheader("Trust policy")
                    _render_findings(trust)
                    if r.get("AttachedPolicies"):
                        st.subheader("Attached customer-managed policies")
                        attached_names = [a.get("PolicyName") for a in (r.get("AttachedPolicies") or [])]
                        for pname in attached_names:
                            pol = next((x for x in data.get("policies", []) if x.get("PolicyName") == pname), None)
                            if pol:
                                st.markdown(f"**Policy:** {pname}")
                                _render_findings(pol.get("Findings") or [])

                    # usage-based hints
                    slu = r.get("ServiceLastUsed", {})
                    services = slu.get("services", [])
                    unused = []
                    for s in services:
                        last = s.get("last_accessed")
                        if last:
                            try:
                                last_dt = dt.fromisoformat(last.replace("Z", "+00:00"))
                                if dt.utcnow() - last_dt > timedelta(days=90):
                                    unused.append(s.get("service"))
                            except Exception:
                                pass
                    if unused:
                        st.subheader("Usage-based Hints")
                        for svc in unused:
                            st.warning(f"Unused service: **{svc}** – consider removing.")
                else:
                    st.info("No findings.")
            elif etype == "user":
                u = next((x for x in data.get("users", []) if x.get("UserName") == name), None)
                if u:
                    st.subheader("Attached customer-managed policies")
                    for ap in (u.get("AttachedPolicies") or []):
                        pname = ap.get("PolicyName")
                        pol = next((x for x in data.get("policies", []) if x.get("PolicyName") == pname), None)
                        if pol:
                            st.markdown(f"**Policy:** {pname}")
                            _render_findings(pol.get("Findings") or [])

                    inline_prefix = f"{name}::INLINE::"
                    inlines = [p for p in data.get("policies", []) if p.get("PolicyName","").startswith(inline_prefix)]
                    if inlines:
                        st.subheader("Inline policies")
                        for pol in inlines:
                            st.markdown(f"**Policy:** {pol.get('PolicyName')}")
                            _render_findings(pol.get("Findings") or [])

                    # usage-based hints
                    slu = u.get("ServiceLastUsed", {})
                    services = slu.get("services", [])
                    unused = []
                    for s in services:
                        last = s.get("last_accessed")
                        if last:
                            try:
                                last_dt = dt.fromisoformat(last.replace("Z", "+00:00"))
                                if dt.utcnow() - last_dt > timedelta(days=90):
                                    unused.append(s.get("service"))
                            except Exception:
                                pass
                    if unused:
                        st.subheader("Usage-based Hints")
                        for svc in unused:
                            st.warning(f"Unused service: **{svc}** – consider removing.")
                else:
                    st.info("No findings.")
            elif etype == "group":
                g = next((x for x in data.get("groups", []) if x.get("GroupName") == name), None)
                if g:
                    # usage-based hints
                    slu = g.get("ServiceLastUsed", {})
                    services = slu.get("services", [])
                    unused = []
                    for s in services:
                        last = s.get("last_accessed")
                        if last:
                            try:
                                last_dt = dt.fromisoformat(last.replace("Z", "+00:00"))
                                if dt.utcnow() - last_dt > timedelta(days=90):
                                    unused.append(s.get("service"))
                            except Exception:
                                pass
                    if unused:
                        st.subheader("Usage-based Hints")
                        for svc in unused:
                            st.warning(f"Unused service: **{svc}** – consider removing.")
                else:
                    st.info("No findings.")

    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")
    # Direct download widget (no extra button-click needed)
    try:
        with open(active_snapshot_path, "r", encoding="utf-8") as f:
            st.download_button(
                "⬇️ Download snapshot (JSON)",
                f.read(),
                file_name=os.path.basename(active_snapshot_path),
                mime="application/json"
            )
    except Exception:
        pass

st.caption("Tip: Click on a node in the graph or use the sidebar to explore IAM entities.")

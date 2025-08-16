import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import streamlit as st
import streamlit.components.v1 as components
from copy import deepcopy

from core.fetch_iam import fetch_iam_data
from core.graph_builder import build_iam_graph, NODE_COLORS, compute_keep_set_from_diff, build_adjacency

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

SNAPSHOT_PATH = "data/iam_snapshot.json"

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
        profile = st.text_input("AWS profile (optional)", value="")
        fast_mode = st.checkbox("⚡ Fast fetch (seconds)", value=True)
        force = st.checkbox("Force fetch (ignore cache)", value=False)
        fetch_btn = st.button("🔁 Fetch latest IAM snapshot")
        show_only_risky = st.checkbox("Show only risky paths", value=False)
        show_only_changes = st.checkbox("Show only changes (added/modified + neighbors)", value=False)
        min_score = st.slider("Min risk score (0-10)", 0, 10, 0)

    with st.expander("Risky items / Changes", expanded=False):
        st.write("Loading snapshot to populate...")

# ---- Fetch action
if 'fetch_btn' in locals() and fetch_btn:
    with st.spinner("Fetching IAM data from AWS..."):
        try:
            fetch_iam_data(
                profile_name=(profile or None),
                out_path=SNAPSHOT_PATH,
                fast_mode=fast_mode,
                force_fetch=force,
            )
            st.sidebar.success("Snapshot saved.")
        except Exception as e:
            st.sidebar.error(f"Fetch failed: {e}")
            st.stop()

# ---- Load snapshot
if not os.path.exists(SNAPSHOT_PATH):
    st.info("No snapshot found. Use the sidebar to fetch from AWS.")
    st.stop()

try:
    with open(SNAPSHOT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    st.error(f"Failed to load snapshot: {e}")
    st.stop()

# ---- Min-score filter
if min_score > 0:
    data = deepcopy(data)
    data["policies"] = [p for p in data.get("policies", []) if (p.get("RiskScore") or 0) >= min_score]
    data["roles"] = [r for r in data.get("roles", []) if (r.get("AssumePolicyRiskScore") or 0) >= min_score]

# ---- Snapshot meta
meta = data.get("_meta", {})
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
    st.markdown(
        f"""
        <div style="background:#111;padding:10px;border-radius:8px;margin-bottom:10px;">
        <b>📦 Snapshot Info</b><br>
        <span style="color:#bbb;">Fetched:</span> {meta.get("fetched_at", "—")}<br>
        <span style="color:#bbb;">Profile:</span> {profile or "default"}<br>
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
        if 'show_only_changes' in locals() and show_only_changes:
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
            elif etype == "user":
                u = next((x for x in data.get("users", []) if x.get("UserName") == name), None)
                if u:
                    st.write("Arn:", u.get("Arn"))
                    st.write("Groups:", u.get("Groups", []))
                    st.write("AttachedPolicies:", [a.get("PolicyName") for a in (u.get("AttachedPolicies") or [])])

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
                    # trust findings + attached policy findings
                    trust = r.get("AssumePolicyFindings") or []
                    st.subheader("Trust policy")
                    _render_findings(trust)
                    if r.get("AttachedPolicies"):
                        st.subheader("Attached customer-managed policies")
                        # map attached names to findings available in snapshot["policies"]
                        attached_names = [a.get("PolicyName") for a in (r.get("AttachedPolicies") or [])]
                        for pname in attached_names:
                            pol = next((x for x in data.get("policies", []) if x.get("PolicyName") == pname), None)
                            if pol:
                                st.markdown(f"**Policy:** {pname}")
                                _render_findings(pol.get("Findings") or [])
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
                    # inline user policy findings (if fetched in non-fast mode)
                    inline_prefix = f"{name}::INLINE::"
                    inlines = [p for p in data.get("policies", []) if p.get("PolicyName","").startswith(inline_prefix)]
                    if inlines:
                        st.subheader("Inline policies")
                        for pol in inlines:
                            st.markdown(f"**Policy:** {pol.get('PolicyName')}")
                            _render_findings(pol.get("Findings") or [])
                else:
                    st.info("No findings.")

    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")
    if st.button("Download snapshot (JSON)"):

        with open(SNAPSHOT_PATH, "r", encoding="utf-8") as f:
            st.download_button(
                "Click to download snapshot.json",
                f.read(),
                file_name="iam_snapshot.json",
                mime="application/json"
            )

st.caption("Tip: Click on a node in the graph or use the sidebar to explore IAM entities.")


# import sys, os
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# import json
# import streamlit as st
# import streamlit.components.v1 as components
# from copy import deepcopy

# from core.fetch_iam import fetch_iam_data
# from core.graph_builder import build_iam_graph, NODE_COLORS

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

# # ---- SIDEBAR / Controls
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

# # ---- Apply min-score filter
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
#             option_display = [f"{t.upper()}: {n}" for (t, n) in risky_choices]
#             sel = st.selectbox("Risky / changed items", options=["-- none --"] + option_display)
#             if sel and sel != "-- none --":
#                 if st.button("Jump to selected"):
#                     _, chosen = sel.split(": ", 1)
#                     typ = sel.split(":")[0].lower()
#                     st.session_state["selected_entity"] = {"type": typ, "name": chosen}
#         else:
#             st.write("No risky/changed items found.")

#         if meta.get("warnings"):
#             st.warning("Warnings during fetch")
#             for w in meta.get("warnings", []):
#                 st.write("-", w)

# # ---- Keep set helper
# def _build_adjacency(snapshot):
#     adj = {}
#     def add_edge(a, b):
#         if not a or not b: return
#         adj.setdefault(a, set()).add(b)
#         adj.setdefault(b, set()).add(a)
#     for u in snapshot.get("users", []):
#         uname = u.get("UserName")
#         if not uname: continue
#         for g in u.get("Groups", []) or []:
#             add_edge(uname, g)
#         for ap in u.get("AttachedPolicies", []) or []:
#             pname = ap.get("PolicyName")
#             if pname: add_edge(uname, pname)
#     for g in snapshot.get("groups", []):
#         gname = g.get("GroupName")
#         if not gname: continue
#         for ap in g.get("AttachedPolicies", []) or []:
#             pname = ap.get("PolicyName")
#             if pname: add_edge(gname, pname)
#     for r in snapshot.get("roles", []):
#         rname = r.get("RoleName")
#         if not rname: continue
#         for ap in r.get("AttachedPolicies", []) or []:
#             pname = ap.get("PolicyName")
#             if pname: add_edge(rname, pname)
#         for pr in r.get("PrincipalsInfo") or []:
#             prval = pr.get("value") if isinstance(pr, dict) else pr
#             if not prval: continue
#             short = prval.split("/")[-1] if "/" in prval else prval
#             pname = f"PRINC:{short}"
#             add_edge(rname, pname)
#     return adj

# def _compute_keep_set_from_diff(snapshot):
#     d = snapshot.get("_meta", {}).get("diff", {}) or {}
#     keep = set()
#     for ent, key_name in [("users", "UserName"), ("groups", "GroupName"), ("roles", "RoleName"), ("policies", "PolicyName")]:
#         ent_diff = d.get(ent, {})
#         for n in ent_diff.get("added", []) + ent_diff.get("modified", []):
#             if n: keep.add(n)
#     if not keep:
#         return set()
#     adj = _build_adjacency(snapshot)
#     for name in list(keep):
#         keep.update(adj.get(name, set()))
#     return keep

# # ---- Layout
# col1, col2 = st.columns([2, 1])

# with col1:
#     st.header("🕸️ IAM Graph — Interactive")

#     # 📦 Snapshot Info Box
#     with st.container():
#         st.markdown(
#             f"""
#             <div style="background:#111;padding:10px;border-radius:8px;margin-bottom:10px;">
#             <b>📦 Snapshot Info</b><br>
#             <span style="color:#bbb;">Fetched:</span> {meta.get("fetched_at", "—")}<br>
#             <span style="color:#bbb;">Profile:</span> {profile or "default"}<br>
#             <span style="color:#bbb;">Mode:</span> {"Fast" if meta.get("fast_mode") else "Full"}<br>
#             <span style="color:#bbb;">Entities:</span> Users: {meta.get("counts",{}).get("users",0)}, 
#             Roles: {meta.get("counts",{}).get("roles",0)}, 
#             Policies: {meta.get("counts",{}).get("policies",0)}
#             </div>
#             """, unsafe_allow_html=True
#         )

#     highlight = st.session_state.get("selected_entity", {}).get("name")

#     try:
#         use_data = data
#         if show_only_changes:
#             keep = _compute_keep_set_from_diff(data)
#             if keep:
#                 filtered = deepcopy(data)
#                 filtered["users"] = [u for u in data.get("users", []) if u.get("UserName") in keep]
#                 filtered["groups"] = [g for g in data.get("groups", []) if g.get("GroupName") in keep]
#                 filtered["roles"] = [r for r in data.get("roles", []) if r.get("RoleName") in keep]
#                 filtered["policies"] = [p for p in data.get("policies", []) if p.get("PolicyName") in keep]
#                 filtered["_meta"] = deepcopy(data.get("_meta", {}))
#                 use_data = filtered
#             else:
#                 st.info("No added/modified entities found in snapshot to show.")

#         # Build graph only if HTML not cached
#         if "graph_html" not in st.session_state:
#             G, html_str, clicked_node = build_iam_graph(
#                 use_data,
#                 show_only_risky=show_only_risky,
#                 highlight_node=highlight,
#                 highlight_color="orange",
#                 highlight_duration=2500
#             )
#             st.session_state["graph_html"] = html_str
#             st.session_state["graph_G"] = G
#         else:
#             G = st.session_state["graph_G"]

#         # Render cached HTML
#         st.markdown('<div class="graph-card">', unsafe_allow_html=True)
#         components.html(f"<div style='width:100%;'>{st.session_state['graph_html']}</div>", height=760, scrolling=True)
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

# with col2:
#     st.header("📋 Details")
#     selected = st.session_state.get("selected_entity")

#     policy_names = ["-- none --"] + sorted([p.get("PolicyName") for p in data.get("policies", []) if p.get("PolicyName")])
#     role_names = ["-- none --"] + sorted([r.get("RoleName") for r in data.get("roles", []) if r.get("RoleName")])
#     user_names = ["-- none --"] + sorted([u.get("UserName") for u in data.get("users", []) if u.get("UserName")])

#     chosen_policy = st.selectbox("Select policy", options=policy_names)
#     chosen_role = st.selectbox("Select role", options=role_names)
#     chosen_user = st.selectbox("Select user", options=user_names)

#     if not selected:
#         if chosen_policy != "-- none --":
#             selected = {"type": "policy", "name": chosen_policy}
#         elif chosen_role != "-- none --":
#             selected = {"type": "role", "name": chosen_role}
#         elif chosen_user != "-- none --":
#             selected = {"type": "user", "name": chosen_user}

#     st.session_state["selected_entity"] = selected

#     st.markdown('<div class="detail-card">', unsafe_allow_html=True)
#     if selected:
#         etype, name = selected["type"], selected["name"]
#         st.subheader(f"{etype.upper()} — {name}")
#         if etype == "policy":
#             p = next((x for x in data.get("policies", []) if x.get("PolicyName") == name), None)
#             if p:
#                 st.metric("RiskScore", p.get("RiskScore", 0))
#                 st.write("IsRisky:", p.get("IsRisky"))
#                 st.write("RiskActions:", p.get("RiskActions"))
#                 st.write("Arn:", p.get("Arn"))
#                 st.json(p.get("Document") or {})
#         elif etype == "role":
#             r = next((x for x in data.get("roles", []) if x.get("RoleName") == name), None)
#             if r:
#                 st.metric("AssumeRiskScore", r.get("AssumePolicyRiskScore", 0))
#                 st.write("AssumePolicyRisk:", r.get("AssumePolicyRisk"))
#                 st.write("AttachedPolicies:", [a.get("PolicyName") for a in (r.get("AttachedPolicies") or [])])
#                 st.write("Arn:", r.get("Arn"))
#                 st.json(r.get("AssumeRolePolicyDocument") or {})
#         elif etype == "user":
#             u = next((x for x in data.get("users", []) if x.get("UserName") == name), None)
#             if u:
#                 st.write("Arn:", u.get("Arn"))
#                 st.write("Groups:", u.get("Groups", []))
#                 st.write("AttachedPolicies:", [a.get("PolicyName") for a in (u.get("AttachedPolicies") or [])])
#     st.markdown('</div>', unsafe_allow_html=True)

# # import boto3
# # import json
# # import os
# # import urllib.parse
# # import logging
# # from datetime import datetime
# # from copy import deepcopy
# # from botocore.exceptions import ClientError, EndpointConnectionError

# # logger = logging.getLogger("fetch_iam")
# # logger.setLevel(logging.INFO)

# # SENSITIVE_ACTIONS = {"iam:passrole", "sts:assumerole"}
# # WILDCARD_ACTION = "*"
# # DEFAULT_SNAPSHOT = "data/iam_snapshot.json"

# # # ---------- Utility Functions ----------
# # def _normalize_action(a): 
# #     return a.lower()

# # def _action_is_risky(action):
# #     if not isinstance(action, str): 
# #         return False
# #     a = _normalize_action(action)
# #     return (a == WILDCARD_ACTION) or ("*" in a) or (a in SENSITIVE_ACTIONS)

# # def _extract_actions_from_statement(stmt):
# #     actions = stmt.get("Action") or stmt.get("NotAction") or []
# #     return [actions] if isinstance(actions, str) else actions

# # def _analyze_policy_document(doc):
# #     """Return (is_risky, list_of_risky_actions, score_int)"""
# #     risky_actions = set()
# #     if not doc: 
# #         return False, [], 0
# #     statements = doc.get("Statement", [])
# #     if isinstance(statements, dict): 
# #         statements = [statements]
# #     for stmt in statements:
# #         try:
# #             for a in _extract_actions_from_statement(stmt):
# #                 if _action_is_risky(a): 
# #                     risky_actions.add(a)
# #         except Exception as e:
# #             logger.warning(f"Failed to parse statement actions: {e}")
# #         # wildcard resource
# #         resources = stmt.get("Resource", [])
# #         if isinstance(resources, str): 
# #             resources = [resources]
# #         for r in resources:
# #             try:
# #                 if isinstance(r, str) and r.strip() == "*":
# #                     risky_actions.add("Resource:*")
# #             except Exception as e:
# #                 logger.warning(f"Failed to parse resources: {e}")
# #     score = min(10, len(risky_actions) * 2)  # 0–10
# #     return (len(risky_actions) > 0, sorted(list(risky_actions)), score)

# # def _read_snapshot(path):
# #     try:
# #         with open(path, "r", encoding="utf-8") as f:
# #             raw = f.read().strip()
# #             return json.loads(raw) if raw else None
# #     except Exception as e:
# #         logger.warning(f"Failed to read snapshot {path}: {e}")
# #         return None

# # # ---------- Improvement 1: Trust Principal Parsing ----------
# # def _parse_principal_value(val):
# #     if isinstance(val, str):
# #         if val.endswith(".amazonaws.com"):
# #             return {"type": "service", "value": val}
# #         elif val.startswith("arn:aws:iam::"):
# #             return {"type": "account", "value": val}
# #         elif "http" in val or "." in val:
# #             return {"type": "federated", "value": val}
# #         else:
# #             return {"type": "unknown", "value": val}
# #     return {"type": "unknown", "value": val}

# # # ---------- Diff helpers ----------
# # def _index_by(items, key):
# #     out = {}
# #     for it in items or []:
# #         k = it.get(key)
# #         if k: out[k] = it
# #     return out

# # def _shallow_equal(a, b):
# #     try:
# #         return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)
# #     except Exception:
# #         return False

# # def _compute_entity_diff(prev_list, new_list, key):
# #     prev = _index_by(prev_list, key)
# #     new = _index_by(new_list, key)
# #     added = sorted([k for k in new.keys() - prev.keys()])
# #     removed = sorted([k for k in prev.keys() - new.keys()])
# #     modified = []
# #     modified_details = {}
# #     for k in new.keys() & prev.keys():
# #         if not _shallow_equal(prev[k], new[k]):
# #             modified.append(k)
# #             diff_keys = []
# #             for field in set(prev[k].keys()) | set(new[k].keys()):
# #                 if prev[k].get(field) != new[k].get(field):
# #                     diff_keys.append(field)
# #             modified_details[k] = diff_keys
# #     return {"added": added, "removed": removed, "modified": sorted(modified), "modified_details": modified_details}

# # def _apply_change_flags(snapshot, diff):
# #     for entity, key in [("users","UserName"),("groups","GroupName"),("roles","RoleName"),("policies","PolicyName")]:
# #         for name in diff[entity]["added"]:
# #             x = next((u for u in snapshot[entity] if u.get(key)==name), None)
# #             if x: x["_changed"] = "added"
# #         for name in diff[entity]["modified"]:
# #             x = next((u for u in snapshot[entity] if u.get(key)==name), None)
# #             if x: x["_changed"] = "modified"

# # # ---------- Improvement 3: Risk Propagation ----------
# # def _propagate_risk(snapshot):
# #     risky_policies = {p["PolicyName"] for p in snapshot["policies"] if p.get("IsRisky")}
# #     risky_roles = {r["RoleName"] for r in snapshot["roles"] if r.get("AssumePolicyRisk")}
    
# #     for role in snapshot["roles"]:
# #         for ap in role.get("AttachedPolicies", []):
# #             if ap.get("PolicyName") in risky_policies:
# #                 role["AssumePolicyRisk"] = True
# #                 risky_roles.add(role["RoleName"])
    
# #     for user in snapshot["users"]:
# #         user_risky = False
# #         for ap in user.get("AttachedPolicies", []):
# #             if ap.get("PolicyName") in risky_policies:
# #                 user_risky = True
# #         if any(role in risky_roles for role in user.get("Groups", [])):
# #             user_risky = True
# #         if user_risky:
# #             user["IsRisky"] = True

# # # ---------- Main Fetch ----------
# # def fetch_iam_data(profile_name=None, out_path=DEFAULT_SNAPSHOT, fast_mode=True, force_fetch=False):
# #     os.makedirs(os.path.dirname(out_path), exist_ok=True)

# #     if not force_fetch and os.path.exists(out_path):
# #         cached = _read_snapshot(out_path)
# #         if cached:
# #             logger.info("Returning cached snapshot (set force_fetch=True to refresh & compute diff).")
# #             return cached

# #     session_args = {"profile_name": profile_name} if profile_name else {}
# #     try:
# #         session = boto3.Session(**session_args) if session_args else boto3.Session()
# #         iam = session.client("iam")
# #     except (ClientError, EndpointConnectionError) as e:
# #         logger.error(f"Failed to create IAM client: {e}")
# #         return {"_meta": {"error": str(e)}}

# #     snapshot = {
# #         "_meta": {
# #             "fetched_at": datetime.utcnow().isoformat() + "Z",
# #             "fast_mode": bool(fast_mode),
# #             "warnings": []
# #         },
# #         "users": [], "groups": [], "roles": [], "policies": []
# #     }

# #     # --- Users ---
# #     try:
# #         paginator = iam.get_paginator("list_users")
# #         for page in paginator.paginate():
# #             for u in page.get("Users", []):
# #                 snapshot["users"].append({
# #                     "UserName": u.get("UserName"),
# #                     "Arn": u.get("Arn"),
# #                     "CreateDate": u.get("CreateDate").isoformat() if u.get("CreateDate") else None
# #                 })
# #         logger.info(f"Fetched {len(snapshot['users'])} users")
# #     except Exception as e:
# #         logger.error(f"list_users failed: {e}")
# #         snapshot["_meta"]["warnings"].append(f"list_users failed: {e}")

# #     # --- Groups ---
# #     try:
# #         paginator = iam.get_paginator("list_groups")
# #         for page in paginator.paginate():
# #             for g in page.get("Groups", []):
# #                 gname = g.get("GroupName")
# #                 entry = {"GroupName": gname}
# #                 if not fast_mode:
# #                     try:
# #                         entry["AttachedPolicies"] = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
# #                         entry["InlinePolicies"] = iam.list_group_policies(GroupName=gname).get("PolicyNames", [])
# #                     except Exception as e:
# #                         entry["AttachedPolicies"] = []
# #                         entry["InlinePolicies"] = []
# #                         snapshot["_meta"]["warnings"].append(f"group {gname} policy fetch failed: {e}")
# #                 snapshot["groups"].append(entry)
# #         logger.info(f"Fetched {len(snapshot['groups'])} groups")
# #     except Exception as e:
# #         logger.error(f"list_groups failed: {e}")
# #         snapshot["_meta"]["warnings"].append(f"list_groups failed: {e}")

# #     # --- Roles ---
# #     try:
# #         paginator = iam.get_paginator("list_roles")
# #         for page in paginator.paginate():
# #             for r in page.get("Roles", []):
# #                 rname = r.get("RoleName")
# #                 assume_raw = r.get("AssumeRolePolicyDocument")
# #                 assume = {}
# #                 try:
# #                     if isinstance(assume_raw, str):
# #                         decoded = urllib.parse.unquote(assume_raw)
# #                         assume = json.loads(decoded)
# #                     elif isinstance(assume_raw, dict):
# #                         assume = assume_raw
# #                 except Exception as e:
# #                     logger.warning(f"decode assume doc for {rname} failed: {e}")
# #                     snapshot["_meta"]["warnings"].append(f"decode assume doc for {rname} failed: {e}")
# #                     assume = {}

# #                 principals_info = []
# #                 stmts = assume.get("Statement", [])
# #                 if isinstance(stmts, dict): stmts = [stmts]
# #                 for s in stmts:
# #                     principal = s.get("Principal", {})
# #                     if isinstance(principal, dict):
# #                         vals = principal.get("AWS") or principal.get("Service") or []
# #                         if isinstance(vals, str): vals = [vals]
# #                         for pr in vals:
# #                             principals_info.append(_parse_principal_value(pr))

# #                 attached, inline = [], []
# #                 if not fast_mode:
# #                     try:
# #                         attached = iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
# #                         inline = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])
# #                     except Exception as e:
# #                         logger.error(f"role {rname} policy fetch failed: {e}")
# #                         snapshot["_meta"]["warnings"].append(f"role {rname} policy fetch failed: {e}")

# #                 is_risky, risky_actions, score = _analyze_policy_document(assume or {})
# #                 snapshot["roles"].append({
# #                     "RoleName": rname,
# #                     "Arn": r.get("Arn"),
# #                     "AssumeRolePolicyDocument": assume,
# #                     "AssumePolicyRisk": is_risky,
# #                     "AssumePolicyRiskActions": risky_actions,
# #                     "AssumePolicyRiskScore": score,
# #                     "PrincipalsInfo": principals_info,
# #                     "AttachedPolicies": attached,
# #                     "InlinePolicies": inline
# #                 })
# #         logger.info(f"Fetched {len(snapshot['roles'])} roles")
# #     except Exception as e:
# #         logger.error(f"list_roles failed: {e}")
# #         snapshot["_meta"]["warnings"].append(f"list_roles failed: {e}")

# #     # --- Users' group membership & policies ---
# #     if not fast_mode:
# #         for user in snapshot.get("users", []):
# #             uname = user.get("UserName")
# #             try:
# #                 groups = iam.list_groups_for_user(UserName=uname).get("Groups", [])
# #                 user["Groups"] = [g.get("GroupName") for g in groups]
# #             except Exception as e:
# #                 logger.error(f"user {uname} group fetch failed: {e}")
# #                 user["Groups"] = []
# #                 snapshot["_meta"]["warnings"].append(f"user {uname} group fetch failed: {e}")
# #             try:
# #                 att = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
# #                 user["AttachedPolicies"] = att
# #                 inline = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
# #                 user["InlinePolicies"] = inline
# #             except Exception as e:
# #                 logger.error(f"user {uname} policy fetch failed: {e}")
# #                 user.setdefault("AttachedPolicies", [])
# #                 user.setdefault("InlinePolicies", [])
# #                 snapshot["_meta"]["warnings"].append(f"user {uname} policy fetch failed: {e}")

# #     # --- Policies ---
# #     scope = "Local" if fast_mode else "All"
# #     try:
# #         for page in iam.get_paginator("list_policies").paginate(Scope=scope):
# #             for p in page.get("Policies", []):
# #                 p_arn = p.get("Arn")
# #                 p_name = p.get("PolicyName")
# #                 entry = {"PolicyName": p_name, "Arn": p_arn, "Document": {}, "IsRisky": False, "RiskActions": [], "RiskScore": 0}
# #                 if not fast_mode:
# #                     try:
# #                         meta = iam.get_policy(PolicyArn=p_arn).get("Policy", {})
# #                         ver = meta.get("DefaultVersionId")
# #                         if ver:
# #                             doc = iam.get_policy_version(PolicyArn=p_arn, VersionId=ver).get("PolicyVersion", {}).get("Document", {})
# #                             entry["Document"] = doc
# #                             is_risky, risk_actions, score = _analyze_policy_document(doc or {})
# #                             entry["IsRisky"] = is_risky
# #                             entry["RiskActions"] = risk_actions
# #                             entry["RiskScore"] = score
# #                     except Exception as e:
# #                         logger.error(f"policy {p_name} doc fetch failed: {e}")
# #                         snapshot["_meta"]["warnings"].append(f"policy {p_name} doc fetch failed: {e}")
# #                 else:
# #                     name_low = (p_name or "").lower()
# #                     if "admin" in name_low or "fullaccess" in name_low or "poweruser" in name_low:
# #                         entry["IsRisky"] = True
# #                         entry["RiskActions"] = ["Name:heuristic"]
# #                         entry["RiskScore"] = 7
# #                 snapshot["policies"].append(entry)
# #         logger.info(f"Fetched {len(snapshot['policies'])} policies")
# #     except Exception as e:
# #         logger.error(f"list_policies failed: {e}")
# #         snapshot["_meta"]["warnings"].append(f"list_policies failed: {e}")

# #     _propagate_risk(snapshot)

# #     snapshot["_meta"]["counts"] = {
# #         "users": len(snapshot.get("users", [])),
# #         "groups": len(snapshot.get("groups", [])),
# #         "roles": len(snapshot.get("roles", [])),
# #         "policies": len(snapshot.get("policies", []))
# #     }

# #     prev = _read_snapshot(out_path)

   
# #     try:
# #         with open(out_path, "w", encoding="utf-8") as f:
# #             json.dump(snapshot, f, indent=2, default=str)
# #     except Exception as e:
# #         snapshot["_meta"]["warnings"].append(f"write_snapshot_failed: {e}")

# #     return snapshot

# # if __name__ == "__main__":
# #     s = fetch_iam_data(fast_mode=True, force_fetch=True)
# #     print("Fetched counts:", s["_meta"]["counts"])
# #     print("Diff:", s["_meta"]["diff"]["counts"])
# #     print("Impact Score:", s["_meta"]["diff"]["impact_score"])

# import boto3
# import json
# import os
# import urllib.parse
# import logging
# from datetime import datetime
# from botocore.exceptions import ClientError, EndpointConnectionError
# from botocore.config import Config

# # ---------- Logging Setup ----------
# os.makedirs("logs", exist_ok=True)
# logger = logging.getLogger("fetch_iam")
# logger.setLevel(logging.INFO)

# # Console handler
# ch = logging.StreamHandler()
# ch.setLevel(logging.INFO)

# # File handler
# fh = logging.FileHandler("logs/fetch_iam.log", encoding="utf-8")
# fh.setLevel(logging.INFO)

# formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
# ch.setFormatter(formatter)
# fh.setFormatter(formatter)

# if not logger.handlers:
#     logger.addHandler(ch)
#     logger.addHandler(fh)

# # ---------- Constants ----------
# SENSITIVE_ACTIONS = {"iam:passrole", "sts:assumerole"}
# WILDCARD_ACTION = "*"
# DEFAULT_SNAPSHOT = "data/iam_snapshot.json"

# # ---------- Utility Functions ----------
# def _normalize_action(a): 
#     return a.lower()

# def _action_is_risky(action):
#     if not isinstance(action, str): 
#         return False
#     a = _normalize_action(action)
#     return (a == WILDCARD_ACTION) or ("*" in a) or (a in SENSITIVE_ACTIONS)

# def _extract_actions_from_statement(stmt):
#     actions = stmt.get("Action") or stmt.get("NotAction") or []
#     return [actions] if isinstance(actions, str) else actions

# def _analyze_policy_document(doc):
#     risky_actions = set()
#     if not doc: 
#         return False, [], 0
#     statements = doc.get("Statement", [])
#     if isinstance(statements, dict): 
#         statements = [statements]
#     for stmt in statements:
#         try:
#             for a in _extract_actions_from_statement(stmt):
#                 if _action_is_risky(a): 
#                     risky_actions.add(a)
#         except Exception as e:
#             logger.warning(f"Failed to parse statement actions: {e}")
#         resources = stmt.get("Resource", [])
#         if isinstance(resources, str): 
#             resources = [resources]
#         for r in resources:
#             try:
#                 if isinstance(r, str) and r.strip() == "*":
#                     risky_actions.add("Resource:*")
#             except Exception as e:
#                 logger.warning(f"Failed to parse resources: {e}")
#     score = min(10, len(risky_actions) * 2)
#     return (len(risky_actions) > 0, sorted(list(risky_actions)), score)

# def _read_snapshot(path):
#     try:
#         with open(path, "r", encoding="utf-8") as f:
#             raw = f.read().strip()
#             return json.loads(raw) if raw else None
#     except Exception as e:
#         logger.warning(f"Failed to read snapshot {path}: {e}")
#         return None

# def _parse_principal_value(val):
#     if isinstance(val, str):
#         if val.endswith(".amazonaws.com"):
#             return {"type": "service", "value": val}
#         elif val.startswith("arn:aws:iam::"):
#             return {"type": "account", "value": val}
#         elif "http" in val or "." in val:
#             return {"type": "federated", "value": val}
#         else:
#             return {"type": "unknown", "value": val}
#     return {"type": "unknown", "value": val}

# def _index_by(items, key):
#     out = {}
#     for it in items or []:
#         k = it.get(key)
#         if k: out[k] = it
#     return out

# def _shallow_equal(a, b):
#     try:
#         return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)
#     except Exception:
#         return False

# def _compute_entity_diff(prev_list, new_list, key):
#     prev = _index_by(prev_list, key)
#     new = _index_by(new_list, key)
#     added = sorted([k for k in new.keys() - prev.keys()])
#     removed = sorted([k for k in prev.keys() - new.keys()])
#     modified = []
#     modified_details = {}
#     for k in new.keys() & prev.keys():
#         if not _shallow_equal(prev[k], new[k]):
#             modified.append(k)
#             diff_keys = []
#             for field in set(prev[k].keys()) | set(new[k].keys()):
#                 if prev[k].get(field) != new[k].get(field):
#                     diff_keys.append(field)
#             modified_details[k] = diff_keys
#     return {"added": added, "removed": removed, "modified": sorted(modified), "modified_details": modified_details}

# def _propagate_risk(snapshot):
#     risky_policies = {p["PolicyName"] for p in snapshot["policies"] if p.get("IsRisky")}
#     risky_roles = {r["RoleName"] for r in snapshot["roles"] if r.get("AssumePolicyRisk")}
    
#     for role in snapshot["roles"]:
#         for ap in role.get("AttachedPolicies", []):
#             if ap.get("PolicyName") in risky_policies:
#                 role["AssumePolicyRisk"] = True
#                 risky_roles.add(role["RoleName"])
    
#     for user in snapshot["users"]:
#         user_risky = False
#         for ap in user.get("AttachedPolicies", []):
#             if ap.get("PolicyName") in risky_policies:
#                 user_risky = True
#         if any(role in risky_roles for role in user.get("Groups", [])):
#             user_risky = True
#         if user_risky:
#             user["IsRisky"] = True

# # ---------- Main Fetch ----------
# def fetch_iam_data(profile_name=None, out_path=DEFAULT_SNAPSHOT, fast_mode=True, force_fetch=False):
#     os.makedirs(os.path.dirname(out_path), exist_ok=True)

#     if not force_fetch and os.path.exists(out_path):
#         cached = _read_snapshot(out_path)
#         if cached:
#             logger.info("Returning cached snapshot (set force_fetch=True to refresh & compute diff).")
#             return cached

#     config = Config(retries={"max_attempts": 5, "mode": "adaptive"})
#     session_args = {"profile_name": profile_name} if profile_name else {}
#     try:
#         session = boto3.Session(**session_args) if session_args else boto3.Session()
#         iam = session.client("iam", config=config)
#     except (ClientError, EndpointConnectionError) as e:
#         logger.error(f"Failed to create IAM client: {e}")
#         return {"_meta": {"error": str(e)}}

#     snapshot = {
#         "_meta": {
#             "fetched_at": datetime.utcnow().isoformat() + "Z",
#             "fast_mode": bool(fast_mode),
#             "warnings": []
#         },
#         "users": [], "groups": [], "roles": [], "policies": []
#     }

#     # --- Users ---
#     try:
#         paginator = iam.get_paginator("list_users")
#         for page in paginator.paginate():
#             for u in page.get("Users", []):
#                 snapshot["users"].append({
#                     "UserName": u.get("UserName"),
#                     "Arn": u.get("Arn"),
#                     "CreateDate": u.get("CreateDate").isoformat() if u.get("CreateDate") else None
#                 })
#         logger.info(f"Fetched {len(snapshot['users'])} users")
#     except Exception as e:
#         logger.error(f"list_users failed: {e}")
#         snapshot["_meta"]["warnings"].append(f"list_users failed: {e}")

#     # --- Groups ---
#     try:
#         paginator = iam.get_paginator("list_groups")
#         for page in paginator.paginate():
#             for g in page.get("Groups", []):
#                 gname = g.get("GroupName")
#                 entry = {"GroupName": gname}
#                 if not fast_mode:
#                     try:
#                         entry["AttachedPolicies"] = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
#                         entry["InlinePolicies"] = iam.list_group_policies(GroupName=gname).get("PolicyNames", [])
#                     except Exception as e:
#                         entry["AttachedPolicies"] = []
#                         entry["InlinePolicies"] = []
#                         snapshot["_meta"]["warnings"].append(f"group {gname} policy fetch failed: {e}")
#                 snapshot["groups"].append(entry)
#         logger.info(f"Fetched {len(snapshot['groups'])} groups")
#     except Exception as e:
#         logger.error(f"list_groups failed: {e}")
#         snapshot["_meta"]["warnings"].append(f"list_groups failed: {e}")

#     # --- Roles ---
#     try:
#         paginator = iam.get_paginator("list_roles")
#         for page in paginator.paginate():
#             for r in page.get("Roles", []):
#                 rname = r.get("RoleName")
#                 assume_raw = r.get("AssumeRolePolicyDocument")
#                 assume = {}
#                 try:
#                     if isinstance(assume_raw, str):
#                         decoded = urllib.parse.unquote(assume_raw)
#                         assume = json.loads(decoded)
#                     elif isinstance(assume_raw, dict):
#                         assume = assume_raw
#                 except Exception as e:
#                     logger.warning(f"decode assume doc for {rname} failed: {e}")
#                     snapshot["_meta"]["warnings"].append(f"decode assume doc for {rname} failed: {e}")
#                     assume = {}

#                 principals_info = []
#                 stmts = assume.get("Statement", [])
#                 if isinstance(stmts, dict): stmts = [stmts]
#                 for s in stmts:
#                     principal = s.get("Principal", {})
#                     if isinstance(principal, dict):
#                         vals = principal.get("AWS") or principal.get("Service") or []
#                         if isinstance(vals, str): vals = [vals]
#                         for pr in vals:
#                             principals_info.append(_parse_principal_value(pr))

#                 attached, inline = [], []
#                 if not fast_mode:
#                     try:
#                         attached = iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
#                         inline = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])
#                     except Exception as e:
#                         snapshot["_meta"]["warnings"].append(f"role {rname} policy fetch failed: {e}")

#                 is_risky, risky_actions, score = _analyze_policy_document(assume or {})
#                 snapshot["roles"].append({
#                     "RoleName": rname,
#                     "Arn": r.get("Arn"),
#                     "AssumeRolePolicyDocument": assume,
#                     "AssumePolicyRisk": is_risky,
#                     "AssumePolicyRiskActions": risky_actions,
#                     "AssumePolicyRiskScore": score,
#                     "PrincipalsInfo": principals_info,
#                     "AttachedPolicies": attached,
#                     "InlinePolicies": inline
#                 })
#         logger.info(f"Fetched {len(snapshot['roles'])} roles")
#     except Exception as e:
#         logger.error(f"list_roles failed: {e}")
#         snapshot["_meta"]["warnings"].append(f"list_roles failed: {e}")

#     # --- Users' group membership & policies ---
#     if not fast_mode:
#         for user in snapshot.get("users", []):
#             uname = user.get("UserName")
#             try:
#                 groups = iam.list_groups_for_user(UserName=uname).get("Groups", [])
#                 user["Groups"] = [g.get("GroupName") for g in groups]
#             except Exception as e:
#                 user["Groups"] = []
#                 snapshot["_meta"]["warnings"].append(f"user {uname} group fetch failed: {e}")
#             try:
#                 att = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
#                 user["AttachedPolicies"] = att
#                 inline = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
#                 user["InlinePolicies"] = inline
#             except Exception as e:
#                 user.setdefault("AttachedPolicies", [])
#                 user.setdefault("InlinePolicies", [])
#                 snapshot["_meta"]["warnings"].append(f"user {uname} policy fetch failed: {e}")

#     # --- Policies ---
#     scope = "Local" if fast_mode else "All"
#     try:
#         for page in iam.get_paginator("list_policies").paginate(Scope=scope):
#             for p in page.get("Policies", []):
#                 p_arn = p.get("Arn")
#                 p_name = p.get("PolicyName")
#                 entry = {"PolicyName": p_name, "Arn": p_arn, "Document": {}, "IsRisky": False, "RiskActions": [], "RiskScore": 0}
#                 if not fast_mode:
#                     try:
#                         meta = iam.get_policy(PolicyArn=p_arn).get("Policy", {})
#                         ver = meta.get("DefaultVersionId")
#                         if ver:
#                             doc = iam.get_policy_version(PolicyArn=p_arn, VersionId=ver).get("PolicyVersion", {}).get("Document", {})
#                             entry["Document"] = doc
#                             is_risky, risk_actions, score = _analyze_policy_document(doc or {})
#                             entry["IsRisky"] = is_risky
#                             entry["RiskActions"] = risk_actions
#                             entry["RiskScore"] = score
#                     except Exception as e:
#                         snapshot["_meta"]["warnings"].append(f"policy {p_name} doc fetch failed: {e}")
#                 else:
#                     name_low = (p_name or "").lower()
#                     if "admin" in name_low or "fullaccess" in name_low or "poweruser" in name_low:
#                         entry["IsRisky"] = True
#                         entry["RiskActions"] = ["Name:heuristic"]
#                         entry["RiskScore"] = 7
#                 snapshot["policies"].append(entry)
#         logger.info(f"Fetched {len(snapshot['policies'])} policies")
#     except Exception as e:
#         snapshot["_meta"]["warnings"].append(f"list_policies failed: {e}")

#     # --- Risk Propagation ---
#     _propagate_risk(snapshot)

#     # --- Counts & Diff ---
#     snapshot["_meta"]["counts"] = {
#         "users": len(snapshot.get("users", [])),
#         "groups": len(snapshot.get("groups", [])),
#         "roles": len(snapshot.get("roles", [])),
#         "policies": len(snapshot.get("policies", []))
#     }

#     prev = _read_snapshot(out_path)
#     diff = {
#         "users": _compute_entity_diff(prev.get("users", []) if prev else [], snapshot["users"], "UserName"),
#         "groups": _compute_entity_diff(prev.get("groups", []) if prev else [], snapshot["groups"], "GroupName"),
#         "roles": _compute_entity_diff(prev.get("roles", []) if prev else [], snapshot["roles"], "RoleName"),
#         "policies": _compute_entity_diff(prev.get("policies", []) if prev else [], snapshot["policies"], "PolicyName"),
#     }
#     diff["counts"] = {
#         "added": sum(len(diff[t]["added"]) for t in ["users","groups","roles","policies"]),
#         "removed": sum(len(diff[t]["removed"]) for t in ["users","groups","roles","policies"]),
#         "modified": sum(len(diff[t]["modified"]) for t in ["users","groups","roles","policies"]),
#     }
#     diff["impact_score"] = (diff["counts"]["added"] * 2) + (diff["counts"]["modified"] * 1) - (diff["counts"]["removed"] * 1)
#     snapshot["_meta"]["diff"] = diff

#     # --- Save snapshot with versioning ---
#     try:
#         ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
#         versioned_path = out_path.replace(".json", f"_{ts}.json")
#         with open(versioned_path, "w", encoding="utf-8") as f:
#             json.dump(snapshot, f, indent=2, default=str)
#         with open(out_path, "w", encoding="utf-8") as f:
#             json.dump(snapshot, f, indent=2, default=str)
#         logger.info(f"Snapshot saved → {versioned_path} and {out_path}")
#     except Exception as e:
#         snapshot["_meta"]["warnings"].append(f"write_snapshot_failed: {e}")
#         logger.error(f"Failed to save snapshot: {e}")

#     return snapshot

# if __name__ == "__main__":
#     s = fetch_iam_data(fast_mode=True, force_fetch=True)
#     logger.info(f"Fetched counts: {s['_meta']['counts']}")
#     logger.info(f"Diff: {s['_meta']['diff']['counts']}")
#     logger.info(f"Impact Score: {s['_meta']['diff']['impact_score']}")

import boto3
import json
import os
import urllib.parse
import logging
from datetime import datetime
from copy import deepcopy
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError, NoRegionError

logger = logging.getLogger("fetch_iam")
logger.setLevel(logging.INFO)

SENSITIVE_ACTIONS = {"iam:passrole", "sts:assumerole"}
WILDCARD_ACTION = "*"
DEFAULT_SNAPSHOT = "data/iam_snapshot.json"
VERSIONED_DIR = "data/snapshots"  # will also store timestamped copies


# ---------- Utility ----------
def _normalize_action(a):
    return a.lower() if isinstance(a, str) else a

def _action_is_risky(action):
    if not isinstance(action, str):
        return False
    a = _normalize_action(action)
    return (a == WILDCARD_ACTION) or ("*" in a) or (a in SENSITIVE_ACTIONS)

def _extract_actions_from_statement(stmt):
    actions = stmt.get("Action") or stmt.get("NotAction") or []
    return [actions] if isinstance(actions, str) else actions

def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def _read_snapshot(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            return json.loads(raw) if raw else None
    except Exception as e:
        logger.warning(f"Failed to read snapshot {path}: {e}")
        return None

# ---------- Principal parsing ----------
def _parse_principal_value(val):
    if isinstance(val, str):
        if val.endswith(".amazonaws.com"):
            return {"type": "service", "value": val}
        elif val.startswith("arn:aws:iam::"):
            return {"type": "account", "value": val}
        elif val in ("*",):
            return {"type": "wildcard", "value": val}
        elif "http" in val or "." in val:
            return {"type": "federated", "value": val}
        else:
            return {"type": "unknown", "value": val}
    return {"type": "unknown", "value": val}

# ---------- Diff helpers ----------
def _index_by(items, key):
    out = {}
    for it in items or []:
        k = it.get(key)
        if k: out[k] = it
    return out

def _shallow_equal(a, b):
    try:
        return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)
    except Exception:
        return False

def _compute_entity_diff(prev_list, new_list, key):
    prev = _index_by(prev_list, key)
    new = _index_by(new_list, key)
    added = sorted([k for k in new.keys() - prev.keys()])
    removed = sorted([k for k in prev.keys() - new.keys()])
    modified = []
    modified_details = {}
    for k in new.keys() & prev.keys():
        if not _shallow_equal(prev[k], new[k]):
            modified.append(k)
            diff_keys = []
            for field in set(prev[k].keys()) | set(new[k].keys()):
                if prev[k].get(field) != new[k].get(field):
                    diff_keys.append(field)
            modified_details[k] = diff_keys
    return {"added": added, "removed": removed, "modified": sorted(modified), "modified_details": modified_details}

def _apply_change_flags(snapshot, diff):
    for entity, key in [("users","UserName"),("groups","GroupName"),("roles","RoleName"),("policies","PolicyName")]:
        for name in diff[entity]["added"]:
            x = next((u for u in snapshot[entity] if u.get(key)==name), None)
            if x: x["_changed"] = "added"
        for name in diff[entity]["modified"]:
            x = next((u for u in snapshot[entity] if u.get(key)==name), None)
            if x: x["_changed"] = "modified"

# ---------- Extended static analyzer ----------
# Lightweight structural checks that work with read-only.
FINDING = lambda code, sev, msg, hint=None, path=None: {
    "code": code, "severity": sev, "message": msg, "hint": hint, "path": path
}

def _svc(action):
    """Return 'service' of 'service:Action' or '*'."""
    if not isinstance(action, str):
        return ""
    if action == "*":
        return "*"
    parts = action.split(":", 1)
    return parts[0].lower() if len(parts) == 2 else action.lower()

def _analyze_policy_document_extended(doc):
    """
    Return:
      {
        "is_risky": bool,
        "risky_actions": [str],
        "score": int (0-10),
        "findings": [ {code,severity,message,hint,path} ]
      }
    """
    findings = []
    risky_actions = set()
    if not doc:
        return {"is_risky": False, "risky_actions": [], "score": 0, "findings": []}

    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    for idx, stmt in enumerate(stmts):
        path = f"Statement[{idx}]"
        effect = (stmt.get("Effect") or "Allow").lower()

        actions = _ensure_list(stmt.get("Action")) or []
        not_actions = _ensure_list(stmt.get("NotAction")) or []
        resources = _ensure_list(stmt.get("Resource")) or []
        cond = stmt.get("Condition") or {}

        # A1: Wildcard in Action/NotAction
        if "*" in actions or any(isinstance(a, str) and "*" in a for a in actions):
            findings.append(FINDING("ACTION_WILDCARD", "high",
                "Action uses '*' or wildcard pattern", "List explicit actions instead of '*'", path))
        if not_actions:
            findings.append(FINDING("NOTACTION_USED", "medium",
                "NotAction is used (hard to reason least-privilege)", "Prefer explicit 'Action' allow list", path))

        # A2: Sensitive actions without guard
        alow = [a.lower() for a in actions if isinstance(a, str)]
        if any(a in alow for a in ["iam:passrole", "sts:assumerole"]):
            if "*" in resources or any(r == "*" for r in resources):
                findings.append(FINDING("SENSITIVE_NO_RESOURCE_SCOPE", "high",
                    "Sensitive action with Resource '*'", "Limit to specific ARNs and require conditions", path))
            if not cond:
                findings.append(FINDING("SENSITIVE_NO_CONDITION", "medium",
                    "Sensitive action without condition", "Add conditions like aws:ResourceTag, aws:PrincipalArn, ExternalId", path))

        # R1: Resource wildcard with Allow
        if effect == "allow":
            if "*" in resources or any(isinstance(r, str) and r.strip() == "*" for r in resources):
                findings.append(FINDING("RESOURCE_WILDCARD", "high",
                    "Resource is '*' with Allow", "Scope resources to specific ARNs or tags", path))

        # KMS: Decrypt without constraints
        if any(_svc(a) == "kms" and a.lower().endswith(":decrypt") for a in alow):
            if "*" in resources or not cond:
                findings.append(FINDING("KMS_DECRYPT_PERMISSIVE", "high",
                    "kms:Decrypt broadly allowed", "Constrain by kms:EncryptionContext conditions and specific key ARNs", path))

        # S3 broad
        if any(_svc(a) == "s3" for a in alow):
            if "*" in resources:
                findings.append(FINDING("S3_BROAD", "medium",
                    "S3 access with Resource '*'", "Scope to bucket and object ARNs; add aws:userid or IP conditions", path))

        # Collect risky actions set (structural)
        for a in actions or []:
            if _action_is_risky(a):
                risky_actions.add(a)
        # Wildcard resource marker:
        if any(isinstance(r, str) and r.strip() == "*" for r in resources):
            risky_actions.add("Resource:*")

    # Score: weighted
    score = 0
    for f in findings:
        score += {"low": 1, "medium": 2, "high": 4}.get(f["severity"], 1)
    score = max(0, min(10, score))

    return {
        "is_risky": len(findings) > 0 or len(risky_actions) > 0,
        "risky_actions": sorted(list(risky_actions)),
        "score": score,
        "findings": findings
    }

def _analyze_trust_policy(assume_doc):
    """Trust policy analysis for roles."""
    findings = []
    if not assume_doc:
        return {"is_risky": False, "risky_actions": [], "score": 0, "findings": []}

    stmts = assume_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    risky_actions = set()
    for idx, s in enumerate(stmts):
        path = f"Trust[{idx}]"
        principal = s.get("Principal", {})
        effect = (s.get("Effect") or "Allow").lower()
        if effect != "allow":
            continue

        if principal == "*" or (isinstance(principal, dict) and any(v == "*" for v in principal.values())):
            findings.append(FINDING("TRUST_WILDCARD_PRINCIPAL", "high",
                "Trust policy allows '*' principal", "Restrict to specific AWS account/roles or services; consider aws:PrincipalOrgID", path))

        # Service principals
        if isinstance(principal, dict):
            for k in ["Service", "AWS", "Federated"]:
                vals = _ensure_list(principal.get(k))
                if any(v == "*" for v in vals):
                    findings.append(FINDING("TRUST_WILDCARD_COMPONENT", "high",
                        f"Trust principal '{k}' uses '*'", "Pin to exact principal", path))

        cond = s.get("Condition") or {}
        # If AWS account principal used, suggest ExternalId/Org constraint
        if isinstance(principal, dict) and ("AWS" in principal):
            if not cond:
                findings.append(FINDING("TRUST_NO_CONDITION", "medium",
                    "Account principal without conditions", "Add external ID or aws:PrincipalOrgID / SourceAccount", path))

        # mark risky
        risky_actions.add("Trust:*")

    score = 0
    for f in findings:
        score += {"low": 1, "medium": 2, "high": 4}.get(f["severity"], 1)
    score = max(0, min(10, score))
    return {
        "is_risky": len(findings) > 0,
        "risky_actions": sorted(list(risky_actions)),
        "score": score,
        "findings": findings
    }


# ---------- Risk propagation ----------
def _propagate_risk(snapshot):
    risky_policies = {p["PolicyName"] for p in snapshot["policies"] if p.get("IsRisky")}
    risky_roles = {r["RoleName"] for r in snapshot["roles"] if r.get("AssumePolicyRisk")}

    for role in snapshot["roles"]:
        for ap in role.get("AttachedPolicies", []) or []:
            if ap.get("PolicyName") in risky_policies:
                role["AssumePolicyRisk"] = True
                risky_roles.add(role["RoleName"])

    for user in snapshot["users"]:
        user_risky = False
        for ap in user.get("AttachedPolicies", []) or []:
            if ap.get("PolicyName") in risky_policies:
                user_risky = True
        # groups could be marked risky if you add logic later
        if user_risky:
            user["IsRisky"] = True


# ---------- Main Fetch ----------
def fetch_iam_data(profile_name=None, out_path=DEFAULT_SNAPSHOT, fast_mode=True, force_fetch=False):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    os.makedirs(VERSIONED_DIR, exist_ok=True)

    if not force_fetch and os.path.exists(out_path):
        cached = _read_snapshot(out_path)
        if cached:
            logger.info("Returning cached snapshot (set force_fetch=True to refresh & compute diff).")
            return cached

    session_args = {"profile_name": profile_name} if profile_name else {}
    try:
        session = boto3.Session(**session_args) if session_args else boto3.Session()
        iam = session.client("iam")
        sts = session.client("sts")
        try:
            caller = sts.get_caller_identity()
            account_id = caller.get("Account")
        except Exception:
            account_id = None
    except (ClientError, EndpointConnectionError, NoCredentialsError, NoRegionError) as e:
        logger.error(f"Failed to create AWS clients: {e}")
        return {"_meta": {"error": str(e)}}

    snapshot = {
        "_meta": {
            "fetched_at": datetime.utcnow().isoformat() + "Z",
            "fast_mode": bool(fast_mode),
            "warnings": [],
            "account_id": account_id
        },
        "users": [], "groups": [], "roles": [], "policies": []
    }

    # --- Users ---
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                snapshot["users"].append({
                    "UserName": u.get("UserName"),
                    "Arn": u.get("Arn"),
                    "CreateDate": u.get("CreateDate").isoformat() if u.get("CreateDate") else None
                })
        logger.info(f"Fetched {len(snapshot['users'])} users")
    except Exception as e:
        logger.error(f"list_users failed: {e}")
        snapshot["_meta"]["warnings"].append(f"list_users failed: {e}")

    # --- Groups ---
    try:
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page.get("Groups", []):
                gname = g.get("GroupName")
                entry = {"GroupName": gname}
                if not fast_mode:
                    try:
                        entry["AttachedPolicies"] = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
                        entry["InlinePolicies"] = iam.list_group_policies(GroupName=gname).get("PolicyNames", [])
                        # NOTE: inline bodies fetched later on-demand if needed
                    except Exception as e:
                        entry["AttachedPolicies"] = []
                        entry["InlinePolicies"] = []
                        snapshot["_meta"]["warnings"].append(f"group {gname} policy fetch failed: {e}")
                snapshot["groups"].append(entry)
        logger.info(f"Fetched {len(snapshot['groups'])} groups")
    except Exception as e:
        logger.error(f"list_groups failed: {e}")
        snapshot["_meta"]["warnings"].append(f"list_groups failed: {e}")

    # --- Roles ---
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                rname = r.get("RoleName")
                assume_raw = r.get("AssumeRolePolicyDocument")
                assume = {}
                try:
                    if isinstance(assume_raw, str):
                        decoded = urllib.parse.unquote(assume_raw)
                        assume = json.loads(decoded)
                    elif isinstance(assume_raw, dict):
                        assume = assume_raw
                except Exception as e:
                    logger.warning(f"decode assume doc for {rname} failed: {e}")
                    snapshot["_meta"]["warnings"].append(f"decode assume doc for {rname} failed: {e}")
                    assume = {}

                principals_info = []
                stmts = assume.get("Statement", [])
                if isinstance(stmts, dict): stmts = [stmts]
                for s in stmts:
                    principal = s.get("Principal", {})
                    if isinstance(principal, dict):
                        vals = principal.get("AWS") or principal.get("Service") or principal.get("Federated") or []
                        if isinstance(vals, str): vals = [vals]
                        for pr in vals:
                            principals_info.append(_parse_principal_value(pr))
                    elif principal == "*":
                        principals_info.append({"type": "wildcard", "value": "*"})

                attached, inline = [], []
                if not fast_mode:
                    try:
                        attached = iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
                        inline = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])
                    except Exception as e:
                        logger.error(f"role {rname} policy fetch failed: {e}")
                        snapshot["_meta"]["warnings"].append(f"role {rname} policy fetch failed: {e}")

                # trust analyzer
                trust_eval = _analyze_trust_policy(assume or {})

                snapshot["roles"].append({
                    "RoleName": rname,
                    "Arn": r.get("Arn"),
                    "AssumeRolePolicyDocument": assume,
                    "AssumePolicyRisk": trust_eval["is_risky"],
                    "AssumePolicyRiskActions": trust_eval["risky_actions"],
                    "AssumePolicyRiskScore": trust_eval["score"],
                    "AssumePolicyFindings": trust_eval["findings"],
                    "PrincipalsInfo": principals_info,
                    "AttachedPolicies": attached,
                    "InlinePolicies": inline
                })
        logger.info(f"Fetched {len(snapshot['roles'])} roles")
    except Exception as e:
        logger.error(f"list_roles failed: {e}")
        snapshot["_meta"]["warnings"].append(f"list_roles failed: {e}")

    # --- Users' group membership & policies ---
    if not fast_mode:
        for user in snapshot.get("users", []):
            uname = user.get("UserName")
            try:
                groups = iam.list_groups_for_user(UserName=uname).get("Groups", [])
                user["Groups"] = [g.get("GroupName") for g in groups]
            except Exception as e:
                logger.error(f"user {uname} group fetch failed: {e}")
                user["Groups"] = []
                snapshot["_meta"]["warnings"].append(f"user {uname} group fetch failed: {e}")
            try:
                att = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                user["AttachedPolicies"] = att
                inline = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
                user["InlinePolicies"] = inline
            except Exception as e:
                logger.error(f"user {uname} policy fetch failed: {e}")
                user.setdefault("AttachedPolicies", [])
                user.setdefault("InlinePolicies", [])
                snapshot["_meta"]["warnings"].append(f"user {uname} policy fetch failed: {e}")

    # --- Policies (CUSTOM ONLY) ---
    # Scope=Local means customer-managed only. We'll ignore AWS-managed on purpose.
    scope = "Local"
    try:
        for page in iam.get_paginator("list_policies").paginate(Scope=scope):
            for p in page.get("Policies", []):
                p_arn = p.get("Arn")
                p_name = p.get("PolicyName")
                entry = {"PolicyName": p_name, "Arn": p_arn, "Document": {},
                         "IsRisky": False, "RiskActions": [], "RiskScore": 0, "Findings": []}
                # fetch default version + analyze
                try:
                    meta = iam.get_policy(PolicyArn=p_arn).get("Policy", {})
                    ver = meta.get("DefaultVersionId")
                    if ver:
                        doc = iam.get_policy_version(PolicyArn=p_arn, VersionId=ver).get("PolicyVersion", {}).get("Document", {})
                        entry["Document"] = doc
                        ext = _analyze_policy_document_extended(doc or {})
                        entry["IsRisky"] = ext["is_risky"]
                        entry["RiskActions"] = ext["risky_actions"]
                        entry["RiskScore"] = ext["score"]
                        entry["Findings"] = ext["findings"]
                except Exception as e:
                    logger.error(f"policy {p_name} doc fetch failed: {e}")
                    snapshot["_meta"]["warnings"].append(f"policy {p_name} doc fetch failed: {e}")

                snapshot["policies"].append(entry)
        logger.info(f"Fetched {len(snapshot['policies'])} customer-managed policies")
    except Exception as e:
        logger.error(f"list_policies failed: {e}")
        snapshot["_meta"]["warnings"].append(f"list_policies failed: {e}")

    # Optionally: Inline policy bodies (users/groups/roles) — analyze too
    if not fast_mode:
        # Users inline
        for u in snapshot.get("users", []):
            uname = u.get("UserName")
            for pname in u.get("InlinePolicies", []) or []:
                try:
                    pol = iam.get_user_policy(UserName=uname, PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    ext = _analyze_policy_document_extended(doc or {})
                    # attach a synthetic policy entry so UI sees/hints them
                    snapshot["policies"].append({
                        "PolicyName": f"{uname}::INLINE::{pname}",
                        "Arn": None,
                        "Document": doc,
                        "IsRisky": ext["is_risky"],
                        "RiskActions": ext["risky_actions"],
                        "RiskScore": ext["score"],
                        "Findings": ext["findings"],
                        "_inline_of": {"type": "user", "name": uname}
                    })
                except Exception as e:
                    snapshot["_meta"]["warnings"].append(f"user inline policy fetch failed {uname}/{pname}: {e}")

        # Groups inline
        for g in snapshot.get("groups", []):
            gname = g.get("GroupName")
            for pname in g.get("InlinePolicies", []) or []:
                try:
                    pol = iam.get_group_policy(GroupName=gname, PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    ext = _analyze_policy_document_extended(doc or {})
                    snapshot["policies"].append({
                        "PolicyName": f"{gname}::INLINE::{pname}",
                        "Arn": None,
                        "Document": doc,
                        "IsRisky": ext["is_risky"],
                        "RiskActions": ext["risky_actions"],
                        "RiskScore": ext["score"],
                        "Findings": ext["findings"],
                        "_inline_of": {"type": "group", "name": gname}
                    })
                except Exception as e:
                    snapshot["_meta"]["warnings"].append(f"group inline policy fetch failed {gname}/{pname}: {e}")

        # Roles inline
        for r in snapshot.get("roles", []):
            rname = r.get("RoleName")
            for pname in r.get("InlinePolicies", []) or []:
                try:
                    pol = iam.get_role_policy(RoleName=rname, PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    ext = _analyze_policy_document_extended(doc or {})
                    snapshot["policies"].append({
                        "PolicyName": f"{rname}::INLINE::{pname}",
                        "Arn": None,
                        "Document": doc,
                        "IsRisky": ext["is_risky"],
                        "RiskActions": ext["risky_actions"],
                        "RiskScore": ext["score"],
                        "Findings": ext["findings"],
                        "_inline_of": {"type": "role", "name": rname}
                    })
                except Exception as e:
                    snapshot["_meta"]["warnings"].append(f"role inline policy fetch failed {rname}/{pname}: {e}")

    # Propagate risk up
    _propagate_risk(snapshot)

    snapshot["_meta"]["counts"] = {
        "users": len(snapshot.get("users", [])),
        "groups": len(snapshot.get("groups", [])),
        "roles": len(snapshot.get("roles", [])),
        "policies": len(snapshot.get("policies", []))
    }

    # Diff vs previous
    prev = _read_snapshot(out_path)
    diff = {
        "users": _compute_entity_diff(prev.get("users", []) if prev else [], snapshot["users"], "UserName"),
        "groups": _compute_entity_diff(prev.get("groups", []) if prev else [], snapshot["groups"], "GroupName"),
        "roles": _compute_entity_diff(prev.get("roles", []) if prev else [], snapshot["roles"], "RoleName"),
        "policies": _compute_entity_diff(prev.get("policies", []) if prev else [], snapshot["policies"], "PolicyName"),
    }
    diff["counts"] = {
        "added": sum(len(diff[t]["added"]) for t in ["users","groups","roles","policies"]),
        "removed": sum(len(diff[t]["removed"]) for t in ["users","groups","roles","policies"]),
        "modified": sum(len(diff[t]["modified"]) for t in ["users","groups","roles","policies"]),
    }
    diff["impact_score"] = (diff["counts"]["added"] * 2) + (diff["counts"]["modified"] * 1) - (diff["counts"]["removed"] * 1)
    snapshot["_meta"]["diff_details"] = {e: diff[e]["modified_details"] for e in ["users","groups","roles","policies"]}
    snapshot["_meta"]["diff"] = diff

    # Save: latest + versioned copy
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, default=str)
        ts_name = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        ver_path = os.path.join(VERSIONED_DIR, f"iam_snapshot_{ts_name}.json")
        with open(ver_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, default=str)
    except Exception as e:
        snapshot["_meta"]["warnings"].append(f"write_snapshot_failed: {e}")

    return snapshot


if __name__ == "__main__":
    s = fetch_iam_data(fast_mode=False, force_fetch=True)
    print("Fetched counts:", s.get("_meta", {}).get("counts"))
    print("Diff:", s.get("_meta", {}).get("diff", {}).get("counts"))
    print("Impact Score:", s.get("_meta", {}).get("diff", {}).get("impact_score"))

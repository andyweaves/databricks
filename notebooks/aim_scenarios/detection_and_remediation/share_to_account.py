# Databricks notebook source
# DBTITLE 1,Overview
# MAGIC %md
# MAGIC ## Share to Account Users — Detection & Remediation
# MAGIC
# MAGIC This notebook detects and optionally remediates resources that have been shared with the built-in **account users** group — i.e. every user in the Databricks account — in violation of access-control policy.
# MAGIC
# MAGIC Supported resource types:
# MAGIC | Resource | Audit action | ACL resource prefix |
# MAGIC |---|---|---|
# MAGIC | Lakeview dashboards | `changeWorkspaceAcl` | `dashboardsv3/` |
# MAGIC | AI/BI Genie spaces | `changeWorkspaceAcl` | `genie/` or `datarooms/` |
# MAGIC | Databricks Apps | `changeAppsAcl` | *(full ACL JSON)* |
# MAGIC
# MAGIC Workspace metadata is sourced from `system.access.workspaces_latest`. Only workspaces with `status = RUNNING` and belonging to the same account as the audit event are included. Remediation uses a workspace-scoped OAuth token minted from an account-admin service principal — the SP must be a member of each workspace it needs to remediate.

# COMMAND ----------

# DBTITLE 1,Prerequisites & Usage
# MAGIC %md
# MAGIC ### Prerequisites
# MAGIC
# MAGIC - Secret scope **`png-testing`** must contain:
# MAGIC   - `account-id` — Databricks account UUID
# MAGIC   - `sp-client-id` — account-admin service principal client ID
# MAGIC   - `sp-client-secret` — service principal client secret
# MAGIC - The SP must be added to any workspace where you want **remediation** to work (detection works account-wide via the audit log regardless).
# MAGIC
# MAGIC ### Widgets
# MAGIC
# MAGIC | Widget | Description |
# MAGIC |---|---|
# MAGIC | `last_n_days` | How far back to search the audit log (default 30 days). |
# MAGIC | `resource_types` | Comma-separated list of resource types to include: `dashboards`, `genie`, `apps`. Select all three to run a full account sweep. |
# MAGIC | `remediate` | Set to `yes` to automatically remove the 'account users' ACL entry from every detected resource. Defaults to `no` (report-only). |
# MAGIC
# MAGIC ### Output columns
# MAGIC
# MAGIC | Column | Description |
# MAGIC |---|---|
# MAGIC | `resource_type` | `dashboards`, `genie`, or `apps` |
# MAGIC | `resource_id` | UUID or app name of the resource |
# MAGIC | `shared_by` | Email of the user who granted the access |
# MAGIC | `resource_url` | Direct link to the resource in its workspace |
# MAGIC | `auto_remediated` | `True` if access was removed in this session |
# MAGIC | `previously_remediated` | `True` if access was already absent when checked |

# COMMAND ----------

# DBTITLE 1,Dashboards shared to all account users — time-windowed report
from __future__ import annotations

import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import pandas as pd
import requests


# ── Data classes ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RemediationResult:
    workspace_id:  str
    resource_id:   str
    resource_type: str
    success:       bool
    message:       str

    def __str__(self) -> str:
        icon = '✓' if self.success else '✗'
        return f"{icon} [{self.resource_type}] {self.resource_id} (ws={self.workspace_id}): {self.message}"


# ── Auditor class ───────────────────────────────────────────────────────────────

class ResourceShareAuditor:
    """
    Audits and optionally remediates Lakeview dashboards, Genie spaces, and
    Databricks Apps shared with the 'account users' group.

    Workspace metadata is resolved via a SQL join against
    system.access.workspaces_latest.  Remediation mints one workspace-scoped
    OAuth token per workspace in parallel, then removes the offending ACL entry
    per resource in parallel.
    """

    ACCOUNTS_HOST: str = "https://accounts.azuredatabricks.net"

    # Resource type → permissions API path template ({host}/api/2.0/...)
    PERMISSIONS_API: dict[str, str] = {
        "dashboards": "/api/2.0/permissions/dashboards/{id}",
        "genie":      "/api/2.0/permissions/genie/{id}",
        "apps":       "/api/2.0/permissions/apps/{id}",
    }

    def __init__(
        self,
        account_id:    str,
        client_id:     str,
        client_secret: str,
    ) -> None:
        self._account_id    = account_id
        self._client_id     = client_id
        self._client_secret = client_secret
        self._acct_token    = self._mint_account_token()
        self._acct_hdrs     = {"Authorization": f"Bearer {self._acct_token}"}
        self.group_id, self.group_name = self._resolve_group()

    # ── Private helpers ──────────────────────────────────────────────────────────

    def _mint_account_token(self) -> str:
        resp = requests.post(
            f"{self.ACCOUNTS_HOST}/oidc/accounts/{self._account_id}/v1/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type":    "client_credentials",
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
                "scope":         "all-apis",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _resolve_group(self) -> tuple[str, str]:
        filter_q = urllib.parse.quote('displayName co "account users"')
        resp = requests.get(
            f"{self.ACCOUNTS_HOST}/api/2.0/accounts/{self._account_id}/scim/v2/Groups"
            f"?filter={filter_q}&attributes=id,displayName",
            headers=self._acct_hdrs,
        )
        resp.raise_for_status()
        groups = resp.json().get("Resources", [])
        if not groups:
            raise ValueError("Could not find 'account users' group in account SCIM")
        return groups[0]["id"], groups[0]["displayName"]

    def _mint_workspace_token(self, host: str) -> Optional[str]:
        resp = requests.post(
            f"{host}/oidc/v1/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type":    "client_credentials",
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
                "scope":         "all-apis",
            },
        )
        return resp.json().get("access_token") if resp.ok else None

    def _remove_permission(
        self,
        workspace_id:  str,
        host:          str,
        token:         str,
        resource_id:   str,
        resource_type: str,
    ) -> RemediationResult:
        """Remove 'account users' from a resource's ACL.

        Dashboards/Genie use GET → filter → PUT flow.
        Apps use a similar pattern but different response shape.
        """
        path = self.PERMISSIONS_API.get(resource_type, "").format(id=resource_id)
        if not path:
            return RemediationResult(workspace_id, resource_id, resource_type, False, "unknown resource type")

        url  = f"{host}{path}"
        hdrs = {"Authorization": f"Bearer {token}"}

        get_resp = requests.get(url, headers=hdrs)
        if not get_resp.ok:
            return RemediationResult(
                workspace_id, resource_id, resource_type, False,
                f"GET {get_resp.status_code}: {get_resp.text[:200]}",
            )

        data    = get_resp.json()
        acl_key = "access_control_list"
        acl     = data.get(acl_key, [])

        new_acl: list[dict] = []
        removed = False
        for entry in acl:
            principal = {
                k: entry[k]
                for k in ("user_name", "group_name", "service_principal_name")
                if k in entry
            }
            if not principal:
                continue
            if entry.get("group_name") == self.group_name:
                removed = True
                continue
            # Flatten all_permissions (dashboards/genie) or keep permission_level (apps)
            if "all_permissions" in entry:
                for perm in entry["all_permissions"]:
                    if not perm.get("inherited", False):
                        new_acl.append({**principal, "permission_level": perm["permission_level"]})
            elif "permission_level" in entry:
                new_acl.append({**principal, "permission_level": entry["permission_level"]})

        if not removed:
            return RemediationResult(workspace_id, resource_id, resource_type, True, "already removed")

        put_resp = requests.put(url, headers=hdrs, json={acl_key: new_acl})
        return RemediationResult(
            workspace_id, resource_id, resource_type, put_resp.ok,
            "permission removed" if put_resp.ok else f"PUT {put_resp.status_code}: {put_resp.text[:200]}",
        )

    # ── Public API ───────────────────────────────────────────────────────────────

    def query_events(
        self,
        last_n_days:    int,
        resource_types: list[str],
    ) -> pd.DataFrame:
        """Query share events for selected resource types.

        Dashboards and Genie use changeWorkspaceAcl with targetUserId.
        Apps use changeAppsAcl with access_control_list containing group name.
        """
        since    = (datetime.now(timezone.utc) - timedelta(days=last_n_days)).strftime("%Y-%m-%d")
        subqueries: list[str] = []

        # Dashboards
        if "dashboards" in resource_types:
            subqueries.append(f"""
                SELECT
                    'dashboards' AS resource_type,
                    a.event_time,
                    a.event_date,
                    a.workspace_id,
                    w.workspace_name,
                    w.workspace_url,
                    a.user_identity.email                                          AS shared_by,
                    split_part(a.request_params['aclChangeResourceName'], '/', 2) AS resource_id,
                    a.request_params['aclPermissionSet']                           AS permission
                FROM system.access.audit a
                INNER JOIN system.access.workspaces_latest w
                        ON a.workspace_id = w.workspace_id
                       AND a.account_id   = w.account_id
                       AND w.status       = 'RUNNING'
                WHERE a.action_name = 'changeWorkspaceAcl'
                  AND a.request_params['targetUserId'] = '{self.group_id}'
                  AND a.request_params['aclChangeResourceName'] LIKE 'dashboardsv3/%'
                  AND a.request_params['aclPermissionSet'] != ''
                  AND a.event_time >= '{since}'
            """)

        # Genie (both genie/ and datarooms/ prefixes)
        if "genie" in resource_types:
            subqueries.append(f"""
                SELECT
                    'genie' AS resource_type,
                    a.event_time,
                    a.event_date,
                    a.workspace_id,
                    w.workspace_name,
                    w.workspace_url,
                    a.user_identity.email                                          AS shared_by,
                    split_part(a.request_params['aclChangeResourceName'], '/', 2) AS resource_id,
                    a.request_params['aclPermissionSet']                           AS permission
                FROM system.access.audit a
                INNER JOIN system.access.workspaces_latest w
                        ON a.workspace_id = w.workspace_id
                       AND a.account_id   = w.account_id
                       AND w.status       = 'RUNNING'
                WHERE a.action_name = 'changeWorkspaceAcl'
                  AND a.request_params['targetUserId'] = '{self.group_id}'
                  AND (   a.request_params['aclChangeResourceName'] LIKE 'genie/%'
                       OR a.request_params['aclChangeResourceName'] LIKE 'datarooms/%')
                  AND a.request_params['aclPermissionSet'] != ''
                  AND a.event_time >= '{since}'
            """)

        # Apps (different action and detection method)
        if "apps" in resource_types:
            subqueries.append(f"""
                SELECT
                    'apps' AS resource_type,
                    a.event_time,
                    a.event_date,
                    a.workspace_id,
                    w.workspace_name,
                    w.workspace_url,
                    a.user_identity.email                 AS shared_by,
                    a.request_params['request_object_id'] AS resource_id,
                    'CAN_USE'                             AS permission
                FROM system.access.audit a
                INNER JOIN system.access.workspaces_latest w
                        ON a.workspace_id = w.workspace_id
                       AND a.account_id   = w.account_id
                       AND w.status       = 'RUNNING'
                WHERE a.action_name = 'changeAppsAcl'
                  AND a.request_params['access_control_list'] LIKE '%{self.group_name}%'
                  AND a.event_time >= '{since}'
            """)

        if not subqueries:
            return pd.DataFrame()

        sql = " UNION ALL ".join(subqueries) + " ORDER BY event_time DESC"
        df  = spark.sql(sql).toPandas()

        if df.empty:
            return df

        df["group_name"]            = self.group_name
        df["group_id"]              = self.group_id
        df["auto_remediated"]       = False
        df["previously_remediated"] = False

        # Build resource URL per type
        def make_url(row):
            base = row["workspace_url"].rstrip("/") if row.get("workspace_url") else ""
            if row["resource_type"] == "dashboards":
                return f"{base}/dashboardsv3/{row['resource_id']}"
            elif row["resource_type"] == "genie":
                return f"{base}/genie/{row['resource_id']}"
            elif row["resource_type"] == "apps":
                return f"{base}/apps/{row['resource_id']}"
            return ""
        df["resource_url"] = df.apply(make_url, axis=1)

        return df

    def remediate(
        self,
        events:      pd.DataFrame,
        pilot_user:  Optional[str] = None,
        max_workers: int = 8,
    ) -> list[RemediationResult]:
        """Remove 'account users' access from all resources in events."""
        to_process = (
            events[events["shared_by"] == pilot_user].copy()
            if pilot_user else events.copy()
        )
        skipped = len(events) - len(to_process)
        if skipped:
            print(f"  Skipping {skipped} row(s) (pilot guard: '{pilot_user}').")
        if to_process.empty:
            print("  No events to remediate.")
            return []

        # Phase 1 — mint one token per unique workspace
        ws_hosts: dict[str, str] = {
            str(row["workspace_id"]): row["workspace_url"]
            for _, row in to_process.drop_duplicates("workspace_id").iterrows()
            if row.get("workspace_url")
        }
        token_map: dict[str, Optional[str]] = {}
        with ThreadPoolExecutor(max_workers=min(max_workers, len(ws_hosts) or 1)) as pool:
            futures = {
                pool.submit(self._mint_workspace_token, host): ws_id
                for ws_id, host in ws_hosts.items()
            }
            for future in as_completed(futures):
                ws_id = futures[future]
                token = future.result()
                if not token:
                    print(f"  Token mint failed for workspace {ws_id} — SP may not be a member.")
                token_map[ws_id] = token

        # Phase 2 — remove permissions in parallel
        tasks:          list[tuple[str, str, str, str, str]] = []
        early_failures: list[RemediationResult]              = []
        for _, row in to_process.iterrows():
            ws_id  = str(row["workspace_id"])
            res_id = row["resource_id"]
            rtype  = row["resource_type"]
            host   = ws_hosts.get(ws_id)
            token  = token_map.get(ws_id)
            if not host:
                early_failures.append(RemediationResult(ws_id, res_id, rtype, False, "no workspace URL"))
            elif not token:
                early_failures.append(RemediationResult(ws_id, res_id, rtype, False, "token unavailable"))
            else:
                tasks.append((ws_id, host, token, res_id, rtype))

        results: list[RemediationResult] = list(early_failures)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures_map = {
                pool.submit(self._remove_permission, ws_id, host, token, res_id, rtype): None
                for ws_id, host, token, res_id, rtype in tasks
            }
            for future in as_completed(futures_map):
                results.append(future.result())

        for result in sorted(results, key=lambda r: (r.resource_type, r.workspace_id, r.resource_id)):
            print(result)
        return results


# ── Widgets ──────────────────────────────────────────────────────────────────────
dbutils.widgets.text(    "last_n_days", "30",  "Look-back window (days)")
dbutils.widgets.dropdown("remediate",   "no", ["no", "yes"], "Remove account users access")
# resource_types widget created via addQueryParameter tool (multi-select)

LAST_N_DAYS    = int(dbutils.widgets.get("last_n_days"))
REMEDIATE      = dbutils.widgets.get("remediate") == "yes"
RESOURCE_TYPES = dbutils.widgets.get("resource_types").split(",")


# ── Initialise ───────────────────────────────────────────────────────────────────
SCOPE   = "png-testing"
auditor = ResourceShareAuditor(
    account_id    = dbutils.secrets.get(SCOPE, "account-id"),
    client_id     = dbutils.secrets.get(SCOPE, "sp-client-id"),
    client_secret = dbutils.secrets.get(SCOPE, "sp-client-secret"),
)
print(f"Group: '{auditor.group_name}'  (id={auditor.group_id})")
print(f"Resource types: {RESOURCE_TYPES}")

# ── Query & display ──────────────────────────────────────────────────────────────
events = auditor.query_events(LAST_N_DAYS, RESOURCE_TYPES)
print(f"Found {len(events)} share event(s) in the last {LAST_N_DAYS} days.")

# ── Remediate ────────────────────────────────────────────────────────────────────
if REMEDIATE:
    print("\nRemediating...")
    results = auditor.remediate(events)
    result_lookup = {r.resource_id: r for r in results}
    events["auto_remediated"]       = events["resource_id"].map(
        lambda x: result_lookup.get(x, RemediationResult("", "", "", False, "")).success
                  and result_lookup.get(x, RemediationResult("", "", "", False, "")).message == "permission removed"
    )
    events["previously_remediated"] = events["resource_id"].map(
        lambda x: result_lookup.get(x, RemediationResult("", "", "", False, "")).success
                  and result_lookup.get(x, RemediationResult("", "", "", False, "")).message == "already removed"
    )
else:
    print("\nRemediation not enabled — set 'remediate' widget to 'yes' to take action.")

display(events)

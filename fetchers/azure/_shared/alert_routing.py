"""Who an Azure Monitor alert reaches: action groups, their receivers, and alert processing rules that suppress or add them."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional
from urllib.parse import urlsplit

ACTION_GROUP_API = "2023-01-01"
PROCESSING_RULE_API = "2021-08-08"

# 2023-01-01's eleven arrays; any other non-empty "*Receivers" key is reported, not dropped.
RECEIVER_ARRAYS = {
    "emailReceivers": "email",
    "smsReceivers": "sms",
    "voiceReceivers": "voice",
    "webhookReceivers": "webhook",
    "itsmReceivers": "itsm",
    "azureAppPushReceivers": "azure_app_push",
    "automationRunbookReceivers": "automation_runbook",
    "logicAppReceivers": "logic_app",
    "azureFunctionReceivers": "azure_function",
    "armRoleReceivers": "arm_role",
    "eventHubReceivers": "event_hub",
}

SUPPRESS_ALL = "RemoveAllActionGroups"
ADD_GROUPS = "AddActionGroups"

# Windows time-zone names are not resolved; the window is judged with the widest UTC offset.
TZ_SLACK = timedelta(hours=14)


def _phone(receiver: dict) -> Optional[str]:
    number = str(receiver.get("phoneNumber") or "")
    return f"+{receiver.get('countryCode') or '?'} ***{number[-4:]}" if number else None


def receiver_target(kind: str, receiver: dict) -> Optional[str]:
    """Who or what is notified, without the secrets some receivers carry in their URLs."""
    if kind in ("email", "azure_app_push"):
        return receiver.get("emailAddress")
    if kind in ("sms", "voice"):
        return _phone(receiver)
    if kind == "webhook":
        return urlsplit(receiver.get("serviceUri") or "").hostname
    if kind == "logic_app":
        return receiver.get("resourceId")
    if kind == "azure_function":
        name = receiver.get("functionName")
        return f"{receiver.get('functionAppResourceId')}/{name}" if name else receiver.get("functionAppResourceId")
    if kind == "automation_runbook":
        return f"{receiver.get('automationAccountId')}/{receiver.get('runbookName')}"
    if kind == "arm_role":
        return receiver.get("roleId")
    if kind == "itsm":
        return receiver.get("workspaceId")
    if kind == "event_hub":
        return f"{receiver.get('eventHubNameSpace')}/{receiver.get('eventHubName')}"
    return None


def action_group_record(raw: dict) -> dict:
    props = raw.get("properties") or {}
    receivers = []
    for key, kind in RECEIVER_ARRAYS.items():
        for receiver in props.get(key) or []:
            status = receiver.get("status")
            receivers.append({
                "type": kind,
                "name": receiver.get("name"),
                "target": receiver_target(kind, receiver),
                "status": status,
                # Only email and SMS carry a status; "not Enabled" means no communications.
                "enabled": status == "Enabled" if status is not None else True,
            })
    unknown = sorted(k for k, v in props.items() if k.endswith("Receivers") and k not in RECEIVER_ARRAYS and v)
    enabled = props.get("enabled", True) is not False
    live = [r for r in receivers if r["enabled"]]
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "short_name": props.get("groupShortName"),
        "enabled": enabled,
        "receivers": sorted(receivers, key=lambda r: (r["type"], r["name"] or "")),
        "enabled_receiver_count": len(live),
        "unrecognized_receiver_arrays": unknown,
        "deliverable": enabled and bool(live),
    }


def _parse(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def schedule_active(schedule: Optional[dict], now: datetime) -> Optional[bool]:
    """True/False when the window decides it; None when a recurrence or a non-UTC zone leaves it open."""
    if not schedule:
        return True
    zone = str(schedule.get("timeZone") or "UTC").strip().lower()
    slack = timedelta(0) if zone in ("utc", "coordinated universal time") else TZ_SLACK
    start, end = _parse(schedule.get("effectiveFrom")), _parse(schedule.get("effectiveUntil"))
    if end and end + slack < now:
        return False
    if start and start - slack > now:
        return False
    if schedule.get("recurrences"):
        return None
    inside = (not start or start + slack <= now) and (not end or now <= end - slack)
    return True if inside else None


def processing_rule_record(raw: dict, now: datetime) -> dict:
    props = raw.get("properties") or {}
    actions = props.get("actions") or []
    action_types = sorted({a.get("actionType") for a in actions if a.get("actionType")})
    enabled = props.get("enabled", True) is not False
    active = schedule_active(props.get("schedule"), now) if enabled else False
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "enabled": enabled,
        "scopes": props.get("scopes") or [],
        "conditions": props.get("conditions") or [],
        "schedule": props.get("schedule"),
        "action_types": action_types,
        "added_action_group_ids": sorted(
            {g for a in actions if a.get("actionType") == ADD_GROUPS for g in a.get("actionGroupIds") or []}
        ),
        "active_now": active,
        "suppresses_notifications": enabled and SUPPRESS_ALL in action_types,
        "description": props.get("description"),
    }


def _in_scope(rule_scopes: Iterable[str], targets: Iterable[str]) -> bool:
    for scope in rule_scopes:
        prefix = scope.rstrip("/").lower()
        for target in targets:
            t = (target or "").lower()
            if t == prefix or t.startswith(prefix + "/"):
                return True
    return False


def applicable_processing_rules(targets: list[str], rules: list[dict]) -> list[dict]:
    """Enabled processing rules whose scope contains one of the alert's target resources."""
    return [r for r in rules if r["enabled"] and r["active_now"] is not False and _in_scope(r["scopes"], targets)]


def route(enabled: bool, group_ids: list[str], targets: list[str], groups: dict, rules: list[dict]) -> dict:
    """Resolve an alert rule's notification path; `groups` is keyed by lower-cased action group id."""
    applicable = applicable_processing_rules(targets, rules)
    certain = [r for r in applicable if r["active_now"] is True and not r["conditions"]]
    added = sorted({g for r in certain for g in r["added_action_group_ids"]})
    resolved = []
    for gid in sorted(set(group_ids) | set(added), key=str.lower):
        group = groups.get(gid.lower())
        resolved.append({
            "id": gid,
            "found": group is not None,
            "added_by_processing_rule": gid in added and gid not in group_ids,
            "enabled": group["enabled"] if group else None,
            "deliverable": group["deliverable"] if group else None,
            "receivers": [r for r in group["receivers"] if r["enabled"]] if group else [],
        })
    routes = enabled and any(g["deliverable"] for g in resolved)
    suppressors = [r for r in applicable if r["suppresses_notifications"]]
    if any(r in certain for r in suppressors):
        suppressed = True
    elif suppressors:
        suppressed = None
    else:
        suppressed = False
    return {
        "resolved_action_groups": resolved,
        "unresolved_action_group_ids": [g["id"] for g in resolved if not g["found"]],
        "routes_to_enabled_receiver": routes,
        "suppressed_by_processing_rules": [r["id"] for r in suppressors],
        "suppressed": suppressed,
        "reaches_human": (routes and suppressed is False) if enabled else False,
    }


def collect_action_groups(rest, subscription_id: str) -> dict:
    from arm_rest import list_all

    listed = list_all(rest, f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/actionGroups", ACTION_GROUP_API)
    return {"groups": [action_group_record(g) for g in listed["items"]], "pages": listed["pages"]}


def fetch_action_group(rest, group_id: str) -> dict:
    """One action group by id, for a reference into another subscription."""
    from arm_rest import get_json

    return action_group_record(get_json(rest, f"{group_id}?api-version={ACTION_GROUP_API}"))


def add_referenced_groups(rest, group_ids: Iterable[str], groups: dict, collector) -> None:
    """Fetch groups referenced from another subscription; 403/404 leave them unresolved, anything else is a failure."""
    for gid in sorted({g for g in group_ids if g}, key=str.lower):
        if gid.lower() in groups:
            continue
        try:
            groups[gid.lower()] = fetch_action_group(rest, gid)
        except Exception as exc:  # noqa: BLE001 — out-of-scope groups are expected, not failures
            if getattr(exc, "status_code", None) not in (403, 404):
                collector.record(f"actionGroups GET ({gid})", exc)


def collect_processing_rules(rest, subscription_id: str, now: datetime) -> dict:
    from arm_rest import list_all

    listed = list_all(
        rest, f"/subscriptions/{subscription_id}/providers/Microsoft.AlertsManagement/actionRules", PROCESSING_RULE_API
    )
    return {"rules": [processing_rule_record(r, now) for r in listed["items"]], "pages": listed["pages"]}

"""Projections of azure-mgmt-monitor 6.x diagnostic-settings models, shared by the Azure fetchers."""

from __future__ import annotations

from azure_common import basename, model_attr

DESTINATION_STORAGE_ACCOUNT = "storage_account"
DESTINATION_LOG_ANALYTICS = "log_analytics_workspace"
DESTINATION_EVENT_HUB = "event_hub"
DESTINATION_PARTNER_SOLUTION = "partner_solution"

CATEGORY_TYPE_LOGS = "Logs"
CATEGORY_TYPE_METRICS = "Metrics"


def resource_uri(resource_id: str) -> str:
    """The SDK substitutes this unquoted after a "/", so a leading slash doubles it."""
    return (resource_id or "").lstrip("/")


def project_category(category) -> dict:
    """One `DiagnosticSettingsCategoryResource` (6.x flattens `properties`)."""
    return {
        "name": model_attr(category, "name"),
        "category_type": model_attr(category, "category_type"),
        "category_groups": list(model_attr(category, "category_groups") or []),
    }


def project_diagnostic_setting(setting) -> dict:
    """One `DiagnosticSettingsResource`; exactly one of category / category_group per log."""
    setting_id = model_attr(setting, "id")
    return {
        "id": setting_id,
        "name": model_attr(setting, "name") or basename(setting_id),
        "storage_account_id": model_attr(setting, "storage_account_id"),
        "workspace_id": model_attr(setting, "workspace_id"),
        "event_hub_name": model_attr(setting, "event_hub_name"),
        "event_hub_authorization_rule_id": model_attr(setting, "event_hub_authorization_rule_id"),
        "marketplace_partner_id": model_attr(setting, "marketplace_partner_id"),
        "log_analytics_destination_type": model_attr(setting, "log_analytics_destination_type"),
        "logs": [
            {
                "category": model_attr(log, "category"),
                "category_group": model_attr(log, "category_group"),
                # ARM omits `enabled` on a category never selected; absent means off.
                "enabled": bool(model_attr(log, "enabled") or False),
            }
            for log in (model_attr(setting, "logs") or [])
        ],
    }


def destinations(setting: dict) -> list[str]:
    """Sinks in use, in a stable order; ARM returns "" as well as null for an unused one."""
    found = []
    if setting.get("storage_account_id"):
        found.append(DESTINATION_STORAGE_ACCOUNT)
    if setting.get("workspace_id"):
        found.append(DESTINATION_LOG_ANALYTICS)
    if setting.get("event_hub_authorization_rule_id") or setting.get("event_hub_name"):
        found.append(DESTINATION_EVENT_HUB)
    if setting.get("marketplace_partner_id"):
        found.append(DESTINATION_PARTNER_SOLUTION)
    return found


def enabled_categories(logs: list[dict]) -> list[str]:
    return sorted({log["category"] for log in logs if log["enabled"] and log["category"]})


def enabled_category_groups(logs: list[dict]) -> list[str]:
    return sorted({log["category_group"] for log in logs if log["enabled"] and log["category_group"]})

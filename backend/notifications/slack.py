"""
notifications/slack.py
───────────────────────
Outbound-only Slack webhook notifications.
NO data is received from Slack — this is a one-way push.

Only finding summaries (title, severity, URL) are sent.
Raw HTTP request/response bodies NEVER leave the machine.
"""

import httpx
from backend.config import settings
from backend.models import Finding


# ── Severity → Slack colour mapping ─────────────────────
SEVERITY_COLORS = {
    "critical": "#B03A2E",
    "high":     "#E67E22",
    "medium":   "#F1C40F",
    "low":      "#2ECC71",
    "info":     "#3498DB",
}

SEVERITY_EMOJI = {
    "critical": "🚨",
    "high":     "⚠️",
    "medium":   "🔶",
    "low":      "🔷",
    "info":     "ℹ️",
}


async def notify_critical_finding(finding: Finding, target_url: str) -> None:
    """
    Send an immediate Slack alert when a critical or high finding is discovered.
    Includes a link to the local dashboard to view full evidence.
    """
    if not settings.slack_configured():
        return

    emoji = SEVERITY_EMOJI.get(finding.severity, "⚠️")
    color = SEVERITY_COLORS.get(finding.severity, "#888888")

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"{emoji} *{finding.severity.upper()} finding detected*\n"
                                f"*Target:* `{target_url}`\n"
                                f"*Module:* `{finding.module}`\n"
                                f"*Finding:* {finding.title}"
                            ),
                        },
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "View Finding Now"},
                                "url": (
                                    f"http://localhost:{settings.FRONTEND_PORT}"
                                    f"/scan/{finding.scan_id}"
                                ),
                                "style": "danger",
                            }
                        ],
                    },
                ],
            }
        ]
    }

    await _send(payload)


async def notify_scan_complete(
    target_url: str,
    scan_id: str,
    counts: dict,
) -> None:
    """
    Send a scan completion summary to Slack.
    Includes finding counts by severity and a link to the dashboard.
    """
    if not settings.slack_configured():
        return

    total = counts.get("total", 0)
    status_emoji = "✅" if counts.get("critical", 0) == 0 else "🚨"

    summary_lines = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(sev, 0)
        if count > 0:
            e = SEVERITY_EMOJI.get(sev, "")
            summary_lines.append(f"{e} *{sev.capitalize()}:* {count}")

    summary_text = "\n".join(summary_lines) if summary_lines else "No findings."

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Scan Complete — {total} finding(s)",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target_url}`"},
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary_text},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Full Report"},
                        "url": (
                            f"http://localhost:{settings.FRONTEND_PORT}"
                            f"/scan/{scan_id}"
                        ),
                    }
                ],
            },
        ]
    }

    await _send(payload)


# ─────────────────────────────────────────────────────────
#  Internal
# ─────────────────────────────────────────────────────────

async def _send(payload: dict) -> None:
    """Fire the webhook. Silently ignore failures (non-blocking)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(settings.SLACK_WEBHOOK_URL, json=payload)
    except Exception:
        pass

"""Shared helpers: config, metrics, alerts, and loop protection."""
import json
import os
from datetime import datetime, timezone

import boto3

DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")
SELF_ROLE_NAME = os.environ.get("SELF_ROLE_NAME", "")

_sns = boto3.client("sns") if TOPIC_ARN else None


def env_list(name, default=""):
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def utcnow():
    return datetime.now(timezone.utc)


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def seconds_between(start, end):
    if not start or not end:
        return None
    return round((end - start).total_seconds(), 1)


def action_status():
    return "dry_run" if DRY_RUN else "remediated"


def emit(scenario, action, status, event_time=None, **fields):
    """Print one JSON line per decision. CloudWatch Logs Insights parses these
    automatically, which is where the time-to-remediate numbers come from."""
    now = utcnow()
    record = {
        "metric": "remediation",
        "scenario": scenario,
        "action": action,
        "status": status,
        "dry_run": DRY_RUN,
        "event_time": event_time,
        "handled_at": now.isoformat(),
        "seconds_to_remediate": seconds_between(parse_ts(event_time), now),
        **fields,
    }
    print(json.dumps(record, default=str))
    return record


def notify(subject, record):
    if _sns:
        _sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=subject[:99],
            Message=json.dumps(record, indent=2, default=str),
        )


def is_self_invoked(detail):
    """Ignore API calls made by this responder, so a fix never re-triggers itself."""
    arn = (detail.get("userIdentity") or {}).get("arn", "")
    return bool(SELF_ROLE_NAME) and f":assumed-role/{SELF_ROLE_NAME}/" in arn

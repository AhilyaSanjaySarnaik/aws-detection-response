"""Respond to attempts to blind audit logging.

Trigger: CloudTrail StopLogging / DeleteTrail / UpdateTrail / PutEventSelectors.
StopLogging is reversed automatically. The others are alert-only: silently
rolling back a trail's configuration could fight a legitimate admin change.
"""
import boto3

from common import action_status, emit, is_self_invoked, notify, DRY_RUN

SCENARIO = "cloudtrail_tampering"


def _client_for(trail):
    # A trail ARN carries its home region; StartLogging must be called there.
    if trail.startswith("arn:"):
        return boto3.client("cloudtrail", region_name=trail.split(":")[3])
    return boto3.client("cloudtrail")


def handler(event, context):
    detail = event.get("detail", {})
    event_time = detail.get("eventTime")
    event_name = detail.get("eventName")

    if detail.get("errorCode") or is_self_invoked(detail):
        return

    trail = (detail.get("requestParameters") or {}).get("name") or (
        (detail.get("requestParameters") or {}).get("trailName")
    )
    context_fields = {
        "trail": trail,
        "trigger": event_name,
        "actor": (detail.get("userIdentity") or {}).get("arn"),
        "source_ip": detail.get("sourceIPAddress"),
    }

    if event_name != "StopLogging" or not trail:
        record = emit(SCENARIO, "alert_only", "alert_only", event_time, **context_fields)
        notify(f"[ALERT] CloudTrail {event_name} on {trail}", record)
        return

    try:
        if not DRY_RUN:
            _client_for(trail).start_logging(Name=trail)
        record = emit(SCENARIO, "restarted_logging", action_status(), event_time, **context_fields)
        notify(f"[REMEDIATED] CloudTrail logging restarted on {trail}", record)
    except Exception as exc:
        record = emit(SCENARIO, "restart_logging", "failed", event_time, error=str(exc), **context_fields)
        notify(f"[FAILED] Could not restart CloudTrail logging on {trail}", record)
        raise

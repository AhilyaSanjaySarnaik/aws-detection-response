"""Contain compromised credentials reported by GuardDuty.

Trigger: GuardDuty findings at or above the configured severity.
- Long-term IAM user key (AKIA...): deactivate the key.
- Assumed role (e.g. stolen EC2 instance credentials): attach a deny-all policy
  for sessions issued before now, which invalidates the stolen session.
- Root, sample findings, protected roles, other finding types: alert only.
"""
import json

import boto3

from common import action_status, emit, env_list, notify, parse_ts, seconds_between, utcnow, DRY_RUN
from logic import DEFAULT_ACTIONABLE_PREFIXES, is_actionable_finding, is_protected_role, revoke_sessions_policy

SCENARIO = "compromised_credentials"
PROTECTED_ROLES = env_list("PROTECTED_ROLE_NAMES")
PROTECTED_PREFIXES = env_list("PROTECTED_ROLE_PREFIXES")
ACTIONABLE_PREFIXES = tuple(env_list("ACTIONABLE_PREFIXES")) or DEFAULT_ACTIONABLE_PREFIXES

iam = boto3.client("iam")


def handler(event, context):
    finding = event.get("detail", {})
    service = finding.get("service") or {}
    key = (finding.get("resource") or {}).get("accessKeyDetails") or {}

    finding_type = finding.get("type", "")
    user_type = key.get("userType")
    user_name = key.get("userName")
    key_id = key.get("accessKeyId", "")
    first_seen = service.get("eventFirstSeen")
    created_at = finding.get("createdAt")
    is_sample = (service.get("additionalInfo") or {}).get("sample") is True

    fields = {
        "finding_id": finding.get("id"),
        "finding_type": finding_type,
        "severity": finding.get("severity"),
        "user_type": user_type,
        "user_name": user_name,
        "access_key_id": key_id,
        # How long GuardDuty took to raise the finding after the first bad API call
        "detection_seconds": seconds_between(parse_ts(first_seen), parse_ts(created_at)),
    }

    action, status, reason = "alert_only", "alert_only", None
    try:
        if is_sample:
            reason = "sample finding"
        elif not is_actionable_finding(finding_type, ACTIONABLE_PREFIXES):
            reason = "finding type not configured for automatic response"
        elif user_type == "Root":
            reason = "root credentials: respond manually"
        elif user_type == "IAMUser" and key_id.startswith("AKIA"):
            if not DRY_RUN:
                iam.update_access_key(UserName=user_name, AccessKeyId=key_id, Status="Inactive")
            action, status = "deactivated_access_key", action_status()
        elif user_type == "AssumedRole" and user_name:
            if is_protected_role(user_name, PROTECTED_ROLES, PROTECTED_PREFIXES):
                reason = "protected role"
            else:
                issued_before = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                if not DRY_RUN:
                    iam.put_role_policy(
                        RoleName=user_name,
                        PolicyName="RevokeOlderSessions",
                        PolicyDocument=json.dumps(revoke_sessions_policy(issued_before)),
                    )
                action, status = "revoked_role_sessions", action_status()
                fields["sessions_issued_before"] = issued_before
        else:
            reason = "no supported credential in finding"
    except Exception as exc:
        record = emit(SCENARIO, action, "failed", first_seen, error=str(exc), **fields)
        notify(f"[FAILED] Credential response for {finding_type}", record)
        raise

    record = emit(SCENARIO, action, status, first_seen, reason=reason, **fields)
    label = "REMEDIATED" if status in ("remediated", "dry_run") else "ALERT"
    notify(f"[{label}] GuardDuty {finding_type}", record)

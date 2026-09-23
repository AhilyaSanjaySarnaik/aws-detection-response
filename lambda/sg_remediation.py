"""Revoke security group rules that open sensitive ports to the internet.

Trigger: CloudTrail AuthorizeSecurityGroupIngress / ModifySecurityGroupRules.
Rather than parsing the request (which varies by API), it re-reads the group's
current rules and removes every one that exposes a sensitive port.
"""
import boto3

from common import action_status, emit, env_list, is_self_invoked, notify, DRY_RUN
from logic import exposes_sensitive_port, find_key

SCENARIO = "sg_open_to_internet"
SENSITIVE_PORTS = [int(p) for p in env_list("SENSITIVE_PORTS", "22,3389")]

ec2 = boto3.client("ec2")


def handler(event, context):
    detail = event.get("detail", {})
    event_time = detail.get("eventTime")

    if detail.get("errorCode") or is_self_invoked(detail):
        return

    group_id = find_key(detail.get("requestParameters"), {"groupId", "GroupId"}) or find_key(
        detail.get("responseElements"), {"groupId", "GroupId"}
    )
    if not group_id:
        emit(SCENARIO, "none", "skipped", event_time, reason="no group id in event")
        return

    try:
        rules = []
        for page in ec2.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [group_id]}]
        ):
            rules.extend(page["SecurityGroupRules"])

        bad = [r for r in rules if exposes_sensitive_port(r, SENSITIVE_PORTS)]
        if not bad:
            emit(SCENARIO, "none", "no_action", event_time, group_id=group_id)
            return

        rule_ids = [r["SecurityGroupRuleId"] for r in bad]
        if not DRY_RUN:
            ec2.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=rule_ids)

        record = emit(
            SCENARIO,
            "revoked_ingress_rules",
            action_status(),
            event_time,
            group_id=group_id,
            rule_ids=rule_ids,
            actor=(detail.get("userIdentity") or {}).get("arn"),
            source_ip=detail.get("sourceIPAddress"),
        )
        notify(f"[REMEDIATED] Internet-exposed port closed on {group_id}", record)
    except Exception as exc:
        record = emit(SCENARIO, "revoke_ingress_rules", "failed", event_time, group_id=group_id, error=str(exc))
        notify(f"[FAILED] Could not close exposed port on {group_id}", record)
        raise

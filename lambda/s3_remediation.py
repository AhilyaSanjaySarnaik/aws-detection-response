"""Lock down S3 buckets that were made public or backdoored to another account.

Trigger: CloudTrail PutBucketPolicy / PutBucketAcl / DeleteBucketPublicAccessBlock.
Actions: re-enable Block Public Access, then strip any policy statement that
grants access outside this account (or explicitly trusted accounts).
"""
import json

import boto3
from botocore.exceptions import ClientError

from common import action_status, emit, env_list, is_self_invoked, notify, DRY_RUN
from logic import split_policy

SCENARIO = "s3_exposure"
PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
TRUSTED_ACCOUNTS = env_list("TRUSTED_ACCOUNT_IDS")
EXCLUDED_BUCKETS = set(env_list("EXCLUDED_BUCKETS"))

s3 = boto3.client("s3")


def _error_code(exc):
    return exc.response.get("Error", {}).get("Code", "")


def handler(event, context):
    detail = event.get("detail", {})
    event_time = detail.get("eventTime")

    if detail.get("errorCode") or is_self_invoked(detail):
        return

    bucket = (detail.get("requestParameters") or {}).get("bucketName")
    if not bucket or bucket in EXCLUDED_BUCKETS:
        return

    own_account = context.invoked_function_arn.split(":")[4]
    actions = []

    try:
        # 1. Block Public Access
        try:
            config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if _error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                raise
            config = {}
        if not all(config.get(key) for key in PAB_KEYS):
            if not DRY_RUN:
                s3.put_public_access_block(
                    Bucket=bucket,
                    PublicAccessBlockConfiguration={key: True for key in PAB_KEYS},
                )
            actions.append("enabled_block_public_access")

        # 2. Cross-account / public policy statements
        removed = []
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        except ClientError as exc:
            if _error_code(exc) != "NoSuchBucketPolicy":
                raise
            policy = None
        if policy:
            keep, removed = split_policy(policy, own_account, TRUSTED_ACCOUNTS)
            if removed:
                if not DRY_RUN:
                    if keep:
                        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({**policy, "Statement": keep}))
                    else:
                        s3.delete_bucket_policy(Bucket=bucket)
                actions.append(f"removed_{len(removed)}_policy_statements")

        if not actions:
            emit(SCENARIO, "none", "no_action", event_time, bucket=bucket, trigger=detail.get("eventName"))
            return

        record = emit(
            SCENARIO,
            "+".join(actions),
            action_status(),
            event_time,
            bucket=bucket,
            trigger=detail.get("eventName"),
            removed_statements=removed,
            actor=(detail.get("userIdentity") or {}).get("arn"),
            source_ip=detail.get("sourceIPAddress"),
        )
        notify(f"[REMEDIATED] S3 bucket {bucket} locked down", record)
    except Exception as exc:
        record = emit(SCENARIO, "lock_down_bucket", "failed", event_time, bucket=bucket, error=str(exc))
        notify(f"[FAILED] Could not lock down S3 bucket {bucket}", record)
        raise

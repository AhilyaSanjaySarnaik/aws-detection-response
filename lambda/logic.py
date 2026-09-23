"""Decision logic for the responders.

Nothing in this module calls AWS, so every rule about *what* counts as
dangerous can be unit tested without an account. The handlers only decide
*how* to apply the result.
"""

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

# Condition keys that tie a "*" principal back to a specific account or org.
# A statement using one of these is scoped, not public.
ACCOUNT_SCOPING_KEYS = {
    "aws:principalaccount",
    "aws:principalorgid",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourceowner",
}


def find_key(obj, names):
    """Return the first string value for any key in `names`, searching nested dicts/lists.

    CloudTrail puts the same field in different places depending on the API
    (e.g. `groupId` vs `ModifySecurityGroupRulesRequest.GroupId`).
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in names and isinstance(value, str):
                return value
            found = find_key(value, names)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_key(item, names)
            if found:
                return found
    return None


# ---------------------------------------------------------------- security groups

def exposes_sensitive_port(rule, sensitive_ports):
    """True if an ingress rule opens a sensitive port (or all ports) to the whole internet."""
    if rule.get("IsEgress"):
        return False
    cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
    if cidr not in OPEN_CIDRS:
        return False
    if rule.get("IpProtocol") == "-1":  # all protocols, all ports
        return True
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if low is None or high is None:
        return False
    if low == -1:  # ICMP "all types"; not a port range
        return False
    return any(low <= port <= high for port in sensitive_ports)


# ---------------------------------------------------------------- S3 bucket policies

def principal_accounts(principal):
    """Accounts referenced by a policy Principal. '*' means anyone.

    Service and Federated principals return an empty list: they are not
    another AWS account and are left alone.
    """
    if principal == "*":
        return ["*"]
    if not isinstance(principal, dict):
        return []
    aws = principal.get("AWS")
    if aws is None:
        return []
    values = aws if isinstance(aws, list) else [aws]
    accounts = []
    for value in values:
        if value == "*":
            accounts.append("*")
        elif value.isdigit() and len(value) == 12:
            accounts.append(value)
        elif value.startswith("arn:"):
            parts = value.split(":")
            accounts.append(parts[4] if len(parts) > 4 and parts[4] else "*")
        else:
            # Unknown format (e.g. a unique ID left behind by a deleted principal).
            # Treated as untrusted: better to flag it than silently keep it.
            accounts.append("*")
    return accounts


def condition_scopes_to_account(condition):
    if not isinstance(condition, dict):
        return False
    for operator_block in condition.values():
        if isinstance(operator_block, dict):
            if any(key.lower() in ACCOUNT_SCOPING_KEYS for key in operator_block):
                return True
    return False


def is_untrusted_grant(statement, own_account, trusted_accounts):
    """True if an Allow statement grants access outside our own/trusted accounts."""
    if statement.get("Effect") != "Allow":
        return False
    if "NotPrincipal" in statement:
        # Allow + NotPrincipal = everyone except a few principals.
        return True
    trusted = {own_account, *trusted_accounts}
    for account in principal_accounts(statement.get("Principal")):
        if account == "*":
            if not condition_scopes_to_account(statement.get("Condition")):
                return True
        elif account not in trusted:
            return True
    return False


def split_policy(policy, own_account, trusted_accounts=()):
    """Split a bucket policy into (statements to keep, statements to remove)."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    keep, remove = [], []
    for statement in statements:
        if is_untrusted_grant(statement, own_account, trusted_accounts):
            remove.append(statement)
        else:
            keep.append(statement)
    return keep, remove


# ---------------------------------------------------------------- GuardDuty / IAM

DEFAULT_ACTIONABLE_PREFIXES = (
    "UnauthorizedAccess:IAMUser/",
    "CredentialAccess:IAMUser/",
    "Exfiltration:IAMUser/",
    "Impact:IAMUser/",
    "Persistence:IAMUser/",
    "PrivilegeEscalation:IAMUser/",
)

PROTECTED_ROLE_PREFIXES = ("AWSServiceRoleFor", "AWSReservedSSO_", "OrganizationAccountAccessRole")


def is_actionable_finding(finding_type, prefixes=DEFAULT_ACTIONABLE_PREFIXES):
    return any(finding_type.startswith(prefix) for prefix in prefixes)


def is_protected_role(role_name, protected_names=(), protected_prefixes=()):
    if role_name in protected_names:
        return True
    return role_name.startswith(tuple(PROTECTED_ROLE_PREFIXES) + tuple(protected_prefixes))


def revoke_sessions_policy(issued_before_iso):
    """Inline policy that denies everything to sessions issued before a timestamp.

    This is the standard way to kill stolen temporary credentials: they can't be
    deactivated like access keys, but they can be made useless. New sessions
    (e.g. the instance legitimately refreshing its role) still work.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RevokeOlderSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": issued_before_iso}},
            }
        ],
    }

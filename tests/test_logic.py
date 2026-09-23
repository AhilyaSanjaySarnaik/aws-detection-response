from logic import (
    exposes_sensitive_port,
    find_key,
    is_actionable_finding,
    is_protected_role,
    revoke_sessions_policy,
    split_policy,
)

OWN = "111111111111"
OTHER = "222222222222"
PORTS = [22, 3389]


def rule(**kw):
    base = {"IsEgress": False, "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv4": "0.0.0.0/0"}
    base.update(kw)
    return base


# ---------------------------------------------------------------- security groups

def test_ssh_open_to_world_is_flagged():
    assert exposes_sensitive_port(rule(), PORTS)


def test_ipv6_open_is_flagged():
    assert exposes_sensitive_port(rule(CidrIpv4=None, CidrIpv6="::/0"), PORTS)


def test_port_range_covering_ssh_is_flagged():
    assert exposes_sensitive_port(rule(FromPort=20, ToPort=25), PORTS)


def test_all_traffic_is_flagged():
    assert exposes_sensitive_port(rule(IpProtocol="-1", FromPort=-1, ToPort=-1), PORTS)


def test_https_open_is_allowed():
    assert not exposes_sensitive_port(rule(FromPort=443, ToPort=443), PORTS)


def test_restricted_cidr_is_allowed():
    assert not exposes_sensitive_port(rule(CidrIpv4="203.0.113.10/32"), PORTS)


def test_egress_is_ignored():
    assert not exposes_sensitive_port(rule(IsEgress=True), PORTS)


def test_icmp_is_ignored():
    assert not exposes_sensitive_port(rule(IpProtocol="icmp", FromPort=-1, ToPort=-1), PORTS)


# ---------------------------------------------------------------- bucket policies

def stmt(principal, effect="Allow", **kw):
    return {"Effect": effect, "Principal": principal, "Action": "s3:GetObject", "Resource": "*", **kw}


def test_own_account_is_kept():
    keep, remove = split_policy({"Statement": [stmt({"AWS": f"arn:aws:iam::{OWN}:root"})]}, OWN)
    assert len(keep) == 1 and not remove


def test_external_account_is_removed():
    keep, remove = split_policy({"Statement": [stmt({"AWS": f"arn:aws:iam::{OTHER}:root"})]}, OWN)
    assert not keep and len(remove) == 1


def test_bare_account_id_is_understood():
    _, remove = split_policy({"Statement": [stmt({"AWS": OTHER})]}, OWN)
    assert len(remove) == 1


def test_trusted_external_account_is_kept():
    keep, _ = split_policy({"Statement": [stmt({"AWS": OTHER})]}, OWN, [OTHER])
    assert len(keep) == 1


def test_public_wildcard_is_removed():
    _, remove = split_policy({"Statement": [stmt("*")]}, OWN)
    assert len(remove) == 1


def test_wildcard_scoped_by_source_account_is_kept():
    s = stmt({"AWS": "*"}, Condition={"StringEquals": {"aws:SourceAccount": OWN}})
    keep, _ = split_policy({"Statement": [s]}, OWN)
    assert len(keep) == 1


def test_service_principal_is_kept():
    keep, _ = split_policy({"Statement": [stmt({"Service": "cloudtrail.amazonaws.com"})]}, OWN)
    assert len(keep) == 1


def test_deny_statements_are_kept():
    keep, _ = split_policy({"Statement": [stmt("*", effect="Deny")]}, OWN)
    assert len(keep) == 1


def test_allow_with_not_principal_is_removed():
    s = {"Effect": "Allow", "NotPrincipal": {"AWS": OWN}, "Action": "s3:*", "Resource": "*"}
    _, remove = split_policy({"Statement": [s]}, OWN)
    assert len(remove) == 1


def test_mixed_principal_list_is_removed():
    _, remove = split_policy({"Statement": [stmt({"AWS": [OWN, OTHER]})]}, OWN)
    assert len(remove) == 1


def test_single_statement_dict_is_handled():
    keep, remove = split_policy({"Statement": stmt({"AWS": OTHER})}, OWN)
    assert not keep and len(remove) == 1


# ---------------------------------------------------------------- misc

def test_find_key_nested():
    event = {"ModifySecurityGroupRulesRequest": {"GroupId": "sg-123"}}
    assert find_key(event, {"groupId", "GroupId"}) == "sg-123"


def test_find_key_in_list():
    event = {"securityGroupRuleSet": {"items": [{"groupId": "sg-456"}]}}
    assert find_key(event, {"groupId"}) == "sg-456"


def test_actionable_findings():
    assert is_actionable_finding("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS")
    assert not is_actionable_finding("Recon:EC2/PortProbeUnprotectedPort")


def test_protected_roles():
    assert is_protected_role("AWSServiceRoleForAmazonGuardDuty")
    assert is_protected_role("admin", protected_names=["admin"])
    assert is_protected_role("cdr-sg_remediation", protected_prefixes=["cdr-"])
    assert not is_protected_role("stratus-role")


def test_revoke_policy_shape():
    statement = revoke_sessions_policy("2026-01-01T00:00:00Z")["Statement"][0]
    assert statement["Effect"] == "Deny"
    assert statement["Condition"]["DateLessThan"]["aws:TokenIssueTime"] == "2026-01-01T00:00:00Z"

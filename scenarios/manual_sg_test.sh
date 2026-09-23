#!/usr/bin/env bash
# Quick test without Stratus: open SSH to the world on a throwaway security group
# and watch the responder close it.
set -euo pipefail
: "${AWS_REGION:?Set AWS_REGION}"

VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
SG_ID=$(aws ec2 create-security-group --group-name cdr-manual-test-$RANDOM \
  --description "cdr manual test" --vpc-id "$VPC_ID" --query GroupId --output text)
echo "Created $SG_ID; opening port 22 to 0.0.0.0/0 at $(date -u +%H:%M:%SZ)"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null

for i in $(seq 1 30); do
  sleep 10
  OPEN=$(aws ec2 describe-security-group-rules --filters Name=group-id,Values="$SG_ID" \
    --query "length(SecurityGroupRules[?IsEgress==\`false\` && FromPort==\`22\`])" --output text)
  if [[ "$OPEN" == "0" ]]; then
    echo "Rule removed after ~$((i * 10))s"
    break
  fi
  echo "Still open after $((i * 10))s..."
done

aws ec2 delete-security-group --group-id "$SG_ID"
echo "Deleted $SG_ID"

#!/usr/bin/env bash
# Detonate real attack techniques with Stratus Red Team, give the pipeline time
# to respond, then clean up. Run from a SANDBOX account only.
#
# Usage: ./scenarios/run_scenarios.sh            # the three fast scenarios
#        ./scenarios/run_scenarios.sh --with-credentials   # adds the slow GuardDuty one
set -euo pipefail

WAIT_SECONDS="${WAIT_SECONDS:-300}"

TECHNIQUES=(
  "aws.exfiltration.ec2-security-group-open-port-22-ingress"
  "aws.exfiltration.s3-backdoor-bucket-policy"
  "aws.defense-evasion.cloudtrail-stop"
)

if [[ "${1:-}" == "--with-credentials" ]]; then
  # Launches an EC2 instance and uses its role credentials from outside AWS.
  # GuardDuty can take 15+ minutes to raise the finding.
  TECHNIQUES+=("aws.credential-access.ec2-steal-instance-credentials")
  WAIT_SECONDS="${WAIT_SECONDS_CREDENTIALS:-1200}"
fi

command -v stratus >/dev/null || { echo "Install Stratus Red Team first: https://github.com/DataDog/stratus-red-team"; exit 1; }
: "${AWS_REGION:?Set AWS_REGION to the region you deployed into (e.g. eu-west-1)}"

for technique in "${TECHNIQUES[@]}"; do
  echo "=================================================="
  echo "Detonating: $technique  ($(date -u +%H:%M:%SZ))"
  echo "=================================================="
  stratus detonate "$technique"

  echo "Waiting ${WAIT_SECONDS}s for detection and response..."
  sleep "$WAIT_SECONDS"

  # Cleanup may report errors when the pipeline has already undone the change.
  # That is expected; the resources are still destroyed.
  stratus cleanup "$technique" || echo "Cleanup reported an error (often expected after remediation)."
done

echo
echo "Done. Measure results with queries/logs_insights.txt in CloudWatch Logs Insights."

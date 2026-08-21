#!/usr/bin/env bash
# Run the static and live scanners, saving output for your findings writeups.
set -euo pipefail

OUT="scan-results/$(date +%Y-%m-%d-%H%M)"
mkdir -p "$OUT"

echo "==> Checkov (static: scans Terraform, no AWS account needed)"
checkov -d terraform/vulnerable --output cli --output json \
  --output-file-path "$OUT/checkov" || true

echo "==> tfsec (static, second opinion)"
tfsec terraform/vulnerable --format json > "$OUT/tfsec.json" || true

echo "==> Prowler (live: requires deployed infrastructure + credentials)"
if [ "${RUN_PROWLER:-0}" = "1" ]; then
  prowler aws --output-directory "$OUT/prowler" --output-formats json-ocsf csv || true
else
  echo "    skipped. Deploy first, then: RUN_PROWLER=1 ./scripts/scan.sh"
fi

echo
echo "Results in $OUT"
echo "Two scanners disagreeing is a FINDING, not a problem. Write it up."

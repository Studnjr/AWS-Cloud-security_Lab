# AWS-001 — S3 bucket readable and enumerable by anonymous users

> **This is a worked example**, written to show the standard to aim for. Replace
> the placeholder ARNs and outputs with your own once you've deployed and
> scanned. Don't submit this as-is — the value is in doing it yourself.

| | |
|---|---|
| **Finding ID** | AWS-001 |
| **Severity** | Critical |
| **Status** | Open |
| **Affected resource** | `arn:aws:s3:::cloudsec-lab-customer-data-a1b2c3d4` |
| **CIS AWS Benchmark** | 2.1.5 |
| **MITRE ATT&CK** | T1530 — Data from Cloud Storage Object |
| **Detected by** | Prowler `s3_bucket_public_access`, confirmed manually |
| **Date** | 2026-03-14 |

---

## 1. Summary

The `customer-data` bucket grants `s3:GetObject` and `s3:ListBucket` to
`Principal: "*"`, and all four S3 Public Access Block protections are disabled.
Any person on the internet, with no AWS account and no credentials, can list
every object in the bucket and download all of them.

The `ListBucket` grant is what makes this Critical rather than High: without it
an attacker must guess object keys, but with it they receive a complete index.

## 2. Evidence

Scanner output:

```bash
prowler aws --check s3_bucket_public_access --output-formats json-ocsf
```

```
FAIL  s3_bucket_public_access
      Bucket cloudsec-lab-customer-data-a1b2c3d4 has public access enabled
      Severity: critical
```

Independent confirmation with no credentials at all — note the `--no-sign-request`
flag, which is what makes this proof rather than a claim:

```bash
aws s3 ls s3://cloudsec-lab-customer-data-a1b2c3d4 --no-sign-request
```

```
2026-03-14 09:12:44       2847 exports/customers-2026-Q1.csv
2026-03-14 09:12:44        193 README.txt
```

Public Access Block state:

```bash
aws s3api get-public-access-block --bucket cloudsec-lab-customer-data-a1b2c3d4
```

```json
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": false,
    "IgnorePublicAcls": false,
    "BlockPublicPolicy": false,
    "RestrictPublicBuckets": false
  }
}
```

## 3. Reproduction

1. From a machine with no AWS credentials configured, run the `--no-sign-request`
   listing above. It returns the object index.
2. Download any listed object:
   `aws s3 cp s3://<bucket>/exports/customers-2026-Q1.csv . --no-sign-request`
3. The same is reachable over plain HTTPS with no tooling:
   `curl https://<bucket>.s3.amazonaws.com/exports/customers-2026-Q1.csv`

Step 3 matters because it means exploitation requires no AWS knowledge
whatsoever — a browser is sufficient.

## 4. Impact

- **Confidentiality:** total loss for all current and future objects. Objects
  added later inherit the policy; this is not a one-time exposure.
- **Reachability:** anonymous internet. No account, no credentials, no rate
  limiting on discovery.
- **Discovery:** S3 bucket names are globally unique and heavily enumerated.
  Public wordlist-based bucket scanners run continuously. Assume any public
  bucket is found within hours, not months.
- **Chaining:** exposed files frequently contain credentials, internal
  hostnames, or employee data usable for phishing. The bucket contents
  determine whether this stops at data loss or becomes initial access.

Real-world grounding: publicly exposed S3 buckets have been the root cause of
numerous large disclosures, and the pattern is common enough that AWS changed
the platform default in April 2023 to block public access on new buckets.

## 5. Remediation

Immediate — re-enable Public Access Block. This overrides both ACLs and bucket
policy, so it is the correct first action even before the policy is cleaned up:

```hcl
resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

Then remove the public statements from the bucket policy entirely, rather than
relying on Public Access Block alone — defence in depth, and it means the
exposure doesn't return if someone disables PAB later.

Verify:

```bash
aws s3 ls s3://<bucket> --no-sign-request
# expected: An error occurred (AccessDenied)
```

## 6. Operational impact of the fix

**This will break anything currently consuming the bucket anonymously.**

Before applying, check CloudTrail data events (or S3 server access logs, if
enabled) for the last 30 days to identify legitimate anonymous readers. Static
website hosting and public asset delivery are real use cases that look identical
to this finding at the config level.

If public read genuinely is required, the correct pattern is CloudFront with
Origin Access Control in front of a private bucket — that gives public delivery
without a public bucket, plus caching and logging.

Rollback is immediate: reverting the PAB settings restores prior behaviour.

Ordering note: apply this during business hours despite it being a security fix.
An access-denied outage discovered at 2am is worse than four more hours of
exposure on a bucket that has likely already been found.

## 7. Detection & evasion

**Log source:** CloudTrail S3 **data events** — not management events. This
distinction matters and is a common gap: data events are **off by default** and
cost extra, so most accounts have no record of object-level reads at all. If
data events aren't enabled, this bucket could be fully exfiltrated with zero
evidence.

**Detection logic:** alert on `GetObject` / `ListBucket` where
`userIdentity.type` is `AWSAccount` with no principal, or where the request is
unsigned — that is the anonymous access signature.

Also alert on the *configuration change itself*:
`PutBucketPublicAccessBlock` and `PutBucketPolicy` where the resulting policy
contains `"Principal": "*"`. Detecting the misconfiguration being introduced is
much cheaper than detecting its exploitation.

**False positives:** legitimate public asset buckets. Maintain an allowlist of
bucket ARNs approved for public read, and alert on anything outside it. Without
that allowlist this detection is unusable in a large account.

**Evasion:** an attacker who reads the bucket over plain HTTPS rather than the
AWS API still generates data events, but one who obtains the object list *once*
and then downloads slowly from many source IPs will defeat volume-threshold
detections. Rate-based rules should key on the bucket, not the source IP.

## 8. References

- AWS — Blocking public access to your Amazon S3 storage
- AWS — Amazon S3 default configuration change, April 2023
- CIS Amazon Web Services Foundations Benchmark, control 2.1.5
- MITRE ATT&CK T1530

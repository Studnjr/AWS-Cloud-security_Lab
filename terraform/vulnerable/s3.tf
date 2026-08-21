# ===========================================================================
# FINDING AWS-001 : Publicly readable S3 bucket
# FINDING AWS-002 : No encryption at rest
# FINDING AWS-003 : No versioning (no recovery from deletion/ransomware)
# FINDING AWS-004 : No access logging (no forensic trail)
#
# CIS AWS Foundations: 2.1.1, 2.1.2, 2.1.5
# MITRE ATT&CK:        T1530 (Data from Cloud Storage Object)
#
# There are FOUR independent mechanisms that can make an S3 bucket public, and
# understanding why there are four is most of the S3 security learning:
#
#   1. Bucket ACL              - legacy, pre-dates IAM policies
#   2. Object ACL              - per-object, survives bucket policy changes
#   3. Bucket policy           - resource-based IAM policy
#   4. Public Access Block     - the override that blocks 1-3
#
# Public Access Block is the important one. Since April 2023 AWS enables it by
# default on new buckets, which is why this file has to EXPLICITLY DISABLE it
# to create the vulnerability. That default change is a good thing to be able
# to talk about: it means "public bucket" findings in 2026 usually indicate
# someone actively turned protection off, not that they forgot to turn it on.
# ===========================================================================

resource "aws_s3_bucket" "customer_data" {
  bucket = "${var.project_name}-customer-data-${random_id.suffix.hex}"

  # Lets `terraform destroy` remove the bucket even if you put objects in it.
  # Convenient for a lab, dangerous in production.
  force_destroy = true
}

# VULNERABILITY: all four guardrails disabled.
resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULNERABILITY: bucket policy grants s3:GetObject to Principal "*".
# Anonymous, unauthenticated, whole internet.
resource "aws_s3_bucket_policy" "customer_data_public" {
  bucket = aws_s3_bucket.customer_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "${aws_s3_bucket.customer_data.arn}/*"
      },
      {
        # Worse than GetObject alone. ListBucket lets an anonymous user
        # ENUMERATE every key. Without it an attacker must guess filenames;
        # with it they get an index. When you write the finding, explain why
        # this single extra permission changes the severity.
        Sid       = "AllowPublicList"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:ListBucket"]
        Resource  = aws_s3_bucket.customer_data.arn
      }
    ]
  })

  # A public-access-block change and a policy change race each other. AWS will
  # reject the policy if PAB is still on, so force the ordering.
  depends_on = [aws_s3_bucket_public_access_block.customer_data]
}

# VULNERABILITY (by omission): no aws_s3_bucket_server_side_encryption_configuration.
# Note that S3 has applied SSE-S3 by default since January 2023, so this is now
# a weaker finding than it used to be. Worth checking what the scanner says
# versus what is actually true in the console -- scanner findings are not
# automatically correct, and noticing that is a genuinely good portfolio moment.

# VULNERABILITY (by omission): no aws_s3_bucket_versioning.
# Without versioning, an attacker (or ransomware) that deletes or overwrites
# objects leaves you no recovery path.

# VULNERABILITY (by omission): no aws_s3_bucket_logging.
# If this bucket is exfiltrated you will have no record of who read what.
# CloudTrail data events are the alternative, and they are off by default too.

# ---------------------------------------------------------------------------
# A second bucket that is NOT public, for comparison. Having a correct example
# alongside the broken one makes your scanner output far easier to interpret,
# and proves your scanning is finding real issues rather than flagging
# everything.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "internal_logs" {
  bucket        = "${var.project_name}-internal-logs-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "internal_logs" {
  bucket = aws_s3_bucket.internal_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "internal_logs" {
  bucket = aws_s3_bucket.internal_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "internal_logs" {
  bucket = aws_s3_bucket.internal_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

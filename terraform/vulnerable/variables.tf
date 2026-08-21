variable "aws_region" {
  description = "Region for the lab. Keep everything in one region to simplify teardown."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for all resource names, so you can find and delete them."
  type        = string
  default     = "cloudsec-lab"
}

# ---------------------------------------------------------------------------
# COST GUARDRAIL
#
# false (default) => only free-tier resources are created: S3, IAM, VPC,
#                    security groups, CloudTrail. Safe to leave applied
#                    briefly while you work.
#
# true            => also creates RDS and EC2. These cost money outside the
#                    12-month free tier, and free-tier limits are easy to
#                    exceed. Flip this on only while working the RDS/EC2
#                    findings, and run `terraform destroy` the same day.
# ---------------------------------------------------------------------------
variable "enable_billable_resources" {
  description = "Create RDS and EC2. Costs money. Read SAFETY.md first."
  type        = bool
  default     = false
}

variable "lab_owner" {
  description = "Your name/handle. Tagged on every resource so orphans are traceable."
  type        = string
  default     = "unset"
}

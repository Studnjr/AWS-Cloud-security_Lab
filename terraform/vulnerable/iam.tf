# ===========================================================================
# FINDING AWS-010 : IAM policy with wildcard Action and Resource
# FINDING AWS-011 : Long-lived access keys instead of roles
# FINDING AWS-012 : Role trust policy allows any AWS principal (confused deputy)
# FINDING AWS-013 : Privilege escalation path via iam:PassRole + ec2:RunInstances
#
# CIS AWS Foundations: 1.15, 1.16, 1.4
# MITRE ATT&CK:        T1078.004 (Valid Accounts: Cloud), T1098.001, T1548
#
# IAM is where you should spend the most time in this project. Network
# misconfigurations are easy to see and easy to explain. IAM misconfigurations
# are subtle, compose in surprising ways, and are how most real cloud breaches
# actually progress. If you can explain an IAM privilege escalation chain in an
# interview, you are ahead of most candidates at any level.
# ===========================================================================

# ---------------------------------------------------------------------------
# AWS-010 / AWS-011 : the classic "we'll fix permissions later" service user
# ---------------------------------------------------------------------------
resource "aws_iam_user" "app_service" {
  name = "${var.project_name}-app-service"
}

# VULNERABILITY: a long-lived access key. Roles with temporary credentials are
# the correct answer for anything running inside AWS. Static keys leak into
# git repos, CI logs, Docker images, and Slack messages -- this is consistently
# one of the most common initial access vectors in real cloud incidents.
#
# NOTE: the generated secret lands in terraform.tfstate IN PLAINTEXT. This is
# a real property of Terraform worth understanding, not a bug in this lab.
# Never commit state. See .gitignore.
resource "aws_iam_access_key" "app_service" {
  user = aws_iam_user.app_service.name
}

# VULNERABILITY: Action "*" on Resource "*". This is AdministratorAccess by
# another name, attached to a service account that probably needed to read one
# S3 bucket.
resource "aws_iam_user_policy" "app_service_admin" {
  name = "app-service-full-access"
  user = aws_iam_user.app_service.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "GodMode"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# AWS-012 : role that anyone in AWS can assume
# ---------------------------------------------------------------------------
resource "aws_iam_role" "partner_integration" {
  name = "${var.project_name}-partner-integration"

  # VULNERABILITY: Principal AWS = "*" means ANY AWS account on earth can call
  # sts:AssumeRole against this. Attackers scan for exactly this.
  #
  # The correct pattern is a specific partner account ARN PLUS an ExternalId
  # condition. Explaining the confused deputy problem -- why the account ARN
  # alone is insufficient when the partner serves multiple customers -- is an
  # excellent thing to write up in this finding.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "partner_integration" {
  name = "partner-read"
  role = aws_iam_role.partner_integration.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket", "iam:ListRoles", "iam:GetRole"]
        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# AWS-013 : privilege escalation via PassRole
#
# This is the most interesting finding in the lab. Nothing below is a wildcard.
# Every scanner will rate these permissions LOW or MEDIUM individually. Chained
# together they are a full path to administrator, and no static scanner will
# tell you that.
#
# The chain:
#   1. Attacker holds the "developer" permissions below.
#   2. ec2:RunInstances + iam:PassRole lets them launch an instance and attach
#      the admin role in ec2_admin_role.
#   3. They put a user-data script on that instance that reads the instance
#      metadata service and exfiltrates the role's temporary credentials.
#   4. They are now administrator.
#
# Demonstrating this manually, then writing it up with the CloudTrail evidence
# each step produces, is the single strongest artifact you can produce from
# this project. It shows you can reason about permission COMPOSITION, which is
# what actually separates cloud security people from checklist runners.
# ---------------------------------------------------------------------------
resource "aws_iam_user" "developer" {
  name = "${var.project_name}-developer"
}

resource "aws_iam_user_policy" "developer_escalation" {
  name = "developer-compute-access"
  user = aws_iam_user.developer.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LooksReasonable"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:DescribeInstances",
          "ec2:DescribeImages",
          "ec2:CreateTags",
          "iam:ListRoles",
          "iam:ListInstanceProfiles",
          "iam:GetInstanceProfile"
        ]
        Resource = "*"
      },
      {
        # THE ACTUAL PROBLEM. Unscoped PassRole means "attach any role you can
        # name to any service you can launch". Scoping Resource to a specific,
        # low-privilege role ARN closes this.
        Sid      = "UnscopedPassRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*"
      }
    ]
  })
}

# The privileged role the developer can pass. In a real account this exists for
# perfectly good reasons -- which is exactly why the escalation works.
resource "aws_iam_role" "ec2_admin_role" {
  name = "${var.project_name}-ec2-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_admin_role" {
  role       = aws_iam_role.ec2_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "ec2_admin" {
  name = "${var.project_name}-ec2-admin-profile"
  role = aws_iam_role.ec2_admin_role.name
}

# ---------------------------------------------------------------------------
# No password policy configured (CIS 1.8-1.11). Another omission finding.
# ---------------------------------------------------------------------------

output "access_key_id" {
  description = "Access key for the over-privileged service user."
  value       = aws_iam_access_key.app_service.id
}

output "access_key_secret" {
  description = "Retrieve with: terraform output -raw access_key_secret"
  value       = aws_iam_access_key.app_service.secret
  sensitive   = true
}

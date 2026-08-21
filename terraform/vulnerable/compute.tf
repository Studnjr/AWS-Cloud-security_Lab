# ===========================================================================
# BILLABLE RESOURCES — created only when enable_billable_resources = true
#
# FINDING AWS-030 : RDS publicly accessible
# FINDING AWS-031 : RDS storage not encrypted
# FINDING AWS-032 : Hardcoded database credentials in source
# FINDING AWS-033 : Backups disabled
# FINDING AWS-034 : EC2 instance metadata service v1 permitted (SSRF -> creds)
#
# CIS AWS Foundations: 2.3.1, 2.3.2, 2.3.3
# MITRE ATT&CK:        T1552.005 (Cloud Instance Metadata API), T1530
#
# Read SAFETY.md before flipping the flag. Destroy the same day.
# ===========================================================================

resource "aws_db_subnet_group" "lab" {
  count = var.enable_billable_resources ? 1 : 0

  name       = "${var.project_name}-db-subnets"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
}

resource "aws_db_instance" "app_database" {
  count = var.enable_billable_resources ? 1 : 0

  identifier     = "${var.project_name}-appdb"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro" # free-tier eligible for 12 months

  allocated_storage = 20
  db_name           = "appdb"

  # VULNERABILITY AWS-032: credentials committed to version control. In a real
  # environment this belongs in Secrets Manager or SSM Parameter Store, and
  # even then the value would land in terraform.tfstate. This is a genuinely
  # hard problem and worth writing up honestly rather than pretending
  # Secrets Manager solves it completely.
  username = "admin"
  password = "SuperSecret123!"

  # VULNERABILITY AWS-030: reachable from the internet.
  publicly_accessible = true
  db_subnet_group_name = aws_db_subnet_group.lab[0].name
  vpc_security_group_ids = [aws_security_group.database.id]

  # VULNERABILITY AWS-031: no encryption at rest.
  storage_encrypted = false

  # VULNERABILITY AWS-033: no backups.
  backup_retention_period = 0

  # No deletion protection, no final snapshot -- convenient for a lab so that
  # `terraform destroy` actually works, dangerous in production.
  deletion_protection = false
  skip_final_snapshot = true

  tags = { Name = "${var.project_name}-appdb" }
}

# ---------------------------------------------------------------------------
# AWS-034 : EC2 with IMDSv1 enabled
#
# This is the instance you use to demonstrate the PassRole escalation chain in
# iam.tf, and it is also the Capital One breach in miniature: SSRF in an app,
# unauthenticated read of 169.254.169.254, temporary role credentials
# exfiltrated.
#
# IMDSv2 requires a PUT to obtain a session token first, which breaks the SSRF
# path because most SSRF primitives can only issue GETs. Being able to explain
# that mechanism precisely is a strong interview answer.
# ---------------------------------------------------------------------------
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "web" {
  count = var.enable_billable_resources ? 1 : 0

  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_a.id
  vpc_security_group_ids = [aws_security_group.web_server.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_admin.name

  # VULNERABILITY: http_tokens = "optional" permits IMDSv1.
  # Setting it to "required" enforces IMDSv2 and is the fix.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  # VULNERABILITY: root volume unencrypted.
  root_block_device {
    encrypted = false
  }

  tags = { Name = "${var.project_name}-web" }
}

output "rds_endpoint" {
  value = var.enable_billable_resources ? aws_db_instance.app_database[0].endpoint : "not created"
}

output "ec2_public_ip" {
  value = var.enable_billable_resources ? aws_instance.web[0].public_ip : "not created"
}

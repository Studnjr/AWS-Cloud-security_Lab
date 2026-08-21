# ===========================================================================
# FINDING AWS-020 : Security group allows SSH (22) from 0.0.0.0/0
# FINDING AWS-021 : Security group allows RDP (3389) from 0.0.0.0/0
# FINDING AWS-022 : Database port exposed to the internet
# FINDING AWS-023 : VPC Flow Logs not enabled
#
# CIS AWS Foundations: 5.2, 5.3, 3.9
# MITRE ATT&CK:        T1190 (Exploit Public-Facing Application),
#                      T1110 (Brute Force)
#
# Ties directly back to the SSH brute-force detection work: this security group
# is the *cause* of the alert. Being able to trace an alert back to the
# misconfiguration that enabled it, and then fix the misconfiguration in code,
# is the full loop that cloud security roles are actually asking for.
# ===========================================================================

resource "aws_vpc" "lab" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.project_name}-igw" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.50.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.50.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-b" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# AWS-020 / AWS-021 : the "temporarily open for debugging" security group
# ---------------------------------------------------------------------------
resource "aws_security_group" "web_server" {
  name        = "${var.project_name}-web-sg"
  description = "INTENTIONALLY INSECURE - lab only"
  vpc_id      = aws_vpc.lab.id

  # Legitimate.
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: SSH from the entire internet. Expect brute-force traffic
  # within minutes of this going live -- which, if you enable CloudTrail and
  # VPC Flow Logs, gives you genuine attack telemetry for free. That is a real
  # dataset you can point detections at, and it beats synthetic data.
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: RDP from the entire internet.
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: unrestricted egress. Less obviously bad than open ingress,
  # and most environments run this way, so think carefully before you rate it.
  # It matters for exfiltration and C2, and a good writeup explains why it is
  # a real finding while acknowledging it is near-universal. Knowing which
  # findings to de-prioritise is as valuable as knowing which to raise.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-web-sg" }
}

# ---------------------------------------------------------------------------
# AWS-022 : database reachable from the internet
# ---------------------------------------------------------------------------
resource "aws_security_group" "database" {
  name        = "${var.project_name}-db-sg"
  description = "INTENTIONALLY INSECURE - lab only"
  vpc_id      = aws_vpc.lab.id

  # VULNERABILITY: MySQL open to the world. Should reference the web server's
  # security group ID as its source, not a CIDR block. Security-group-to-
  # security-group references are the idiomatic AWS answer and worth knowing.
  ingress {
    description = "MySQL from anywhere"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-db-sg" }
}

# VULNERABILITY (by omission): AWS-023, no aws_flow_log on the VPC.
# Without flow logs there is no record of network connections -- no way to
# answer "what did the attacker talk to" after an incident. Flow logs to
# CloudWatch cost money per GB ingested; flow logs to S3 are cheaper. This is
# a deliberate omission you should FIX in the remediated version and write up
# the cost tradeoff, because that tradeoff is why it is missing in real
# environments too.

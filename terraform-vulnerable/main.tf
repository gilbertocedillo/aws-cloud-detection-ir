# ============================================================
# VULNERABLE stack - INTENTIONALLY MISCONFIGURED for detection/scanner demos.
# DO NOT APPLY in a real account. Each issue is numbered SEC-0x and the
# terraform-secure/ stack contains the fix with the same number.
# ============================================================
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
provider "aws" { region = var.aws_region }

data "aws_vpc" "default" { default = true }
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter { name = "name", values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"] }
}

# --- SEC-01 VULN: Public S3 bucket ---
resource "aws_s3_bucket" "data" {
  bucket = "${var.project_name}-data-vuln"
}
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read" # SEC-01: anyone on the internet can read objects
}
# SEC-01: NO aws_s3_bucket_public_access_block resource exists here.

# --- SEC-02 VULN: SSH open to the world ---
resource "aws_security_group" "web" {
  name   = "${var.project_name}-web-vuln"
  vpc_id = data.aws_vpc.default.id
  ingress {
    description = "SSH from anywhere - SEC-02"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- SEC-04 VULN: IAM wildcard policy ---
resource "aws_iam_policy" "wildcard" {
  name = "${var.project_name}-wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "WildcardAdmin"
      Effect   = "Allow"
      Action   = "*" # SEC-04: full wildcard actions
      Resource = "*" # SEC-04: on all resources
    }]
  })
}
resource "aws_iam_role" "app" {
  name = "${var.project_name}-app-vuln"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy_attachment" "wildcard" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.wildcard.arn
}
resource "aws_iam_instance_profile" "app" {
  name = "${var.project_name}-app-vuln"
  role = aws_iam_role.app.name
}

resource "aws_instance" "web" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  # SEC-03 VULN: unencrypted root volume; IMDSv2 also not enforced (no metadata_options)
  root_block_device {
    encrypted   = false # SEC-03
    volume_type = "gp3"
    volume_size = 20
  }
  tags = { Name = "${var.project_name}-web-vuln" }
}

# --- SEC-05 VULN: No CloudTrail, no GuardDuty ---
# There is deliberately NO aws_cloudtrail and NO aws_guardduty_detector in this
# stack: API activity is not logged and managed threat detection is off, so
# DET-01..DET-08 in the companion repo have nothing to detect with.

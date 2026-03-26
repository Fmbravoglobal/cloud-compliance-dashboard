terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
provider "aws" { region = var.aws_region }

resource "aws_s3_bucket" "compliance_reports" {
  bucket = "${var.prefix}-compliance-reports"
  tags = { Project = "cloud-compliance-dashboard" }
}

resource "aws_s3_bucket_public_access_block" "compliance_reports" {
  bucket                  = aws_s3_bucket.compliance_reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "compliance_key" {
  description         = "KMS key for compliance dashboard"
  enable_key_rotation = true
  tags = { Project = "cloud-compliance-dashboard" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.compliance_key.arn
    }
  }
}

resource "aws_dynamodb_table" "compliance_findings" {
  name         = "${var.prefix}-compliance-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "resource_id"
  range_key    = "evaluated_at"

  attribute {
    name = "resource_id"
    type = "S"
  }
  attribute {
    name = "evaluated_at"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.compliance_key.arn
  }

  tags = { Project = "cloud-compliance-dashboard" }
}

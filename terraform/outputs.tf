output "compliance_bucket" {
  value = aws_s3_bucket.compliance_reports.bucket
}
output "findings_table" {
  value = aws_dynamodb_table.compliance_findings.name
}

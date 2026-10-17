## ReportForge infrastructure (excerpt) — Terraform

resource "aws_instance" "reportforge" {
  ami           = "ami-0abc123"
  instance_type = "t3.small"
  iam_instance_profile = aws_iam_instance_profile.reportforge.name

  metadata_options {
    # [AppSec: http_tokens = "optional" means IMDSv1 is still accepted.
    #  Noted, but the instance isn't directly internet-facing. Rated LOW.]
    #Changing the "Optional" to "Required"
    http_tokens                 = "required"
    #Changing limit from 2 to 1
    http_put_response_hop_limit = 1
  }
}

# The instance role the app runs as.
resource "aws_iam_role_policy" "reportforge" {
  name = "reportforge-s3"
  role = aws_iam_role.reportforge.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # REMEDIATION (Least Privilege / CWE-269): the app only READS templates,
        # so it must not hold s3:PutObject. Removing write access means stolen
        # credentials cannot plant a malicious template — this alone severs the
        # chain even if the deserialization sink were left vulnerable.
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::reportforge-config-prod",
          "arn:aws:s3:::reportforge-config-prod/*"
        ]
      }
    ]
  })
}

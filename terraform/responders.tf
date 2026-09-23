# One Lambda + one IAM role + one EventBridge rule per responder.
# Each role gets only the permissions its own responder needs.
# env/statements/pattern are stored as JSON strings so every entry has the
# same type, which for_each requires.

locals {
  trail_bucket_name = var.create_trail ? aws_s3_bucket.trail[0].id : ""

  responders = {
    sg_remediation = {
      handler     = "sg_remediation.handler"
      description = "Revokes security group rules exposing sensitive ports to the internet"
      env = jsonencode({
        SENSITIVE_PORTS = join(",", [for p in var.sensitive_ports : tostring(p)])
      })
      statements = jsonencode([
        {
          Effect   = "Allow"
          Action   = ["ec2:DescribeSecurityGroupRules"]
          Resource = "*"
        },
        {
          Effect   = "Allow"
          Action   = ["ec2:RevokeSecurityGroupIngress"]
          Resource = "arn:${local.partition}:ec2:${var.region}:${local.account_id}:security-group/*"
        },
      ])
      pattern = jsonencode({
        source        = ["aws.ec2"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
        }
      })
    }

    s3_remediation = {
      handler     = "s3_remediation.handler"
      description = "Re-enables Block Public Access and strips cross-account bucket policy grants"
      env = jsonencode({
        TRUSTED_ACCOUNT_IDS = join(",", var.trusted_account_ids)
        EXCLUDED_BUCKETS    = local.trail_bucket_name
      })
      statements = jsonencode([
        {
          Effect = "Allow"
          Action = [
            "s3:GetBucketPublicAccessBlock",
            "s3:PutBucketPublicAccessBlock",
            "s3:GetBucketPolicy",
            "s3:PutBucketPolicy",
            "s3:DeleteBucketPolicy",
          ]
          Resource = "arn:${local.partition}:s3:::*"
        },
      ])
      pattern = jsonencode({
        source        = ["aws.s3"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          eventName   = ["PutBucketPolicy", "PutBucketAcl", "DeleteBucketPublicAccessBlock"]
        }
      })
    }

    cloudtrail_remediation = {
      handler     = "cloudtrail_remediation.handler"
      description = "Restarts stopped CloudTrail logging and alerts on trail tampering"
      env         = jsonencode({})
      statements = jsonencode([
        {
          Effect   = "Allow"
          Action   = ["cloudtrail:StartLogging"]
          Resource = "arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"
        },
      ])
      pattern = jsonencode({
        source        = ["aws.cloudtrail"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["cloudtrail.amazonaws.com"]
          eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
        }
      })
    }

    credential_response = {
      handler     = "credential_response.handler"
      description = "Deactivates leaked access keys and revokes stolen role sessions from GuardDuty findings"
      env = jsonencode({
        PROTECTED_ROLE_NAMES    = join(",", var.protected_role_names)
        PROTECTED_ROLE_PREFIXES = "${var.project}-"
      })
      statements = jsonencode([
        {
          Effect   = "Allow"
          Action   = ["iam:UpdateAccessKey"]
          Resource = "arn:${local.partition}:iam::${local.account_id}:user/*"
        },
        {
          Effect   = "Allow"
          Action   = ["iam:PutRolePolicy"]
          Resource = "arn:${local.partition}:iam::${local.account_id}:role/*"
        },
      ])
      pattern = jsonencode({
        source        = ["aws.guardduty"]
        "detail-type" = ["GuardDuty Finding"]
        detail = {
          severity = [{ numeric = [">=", var.min_guardduty_severity] }]
        }
      })
    }
  }
}

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/build/lambda.zip"
  excludes    = ["__pycache__"]
}

resource "aws_iam_role" "responder" {
  for_each = local.responders
  name     = "${var.project}-${each.key}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "responder" {
  for_each          = local.responders
  name              = "/aws/lambda/${var.project}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role_policy" "responder" {
  for_each = local.responders
  name     = "responder"
  role     = aws_iam_role.responder[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(jsondecode(each.value.statements), [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.responder[each.key].arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
    ])
  })
}

resource "aws_lambda_function" "responder" {
  for_each         = local.responders
  function_name    = "${var.project}-${each.key}"
  description      = each.value.description
  role             = aws_iam_role.responder[each.key].arn
  handler          = each.value.handler
  runtime          = "python3.12"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = merge(jsondecode(each.value.env), {
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
      DRY_RUN         = tostring(var.dry_run)
      SELF_ROLE_NAME  = aws_iam_role.responder[each.key].name
    })
  }

  depends_on = [
    aws_cloudwatch_log_group.responder,
    aws_iam_role_policy.responder,
  ]
}

resource "aws_cloudwatch_event_rule" "responder" {
  for_each      = local.responders
  name          = "${var.project}-${each.key}"
  description   = each.value.description
  event_pattern = each.value.pattern
}

resource "aws_cloudwatch_event_target" "responder" {
  for_each = local.responders
  rule     = aws_cloudwatch_event_rule.responder[each.key].name
  arn      = aws_lambda_function.responder[each.key].arn
}

resource "aws_lambda_permission" "eventbridge" {
  for_each      = local.responders
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.responder[each.key].arn
}

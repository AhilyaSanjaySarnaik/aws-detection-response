output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "responder_functions" {
  value = { for k, f in aws_lambda_function.responder : k => f.function_name }
}

output "responder_log_groups" {
  description = "Select these in CloudWatch Logs Insights to measure time to remediate."
  value       = [for g in aws_cloudwatch_log_group.responder : g.name]
}

output "trail_bucket" {
  value = var.create_trail ? aws_s3_bucket.trail[0].id : null
}

output "dry_run" {
  value = var.dry_run
}

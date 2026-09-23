variable "region" {
  description = "Region to deploy into. Detection and response only cover this region."
  type        = string
  default     = "eu-west-1"
}

variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "cdr"
}

variable "alert_email" {
  description = "Email address for alerts. You must confirm the subscription email AWS sends."
  type        = string
}

variable "dry_run" {
  description = "If true, responders log and alert but change nothing. Start with true."
  type        = bool
  default     = true
}

variable "create_trail" {
  description = "Create a CloudTrail trail. Required for EventBridge to receive API-call events. Set false if the account already has one (a second trail is billed)."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Create a GuardDuty detector. Set false if GuardDuty is already enabled in this region."
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub (extra cost after the free trial)."
  type        = bool
  default     = false
}

variable "sensitive_ports" {
  description = "Ports that must never be open to 0.0.0.0/0 or ::/0."
  type        = list(number)
  default     = [22, 3389]
}

variable "min_guardduty_severity" {
  description = "Minimum GuardDuty severity routed to the credential responder (4 = Medium)."
  type        = number
  default     = 4
}

variable "trusted_account_ids" {
  description = "Other AWS accounts allowed in bucket policies."
  type        = list(string)
  default     = []
}

variable "protected_role_names" {
  description = "IAM roles the credential responder must never modify (e.g. your admin role)."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  type    = number
  default = 14
}

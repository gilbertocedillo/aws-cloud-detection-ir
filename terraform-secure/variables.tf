variable "aws_region"   { type = string, default = "us-east-1" }
variable "project_name" { type = string, default = "cloud-ir-lab" }
variable "operator_ip"  { type = string, default = "203.0.113.10/32", description = "Your IP /32 for scoped admin access" }

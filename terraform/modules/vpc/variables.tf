variable "name_prefix" {
  description = "Prefix applied to the Name tag of every resource in this module"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC"
  type        = string
}

variable "subnet_cidr" {
  description = "CIDR block for the single public subnet"
  type        = string
}

variable "management_ingress_cidrs" {
  description = <<-EOT
    Source CIDRs allowed to reach SSH, RDP and WinRM. Instruqt's virtual browser
    and Guacamole containers have no stable egress range, so the lab default is
    0.0.0.0/0. Narrow this if you run the stack outside Instruqt.
  EOT
  type        = list(string)
}

variable "common_tags" {
  description = "Tags merged into every resource in this module"
  type        = map(string)
}

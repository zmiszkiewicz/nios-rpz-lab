variable "name_prefix" {
  description = "Prefix applied to the Name tag of every resource in this module"
  type        = string
}

variable "ubuntu_ami_name_filter" {
  description = "AMI name filter for the base image"
  type        = string
  default     = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
}

variable "instance_type" {
  description = "EC2 instance type. The host only runs dig, so keep it tiny."
  type        = string
  default     = "t3.micro"
}

variable "private_ip" {
  description = "Static private IP for the unmanaged host"
  type        = string
}

variable "public_resolver" {
  description = "Public DNS service the host uses instead of the Grid Master"
  type        = string
  default     = "8.8.8.8"
}

variable "fallback_resolver" {
  description = "Second public resolver, so the bypass is not a single point of failure"
  type        = string
  default     = "1.1.1.1"
}

variable "gm_private_ip" {
  description = <<-EOT
    Grid Master LAN1 address. Baked into the host's use-corporate-dns.sh helper
    so the participant can switch it onto the governed resolver in one command.
  EOT
  type        = string
}

variable "subnet_id" {
  description = "Subnet for the host's ENI"
  type        = string
}

variable "security_group_id" {
  description = "Security group applied to the host's ENI"
  type        = string
}

variable "key_name" {
  description = "EC2 key pair name for SSH access"
  type        = string
}

variable "common_tags" {
  description = "Tags merged into every resource in this module"
  type        = map(string)
}

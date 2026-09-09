variable "name_prefix" {
  description = "Prefix applied to the Name tag of every resource in this module"
  type        = string
}

variable "niosx_ami_id" {
  description = <<-EOT
    AMI ID of the privately shared Infoblox NIOS-X image, not the AWS
    Marketplace listing. Required at module level; the root module carries the
    default.
  EOT
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.niosx_ami_id))
    error_message = "niosx_ami_id must look like ami-0123456789abcdef0."
  }
}

variable "niosx_instance_type" {
  description = "EC2 instance type for the NIOS-X host. m5.large is the documented minimum."
  type        = string
  default     = "m5.large"
}

variable "join_token" {
  description = <<-EOT
    Infoblox CSP join token. Handed to cloud-init and used once, at first boot,
    to register the host against the tenant that issued it. Sensitive: it is a
    credential for that tenant.
  EOT
  type        = string
  sensitive   = true
}

variable "private_ip" {
  description = <<-EOT
    Static private IP for the NIOS-X host. This doubles as the resolver address
    baked into the desktop at boot, so changing it changes what the desktop
    queries.
  EOT
  type        = string
}

variable "subnet_id" {
  description = "Subnet for the NIOS-X ENI"
  type        = string
}

variable "security_group_id" {
  description = "Security group applied to the NIOS-X ENI"
  type        = string
}

variable "key_name" {
  description = "Name of the EC2 key pair for support access to the host"
  type        = string
}

variable "common_tags" {
  description = "Tags merged into every resource in this module"
  type        = map(string)
}

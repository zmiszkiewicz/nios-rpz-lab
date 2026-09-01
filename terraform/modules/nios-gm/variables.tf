variable "name_prefix" {
  description = "Prefix applied to the Name tag of every resource in this module"
  type        = string
}

variable "nios_ami_id" {
  description = <<-EOT
    AMI ID of the privately shared Infoblox vNIOS image, not the AWS Marketplace
    listing. Required at module level; the root module carries the default.
  EOT
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.nios_ami_id))
    error_message = "nios_ami_id must look like ami-0123456789abcdef0."
  }
}

variable "instance_type" {
  description = "EC2 instance type for the Grid Master. IB-V825 expects 4 vCPU / 16 GB."
  type        = string
  default     = "m5.xlarge"
}

variable "temp_license" {
  description = <<-EOT
    Space-separated NIOS temporary licence tokens written into the
    #infoblox-config user_data. The `rpz` token grants DNS Firewall, which
    `zone_rp` creation requires.
  EOT
  type        = string
  default     = "nios IB-V825 enterprise dns dhcp cloud rpz"
}

variable "admin_password" {
  description = "Initial password for the NIOS `admin` account"
  type        = string
  sensitive   = true
}

variable "subnet_id" {
  description = "Subnet for both Grid Master ENIs — they must share an AZ"
  type        = string
}

variable "security_group_id" {
  description = "Security group applied to both Grid Master ENIs"
  type        = string
}

variable "key_name" {
  description = "Name of the EC2 key pair for remote console access"
  type        = string
}

variable "mgmt_private_ip" {
  description = "Static private IP for the MGMT interface"
  type        = string
}

variable "lan1_private_ip" {
  description = "Static private IP for the LAN1 interface. This is the address lab clients use as their resolver."
  type        = string
}

variable "subnet_netmask" {
  description = "Dotted-quad netmask of the subnet, for the NIOS interface config"
  type        = string
}

variable "gateway_ip" {
  description = "Default gateway for the NIOS interfaces"
  type        = string
}

variable "common_tags" {
  description = "Tags merged into every resource in this module"
  type        = map(string)
}

variable "name_prefix" {
  description = "Prefix applied to the Name tag of every resource in this module"
  type        = string
}

variable "windows_ami_name_filter" {
  description = "AMI name filter for the desktop base image"
  type        = string
  default     = "Windows_Server-2022-English-Full-Base-*"
}

variable "instance_type" {
  description = "EC2 instance type for the desktop"
  type        = string
  default     = "t3.medium"
}

variable "admin_password" {
  description = "Password set on the local Administrator account, also used by Guacamole and WinRM"
  type        = string
  sensitive   = true
}

variable "dns_server_ip" {
  description = "Resolver the desktop is pinned to — the Grid Master's LAN1 address"
  type        = string
}

variable "grid_manager_url" {
  description = "Grid Manager URL, dropped on the desktop as a shortcut"
  type        = string
}

variable "subnet_id" {
  description = "Subnet for the desktop ENI"
  type        = string
}

variable "security_group_id" {
  description = "Security group applied to the desktop ENI"
  type        = string
}

variable "key_name" {
  description = "Name of the EC2 key pair, needed for get-password-data fallback"
  type        = string
}

variable "private_ip" {
  description = "Static private IP for the desktop"
  type        = string
}

variable "common_tags" {
  description = "Tags merged into every resource in this module"
  type        = map(string)
}

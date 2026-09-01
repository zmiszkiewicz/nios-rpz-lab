###############################################################################
# Required — no defaults, must be supplied via TF_VAR_* or a .tfvars file
###############################################################################

variable "nios_ami_id" {
  description = <<-EOT
    AMI ID of the privately shared Infoblox vNIOS image, NOT the AWS Marketplace
    listing. Region- and account-specific, so there is no sensible default.
    Export as TF_VAR_nios_ami_id.
  EOT
  type        = string
}

variable "windows_admin_password" {
  description = "Password for the Windows Administrator account on the desktop"
  type        = string
  sensitive   = true
}

variable "nios_admin_password" {
  description = "Initial password for the NIOS `admin` account"
  type        = string
  sensitive   = true
}

###############################################################################
# Environment
###############################################################################

variable "aws_region" {
  description = "AWS region for the whole stack. Single region by design."
  type        = string
  default     = "eu-central-1"
}

variable "instruqt_id" {
  description = <<-EOT
    Instruqt participant ID, used to namespace resource names so concurrent
    runs never collide. Set from INSTRUQT_PARTICIPANT_ID in setup-shell.
  EOT
  type        = string
  default     = "local"
}

###############################################################################
# Networking
###############################################################################

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC"
  type        = string
  default     = "10.100.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the single public subnet"
  type        = string
  default     = "10.100.0.0/24"
}

variable "management_ingress_cidrs" {
  description = <<-EOT
    Source CIDRs allowed to reach Grid Manager, SSH, RDP and WinRM. Instruqt's
    virtual browser and Guacamole containers have no published egress range, so
    the lab default is open. Narrow it if you run this outside Instruqt.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "nios_mgmt_private_ip" {
  description = "Static private IP for the Grid Master MGMT interface"
  type        = string
  default     = "10.100.0.10"
}

variable "nios_lan1_private_ip" {
  description = <<-EOT
    Static private IP for the Grid Master LAN1 interface. This doubles as the
    resolver address baked into the desktop at boot, so changing it changes
    what the desktop queries.
  EOT
  type        = string
  default     = "10.100.0.11"
}

variable "desktop_private_ip" {
  description = "Static private IP for the Windows desktop"
  type        = string
  default     = "10.100.0.110"
}

###############################################################################
# Sizing and images
###############################################################################

variable "nios_instance_type" {
  description = "Instance type for the Grid Master. IB-V825 expects 4 vCPU / 16 GB."
  type        = string
  default     = "m5.xlarge"
}

variable "nios_temp_license" {
  description = <<-EOT
    NIOS temporary licence tokens for the #infoblox-config user_data. The `rpz`
    token grants DNS Firewall; without it the Response Policy Zone cannot be
    created and the lab has no content. Verify on first deploy — see the
    Troubleshooting section of the README.
  EOT
  type        = string
  default     = "nios IB-V825 enterprise dns dhcp cloud rpz"
}

variable "desktop_instance_type" {
  description = "Instance type for the Windows desktop"
  type        = string
  default     = "t3.medium"
}

variable "windows_ami_name_filter" {
  description = "AMI name filter for the desktop base image"
  type        = string
  default     = "Windows_Server-2022-English-Full-Base-*"
}

###############################################################################
# Misc
###############################################################################

variable "private_key_filename" {
  description = "Filename for the generated SSH private key, written next to the root module"
  type        = string
  default     = "instruqt-lab-key.pem"
}

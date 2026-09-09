###############################################################################
# NIOS-X image
###############################################################################

variable "niosx_ami_id" {
  description = <<-EOT
    AMI ID of the privately shared Infoblox NIOS-X image, NOT the AWS
    Marketplace listing.

    The default is the NIOS-X image tech-summit-security-niosx uses in
    eu-central-1, paired there with the same m5.large sizing this lab uses.
    Every other Infoblox lab in this organisation hardcodes its equivalent in a
    `locals` block; a variable with a default keeps that zero-configuration
    behaviour while still allowing an override with TF_VAR_niosx_ami_id when the
    image is rotated or the region changes.

    Region-specific. If you move the lab out of eu-central-1 you must change it.
  EOT
  type        = string
  default     = "ami-08659b5070b66249d"
}

###############################################################################
# Required — no defaults, must be supplied via TF_VAR_* or a .tfvars file
###############################################################################

variable "windows_admin_password" {
  description = "Password for the Windows Administrator account on the desktop"
  type        = string
  sensitive   = true
}

variable "infoblox_join_token" {
  description = <<-EOT
    Infoblox CSP join token, the only credential the NIOS-X host is given. It is
    written into the host's cloud-config and used once, at first boot, to
    register the host against the tenant that issued it.

    Deliberately has no default: it is tenant-specific and short-lived, and a
    stale default would produce a host that silently never registers.
    track_scripts/setup-shell exports it as TF_VAR_infoblox_join_token from an
    Instruqt secret.
  EOT
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
    Source CIDRs allowed to reach SSH, RDP and WinRM. Instruqt's virtual browser
    and Guacamole containers have no published egress range, so the lab default
    is open. Narrow it if you run this outside Instruqt.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "niosx_private_ip" {
  description = <<-EOT
    Static private IP for the NIOS-X host. This doubles as the resolver address
    baked into the desktop at boot, so changing it changes what the desktop
    queries. .200 matches the address the other NIOS-X labs in this
    organisation use, which keeps runbooks interchangeable.
  EOT
  type        = string
  default     = "10.100.0.200"
}

variable "desktop_private_ip" {
  description = "Static private IP for the Windows desktop"
  type        = string
  default     = "10.100.0.110"
}

###############################################################################
# Sizing and images
###############################################################################

variable "niosx_instance_type" {
  description = <<-EOT
    Instance type for the NIOS-X host. m5.large is the documented minimum for a
    NIOS-X host running the DNS Forwarding Proxy service, and it is what the
    other NIOS-X labs here use. Smaller types boot but fail to register.
  EOT
  type        = string
  default     = "m5.large"
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
# Infoblox portal
###############################################################################

variable "portal_url" {
  description = <<-EOT
    Infoblox Portal URL, dropped on the desktop as a shortcut. Override it if
    your tenant lives in a regional instance such as csp.eu.infoblox.com.
  EOT
  type        = string
  default     = "https://portal.infoblox.com"
}

###############################################################################
# Misc
###############################################################################

variable "private_key_filename" {
  description = "Filename for the generated SSH private key, written next to the root module"
  type        = string
  default     = "instruqt-lab-key.pem"
}

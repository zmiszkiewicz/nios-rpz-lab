###############################################################################
# Blocking Generative AI with NIOS RPZ — root configuration
###############################################################################
# Deploys, in one AWS region:
#   * a VPC with a single public subnet and two scoped security groups
#   * a vNIOS Grid Master from a privately shared AMI
#   * a Windows Server 2022 desktop whose resolver is the Grid Master
#
# Everything the participant configures — recursion, the Response Policy Zone,
# the block rules — is done at runtime through Grid Manager or the WAPI scripts
# in ../scripts. Terraform deliberately does not pre-create any of it; that is
# the lab's actual content.
###############################################################################

locals {
  name_prefix = "nios-rpz-${var.instruqt_id}"

  common_tags = {
    Environment = "Lab"
    Project     = "NIOS-RPZ-GenAI"
    ManagedBy   = "Terraform"
    Track       = "nios-rpz-genai-block"
    Participant = var.instruqt_id
  }

  # Dotted-quad form of the subnet prefix, which is what NIOS wants in its
  # #infoblox-config block.
  subnet_netmask = cidrnetmask(var.subnet_cidr)
}

###############################################################################
# SSH key pair
###############################################################################
# Written to disk so track_scripts can fall back to `aws ec2 get-password-data`
# if the desktop's user_data password reset ever fails.
###############################################################################

resource "tls_private_key" "lab" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "lab" {
  key_name   = "${local.name_prefix}-key"
  public_key = tls_private_key.lab.public_key_openssh

  tags = local.common_tags
}

resource "local_sensitive_file" "private_key" {
  filename        = "${path.module}/${var.private_key_filename}"
  content         = tls_private_key.lab.private_key_pem
  file_permission = "0400"
}

###############################################################################
# Networking
###############################################################################

module "vpc" {
  source = "./modules/vpc"

  name_prefix              = local.name_prefix
  vpc_cidr                 = var.vpc_cidr
  subnet_cidr              = var.subnet_cidr
  management_ingress_cidrs = var.management_ingress_cidrs
  common_tags              = local.common_tags
}

###############################################################################
# NIOS Grid Master
###############################################################################

module "nios_gm" {
  source = "./modules/nios-gm"

  name_prefix       = local.name_prefix
  nios_ami_id       = var.nios_ami_id
  instance_type     = var.nios_instance_type
  temp_license      = var.nios_temp_license
  admin_password    = var.nios_admin_password
  subnet_id         = module.vpc.subnet_id
  security_group_id = module.vpc.nios_security_group_id
  key_name          = aws_key_pair.lab.key_name
  mgmt_private_ip   = var.nios_mgmt_private_ip
  lan1_private_ip   = var.nios_lan1_private_ip
  subnet_netmask    = local.subnet_netmask
  gateway_ip        = module.vpc.subnet_gateway_ip
  common_tags       = local.common_tags

  # NIOS needs a default route the moment it boots, or licensing and NTP hang.
  depends_on = [module.vpc]
}

###############################################################################
# Windows desktop
###############################################################################

module "desktop" {
  source = "./modules/desktop"

  name_prefix             = local.name_prefix
  windows_ami_name_filter = var.windows_ami_name_filter
  instance_type           = var.desktop_instance_type
  admin_password          = var.windows_admin_password
  dns_server_ip           = var.nios_lan1_private_ip
  grid_manager_url        = module.nios_gm.grid_manager_url
  subnet_id               = module.vpc.subnet_id
  security_group_id       = module.vpc.desktop_security_group_id
  key_name                = aws_key_pair.lab.key_name
  private_ip              = var.desktop_private_ip
  common_tags             = local.common_tags

  depends_on = [module.vpc]
}

###############################################################################
# Blocking Generative AI with Infoblox Threat Defense — root configuration
###############################################################################
# Deploys, in one AWS region:
#   * a VPC with a single public subnet and two scoped security groups
#   * a NIOS-X host that becomes the lab's DNS Forwarding Proxy, registered
#     against the Infoblox CSP tenant with a join token at first boot
#   * a Windows Server 2022 desktop whose resolver is that DFP
#
# The DFP is the only thing the lab needs on the infrastructure side: once the
# desktop's queries are forwarded to Threat Defense, everything the participant
# configures happens in the Infoblox portal. The security policy, the custom
# list of generative AI domains, the category filter, the block action, the
# Insight they inspect afterwards — Terraform pre-creates none of it, because
# building it is the lab's actual content.
#
# The one exception is enabling the DFP service itself, which cannot happen
# until the host has registered. scripts/setup_dfp.py does that over
# the API after apply.
###############################################################################

locals {
  name_prefix = "ibtd-genai-${var.instruqt_id}"

  common_tags = {
    Environment = "Lab"
    Project     = "IBTD-GenAI"
    ManagedBy   = "Terraform"
    Track       = "nios-rpz-genai-block"
    Participant = var.instruqt_id
  }
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
# NIOS-X host — the DNS Forwarding Proxy
###############################################################################

module "niosx_dfp" {
  source = "./modules/niosx-dfp"

  name_prefix         = local.name_prefix
  niosx_ami_id        = var.niosx_ami_id
  niosx_instance_type = var.niosx_instance_type
  join_token          = var.infoblox_join_token
  private_ip          = var.niosx_private_ip
  subnet_id           = module.vpc.subnet_id
  security_group_id   = module.vpc.niosx_security_group_id
  key_name            = aws_key_pair.lab.key_name
  common_tags         = local.common_tags

  # The host tries to register with the CSP within seconds of booting, so the
  # route to the internet gateway has to exist before it starts.
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
  dns_server_ip           = var.niosx_private_ip
  portal_url              = var.portal_url
  subnet_id               = module.vpc.subnet_id
  security_group_id       = module.vpc.desktop_security_group_id
  key_name                = aws_key_pair.lab.key_name
  private_ip              = var.desktop_private_ip
  common_tags             = local.common_tags

  # dns_server_ip is var.niosx_private_ip rather than a module output on
  # purpose. The desktop only needs the address, not a running DFP, so taking it
  # from the variable lets the two instances build in parallel instead of
  # serialising the apply behind the NIOS-X host.
  depends_on = [module.vpc]
}

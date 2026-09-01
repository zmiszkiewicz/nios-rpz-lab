###############################################################################
# NIOS Grid Master module
###############################################################################
# Built from a privately shared Infoblox AMI — NOT the AWS Marketplace listing.
# The AMI ID is a required variable with no default: it is account-, region- and
# version-specific, and the brief forbids hardcoding it. Pass it as
# TF_VAR_nios_ami_id. See the repo README for how to find yours.
#
# Two ENIs in the same AZ, MGMT on device_index 0 and LAN1 on device_index 1,
# with the Elastic IP on LAN1 — that is the layout every working vNIOS lab in
# this organisation uses, and vNIOS will not come up cleanly if it is changed.
###############################################################################

resource "aws_network_interface" "mgmt" {
  subnet_id       = var.subnet_id
  private_ips     = [var.mgmt_private_ip]
  security_groups = [var.security_group_id]

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-gm-mgmt-nic" })
}

resource "aws_network_interface" "lan1" {
  subnet_id       = var.subnet_id
  private_ips     = [var.lan1_private_ip]
  security_groups = [var.security_group_id]

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-gm-lan1-nic" })
}

resource "aws_instance" "gm" {
  ami           = var.nios_ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  network_interface {
    network_interface_id = aws_network_interface.mgmt.id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.lan1.id
    device_index         = 1
  }

  # NIOS reads this cloud-init dialect at first boot. The temp_license line is
  # the one that matters for this lab: without a DNS Firewall (RPZ) entitlement
  # the participant cannot create a Response Policy Zone at all. See
  # var.temp_license.
  user_data = <<-EOF
#infoblox-config
temp_license: ${var.temp_license}
remote_console_enabled: y
default_admin_password: "${var.admin_password}"
lan1:
  v4_addr: ${var.lan1_private_ip}
  v4_netmask: ${var.subnet_netmask}
  v4_gw: ${var.gateway_ip}
mgmt:
  v4_addr: ${var.mgmt_private_ip}
  v4_netmask: ${var.subnet_netmask}
  v4_gw: ${var.gateway_ip}
EOF

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-nios-gm" })
}

resource "aws_eip" "gm" {
  domain = "vpc"

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-gm-eip" })
}

resource "aws_eip_association" "gm" {
  network_interface_id = aws_network_interface.lan1.id
  allocation_id        = aws_eip.gm.id
  private_ip_address   = var.lan1_private_ip

  depends_on = [aws_instance.gm]
}

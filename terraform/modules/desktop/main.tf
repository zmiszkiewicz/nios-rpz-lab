###############################################################################
# Desktop module — Windows workstation the participant drives from the browser
###############################################################################
# Windows Server 2022 with Edge, reached over RDP through the Instruqt
# gcr.io/instruqt/guacamole container. Its resolver is pinned to the NIOS-X
# DFP's private address at boot, which is what puts it behind Threat Defense.
###############################################################################

data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = [var.windows_ami_name_filter]
  }
}

resource "aws_network_interface" "desktop" {
  subnet_id       = var.subnet_id
  private_ips     = [var.private_ip]
  security_groups = [var.security_group_id]

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-desktop-nic" })
}

resource "aws_instance" "desktop" {
  ami           = data.aws_ami.windows.id
  instance_type = var.instance_type
  key_name      = var.key_name

  network_interface {
    network_interface_id = aws_network_interface.desktop.id
    device_index         = 0
  }

  user_data = templatefile("${path.module}/templates/desktop-init.ps1.tpl", {
    admin_password = var.admin_password
    dns_server_ip  = var.dns_server_ip
    portal_url     = var.portal_url
  })

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-desktop" })
}

resource "aws_eip" "desktop" {
  domain = "vpc"

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-desktop-eip" })
}

resource "aws_eip_association" "desktop" {
  network_interface_id = aws_network_interface.desktop.id
  allocation_id        = aws_eip.desktop.id
  private_ip_address   = var.private_ip

  depends_on = [aws_instance.desktop]
}

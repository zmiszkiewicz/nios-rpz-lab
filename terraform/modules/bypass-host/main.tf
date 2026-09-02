###############################################################################
# Bypass-host module — the unmanaged workload that sidesteps the RPZ
###############################################################################
# A cheap Ubuntu box whose resolver is a public DNS service rather than the
# Grid Master. It exists to make one point that no amount of RPZ configuration
# can: a DNS-layer policy only governs clients that actually ask you.
#
# Linux over SSH rather than another Windows desktop: the whole demonstration is
# dig commands, it boots in under a minute, and it costs about a penny an hour.
# Same shape as the Linux workload host in the genai lab.
###############################################################################

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = [var.ubuntu_ami_name_filter]
  }
}

resource "aws_network_interface" "bypass" {
  subnet_id       = var.subnet_id
  private_ips     = [var.private_ip]
  security_groups = [var.security_group_id]

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-bypass-nic" })
}

resource "aws_instance" "bypass" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = var.key_name

  network_interface {
    network_interface_id = aws_network_interface.bypass.id
    device_index         = 0
  }

  user_data = templatefile("${path.module}/templates/bypass-init.sh.tpl", {
    public_resolver   = var.public_resolver
    fallback_resolver = var.fallback_resolver
    gm_ip             = var.gm_private_ip
  })

  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-unmanaged-host"
    Role = "bypass-demo"
  })
}

resource "aws_eip" "bypass" {
  domain = "vpc"

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-bypass-eip" })
}

resource "aws_eip_association" "bypass" {
  network_interface_id = aws_network_interface.bypass.id
  allocation_id        = aws_eip.bypass.id
  private_ip_address   = var.private_ip

  depends_on = [aws_instance.bypass]
}

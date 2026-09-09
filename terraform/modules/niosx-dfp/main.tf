###############################################################################
# NIOS-X host module — the lab's DNS Forwarding Proxy
###############################################################################
# Built from the privately shared Infoblox NIOS-X AMI, the same image
# tech-summit-security-niosx uses. One instance, one ENI, one Elastic IP.
#
# A NIOS-X host is not configured the way a vNIOS Grid Master is. There is no
# #infoblox-config block and no local admin password: the only thing handed to
# the instance is a join token, and the host phones home to the Infoblox CSP on
# first boot to register itself against the tenant that issued the token. From
# that moment the host is managed entirely from the portal, not from Terraform.
#
# Which is also why this module stops at "a registered host". Turning on the
# DNS Forwarding Proxy *service* is a CSP-side operation against an object that
# does not exist until registration completes, so Terraform cannot express it in
# the same apply — there is nothing to reference. scripts/setup_dfp.py
# waits for the host to appear in the tenant and enables the DFP service over
# the API afterwards.
###############################################################################

###############################################################################
# ENI
###############################################################################
# Static private IP, because the desktop's resolver address is baked into its
# user_data at boot and the two have to agree without a lookup.
###############################################################################

resource "aws_network_interface" "dfp" {
  subnet_id       = var.subnet_id
  private_ips     = [var.private_ip]
  security_groups = [var.security_group_id]

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-dfp-nic" })
}

resource "aws_instance" "dfp" {
  ami           = var.niosx_ami_id
  instance_type = var.niosx_instance_type
  key_name      = var.key_name

  network_interface {
    network_interface_id = aws_network_interface.dfp.id
    device_index         = 0
  }

  # The join token is the entire bootstrap. cloud-init hands it to the NIOS-X
  # host_setup module, which registers the host with the CSP tenant that issued
  # the token. Keep this heredoc exactly as it is: NIOS-X parses it as YAML and
  # is unforgiving about the shape.
  user_data = <<-EOF
    #cloud-config
    host_setup:
      jointoken: "${var.join_token}"
  EOF

  # IMDSv2 only. Nothing in the lab reads instance metadata, so requiring a
  # token costs nothing and keeps the host off the standard scan findings.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-niosx-dfp" })
}

###############################################################################
# Elastic IP
###############################################################################
# Two reasons, both load bearing. The host needs outbound internet to reach
# csp.infoblox.com and to resolve recursively once it is forwarding, and a
# stable public address gives support a way in when a lab run goes wrong.
###############################################################################

resource "aws_eip" "dfp" {
  domain = "vpc"

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-dfp-eip" })
}

resource "aws_eip_association" "dfp" {
  network_interface_id = aws_network_interface.dfp.id
  allocation_id        = aws_eip.dfp.id
  private_ip_address   = var.private_ip

  depends_on = [aws_instance.dfp]
}

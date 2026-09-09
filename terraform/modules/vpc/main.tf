###############################################################################
# VPC module — networking for the Threat Defense GenAI lab
###############################################################################
# One VPC, one public subnet, single-AZ. Everything in the lab talks to
# everything else over private addresses inside that one subnet, and both hosts
# need outbound internet: the NIOS-X host to reach the Infoblox CSP, the desktop
# to browse. Nothing here is highly available on purpose.
###############################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-vpc" })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-public-subnet" })
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-igw" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-public-rt" })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

###############################################################################
# Security group — NIOS-X DNS Forwarding Proxy
###############################################################################
# Scoped tighter than the other Infoblox labs in this repo, which open DNS to
# 0.0.0.0/0. Port 53 here is reachable from inside the VPC only, so the DFP is
# never an open resolver on the internet. The challenge checks reach DNS by
# running the lookup on the desktop over WinRM rather than by querying the DFP
# directly from the Instruqt shell container.
#
# There is no management ingress rule for a UI: a NIOS-X host has no local web
# interface. It is administered from the Infoblox portal, so the only inbound
# port beyond DNS is SSH for support access.
#
# Egress has to stay wide open. The host needs 443 outbound to csp.infoblox.com
# to register itself with the join token on first boot, to keep its control
# channel up, and to forward the queries it receives. Narrowing this is the
# fastest way to produce a host that never appears in the portal.
###############################################################################

resource "aws_security_group" "niosx" {
  name        = "${var.name_prefix}-niosx-sg"
  description = "NIOS-X DFP: DNS from the VPC, outbound to the Infoblox CSP"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Remote console / support access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.management_ingress_cidrs
  }

  ingress {
    description = "DNS over UDP from lab clients"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "DNS over TCP from lab clients"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "ICMP from lab clients"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Registration with the Infoblox CSP and recursive resolution"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-niosx-sg" })
}

###############################################################################
# Security group — Windows desktop
###############################################################################
# Egress deliberately omits TCP/UDP 853. Security groups are allow-only, so the
# port is excluded by splitting the range around it: 1-852 and 854-65535.
#
# 853 is DNS-over-TLS and DNS-over-QUIC. If the browser or the OS can open it,
# it resolves against a public encrypted resolver instead of the DFP, the DFP
# never sees the query, and Threat Defense looks like it is not working — no
# block page, no Insight, nothing in Application Discovery. Closing the port is
# what guarantees every lookup on this host is one the DFP forwards.
#
# DoH (443) cannot be excluded the same way without breaking the web, so it is
# handled on the host instead — see
# modules/desktop/templates/desktop-init.ps1.tpl.
#
# AWS restricts rule descriptions to
# ^[0-9A-Za-z_ .:/()#,@\[\]+=&;{}!$*-]*$ — no em dashes, no apostrophes.
# Keep every description in this file plain ASCII.
###############################################################################

resource "aws_security_group" "desktop" {
  name        = "${var.name_prefix}-desktop-sg"
  description = "Windows desktop: RDP and WinRM in, everything out except DoT/DoQ"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "RDP via the Instruqt Guacamole container"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.management_ingress_cidrs
  }

  ingress {
    description = "WinRM for lab automation and challenge checks"
    from_port   = 5985
    to_port     = 5985
    protocol    = "tcp"
    cidr_blocks = var.management_ingress_cidrs
  }

  ingress {
    description = "ICMP from within the VPC"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "TCP below DNS-over-TLS"
    from_port   = 1
    to_port     = 852
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "TCP above DNS-over-TLS"
    from_port   = 854
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "UDP below DNS-over-QUIC"
    from_port   = 1
    to_port     = 852
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "UDP above DNS-over-QUIC"
    from_port   = 854
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "ICMP"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-desktop-sg" })
}

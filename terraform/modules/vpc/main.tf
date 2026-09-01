###############################################################################
# VPC module — networking for the NIOS RPZ GenAI lab
###############################################################################
# One VPC, one public subnet. The subnet is deliberately single-AZ: a vNIOS
# Grid Master needs its MGMT and LAN1 ENIs in the same availability zone.
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
# Security group — NIOS Grid Master
###############################################################################
# Scoped tighter than the other Infoblox labs in this repo, which open DNS to
# 0.0.0.0/0. Port 53 here is reachable from inside the VPC only, so the Grid
# Master is never an open resolver on the internet. The challenge checks reach
# DNS by running the lookup on the desktop over WinRM rather than by querying
# the GM directly from the Instruqt shell container.
###############################################################################

resource "aws_security_group" "nios" {
  name        = "${var.name_prefix}-nios-sg"
  description = "NIOS Grid Master: Grid Manager UI/WAPI from anywhere, DNS from the VPC only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Grid Manager UI and WAPI"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.management_ingress_cidrs
  }

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
    description = "Recursive resolution and Infoblox services"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.common_tags, { Name = "${var.name_prefix}-nios-sg" })
}

###############################################################################
# Security group — Windows desktop
###############################################################################
# Egress deliberately omits TCP/UDP 853. Security groups are allow-only, so the
# port is excluded by splitting the range around it. That stops the browser or
# OS falling back to DNS-over-TLS / DNS-over-QUIC and silently bypassing the
# RPZ. DoH (443) cannot be excluded the same way without breaking the web, so
# it is handled on the host — see modules/desktop/templates/desktop-init.ps1.tpl
# and the DoH bootstrap rules in scripts/domains.py.
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

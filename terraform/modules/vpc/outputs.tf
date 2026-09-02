output "vpc_id" {
  description = "ID of the lab VPC"
  value       = aws_vpc.main.id
}

output "subnet_id" {
  description = "ID of the public subnet holding the Grid Master and the desktop"
  value       = aws_subnet.public.id
}

output "availability_zone" {
  description = "AZ of the public subnet — both Grid Master ENIs must land here"
  value       = aws_subnet.public.availability_zone
}

output "subnet_gateway_ip" {
  description = "First usable address in the subnet, used as the NIOS default gateway"
  value       = cidrhost(var.subnet_cidr, 1)
}

output "nios_security_group_id" {
  description = "Security group for the NIOS Grid Master interfaces"
  value       = aws_security_group.nios.id
}

output "desktop_security_group_id" {
  description = "Security group for the Windows desktop"
  value       = aws_security_group.desktop.id
}

output "bypass_security_group_id" {
  description = "Security group for the unmanaged bypass host"
  value       = aws_security_group.bypass.id
}

output "bypass_security_group_name" {
  description = "Name of the bypass security group — lock_dns_egress.py looks it up by name"
  value       = aws_security_group.bypass.name
}

output "internet_gateway_id" {
  description = "IGW ID, used by instances to order their creation correctly"
  value       = aws_internet_gateway.gw.id
}

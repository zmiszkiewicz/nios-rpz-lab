output "vpc_id" {
  description = "ID of the lab VPC"
  value       = aws_vpc.main.id
}

output "subnet_id" {
  description = "ID of the public subnet holding the NIOS-X host and the desktop"
  value       = aws_subnet.public.id
}

output "availability_zone" {
  description = "AZ of the public subnet — everything in the lab lands here"
  value       = aws_subnet.public.availability_zone
}

output "subnet_gateway_ip" {
  description = "First usable address in the subnet, the default gateway for lab hosts"
  value       = cidrhost(var.subnet_cidr, 1)
}

output "niosx_security_group_id" {
  description = "Security group for the NIOS-X DFP interface"
  value       = aws_security_group.niosx.id
}

output "desktop_security_group_id" {
  description = "Security group for the Windows desktop"
  value       = aws_security_group.desktop.id
}

output "internet_gateway_id" {
  description = "IGW ID, used by instances to order their creation correctly"
  value       = aws_internet_gateway.gw.id
}

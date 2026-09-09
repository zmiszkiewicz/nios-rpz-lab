output "private_ip" {
  description = "Private IP of the NIOS-X host — the resolver address lab clients point at"
  value       = var.private_ip
}

output "public_ip" {
  description = "Elastic IP of the NIOS-X host — outbound to the CSP and support access"
  value       = aws_eip.dfp.public_ip
}

output "instance_id" {
  description = "EC2 instance ID of the NIOS-X host"
  value       = aws_instance.dfp.id
}

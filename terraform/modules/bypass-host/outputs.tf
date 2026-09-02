output "instance_id" {
  description = "EC2 instance ID of the unmanaged host"
  value       = aws_instance.bypass.id
}

output "public_ip" {
  description = "Elastic IP of the unmanaged host — SSH target"
  value       = aws_eip.bypass.public_ip
}

output "private_ip" {
  description = "Private IP of the unmanaged host"
  value       = var.private_ip
}

output "public_resolver" {
  description = "The public resolver this host uses to bypass the Grid Master"
  value       = var.public_resolver
}

output "ssh_command" {
  description = "Ready-to-paste SSH command for the assignment"
  value       = "ssh -o StrictHostKeyChecking=no -i instruqt-lab-key.pem ubuntu@${aws_eip.bypass.public_ip}"
}

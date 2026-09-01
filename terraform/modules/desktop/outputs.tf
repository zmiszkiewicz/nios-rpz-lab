output "instance_id" {
  description = "EC2 instance ID of the desktop"
  value       = aws_instance.desktop.id
}

output "public_ip" {
  description = "Elastic IP of the desktop — RDP and WinRM target"
  value       = aws_eip.desktop.public_ip
}

output "private_ip" {
  description = "Private IP of the desktop"
  value       = var.private_ip
}

output "ami_id" {
  description = "Resolved Windows AMI the desktop was built from"
  value       = data.aws_ami.windows.id
}

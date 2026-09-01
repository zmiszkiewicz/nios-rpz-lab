output "instance_id" {
  description = "EC2 instance ID of the Grid Master"
  value       = aws_instance.gm.id
}

output "public_ip" {
  description = "Elastic IP on LAN1 — Grid Manager UI and WAPI endpoint"
  value       = aws_eip.gm.public_ip
}

output "lan1_private_ip" {
  description = "LAN1 private IP — the resolver address lab clients point at"
  value       = var.lan1_private_ip
}

output "mgmt_private_ip" {
  description = "MGMT private IP"
  value       = var.mgmt_private_ip
}

output "grid_manager_url" {
  description = "Grid Manager URL reachable over the Elastic IP"
  value       = "https://${aws_eip.gm.public_ip}"
}

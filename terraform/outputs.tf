###############################################################################
# Outputs consumed by track_scripts/setup-shell
###############################################################################
# Every one of these is read with `terraform output -raw <name>` and turned into
# both a shell export and an Instruqt agent variable. Renaming any of them means
# editing setup-shell too.
###############################################################################

output "gm_public_ip" {
  description = "Grid Master Elastic IP — Grid Manager UI and WAPI endpoint"
  value       = module.nios_gm.public_ip
}

output "gm_lan1_private_ip" {
  description = "Grid Master LAN1 private IP — the resolver the desktop points at"
  value       = module.nios_gm.lan1_private_ip
}

output "gm_mgmt_private_ip" {
  description = "Grid Master MGMT private IP"
  value       = module.nios_gm.mgmt_private_ip
}

output "gm_instance_id" {
  description = "EC2 instance ID of the Grid Master"
  value       = module.nios_gm.instance_id
}

output "desktop_public_ip" {
  description = "Desktop Elastic IP — RDP via Guacamole and WinRM for checks"
  value       = module.desktop.public_ip
}

output "desktop_private_ip" {
  description = "Desktop private IP"
  value       = module.desktop.private_ip
}

output "desktop_instance_id" {
  description = "EC2 instance ID of the desktop"
  value       = module.desktop.instance_id
}

output "vpc_id" {
  description = "ID of the lab VPC"
  value       = module.vpc.vpc_id
}

output "grid_manager_url" {
  description = "Grid Manager URL over the Elastic IP"
  value       = module.nios_gm.grid_manager_url
}

output "private_key_path" {
  description = "Path to the generated SSH private key"
  value       = local_sensitive_file.private_key.filename
}

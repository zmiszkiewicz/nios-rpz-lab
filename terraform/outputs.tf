###############################################################################
# Outputs consumed by track_scripts/setup-shell
###############################################################################
# Every one of these is read with `terraform output -raw <name>` and turned into
# both a shell export and an Instruqt agent variable. Renaming any of them means
# editing setup-shell too.
###############################################################################

output "dfp_public_ip" {
  description = "Elastic IP of the NIOS-X DFP — outbound to the CSP and support access"
  value       = module.niosx_dfp.public_ip
}

output "dfp_private_ip" {
  description = "Private IP of the NIOS-X DFP — the resolver the desktop points at"
  value       = module.niosx_dfp.private_ip
}

output "dfp_instance_id" {
  description = "EC2 instance ID of the NIOS-X DFP"
  value       = module.niosx_dfp.instance_id
}

output "desktop_public_ip" {
  description = "Desktop Elastic IP — RDP via Guacamole and WinRM for checks"
  value       = module.desktop.public_ip
}

output "desktop_private_ip" {
  description = "Desktop private IP"
  value       = module.desktop.private_ip
}

output "vpc_id" {
  description = "ID of the lab VPC"
  value       = module.vpc.vpc_id
}

output "subnet_id" {
  description = "ID of the public subnet holding both instances"
  value       = module.vpc.subnet_id
}

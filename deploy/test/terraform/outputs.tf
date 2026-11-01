output "ipv4" {
  value = hcloud_server.stack.ipv4_address
}

output "ipv6" {
  value = hcloud_server.stack.ipv6_address
}

output "placement" {
  description = "What was chosen and why the others were not."
  value = {
    server_type = hcloud_server.stack.server_type
    location    = hcloud_server.stack.location
    report      = module.placement.report
  }
}

output "ssh" {
  value = "ssh ${var.deploy_user}@${hcloud_server.stack.ipv4_address}"
}

output "deploy_command" {
  description = "Deploy the stack to the new server."
  value       = var.domain == "" ? "./deploy/test/deploy.sh ${var.deploy_user}@${hcloud_server.stack.ipv4_address}" : "./deploy/test/deploy.sh ${var.deploy_user}@${hcloud_server.stack.ipv4_address}  # after: init.sh --domain ${var.domain} --edge"
}

output "urls" {
  value = [for h in local.hosts : "https://${h}.${var.domain}"]
}

output "dns_managed" {
  value = var.dns_zone != ""
}

output "dns_nameservers" {
  description = "Set these as the domain's nameservers at the registrar (only when create_dns_zone is on)."
  value       = var.dns_zone != "" && var.create_dns_zone ? hcloud_zone.managed[0].authoritative_nameservers.assigned : []
}

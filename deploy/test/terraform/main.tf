data "hcloud_server_types" "all" {}

# Hetzner capacity is limited and varies per location, so the (type, location) pair is chosen from
# what the API reports as available right now, in the order of the preference lists.
module "placement" {
  source = "./modules/placement"

  server_type_preference = var.server_type_preference
  location_preference    = var.location_preference
  allow_deprecated       = var.allow_deprecated_types

  server_types = [
    for t in data.hcloud_server_types.all.server_types : {
      id   = t.id
      name = t.name
      locations = [
        for l in t.locations : {
          name          = l.name
          available     = l.available
          is_deprecated = l.is_deprecated
        }
      ]
    }
  ]
}

locals {
  labels = merge({ project = "nodetide", stack = "test", managed-by = "terraform" }, var.labels)
  hosts  = var.domain == "" ? [] : ["nt-node", "nt-rp", "nt-grafana", "nt-verifier"] # no public wallet: the web client at nt-node is the wallet
  # the zone: created here (create_dns_zone) or an existing one
  zone_name = var.dns_zone == "" ? "" : (var.create_dns_zone ? hcloud_zone.managed[0].name : data.hcloud_zone.this[0].name)
}

resource "hcloud_ssh_key" "deploy" {
  name       = "${var.name}-deploy"
  public_key = var.ssh_public_key
  labels     = local.labels
}

resource "hcloud_firewall" "web" {
  name   = "${var.name}-web"
  labels = local.labels

  rule {
    description = "ssh"
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.ssh_allowed_cidrs
  }

  rule {
    description = "http (certificate issuance, redirect)"
    direction   = "in"
    protocol    = "tcp"
    port        = "80"
    source_ips  = ["0.0.0.0/0", "::/0"]
  }

  rule {
    description = "https"
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = ["0.0.0.0/0", "::/0"]
  }

  rule {
    description = "smtp (mail for the sigchain responder; IMAP and submission stay inside the docker network)"
    direction   = "in"
    protocol    = "tcp"
    port        = "25"
    source_ips  = ["0.0.0.0/0", "::/0"]
  }

  rule {
    description = "ping"
    direction   = "in"
    protocol    = "icmp"
    source_ips  = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_server" "stack" {
  name         = var.name
  image        = var.image
  server_type  = try(module.placement.chosen.type, "none")
  location     = try(module.placement.chosen.location, "none")
  ssh_keys     = [hcloud_ssh_key.deploy.id]
  firewall_ids = [hcloud_firewall.web.id]
  labels       = local.labels

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    deploy_user    = var.deploy_user
    ssh_public_key = trimspace(var.ssh_public_key)
  })

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  lifecycle {
    precondition {
      condition     = module.placement.chosen != null
      error_message = <<-EOT
        None of the preferred server types is available in the preferred locations right now.
        Checked (type, location, state):
        ${join("\n        ", module.placement.report)}
        Available in other locations: ${length(module.placement.available_elsewhere) == 0 ? "nothing from the preference list" : join(", ", module.placement.available_elsewhere)}
        Widen server_type_preference / location_preference, or retry later.
      EOT
    }

    # Stock changes, cloud-init or image edits must never rebuild a server that holds state.
    ignore_changes = [user_data, image, ssh_keys, server_type, location]
  }
}

# The registrar only has to delegate the domain to Hetzner's nameservers once (see the `dns_nameservers` output);
# every record after that is managed here.
resource "hcloud_zone" "managed" {
  count  = var.dns_zone != "" && var.create_dns_zone ? 1 : 0
  name   = var.dns_zone
  mode   = "primary"
  ttl    = 3600
  labels = local.labels
}

data "hcloud_zone" "this" {
  count = var.dns_zone != "" && !var.create_dns_zone ? 1 : 0
  name  = var.dns_zone
}

resource "hcloud_zone_rrset" "a" {
  for_each = var.dns_zone == "" ? toset([]) : toset(local.hosts)

  zone = local.zone_name
  name = trimsuffix("${each.key}.${var.domain}", ".${var.dns_zone}")
  type = "A"
  ttl  = 300

  records = [{ value = hcloud_server.stack.ipv4_address, comment = "nodetide test stack" }]
}

resource "hcloud_zone_rrset" "aaaa" {
  for_each = var.dns_zone == "" ? toset([]) : toset(local.hosts)

  zone = local.zone_name
  name = trimsuffix("${each.key}.${var.domain}", ".${var.dns_zone}")
  type = "AAAA"
  ttl  = 300

  records = [{ value = hcloud_server.stack.ipv6_address, comment = "nodetide test stack" }]
}

# ---- mail for the sigchain responder (deploy/test, profile "mail") ---------------------------------------------------
# chains@<domain> receives on port 25 at nt-mail.<domain>. Records: MX, SPF, DKIM (key made here, private half goes to the
# server by the deploy job), DMARC; and the reverse DNS of the server's addresses, which other mail servers check.
locals {
  mail      = var.mail_enabled && var.dns_zone != "" && var.domain != ""
  mail_host = "nt-mail.${var.domain}"
  # record names relative to the zone ("test" for test.example.org in example.org)
  mail_apex = trimsuffix(var.domain, ".${var.dns_zone}")
  dkim_pub  = local.mail ? join("", slice(split("\n", trimspace(tls_private_key.dkim[0].public_key_pem)), 1, length(split("\n", trimspace(tls_private_key.dkim[0].public_key_pem))) - 1)) : ""
  dkim_txt  = "v=DKIM1; k=rsa; p=${local.dkim_pub}"
  # a TXT value is quoted strings of at most 255 characters
  dkim_txt_value = join(" ", [for i in range(0, ceil(length(local.dkim_txt) / 255)) : "\"${substr(local.dkim_txt, i * 255, 255)}\""])
}

resource "tls_private_key" "dkim" {
  count     = local.mail ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "hcloud_zone_rrset" "mail_a" {
  count = local.mail ? 1 : 0

  zone    = local.zone_name
  name    = "nt-mail.${local.mail_apex}"
  type    = "A"
  ttl     = 300
  records = [{ value = hcloud_server.stack.ipv4_address, comment = "mail for the sigchain responder" }]
}

resource "hcloud_zone_rrset" "mail_aaaa" {
  count = local.mail ? 1 : 0

  zone    = local.zone_name
  name    = "nt-mail.${local.mail_apex}"
  type    = "AAAA"
  ttl     = 300
  records = [{ value = hcloud_server.stack.ipv6_address, comment = "mail for the sigchain responder" }]
}

resource "hcloud_zone_rrset" "mail_mx" {
  count = local.mail ? 1 : 0

  zone    = local.zone_name
  name    = local.mail_apex
  type    = "MX"
  ttl     = 300
  records = [{ value = "10 ${local.mail_host}.", comment = "sigchain responder" }]
}

resource "hcloud_zone_rrset" "mail_spf" {
  count = local.mail ? 1 : 0

  zone    = local.zone_name
  name    = local.mail_apex
  type    = "TXT"
  ttl     = 300
  records = [{ value = "\"v=spf1 mx -all\"", comment = "only the MX host sends for this domain" }]
}

resource "hcloud_zone_rrset" "mail_dkim" {
  count = local.mail ? 1 : 0

  zone    = local.zone_name
  name    = "mail._domainkey.${local.mail_apex}"
  type    = "TXT"
  ttl     = 300
  records = [{ value = local.dkim_txt_value, comment = "DKIM key, selector mail" }]
}

resource "hcloud_zone_rrset" "mail_dmarc" {
  count = local.mail ? 1 : 0

  zone    = local.zone_name
  name    = "_dmarc.${local.mail_apex}"
  type    = "TXT"
  ttl     = 300
  records = [{ value = "\"v=DMARC1; p=quarantine; adkim=s; aspf=s\"", comment = "mail that fails both checks is not ours" }]
}

resource "hcloud_rdns" "mail_v4" {
  count = local.mail ? 1 : 0

  server_id  = hcloud_server.stack.id
  ip_address = hcloud_server.stack.ipv4_address
  dns_ptr    = local.mail_host
}

resource "hcloud_rdns" "mail_v6" {
  count = local.mail ? 1 : 0

  server_id  = hcloud_server.stack.id
  ip_address = hcloud_server.stack.ipv6_address
  dns_ptr    = local.mail_host
}

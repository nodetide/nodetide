variable "name" {
  description = "Name prefix for every resource."
  type        = string
  default     = "nodetide-test"
}

variable "domain" {
  description = "Base domain of the test stack; it serves nt-node.<domain>, nt-rp.<domain> and nt-wallet.<domain>."
  type        = string
  default     = ""
}

variable "dns_zone" {
  description = "Name of an existing Hetzner DNS zone that contains `domain` (e.g. example.com). Empty = do not manage DNS."
  type        = string
  default     = ""
}

variable "create_dns_zone" {
  description = "Create the Hetzner DNS zone `dns_zone` here instead of expecting it to exist (then delegate the domain to the nameservers in the dns_nameservers output)."
  type        = bool
  default     = false
}

variable "server_type_preference" {
  description = "Server types in order of preference. The first one actually in stock in an acceptable location is used."
  type        = list(string)
  default     = ["cx23", "cpx22", "cax11", "cx33", "cpx32", "cax21"]
}

variable "location_preference" {
  description = "Locations in order of preference."
  type        = list(string)
  default     = ["fsn1", "nbg1", "hel1"]
}

variable "allow_deprecated_types" {
  description = "Also accept server types Hetzner has deprecated in a location."
  type        = bool
  default     = false
}

variable "image" {
  description = "OS image."
  type        = string
  default     = "ubuntu-24.04"
}

variable "ssh_public_key" {
  description = "Public key (single line) that may log in as root and as the deploy user."
  type        = string
}

variable "ssh_allowed_cidrs" {
  description = "Source ranges allowed to reach SSH. Open by default because CI runners have no fixed address; restrict if you can."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}

variable "deploy_user" {
  description = "Unprivileged user (in the docker group) that deploy.sh connects as."
  type        = string
  default     = "deploy"
}

variable "labels" {
  description = "Extra labels for all resources."
  type        = map(string)
  default     = {}
}

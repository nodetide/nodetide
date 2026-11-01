terraform {
  required_version = ">= 1.10.0"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.54"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# The token comes from the HCLOUD_TOKEN environment variable.
provider "hcloud" {}

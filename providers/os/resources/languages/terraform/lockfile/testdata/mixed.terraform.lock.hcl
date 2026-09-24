# This file is maintained automatically by "terraform init".
# Manual edits may be lost in future updates.

provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:ltYPMnfzETy+S3VDhirIBgt2sfY/gJFiCPWnTsSkN+k=",
    "zh:0cd0b11e5cafd84e05be4088ccf28a01a3dbae8e1ce71e3b91f7b27aca633b7b",
    "zh:1a2b3c4d5e6f708192a3b4c5d6e7f80911223344556677889900aabbccddeeff",
  ]
}

provider "registry.opentofu.org/hashicorp/random" {
  version     = "3.6.0"
  constraints = ">= 3.0.0"
  hashes = [
    "h1:abc123=",
  ]
}

provider "artifactory.acme.com/tf/acme/docker" {
  version = "1.4.2"
  hashes = [
    "zh:ffeeddccbbaa00998877665544332211807f6e5d4c3b2a1908070605040302f1",
  ]
}

# A provider Terraform pinned without recording a constraint: required_providers
# named the source with no version.
provider "registry.terraform.io/integrations/github" {
  version = "5.42.0"
}

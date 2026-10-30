terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    docker = {
      source = "kreuzwerker/docker"
    }
    # Legacy shorthand: a constraint with no source. Terraform implies
    # hashicorp/random from the local name.
    random = "~> 3.6"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
}

# The shape real repositories use: a repo, a subdirectory and a pinned ref.
module "project_factory" {
  source = "git::https://github.com/verily-src/verily-health-iac.git//modules/base-project-factory?ref=v0.6.0"
}

# A local module is not a third-party dependency.
module "local" {
  source = "./modules/networking"
}

# A source built from a variable cannot be resolved without a full Terraform
# evaluation context, so it contributes nothing rather than a guess.
module "dynamic" {
  source = "git::https://github.com/acme/${var.repo}.git"
}

# A fetcher with no stable public coordinate.
module "bucket" {
  source = "s3::https://bucket.s3.amazonaws.com/vpc.zip"
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

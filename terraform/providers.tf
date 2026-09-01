terraform {
  # track_scripts/setup-shell installs Terraform 1.10.5 from releases.hashicorp.com,
  # the version every *-live-exchange lab in this org pins. Keep the two in step.
  required_version = "~> 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.20"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.4"
    }
  }
}

# Credentials come from the environment. Instruqt's AWS sandbox exports
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in track_scripts/setup-shell.
provider "aws" {
  region = var.aws_region
}

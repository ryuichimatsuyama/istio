########################################
# Provider to connect to AWS
#
# https://www.terraform.io/docs/providers/aws/
########################################

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.47.0"
    }
  }

  # backend "s3" {} # use local backend to first create S3 bucket to store .tfstate later
}
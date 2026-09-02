terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.28"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.17"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.38"
    }
    argocd = {
      source  = "argoproj-labs/argocd"
      version = "~> 7.15"
    }
    pagerduty = {
      source  = "PagerDuty/pagerduty"
      version = "~> 3.35"
    }
  }
}
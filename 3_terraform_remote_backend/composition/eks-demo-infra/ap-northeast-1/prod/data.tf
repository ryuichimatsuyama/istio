data "aws_availability_zones" "available" {
  # Exclude local zones
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  name               = "ex-${basename(path.cwd)}"

  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    Test       = local.name
    GithubRepo = "terraform-aws-eks"
    GithubOrg  = "terraform-aws-modules"
  }

  alertmanager_secrets = {
    pagerduty = {
      name = var.pagerduty_secret_name
      data = {
        (var.pagerduty_secret_key) = pagerduty_service_integration.alertmanager.integration_key
      }
    }

    slack = {
      name = var.slack_secret_name
      data = {
        (var.slack_secret_key) = var.slack_webhook_url
      }
    }
  }
}

data "kubernetes_secret" "argocd_initial_admin" {
  depends_on = [helm_release.argocd]
  metadata {
    name      = "argocd-initial-admin-secret"
    namespace = "argocd"
  }
}

data "pagerduty_user" "me" {
  email = var.pagerduty_user_email
}

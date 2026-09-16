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

  zone_id = one(data.cloudflare_zones.this.result).id

  fqdn = "${var.hostname}.${var.domain}"

  github_oidc_url = "https://token.actions.githubusercontent.com"

  github_pr_subject = format(
    "repo:%s/%s:pull_request",
    var.github_owner,
    var.github_repository
  )
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

data "cloudflare_zones" "this" {
  name = var.domain

  account = {
    id = var.cloudflare_account_id
  }
}

data "tls_certificate" "github_actions" {
  url = local.github_oidc_url
}

data "aws_iam_policy_document" "github_actions_pr_validation" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRoleWithWebIdentity"
    ]

    principals {
      type = "Federated"

      identifiers = [
        aws_iam_openid_connect_provider.github_actions.arn
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"

      values = [
        "sts.amazonaws.com"
      ]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"

      values = [
        local.github_pr_subject
      ]
    }
  }
}

data "aws_iam_policy_document" "github_actions_pr_validation_eks" {
  statement {
    sid    = "DescribeEksCluster"
    effect = "Allow"

    actions = [
      "eks:DescribeCluster"
    ]

    resources = [
      module.eks.cluster_arn
    ]
  }
}

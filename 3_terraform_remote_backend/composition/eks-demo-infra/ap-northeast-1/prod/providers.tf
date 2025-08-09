########################################
# Provider to connect to AWS
# https://www.terraform.io/docs/providers/aws/
########################################
provider "aws" {
  region = var.region
  # profile = var.profile_name

  assume_role {
    role_arn = "arn:aws:iam::${var.account_id}:role/${var.role_name}"
  }
}

# In case of not creating the cluster, this will be an incompletely configured, unused provider, which poses no problem.
# ref: https://github.com/terraform-aws-modules/terraform-aws-eks/blob/v12.1.0/README.md#conditional-creation, https://github.com/terraform-aws-modules/terraform-aws-eks/issues/911
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}
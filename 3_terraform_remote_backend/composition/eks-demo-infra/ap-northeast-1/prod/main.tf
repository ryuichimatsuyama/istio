########################################
# VPC
########################################
module "vpc" {
  source = "../../../../infrastructure_modules/vpc" # using infra module VPC which acts like a facade to many sub-resources

  name                 = var.app_name
  cidr                 = var.cidr
  azs                  = var.azs
  private_subnets      = var.private_subnets
  public_subnets       = var.public_subnets
  database_subnets     = var.database_subnets
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support
  enable_nat_gateway   = var.enable_nat_gateway
  single_nat_gateway   = var.single_nat_gateway

  ## Public Security Group ##
  public_ingress_with_cidr_blocks = var.public_ingress_with_cidr_blocks

  ## Private Security Group ##
  # bastion EC2 not created yet
  # bastion_sg_id  = module.bastion.security_group_id

  ## Database security group ##
  # DB Controller EC2 not created yet
  # databse_computed_ingress_with_db_controller_source_security_group_id = module.db_controller_instance.security_group_id
  create_eks = var.create_eks
  # pass EKS worker SG to DB SG after creating EKS module at composition layer
  databse_computed_ingress_with_eks_worker_source_security_group_ids = local.databse_computed_ingress_with_eks_worker_source_security_group_ids

  # cluster_name = local.cluster_name

  ## Common tag metadata ##
  env      = var.env
  app_name = var.app_name
  tags     = local.vpc_tags
  region   = var.region
}

########################################
# EKS
########################################
module "eks" {
  source = "../../../../infrastructure_modules/eks"

  ## EKS ##
  create_eks                     = var.create_eks
  cluster_version                = var.cluster_version
  cluster_name                   = local.cluster_name
  cluster_endpoint_public_access = var.cluster_endpoint_public_access
  vpc_id                         = module.vpc.vpc_id
  subnets                        = module.vpc.private_subnets

  # note: either pass worker_groups or node_groups
  # this is for (EKSCTL API) unmanaged node group
  self_managed_node_groups = var.self_managed_node_groups

  # this is for (EKS API) managed node group
  eks_managed_node_groups = var.eks_managed_node_groups

  manage_aws_auth_configmap = var.manage_aws_auth_configmap
  create_aws_auth_configmap = var.create_aws_auth_configmap
  # add roles that can access K8s cluster
  aws_auth_roles = local.aws_auth_roles
  # add IAM users who can access K8s cluster
  aws_auth_users = var.aws_auth_users

  ## Common tag metadata ##
  env      = var.env
  app_name = var.app_name
  tags     = local.eks_tags
  region   = var.region
}
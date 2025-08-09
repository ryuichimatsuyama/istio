locals {
  tags = {
    Environment = var.env
    Application = var.app_name
    Terraform   = true
  }

  ## VPC ##
  vpc_name = "vpc-${var.region_tag[var.region]}-${var.env}-${var.app_name}"
  vpc_tags = merge(
    local.tags,
    tomap({
      "VPC-Name" = local.vpc_name
    })
  )

  # EKS module not created yet, so assign empty list
  databse_computed_ingress_with_eks_worker_source_security_group_ids = []
  # add three ingress rules from EKS worker SG to DB SG only when creating EKS cluster
  # databse_computed_ingress_with_eks_worker_source_security_group_ids = var.create_eks ? [
  #   {
  #     rule                     = "mongodb-27017-tcp"
  #     source_security_group_id = module.eks.worker_security_group_id
  #     description              = "mongodb-27017 from EKS SG in private subnet"
  #   },
  #   {
  #     rule                     = "mongodb-27018-tcp"
  #     source_security_group_id = module.eks.worker_security_group_id
  #     description              = "mongodb-27018 from EKS SG in private subnet"

  #   },
  #   {
  #     rule                     = "mongodb-27019-tcp"
  #     source_security_group_id = module.eks.worker_security_group_id
  #     description              = "mongodb-27019 from EKS SG in private subnet"
  #   }
  # ] : []
}
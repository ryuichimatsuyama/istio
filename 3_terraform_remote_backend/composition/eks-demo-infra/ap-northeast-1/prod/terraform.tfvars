########################################
# Environment setting
########################################
region           = "ap-northeast-1"

########################################
# VPC
########################################
enable_nat_gateway   = "true" # need internet connection for worker nodes in private subnets to be able to join the cluster 
single_nat_gateway   = "true"
public_subnet_tags = {
  "kubernetes.io/role/elb" = 1
}

private_subnet_tags = {
  "kubernetes.io/role/internal-elb" = 1
}

########################################
# EKS
########################################
kubernetes_version                = 1.33
endpoint_public_access = true

enable_cluster_creator_admin_permissions = true

compute_config = {
  enabled    = true
  node_pools = ["general-purpose"]
}

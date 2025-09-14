module "key_pair" {
  source = "../../resource_modules/compute/ec2_key_pair"

  key_name   = local.key_pair_name
  public_key = local.public_key
}

# ref: https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/examples/complete/main.tf#L5-L33
module "eks_cluster" {
  source = "../../resource_modules/container/eks"

  create = var.create_eks

  name                   = var.cluster_name
  kubernetes_version                = var.cluster_version
  endpoint_public_access = var.cluster_endpoint_public_access

  enabled_cluster_log_types = var.enabled_cluster_log_types
  cloudwatch_log_group_retention_in_days = var.cluster_log_retention_in_days

  # WARNING: changing this will force recreating an entire EKS cluster!!!
  # enable k8s secret encryption using AWS KMS. Ref: https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/examples/secrets_encryption/main.tf#L88
  encryption_config = {
    provider_key_arn = module.k8s_secret_kms_key.arn
    resources        = ["secrets"]
  }

  vpc_id     = var.vpc_id
  subnet_ids = var.subnets

  # Self Managed Node Group(s)
  # self_managed_node_groups takes precedence to self_managed_node_group_defaults
  self_managed_node_groups = local.self_managed_node_groups

  # Extend node-to-node security group rules. Ref: https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/examples/self_managed_node_group/main.tf#L78
  # WARNING: need this for metrics-server to work, asn well as istio ingress/egress's readiness to work at http://:15021/healthz/ready. Ref: https://github.com/kubernetes-sigs/metrics-server/issues/1024#issuecomment-1124870217
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    },
    egress_all = {
      description = "Node to all ports/protocols" # WARNING: need this for egress to mongoDB 27017-27019
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    },
    ingress_cluster_api_ephemeral_ports_tcp = {
      description                   = "Cluster API to K8S services running on nodes"
      protocol                      = "tcp"
      from_port                     = 1025
      to_port                       = 65535
      type                          = "ingress"
      source_cluster_security_group = true
    },
  }

  # WARNING: needs this to allow kubeseal to work. Ref: https://github.com/bitnami-labs/sealed-secrets/issues/699#issuecomment-1064424553
  security_group_additional_rules = {
    egress_nodes_ephemeral_ports_tcp = {
      description                = "Cluster API to K8S services running on nodes"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "egress"
      source_node_security_group = true
    }
  }

  tags = var.tags

  addons = var.addons
}

# IRSA ##
module "cluster_autoscaler_iam_assumable_role" {
  source = "../../resource_modules/identity/iam/iam-assumable-role-with-oidc"

  create_role                   = var.create_eks ? true : false
  role_name                     = local.cluster_autoscaler_iam_role_name
  provider_url                  = replace(module.eks_cluster.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns              = [module.cluster_autoscaler_iam_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:${var.cluster_autoscaler_service_account_namespace}:${var.cluster_autoscaler_service_account_name}"] # <------- IRSA for Cluster Autoscaler pod by specifying namespace and service account 
}

module "cluster_autoscaler_iam_policy" {
  source = "../../resource_modules/identity/iam/iam-policy"

  create_policy = var.create_eks ? true : false
  description   = local.cluster_autoscaler_iam_policy_description
  name          = local.cluster_autoscaler_iam_policy_name
  path          = local.cluster_autoscaler_iam_policy_path
  policy        = data.aws_iam_policy_document.cluster_autoscaler.json
}

module "efs_irsa_iam_assumable_role" {
  source = "../../resource_modules/identity/iam/iam-assumable-role-with-oidc"

  create_role  = var.create_eks ? true : false
  role_name    = local.efs_irsa_iam_role_name
  provider_url = replace(module.eks_cluster.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns = [module.efs_csi_iam_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:${var.efs_irsa_service_account_namespace}:${var.efs_irsa_service_account_name}"]
}

module "efs_csi_iam_policy" {
  source = "../../resource_modules/identity/iam/iam-policy"

  create_policy = var.create_eks ? true : false
  description   = local.efs_csi_iam_policy_description
  name          = local.efs_csi_iam_policy_name
  path          = local.efs_csi_iam_policy_path
  policy        = data.aws_iam_policy_document.efs_csi.json
}

########################################
## KMS for K8s secret's DEK (data encryption key) encryption
########################################
module "k8s_secret_kms_key" {
  source = "../../resource_modules/identity/kms_key"

  name                    = local.k8s_secret_kms_key_name
  description             = local.k8s_secret_kms_key_description
  deletion_window_in_days = local.k8s_secret_kms_key_deletion_window_in_days
  tags                    = local.k8s_secret_kms_key_tags
  policy                  = data.aws_iam_policy_document.k8s_api_server_decryption.json
  enable_key_rotation     = true
}

module "efs_security_group" {
  source = "../../resource_modules/compute/security_group" # <----- SGモデュールを再利用

  name        = local.efs_security_group_name
  description = local.efs_security_group_description
  vpc_id      = var.vpc_id

  ingress_with_cidr_blocks                                 = local.efs_ingress_with_cidr_blocks
  computed_ingress_with_cidr_blocks                        = local.efs_computed_ingress_with_cidr_blocks
  number_of_computed_ingress_with_cidr_blocks              = local.efs_number_of_computed_ingress_with_cidr_blocks
  computed_ingress_with_source_security_group_id           = local.efs_computed_ingress_with_source_security_group_id
  number_of_computed_ingress_with_source_security_group_id = local.efs_computed_ingress_with_source_security_group_count

  egress_rules = ["all-all"]

  tags = local.efs_security_group_tags
}

module "efs" {
  source = "../../resource_modules/storage/efs"

  ## EFS FILE SYSTEM ## 
  encrypted = local.efs_encrypted # <----EFSのデータを暗号化するか
  tags      = local.efs_tags

  ## EFS MOUNT TARGET ## 
  mount_target_subnet_ids = var.efs_mount_target_subnet_ids  # <----EFSをどのSubnet内に作成するか（Private subnetがベスト）
  security_group_ids      = [module.efs_security_group.this_security_group_id] # <----EFSに関連づけるSGのリスト
}
## EKS ## 
variable "create_eks" {}
variable "cluster_version" {
  description = "Kubernetes version to use for the EKS cluster."
  type        = string
}
variable "cluster_name" {}
variable "cluster_endpoint_public_access" {
  description = "Indicates whether or not the Amazon EKS public API server endpoint is enabled"
}

variable "subnets" {
  type = list(string)
}

variable "vpc_id" {}

variable "worker_groups" {
  type    = any
  default = []
}
variable "self_managed_node_groups" {
  description = "Map of self-managed node group definitions to create"
  type        = any
  default     = {}
}

variable "eks_managed_node_groups" {
  description = "Map of EKS managed node group definitions to create"
  type        = any
  default     = {}
}

variable "create_aws_auth_configmap" {
  description = "Determines whether to create the aws-auth configmap. NOTE - this is only intended for scenarios where the configmap does not exist (i.e. - when using only self-managed node groups). Most users should use `manage_aws_auth_configmap`"
  type        = bool
  default     = false
}

variable "manage_aws_auth_configmap" {
  description = "Determines whether to manage the aws-auth configmap"
  type        = bool
  default     = false
}

variable "aws_auth_accounts" {
  description = "Additional AWS account numbers to add to the aws-auth configmap."
  type        = list(string)
  default = [
    "777777777777",
    "888888888888",
  ]
}

variable "aws_auth_roles" {
  description = "List of role maps to add to the aws-auth configmap"
  type        = list(any)
  default     = []
}

variable "worker_additional_security_group_ids" {
  description = "A list of additional security group ids to attach to worker instances"
  type        = list(string)
  default     = []
}

variable "aws_auth_users" {
  description = "List of user maps to add to the aws-auth configmap"
  type        = list(any)
  default     = []
}

variable "enable_irsa" {
  description = "Whether to create OpenID Connect Provider for EKS to enable IRSA"
  default     = false
}

variable "enabled_cluster_log_types" {
  default     = []
  description = "A list of the desired control plane logging to enable. For more information, see Amazon EKS Control Plane Logging documentation (https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)"
  type        = list(string)
}

variable "cluster_log_retention_in_days" {
  default     = 90
  description = "Number of days to retain log events. Default retention - 90 days."
  type        = number
}

## Metatada ##
variable "region" {
}

variable "env" {
}

variable "app_name" {
}

variable "tags" {
  type = map(string)
}

variable "region_tag" {
  type = map(any)

  default = {
    "us-east-1"      = "ue1"
    "us-west-1"      = "uw1"
    "eu-west-1"      = "ew1"
    "eu-central-1"   = "ec1"
    "ap-northeast-1" = "apne1"
  }
}

variable "environment_tag" {
  type = map(any)

  default = {
    "prod"    = "prod"
    "qa"      = "qa"
    "staging" = "staging"
    "dev"     = "dev"
  }
}

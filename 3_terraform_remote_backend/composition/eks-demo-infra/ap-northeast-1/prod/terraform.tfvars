########################################
# Environment setting
########################################
region           = "ap-northeast-1"
account_id       = "038314702298"
role_name        = "Admin"
profile_name     = "aws-demo"
env              = "prod"
application_name = "terraform-eks"
app_name         = "terraform-eks"

########################################
# VPC
########################################
cidr                 = "10.1.0.0/16"
azs                  = ["ap-northeast-1a", "ap-northeast-1c", "ap-northeast-1d"]
public_subnets       = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"] # 256 IPs per subnet
private_subnets      = ["10.1.101.0/24", "10.1.102.0/24", "10.1.103.0/24"]
database_subnets     = ["10.1.105.0/24", "10.1.106.0/24", "10.1.107.0/24"]
enable_dns_hostnames = "true"
enable_dns_support   = "true"
enable_nat_gateway   = "true" # need internet connection for worker nodes in private subnets to be able to join the cluster 
single_nat_gateway   = "true"


## Public Security Group ##
public_ingress_with_cidr_blocks = []

create_eks = true

########################################
# EKS
########################################
cluster_version                = 1.28
cluster_endpoint_public_access = true # need this otherwise can't access EKS from outside VPC. Ref: https://github.com/terraform-aws-modules/terraform-aws-eks#input_cluster_endpoint_public_access

# if set to true, AWS IAM Authenticator will use IAM role specified in "role_name" to authenticate to a cluster
authenticate_using_role = true

# if set to true, AWS IAM Authenticator will use AWS Profile name specified in profile_name to authenticate to a cluster instead of access key and secret access key
authenticate_using_aws_profile = false

# add other IAM users who can access a K8s cluster (by default, the IAM user who created a cluster is given access already)
aws_auth_users = []

# WARNING: mixing managed and unmanaged node groups will render unmanaged nodes to be unable to connect to internet & join the cluster when restarting.
# how many groups of K8s worker nodes you want? Specify at least one group of worker node
# gotcha: managed node group doesn't support 1) propagating taint to K8s nodes and 2) custom userdata. Ref: https://eksctl.io/usage/eks-managed-nodes/#feature-parity-with-unmanaged-nodegroups
node_groups = {
  # staging = {
  #   desired_capacity = 1
  #   max_capacity     = 3
  #   min_capacity     = 1

  #   instance_type = "m3.large"
  #   k8s_labels = {
  #     env = "staging"
  #     managed-node = "true"
  #     GithubRepo  = "terraform-aws-eks"
  #     GithubOrg   = "terraform-aws-modules"
  #   }
  #   additional_tags = {
  #     "k8s.io/cluster-autoscaler/managed-node" = "true",
  #     "k8s.io/cluster-autoscaler/enabled" = "true",
  #     "k8s.io/cluster-autoscaler/node-template/taint/staging-only" = "true:PreferNoSchedule" # currently managed group can't assign taint to nodes from tags. Ref: https://eksctl.io/usage/eks-managed-nodes/#feature-parity-with-unmanaged-nodegroups
  #   }
  # },
}

# note (only for unmanaged node group)
# gotcha: need to use kubelet_extra_args to propagate taints/labels to K8s node, because ASG tags not being propagated to k8s node objects.
# ref: https://github.com/kubernetes/autoscaler/issues/1793#issuecomment-517417680
# ref: https://github.com/kubernetes/autoscaler/issues/2434#issuecomment-576479025
# example: https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/examples/self_managed_node_group/main.tf#L102-L194
self_managed_node_groups = {
  prod = {
    name          = "worker-group-prod-1"
    instance_type = "t3.medium" # since we are using AWS-VPC-CNI, allocatable pod IPs are defined by instance size: https://docs.google.com/spreadsheets/d/1MCdsmN7fWbebscGizcK6dAaPGS-8T_dYxWp0IdwkMKI/edit#gid=1549051942, https://github.com/awslabs/amazon-eks-ami/blob/master/files/eni-max-pods.txt
    max_size      = 1
    min_size      = 1
    desired_size  = 1 # this will be ignored if cluster autoscaler is enabled: asg_desired_capacity: https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/docs/autoscaling.md#notes
    # this userdata will 1) block access to metadata to avoid pods from using node's IAM instance profile, 2) create /mnt/efs and auto-mount EFS to it using fstab, 3) install AWS Inspector agent,  4) install SSM agent. Note: userdata script doesn't resolve shell variable defined within,
    # ref: https://docs.aws.amazon.com/eks/latest/userguide/restrict-ec2-credential-access.html
    # UPDATE: Datadog agent needs to ping the EC2 metadata endpoint to retrieve the instance id and resolve duplicated hosts to be a single host, and currently no altenative solution so need to allow access to instance metadata unfortunately otherwise infra hosts get counted twice
    # additional_userdata = "yum install -y iptables-services; iptables --insert FORWARD 1 --in-interface eni+ --destination 169.254.169.254/32 --jump DROP; iptables-save | tee /etc/sysconfig/iptables; systemctl enable --now iptables; sudo mkdir /mnt/efs; sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport fs-02940981.efs.us-east-1.amazonaws.com:/ /mnt/efs; echo 'fs-02940981.efs.us-east-1.amazonaws.com:/ /mnt/efs nfs defaults,vers=4.1 0 0' >> /etc/fstab; sudo yum install -y https://s3.us-east-1.amazonaws.com/amazon-ssm-us-east-1/latest/linux_amd64/amazon-ssm-agent.rpm; sudo systemctl enable amazon-ssm-agent; sudo systemctl start amazon-ssm-agent"
    # escape double qoute in TF variable to avoid /bin/bash not found error when executing install-linx.sh. Ref: https://discuss.hashicorp.com/t/how-can-i-escape-double-quotes-in-a-variable-value/4697/2
    
    # use KMS key to encrypt EKS worker node's root EBS volumes
    # ref: https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/examples/self_managed_node_group/main.tf#L204C11-L215
    block_device_mappings = {
      xvda = {
        device_name = "/dev/xvda"
        ebs = {
          volume_size = 100
          volume_type = "gp3"
          encrypted   = true
          delete_on_termination = true
        }
      }
    }

    ami_type = "AL2_x86_64"
    #bootstrap_extra_args = "--kubelet-extra-args '--node-labels=env=prod,unmanaged-node=true,k8s_namespace=prod --register-with-taints=prod-only=true:NoSchedule'" # for unmanaged nodes, taints and labels work only with extra-arg, not ASG tags. Ref: https://aws.amazon.com/blogs/opensource/improvements-eks-worker-node-provisioning/
    
    # this userdata will 1) block access to metadata to avoid pods from using node's IAM instance profile, 2) create /mnt/efs and auto-mount EFS to it using fstab, 3) install AWS Inspector agent, 4) install SSM agent. Note: userdata script doesn't resolve shell variable defined within
    # UPDATE: Datadog agent needs to ping the EC2 metadata endpoint to retrieve the instance id and resolve duplicated hosts to be a single host, and currently no altenative solution so need to allow access to instance metadata unfortunately otherwise infra hosts get counted twice
    #additional_userdata = "yum install -y iptables-services; iptables --insert FORWARD 1 --in-interface eni+ --destination 169.254.169.254/32 --jump DROP; iptables-save | tee /etc/sysconfig/iptables; systemctl enable --now iptables; sudo mkdir /mnt/efs; sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport fs-02940981.efs.us-east-1.amazonaws.com:/ /mnt/efs; echo 'fs-02940981.efs.us-east-1.amazonaws.com:/ /mnt/efs nfs defaults,vers=4.1 0 0' >> /etc/fstab; sudo yum install -y https://s3.us-east-1.amazonaws.com/amazon-ssm-us-east-1/latest/linux_amd64/amazon-ssm-agent.rpm; sudo systemctl enable amazon-ssm-agent; sudo systemctl start amazon-ssm-agent"
    # escape double qoute in TF variable to avoid /bin/bash not found error when executing install-linx.sh. Ref: https://discuss.hashicorp.com/t/how-can-i-escape-double-quotes-in-a-variable-value/4697/2
    post_bootstrap_user_data = <<-EOT
    # mount EFS
    sudo mkdir /mnt/efs; sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport fs-0c95bfffb1f408743.efs.ap-northeast-1.amazonaws.com:/ /mnt/efs; echo 'fs-0c95bfffb1f408743.efs.ap-northeast-1.amazonaws.com:/ /mnt/efs nfs defaults,vers=4.1 0 0' >> /etc/fstab;
    EOT

    tags = {
      "unmanaged-node"                    = "true"
      "k8s.io/cluster-autoscaler/enabled" = "true" # need this tag so clusterautoscaler auto-discovers node group: https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/docs/autoscaling.md
      "k8s_namespace"                     = "prod"
      "env"                               = "prod"
    }
  },
}

manage_aws_auth_configmap = true
create_aws_auth_configmap = true

enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

## IRSA (IAM role for service account) ##
cluster_autoscaler_service_account_namespace = "kube-system"
cluster_autoscaler_service_account_name      = "cluster-autoscaler-aws-cluster-autoscaler"
efs_irsa_service_account_namespace                = "kube-system"
efs_irsa_service_account_name                     = "efs-csi-controller-sa"

addons = {
    coredns                = {}
    kube-proxy             = {}
    aws-efs-csi-driver     = {} 
    vpc-cni                = {
      before_compute = true
    }
  }
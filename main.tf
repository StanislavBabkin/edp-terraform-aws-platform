# ====================================================== #
# Create the AWS IAM role: EKSDeployerRole to deploy EKS #
# ====================================================== #

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "deployer" {
  name                  = var.deployer_role_name
  description           = "IAM role to assume in order to deploy and manage EKS cluster"
  assume_role_policy    = data.aws_iam_policy_document.assume_role_policy.json
  force_detach_policies = true
  permissions_boundary  = var.iam_permissions_boundary_policy_arn

  inline_policy {
    name = "EKSDeployer"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "acm:*",
            "autoscaling:AttachInstances",
            "autoscaling:AttachLoadBalancers",
            "autoscaling:AttachLoadBalancerTargetGroups",
            "autoscaling:CreateAutoScalingGroup",
            "autoscaling:CreateLaunchConfiguration",
            "autoscaling:CreateOrUpdateTags",
            "autoscaling:DeleteAutoScalingGroup",
            "autoscaling:DeleteLaunchConfiguration",
            "autoscaling:DeleteTags",
            "autoscaling:Describe*",
            "autoscaling:DetachInstances",
            "autoscaling:DetachLoadBalancers",
            "autoscaling:DetachLoadBalancerTargetGroups",
            "autoscaling:SetDesiredCapacity",
            "autoscaling:UpdateAutoScalingGroup",
            "autoscaling:SuspendProcesses",
            "ec2:AllocateAddress",
            "ec2:AssignPrivateIpAddresses",
            "ec2:Associate*",
            "ec2:AttachInternetGateway",
            "ec2:AttachNetworkInterface",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:CreateDefaultSubnet",
            "ec2:CreateDhcpOptions",
            "ec2:CreateEgressOnlyInternetGateway",
            "ec2:CreateInternetGateway",
            "ec2:CreateNatGateway",
            "ec2:CreateNetworkInterface",
            "ec2:CreateRoute",
            "ec2:CreateRouteTable",
            "ec2:CreateSecurityGroup",
            "ec2:CreateSubnet",
            "ec2:CreateTags",
            "ec2:CreateVolume",
            "ec2:CreateVpc",
            "ec2:CreateVpcEndpoint",
            "ec2:DeleteDhcpOptions",
            "ec2:DeleteEgressOnlyInternetGateway",
            "ec2:DeleteInternetGateway",
            "ec2:DeleteNatGateway",
            "ec2:DeleteNetworkInterface",
            "ec2:DeleteRoute",
            "ec2:DeleteRouteTable",
            "ec2:DeleteSecurityGroup",
            "ec2:DeleteSubnet",
            "ec2:DeleteTags",
            "ec2:DeleteVolume",
            "ec2:DeleteVpc",
            "ec2:DeleteVpnGateway",
            "ec2:Describe*",
            "ec2:DetachInternetGateway",
            "ec2:DetachNetworkInterface",
            "ec2:DetachVolume",
            "ec2:Disassociate*",
            "ec2:ModifySubnetAttribute",
            "ec2:ModifyVpcAttribute",
            "ec2:ModifyVpcEndpoint",
            "ec2:ReleaseAddress",
            "ec2:RevokeSecurityGroupEgress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
            "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
            "ec2:CreateLaunchTemplate",
            "ec2:CreateLaunchTemplateVersion",
            "ec2:DeleteLaunchTemplate",
            "ec2:DeleteLaunchTemplateVersions",
            "ec2:Describe*",
            "ec2:GetLaunchTemplateData",
            "ec2:ModifyLaunchTemplate",
            "ec2:RunInstances",
            "eks:CreateCluster",
            "eks:DeleteCluster",
            "eks:DescribeCluster",
            "eks:ListClusters",
            "eks:UpdateClusterConfig",
            "eks:UpdateClusterVersion",
            "eks:DescribeUpdate",
            "eks:TagResource",
            "eks:UntagResource",
            "eks:ListTagsForResource",
            "eks:CreateFargateProfile",
            "eks:DeleteFargateProfile",
            "eks:DescribeFargateProfile",
            "eks:ListFargateProfiles",
            "eks:CreateNodegroup",
            "eks:DeleteNodegroup",
            "eks:DescribeNodegroup",
            "eks:ListNodegroups",
            "eks:UpdateNodegroupConfig",
            "eks:UpdateNodegroupVersion",
            "elasticfilesystem:*",
            "elasticloadbalancing:*",
            "iam:AddRoleToInstanceProfile",
            "iam:AttachRolePolicy",
            "iam:CreateInstanceProfile",
            "iam:CreateOpenIDConnectProvider",
            "iam:CreateServiceLinkedRole",
            "iam:CreatePolicy",
            "iam:CreatePolicyVersion",
            "iam:CreateRole",
            "iam:DeleteInstanceProfile",
            "iam:DeleteOpenIDConnectProvider",
            "iam:DeletePolicy",
            "iam:DeletePolicyVersion",
            "iam:DeleteRole",
            "iam:DeleteRolePolicy",
            "iam:DeleteServiceLinkedRole",
            "iam:DetachRolePolicy",
            "iam:GetInstanceProfile",
            "iam:GetOpenIDConnectProvider",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:List*",
            "iam:PassRole",
            "iam:PutRolePolicy",
            "iam:RemoveRoleFromInstanceProfile",
            "iam:TagInstanceProfile",
            "iam:TagOpenIDConnectProvider",
            "iam:TagPolicy",
            "iam:TagRole",
            "iam:UnTagInstanceProfile",
            "iam:UntagOpenIDConnectProvider",
            "iam:UnTagPolicy",
            "iam:UnTagRole",
            "iam:UpdateAssumeRolePolicy",
            "logs:CreateLogGroup",
            "logs:DescribeLogGroups",
            "logs:DeleteLogGroup",
            "logs:ListTagsLogGroup",
            "logs:PutRetentionPolicy",
            "kms:CreateAlias",
            "kms:CreateGrant",
            "kms:CreateKey",
            "kms:DeleteAlias",
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:GetKeyRotationStatus",
            "kms:ListAliases",
            "kms:ListResourceTags",
            "kms:ScheduleKeyDeletion",
            "route53:*",
            "s3:*"
          ]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }

  inline_policy {
    name = "EKSIdentityProviderFullAccess"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "eks:DescribeIdentityProviderConfig",
            "eks:AssociateIdentityProviderConfig",
            "eks:ListIdentityProviderConfigs",
            "eks:DisassociateIdentityProviderConfig"
          ]
          Effect   = "Allow"
          Resource = "arn:aws:eks:*:${data.aws_caller_identity.current.account_id}:cluster/*"
        },
      ]
    })
  }

  tags = merge(var.tags, tomap({ "Name" = var.deployer_role_name }))
}

# ================================================================================== #
# Create the AWS IAM role: ServiceRoleForEKSWorkerNode to connect to the EKS cluster #
# ================================================================================== #

data "aws_iam_policy_document" "workers_assume_role_policy" {
  statement {
    sid = "EKSWorkerAssumeRole"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type        = "Service"
      identifiers = [local.ec2_principal]
    }
  }
}

resource "aws_iam_instance_profile" "workers" {
  name_prefix = local.worker_group_role_name
  role        = aws_iam_role.workers.name

  tags = merge(var.tags, tomap({ "Name" = local.worker_group_role_name }))

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "workers" {
  name                  = local.worker_group_role_name
  description           = "IAM role to be used by worker group nodes"
  assume_role_policy    = data.aws_iam_policy_document.workers_assume_role_policy.json
  permissions_boundary  = var.iam_permissions_boundary_policy_arn
  force_detach_policies = true
  tags                  = merge(var.tags, tomap({ "Name" = local.worker_group_role_name }))
}

resource "aws_iam_role_policy_attachment" "workers_AmazonEKSWorkerNodePolicy" {
  policy_arn = "${local.policy_arn_prefix}/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.workers.name
}

resource "aws_iam_role_policy_attachment" "workers_AmazonEKS_CNI_Policy" {
  policy_arn = "${local.policy_arn_prefix}/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.workers.name
}

resource "aws_iam_role_policy_attachment" "workers_AmazonSSMManagedInstanceCore" {
  policy_arn = "${local.policy_arn_prefix}/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.workers.name
}

resource "aws_iam_role_policy_attachment" "workers_AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = aws_iam_policy.workers_amazon_ec2_container_registry_read_only.arn
  role       = aws_iam_role.workers.name
}

resource "aws_iam_policy" "workers_amazon_ec2_container_registry_read_only" {
  name        = "${replace(title(var.platform_name), "-", "")}EC2ContainerRegistryReadOnly"
  description = "The read-only policy for ${var.platform_name} tenant registry"
  policy      = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:DescribeImages",
                "ecr:BatchGetImage",
                "ecr:GetLifecyclePolicy",
                "ecr:GetLifecyclePolicyPreview",
                "ecr:ListTagsForResource",
                "ecr:DescribeImageScanFindings"
            ],
            "Resource": [
                "arn:aws:ecr:${var.region}:602401143452:repository/*",
                "arn:aws:ecr:${var.region}:${local.aws_account_id}:repository/*"
            ]
        }
    ]
  })
}

# ====================== #
# Deploy AWS EKS Cluster #
# ====================== #

# module "vpc" {
#   source  = "terraform-aws-modules/vpc/aws"
#   version = "3.14.4"

#   name = var.platform_name

#   create_vpc = var.create_vpc

#   cidr            = var.platform_cidr
#   azs             = var.subnet_azs
#   private_subnets = var.private_cidrs
#   public_subnets  = var.public_cidrs

#   map_public_ip_on_launch = false
#   enable_dns_hostnames    = true
#   enable_dns_support      = true
#   enable_nat_gateway      = true
#   single_nat_gateway      = true
#   one_nat_gateway_per_az  = false

#   tags = var.tags
# }

# module "acm" {
#   source  = "terraform-aws-modules/acm/aws"
#   version = "4.0.1"

#   domain_name = var.platform_domain_name
#   zone_id     = data.aws_route53_zone.this.zone_id

#   subject_alternative_names = [
#     "*.${var.platform_name}.${var.platform_domain_name}",
#     "${var.platform_name}.${var.platform_domain_name}",
#   ]

#   wait_for_validation = true
#   validation_method   = "DNS"

#   tags = merge(var.tags, tomap({ "Name" = var.platform_name }))
# }

# module "alb" {
#   source  = "terraform-aws-modules/alb/aws"
#   version = "7.0.0"

#   name            = "${var.platform_name}-ingress-alb"
#   security_groups = compact(concat(tolist([local.default_security_group_id]), var.infrastructure_public_security_group_ids))
#   enable_http2    = false
#   subnets         = module.vpc.public_subnets
#   vpc_id          = module.vpc.vpc_id

#   http_tcp_listeners = [
#     {
#       port        = 80
#       protocol    = "HTTP"
#       action_type = "forward"
#     }
#   ]

#   https_listeners = [
#     {
#       port               = 443
#       protocol           = "HTTPS"
#       certificate_arn    = module.acm.acm_certificate_arn
#       target_group_index = 1
#       ssl_policy         = var.ssl_policy
#     }
#   ]

#   target_groups = local.target_groups
#   idle_timeout  = 300

#   tags = var.tags
# }

# module "elb" {
#   source  = "terraform-aws-modules/elb/aws"
#   version = "3.0.1"

#   create_elb = var.create_elb

#   name = format("%s-infra-external", var.platform_name)

#   subnets         = module.vpc.public_subnets
#   security_groups = compact(concat(tolist([local.default_security_group_id]), var.infrastructure_public_security_group_ids))
#   tags            = merge(var.tags, tomap({ "Name" = "${var.platform_name}-infra-external" }))
#   internal        = false
#   idle_timeout    = 300

#   listener = [
#     {
#       # ELB 443 port should point to nginx-ingress NodePort (32080) for HTTP traffic
#       instance_port      = "32080"
#       instance_protocol  = "http"
#       lb_port            = "443"
#       lb_protocol        = "https"
#       ssl_certificate_id = module.acm.acm_certificate_arn
#     },
#     {
#       # ELB 80 port should point to nginx-ingress NodePort (32080) for HTTP traffic
#       # gerrit requires 80 port to be openned, since it's used by gerrit-jenkins plugin
#       instance_port     = "32080"
#       instance_protocol = "http"
#       lb_port           = "80"
#       lb_protocol       = "http"
#     },
#     {
#       instance_port     = "30022"
#       instance_protocol = "tcp"
#       lb_port           = "30022" //Gerrit port
#       lb_protocol       = "tcp"
#     }
#   ]

#   health_check = {
#     target              = "TCP:22"
#     interval            = 30
#     healthy_threshold   = 2
#     unhealthy_threshold = 2
#     timeout             = 5
#   }
# }

# module "eks" {
#   source  = "terraform-aws-modules/eks/aws"
#   version = "17.24.0"

#   cluster_name    = var.platform_name
#   vpc_id          = module.vpc.vpc_id
#   subnets         = module.vpc.private_subnets
#   cluster_version = var.cluster_version
#   enable_irsa     = var.enable_irsa

#   manage_cluster_iam_resources = false
#   cluster_iam_role_name        = aws_iam_role.deployer.name
#   manage_worker_iam_resources  = false

#   cluster_create_security_group = false
#   cluster_security_group_id     = local.default_security_group_id
#   worker_create_security_group  = false
#   worker_security_group_id      = local.default_security_group_id

#   cluster_endpoint_private_access = true
#   write_kubeconfig                = false

#   worker_groups_launch_template = [
#     {
#       name                                     = "${var.platform_name}-on-demand"
#       override_instance_types                  = var.demand_instance_types
#       subnets                                  = [module.vpc.private_subnets[0]]
#       asg_min_size                             = var.demand_min_nodes_count
#       asg_max_size                             = var.demand_max_nodes_count
#       asg_desired_capacity                     = var.demand_desired_nodes_count
#       on_demand_percentage_above_base_capacity = 100
#       additional_userdata                      = var.add_userdata
#       kubelet_extra_args                       = "--node-labels=node.kubernetes.io/lifecycle=normal"
#       suspended_processes                      = ["AZRebalance", "ReplaceUnhealthy"]
#       public_ip                                = false
#       target_group_arns                        = module.alb.target_group_arns
#       load_balancers                           = [module.elb.elb_id]
#       root_volume_size                         = 50
#       enable_monitoring                        = false

#       iam_instance_profile_name = var.worker_iam_instance_profile_name
#       key_name                  = var.key_name
#     },
#     {
#       name                    = "${var.platform_name}-spot"
#       override_instance_types = var.spot_instance_types
#       subnets                 = [module.vpc.private_subnets[0]]
#       spot_instance_pools     = 3
#       asg_min_size            = var.spot_min_nodes_count
#       asg_max_size            = var.spot_max_nodes_count
#       asg_desired_capacity    = var.spot_desired_nodes_count
#       additional_userdata     = var.add_userdata
#       kubelet_extra_args      = "--node-labels=node.kubernetes.io/lifecycle=spot"
#       suspended_processes     = []
#       public_ip               = false
#       target_group_arns       = module.alb.target_group_arns
#       load_balancers          = [module.elb.elb_id]
#       root_volume_size        = 50
#       enable_monitoring       = false

#       iam_instance_profile_name = var.worker_iam_instance_profile_name
#       key_name                  = var.key_name
#     },
#   ]

#   map_users = var.map_users
#   map_roles = var.map_roles

#   tags = var.tags
# }

# module "records" {
#   source    = "terraform-aws-modules/route53/aws//modules/records"
#   version   = "2.9.0"
#   zone_name = var.platform_domain_name
#   records = [
#     {
#       name    = "*.${var.platform_name}"
#       type    = "CNAME"
#       ttl     = 300
#       records = [module.alb.lb_dns_name]
#     }
#   ]
# }
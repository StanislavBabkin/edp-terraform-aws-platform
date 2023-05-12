data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}

data "aws_security_group" "default" {
  vpc_id = module.vpc.vpc_id

  filter {
    name   = "group-name"
    values = ["default"]
  }
}

data "aws_route53_zone" "this" {
  name         = var.platform_domain_name
  private_zone = false
}

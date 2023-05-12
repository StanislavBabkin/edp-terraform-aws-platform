locals {
  aws_account_id = data.aws_caller_identity.current.account_id

  ec2_principal          = "ec2.${data.aws_partition.current.dns_suffix}"
  policy_arn_prefix      = "arn:${data.aws_partition.current.partition}:iam::aws:policy"
  worker_group_role_name = "ServiceRoleForEKS${replace(title(var.platform_name), "-", "")}WorkerNode"
}

locals {
  target_groups = [
    {
      "name"                 = "${var.platform_name}-infra-alb-http"
      "backend_port"         = "32080"
      "backend_protocol"     = "HTTP"
      "deregistration_delay" = "20"
      "health_check_matcher" = "404" # ingress default-backend response code
    },
    {
      "name"                 = "${var.platform_name}-infra-alb-https"
      "backend_port"         = "32443"
      "backend_protocol"     = "HTTPS"
      "deregistration_delay" = "20"
      "health_check_matcher" = "404" # ingress default-backend response code
    },
  ]

  default_security_group_id = data.aws_security_group.default.id
}



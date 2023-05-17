# Template file to use as an example to create terraform.tfvars file. Fill the gaps instead of <...>
# More details on each variable can be found in the variables.tf file

region = "eu-central-1" # mandatory

platform_name = "mdkz-rnd" # mandatory

role_arn = "" # role to assume to run terraform apply, isn't mandatory

iam_permissions_boundary_policy_arn = "" # mandatory

tags = {
  "SysName"      = "EPAM"
  "SysOwner"     = "MDKZ-RND"
  "Environment"  = "MDKZ-RND-demo"
  "CostCenter"   = "2023"
  "BusinessUnit" = "Maestro3-EDP"
  "Department"   = "MDKZ-RND"
  "user:tag"     = "TestEKS"
}

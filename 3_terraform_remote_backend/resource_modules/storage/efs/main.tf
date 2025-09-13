# Ref: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system
resource "aws_efs_file_system" "this" {
  creation_token = "terraform-efs"
  encrypted      = var.encrypted

  tags = var.tags

  lifecycle {
    prevent_destroy = "false" # run "terraform taint" to push this change if terraform doesn't pick it up by itself 
  }

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}

# Ref: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_mount_target
resource "aws_efs_mount_target" "this" {
  count = length(var.mount_target_subnet_ids)

  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = var.mount_target_subnet_ids[count.index]
  security_groups = var.security_group_ids
}
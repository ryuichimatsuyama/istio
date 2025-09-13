########################################
# EFS FILE SYSTEM
########################################
output "efs_id" {
  value = aws_efs_file_system.this.id
}

output "efs_arn" {
  value = aws_efs_file_system.this.arn
}

output "efs_dns_name" {
  value = aws_efs_file_system.this.dns_name
}

########################################
# EFS MOUNT TARGET
########################################
output "efs_mount_target_id" {
  value = aws_efs_mount_target.this.*.id
}

output "efs_mount_target_dns_name" {
  value = aws_efs_mount_target.this.*.dns_name
}

output "efs_mount_target_network_interface_id" {
  value = aws_efs_mount_target.this.*.network_interface_id
}
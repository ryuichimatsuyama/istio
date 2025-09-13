## EFS FILE SYSTEM ## 
variable "encrypted" {}

variable "tags" {
  type = map(any)
}

## EFS MOUNT TARGET ## 
variable "mount_target_subnet_ids" {
  type = list(any)
}
variable "security_group_ids" {
  type = list(any)
}
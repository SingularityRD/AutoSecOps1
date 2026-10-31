resource "aws_cloudwatch_log_group" "autosecops_log_group" {
  name              = "/ecs/${var.name_prefix}"
  retention_in_days = var.log_retention_in_days
}

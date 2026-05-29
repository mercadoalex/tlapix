# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "instance_public_ip" {
  description = "Public IP of the Tlapix demo instance"
  value       = var.use_spot_instance ? aws_spot_instance_request.tlapix[0].public_ip : aws_instance.tlapix[0].public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = var.use_spot_instance ? aws_spot_instance_request.tlapix[0].spot_instance_id : aws_instance.tlapix[0].id
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = var.key_pair_name == "" ? "ssh -i ${path.module}/tlapix-key.pem ubuntu@${var.use_spot_instance ? aws_spot_instance_request.tlapix[0].public_ip : aws_instance.tlapix[0].public_ip}" : "ssh -i <your-key.pem> ubuntu@${var.use_spot_instance ? aws_spot_instance_request.tlapix[0].public_ip : aws_instance.tlapix[0].public_ip}"
}

output "web_ui_url" {
  description = "URL for the Tlapix Web UI"
  value       = "http://${var.use_spot_instance ? aws_spot_instance_request.tlapix[0].public_ip : aws_instance.tlapix[0].public_ip}:8080"
}

output "prometheus_url" {
  description = "URL for the Prometheus metrics endpoint"
  value       = "http://${var.use_spot_instance ? aws_spot_instance_request.tlapix[0].public_ip : aws_instance.tlapix[0].public_ip}:9090/metrics"
}

output "estimated_hourly_cost" {
  description = "Estimated hourly cost for the instance"
  value       = var.use_spot_instance ? "~$0.025/hr (spot)" : "~$0.08/hr (on-demand)"
}

output "setup_log_command" {
  description = "Command to check the setup progress"
  value       = "ssh ... 'tail -f /var/log/tlapix-setup.log'"
}

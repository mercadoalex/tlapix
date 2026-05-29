# -----------------------------------------------------------------------------
# General
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "tlapix"
}

variable "environment" {
  description = "Environment name (demo, staging, prod)"
  type        = string
  default     = "demo"
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH into the instance"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this to your IP in production
}

variable "allowed_web_cidrs" {
  description = "CIDR blocks allowed to access the Web UI and Prometheus"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this to your IP in production
}

# -----------------------------------------------------------------------------
# Compute
# -----------------------------------------------------------------------------

variable "instance_type" {
  description = "EC2 instance type (t3.large recommended for Rust compilation)"
  type        = string
  default     = "t3.large"
}

variable "use_spot_instance" {
  description = "Use a spot instance to reduce costs (~70% cheaper)"
  type        = bool
  default     = true
}

variable "spot_max_price" {
  description = "Maximum hourly price for spot instance (empty = on-demand price)"
  type        = string
  default     = ""
}

variable "root_volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 30
}

variable "key_pair_name" {
  description = "Name of an existing EC2 key pair for SSH access (leave empty to create one)"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# TLS Simulation
# -----------------------------------------------------------------------------

variable "tls_server_count" {
  description = "Number of TLS servers to simulate (each with different cert properties)"
  type        = number
  default     = 4
}

variable "enable_pebble_acme" {
  description = "Enable Pebble (local ACME server) for renewal demos"
  type        = bool
  default     = true
}

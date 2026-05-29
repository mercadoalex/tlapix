# -----------------------------------------------------------------------------
# Security Groups
# -----------------------------------------------------------------------------

resource "aws_security_group" "tlapix" {
  name_prefix = "${var.project_name}-"
  description = "Security group for Tlapix demo instance"
  vpc_id      = aws_vpc.tlapix.id

  # SSH access
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  # Tlapix Web UI
  ingress {
    description = "Tlapix Web UI"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
  }

  # Prometheus metrics endpoint
  ingress {
    description = "Prometheus metrics"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
  }

  # Pebble ACME server (for demo access)
  ingress {
    description = "Pebble ACME"
    from_port   = 14000
    to_port     = 14000
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
  }

  # All outbound traffic
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# SSH Key Pair (created if not provided)
# -----------------------------------------------------------------------------

resource "tls_private_key" "tlapix" {
  count     = var.key_pair_name == "" ? 1 : 0
  algorithm = "ED25519"
}

resource "aws_key_pair" "tlapix" {
  count      = var.key_pair_name == "" ? 1 : 0
  key_name   = "${var.project_name}-key"
  public_key = tls_private_key.tlapix[0].public_key_openssh

  tags = {
    Name = "${var.project_name}-key"
  }
}

resource "local_file" "private_key" {
  count           = var.key_pair_name == "" ? 1 : 0
  content         = tls_private_key.tlapix[0].private_key_openssh
  filename        = "${path.module}/tlapix-key.pem"
  file_permission = "0600"
}

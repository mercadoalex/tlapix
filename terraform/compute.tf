# -----------------------------------------------------------------------------
# EC2 Instance — Tlapix Demo Server
# -----------------------------------------------------------------------------

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# On-demand instance (when spot is disabled)
resource "aws_instance" "tlapix" {
  count = var.use_spot_instance ? 0 : 1

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_pair_name != "" ? var.key_pair_name : aws_key_pair.tlapix[0].key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.tlapix.id]

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = base64encode(local.user_data_script)

  tags = {
    Name = "${var.project_name}-demo"
  }
}

# Spot instance (default — ~70% cheaper)
resource "aws_spot_instance_request" "tlapix" {
  count = var.use_spot_instance ? 1 : 0

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_pair_name != "" ? var.key_pair_name : aws_key_pair.tlapix[0].key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.tlapix.id]

  spot_type            = "one-time"
  wait_for_fulfillment = true

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = base64encode(local.user_data_script)

  tags = {
    Name = "${var.project_name}-demo-spot"
  }
}

# -----------------------------------------------------------------------------
# User Data Script — Installs everything Tlapix needs
# -----------------------------------------------------------------------------

locals {
  user_data_script = <<-EOF
    #!/bin/bash
    set -euo pipefail
    exec > /var/log/tlapix-setup.log 2>&1

    echo "=== Tlapix Demo Setup Starting ==="
    export DEBIAN_FRONTEND=noninteractive

    # System updates
    apt-get update -y
    apt-get upgrade -y

    # Install system dependencies
    apt-get install -y \
      build-essential \
      pkg-config \
      libssl-dev \
      libelf-dev \
      clang \
      llvm \
      linux-tools-$(uname -r) \
      linux-headers-$(uname -r) \
      docker.io \
      docker-compose-plugin \
      git \
      curl \
      jq \
      openssl \
      ca-certificates

    # Enable and start Docker
    systemctl enable docker
    systemctl start docker
    usermod -aG docker ubuntu

    # Install Rust (as ubuntu user)
    su - ubuntu -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
    su - ubuntu -c 'source ~/.cargo/env && rustup install nightly'
    su - ubuntu -c 'source ~/.cargo/env && rustup component add rust-src --toolchain nightly'

    # Install bpf-linker
    su - ubuntu -c 'source ~/.cargo/env && cargo install bpf-linker'

    # Clone Tlapix repository
    su - ubuntu -c 'git clone https://github.com/mercadoalex/tlapix.git ~/tlapix'

    # Create directories
    mkdir -p /etc/tlapix /opt/tlapix/models /var/lib/tlapix

    # Verify kernel supports eBPF
    echo "=== Kernel Version ==="
    uname -r
    echo "=== BPF Support ==="
    ls /sys/kernel/btf/vmlinux && echo "BTF: OK" || echo "BTF: NOT FOUND"

    # Build Tlapix (userspace only — eBPF build needs manual step)
    su - ubuntu -c 'source ~/.cargo/env && cd ~/tlapix && cargo build --release'

    echo "=== Tlapix Demo Setup Complete ==="
    echo ""
    echo "Next steps:"
    echo "  1. SSH in: ssh -i tlapix-key.pem ubuntu@<public-ip>"
    echo "  2. Build eBPF: cd ~/tlapix && cargo xtask build-ebpf --release"
    echo "  3. Run demo: cd ~/tlapix/demo && ./setup-ca.sh && ./issue-certs.sh"
    echo "  4. Start: docker compose up -d"
    echo ""
  EOF
}

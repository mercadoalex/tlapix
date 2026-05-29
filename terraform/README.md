# Tlapix Terraform — Demo Infrastructure

Provisions an EC2 instance (spot by default) with everything needed to run the Tlapix demo: Ubuntu 22.04, Rust toolchain, bpf-linker, Docker, and the Tlapix repository pre-cloned and built.

## Cost

| Mode | Hourly | Monthly (24/7) | Monthly (4 hrs/week) |
|------|--------|----------------|---------------------|
| Spot `t3.large` | ~$0.025 | ~$18 | ~$0.40 |
| On-demand `t3.large` | ~$0.08 | ~$60 | ~$1.30 |

**Typical usage: $1-5/month** (spin up for demos, shut down after).

## Quick Start

```bash
cd terraform

# 1. Copy and edit variables
cp terraform.tfvars.example terraform.tfvars
# Edit: set your IP in allowed_ssh_cidrs

# 2. Initialize and apply
terraform init
terraform apply

# 3. Wait ~5 minutes for setup to complete, then SSH in
ssh -i tlapix-key.pem ubuntu@$(terraform output -raw instance_public_ip)

# 4. On the instance: build eBPF and run demo
cd ~/tlapix
cargo xtask build-ebpf --release
cd demo
./setup-ca.sh
./issue-certs.sh
docker compose up -d

# 5. Access the Web UI from your browser
open $(terraform output -raw web_ui_url)
```

## Tear Down

```bash
terraform destroy
```

This removes everything (instance, VPC, security group, key pair). No lingering costs.

## Files

| File | Purpose |
|------|---------|
| `versions.tf` | Terraform and provider versions |
| `variables.tf` | All configurable inputs |
| `network.tf` | VPC, subnet, internet gateway, routing |
| `security.tf` | Security group, SSH key pair |
| `compute.tf` | EC2 instance (spot or on-demand), user data script |
| `outputs.tf` | IP addresses, URLs, SSH command |
| `terraform.tfvars.example` | Example variable values |

## What Gets Installed (User Data)

The instance bootstraps automatically with:
- Ubuntu 22.04 LTS (kernel 5.15+ with eBPF/BTF support)
- Rust stable + nightly toolchains
- `bpf-linker` for eBPF compilation
- Docker + Docker Compose plugin
- Build tools (clang, llvm, libelf, linux-headers)
- Tlapix repository cloned and built (userspace)
- OpenSSL for certificate generation

## Security Notes

- **Restrict `allowed_ssh_cidrs`** to your IP only (`curl ifconfig.me`)
- The generated SSH key (`tlapix-key.pem`) is saved locally — don't commit it
- The instance runs as a spot request — it may be interrupted (data on EBS persists)
- All EBS volumes are encrypted by default
- No IAM roles are attached (Tlapix doesn't need AWS API access for the demo)

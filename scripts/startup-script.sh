#!/bin/bash
set -e

# Redirect all output to log file
exec > >(tee -a /var/log/startup-script.log) 2>&1
echo "Starting SAM Host VM bootstrap..."

# Kill unattended-upgrades to avoid apt lock
systemctl stop unattended-upgrades.service || true
killall unattended-upgrades || true

# 1. Update and install packages
apt-get update
apt-get upgrade -y
apt-get install -y curl wget git iptables iproute2 socat jq build-essential docker.io acl

# 2. Check if nested virtualization is enabled
if [ ! -e /dev/kvm ]; then
    echo "ERROR: /dev/kvm not found! Nested virtualization is not enabled."
    exit 1
fi

# Ensure KVM permissions allow execution
chmod 0666 /dev/kvm

# 3. Install Firecracker v1.16.1
curl --retry 5 --retry-connrefused --retry-delay 5 -LO https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.1/firecracker-v1.16.1-x86_64.tgz
tar -xzf firecracker-v1.16.1-x86_64.tgz
mv release-v1.16.1-x86_64/firecracker-v1.16.1-x86_64 /usr/local/bin/firecracker
chmod +x /usr/local/bin/firecracker
rm -rf release-v1.16.1-x86_64 firecracker-v1.16.1-x86_64.tgz

# Enable IP forwarding (just in case we need it for TAP/NAT later)
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-ipforward.conf

# 4. Install SAM Mesh binaries & MicroVM files
# Check if custom binaries/rootfs were injected via GCP metadata (GCS URL)
BIN_URL=$(curl --retry 5 --retry-connrefused --retry-delay 5 -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/sam-binaries-url" || true)

if [ -n "$BIN_URL" ] && [ "$BIN_URL" != "null" ]; then
    echo "Found custom artifacts URL: $BIN_URL. Downloading from GCS..."
    # Download SAM binaries
    gcloud storage cp "$BIN_URL/sam-node" /usr/local/bin/
    gcloud storage cp "$BIN_URL/sam-box" /usr/local/bin/
    chmod +x /usr/local/bin/sam-*
    
    # Download the pre-built MicroVM rootfs
    mkdir -p /opt/microvm
    gcloud storage cp "$BIN_URL/rootfs.ext4" /opt/microvm/rootfs.ext4
    # Download the launch script and the collector that reports on the run
    gcloud storage cp "$BIN_URL/launch-microvms.sh" /opt/microvm/launch-microvms.sh
    gcloud storage cp "$BIN_URL/collect-fleet.sh" /opt/microvm/collect-fleet.sh || true
    chmod +x /opt/microvm/collect-fleet.sh 2>/dev/null || true
else
    echo "No custom binaries specified. Installing latest release from github..."
    export SAM_INSTALL_DIR=/usr/local/bin
    curl --retry 5 --retry-connrefused --retry-delay 5 -sL https://sam-mesh.dev/install.sh | bash
fi

# Download the uncompressed Linux kernel for Firecracker.
#
# It has to be one built with CONFIG_TUN. An agent sandbox has no network
# device and reaches the mesh through a tun, so a kernel without the driver
# gives it no route at all and its init exits before it can say why. The
# quickstart kernel this used to fetch does not have it, and neither do the
# 5.10 or 6.1 CI kernels; 6.18 does. Each image has its .config published
# beside it, so this is checkable rather than folklore.
mkdir -p /opt/microvm
FC_KERNEL_URL="${FC_KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260819-0a745def42dd-0/x86_64/debug/vmlinux-6.18.41}"
curl --retry 5 --retry-connrefused --retry-delay 5 -fsSL -o /opt/microvm/vmlinux.bin "${FC_KERNEL_URL}"

if ! strings /opt/microvm/vmlinux.bin | grep -q "Universal TUN/TAP"; then
    echo "FATAL: guest kernel has no TUN driver; agent sandboxes cannot build a route" >&2
    exit 1
fi

# Ensure launch script is executable (if it was downloaded via GCS)
chmod +x /opt/microvm/launch-microvms.sh || true

echo "SAM Host bootstrap finished successfully."

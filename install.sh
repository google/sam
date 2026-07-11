#!/usr/bin/env bash
set -e

REPO="google/sam"
INSTALL_DIR="/usr/local/bin"

echo "Installing SAM from $REPO..."

# Get OS and Arch
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_NAME="Linux";;
    Darwin*)    OS_NAME="Darwin";;
    *)          echo "Unsupported OS: ${OS}"; exit 1;;
esac

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64*)    ARCH_NAME="x86_64";;
    aarch64*)   ARCH_NAME="arm64";;
    arm64*)     ARCH_NAME="arm64";;
    *)          echo "Unsupported architecture: ${ARCH}"; exit 1;;
esac

# Get latest release version
echo "Fetching latest release information..."
LATEST_RELEASE_URL="https://api.github.com/repos/${REPO}/releases/latest"
VERSION=$(curl -s $LATEST_RELEASE_URL | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
    echo "Error: Could not find the latest release."
    exit 1
fi

echo "Found latest version: ${VERSION}"

# Construct download URL (matches goreleaser name template)
TAR_NAME="sam_${OS_NAME}_${ARCH_NAME}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TAR_NAME}"

# Create a temporary directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

echo "Downloading ${DOWNLOAD_URL}..."
if ! curl -sfL -o "${TAR_NAME}" "${DOWNLOAD_URL}"; then
    echo "Error: Failed to download ${DOWNLOAD_URL}"
    rm -rf "$TMP_DIR"
    exit 1
fi

echo "Extracting..."
tar -xzf "${TAR_NAME}"

echo "Installing to ${INSTALL_DIR} (may require sudo)..."
# In some environments, sudo might not be available or required
if [ -w "$INSTALL_DIR" ]; then
    mv sam-node sam-control-plane sam-router mcp-client "$INSTALL_DIR/" 2>/dev/null || true
else
    sudo mv sam-node sam-control-plane sam-router mcp-client "$INSTALL_DIR/" 2>/dev/null || true
fi

# Cleanup
cd - > /dev/null
rm -rf "$TMP_DIR"

echo "Successfully installed SAM (${VERSION}) to ${INSTALL_DIR}"
echo "Run 'sam-node --help' to get started."

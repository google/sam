#!/bin/bash
set -e

# The Dockerfile below copies repo-relative paths, so the build context has to
# be the repo root regardless of where this was invoked from.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Usage: ./scripts/build-rootfs.sh [GCS_URL]
GCS_URL=${1:-}

# The guest ships the canonical agent harness, not the chaos agent. The chaos
# agent is driven by a real model and is the right tool for asking whether the
# mesh survives an autonomous caller; it is the wrong one for a scale run,
# because it never issues the same request twice and needs model credentials
# inside the sandbox, which is the arrangement this design exists to avoid.
AGENT_SRC="${AGENT_SRC:-development/examples/agent-harness}"

echo "Building Alpine rootfs: python and ${AGENT_SRC}..."
cat << EOF > Dockerfile
FROM golang:1.26.5 AS init
WORKDIR /src
COPY cmd/nano-init/go.mod cmd/nano-init/go.sum ./
RUN go mod download
COPY cmd/nano-init/ ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /nano-init .

FROM alpine:3.18
# python for the agent, and nothing else. nano-init carries its own TCP stack
# and speaks netlink directly, so there is no tun2proxy to download, no socat
# and no iproute2. That also removes the last unverified binary from this
# image: tun2proxy arrived by curl from a GitHub release with no checksum.
RUN apk add --no-cache python3 py3-pip

COPY ${AGENT_SRC} /app/agent
RUN pip3 install --no-cache-dir -r /app/agent/requirements.txt --break-system-packages

COPY --from=init /nano-init /usr/local/bin/nano-init
RUN rm -f /sbin/init
COPY --chmod=755 scripts/microvm-init.sh /sbin/init
EOF

# Build the docker container
docker build -t agent-rootfs -f Dockerfile .
CONTAINER_ID=$(docker create agent-rootfs)
docker export $CONTAINER_ID > rootfs.tar
docker rm $CONTAINER_ID

# Create the ext4 image. The size is the agent's, not the base system's: the
# harness needs a couple of hundred megabytes and a LangChain agent needs well
# over a gigabyte, and an image that is too small fails during the copy rather
# than at boot, which is a confusing place to find out.
ROOTFS_MB="${ROOTFS_MB:-500}"
dd if=/dev/zero of=rootfs.ext4 bs=1M count="${ROOTFS_MB}"
mkfs.ext4 rootfs.ext4
mkdir -p /tmp/rootfs

# Use a privileged docker container to mount and populate the ext4 image without requiring sudo on the host
docker run --rm --privileged -v "$(pwd)":/work alpine sh -c '
    mkdir -p /mnt/rootfs
    mount /work/rootfs.ext4 /mnt/rootfs
    tar -xf /work/rootfs.tar -C /mnt/rootfs
    sync
    umount /mnt/rootfs || true
'

rm rootfs.tar Dockerfile
echo "Rootfs built successfully at rootfs.ext4"

if [ -n "$GCS_URL" ]; then
    echo "Uploading rootfs.ext4 to $GCS_URL..."
    gcloud storage cp rootfs.ext4 "$GCS_URL/rootfs.ext4"
    echo "Upload complete!"
fi

#!/bin/bash
set -e

VM_NAME_PREFIX="sam-minions"
ZONE="us-central1-a"
PROJECT="ipv6-project-379110"
GCS_URL=""
COUNT=1
MACHINE_TYPE="n2-standard-64"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --prefix) VM_NAME_PREFIX="$2"; shift ;;
        --zone) ZONE="$2"; shift ;;
        --project) PROJECT="$2"; shift ;;
        --local-binaries) GCS_URL="$2"; shift ;;
        --count) COUNT="$2"; shift ;;
        --machine-type) MACHINE_TYPE="$2"; shift ;;
        # Spot is the right default for a fleet of minions, and the wrong one for
        # a measurement: a run reclaimed halfway through produces no result and
        # costs the same as one that finished.
        --no-spot) SPOT=0 ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ "${SPOT:-1}" -eq 1 ]; then
    # Spot cannot migrate and must not be restarted for us; it goes away and the
    # run goes with it, which is the trade being made when spot is chosen.
    SCHEDULING="--provisioning-model=SPOT --preemption-notice-duration=0s --instance-termination-action=STOP --no-restart-on-failure --maintenance-policy=TERMINATE"
else
    # A standard instance can live-migrate, and must, or a routine host
    # maintenance window ends the experiment: that is what terminated a soak
    # here two hours in, on an instance that was deliberately not spot.
    SCHEDULING="--provisioning-model=STANDARD --restart-on-failure --maintenance-policy=MIGRATE"
fi

METADATA="enable-osconfig=TRUE"

if [ -n "$GCS_URL" ]; then
    echo "Building local binaries for injection..."
    # Make sure we build for Linux x86_64 since the VM is Debian x86_64
    GOOS=linux GOARCH=amd64 go build -o /tmp/sam-node ./cmd/sam-node
    GOOS=linux GOARCH=amd64 go build -o /tmp/sam-box ./cmd/sam-box
    
    echo "Uploading binaries to GCS: $GCS_URL"
    gcloud storage cp /tmp/sam-node "$GCS_URL/sam-node"
    gcloud storage cp /tmp/sam-box "$GCS_URL/sam-box"
    
    echo "Uploading rootfs.ext4 and launch script to GCS..."
    if [ ! -f "rootfs.ext4" ]; then
        echo "WARNING: rootfs.ext4 not found in current directory! Please run build-rootfs.sh first."
    else
        gcloud storage cp rootfs.ext4 "$GCS_URL/rootfs.ext4"
    fi
    gcloud storage cp scripts/launch-microvms.sh "$GCS_URL/launch-microvms.sh"
    # A run that cannot report on itself is not worth the machine it ran on.
    gcloud storage cp tests/scale/collect-fleet.sh "$GCS_URL/collect-fleet.sh"
    
    METADATA="enable-osconfig=TRUE,sam-binaries-url=$GCS_URL"
fi

echo "Provisioning $COUNT GCP Scale Experiment VM(s) with prefix '${VM_NAME_PREFIX}' in ${ZONE} (${PROJECT})..."

if [ "$COUNT" -eq 1 ]; then
    # Create a single instance
    gcloud beta compute instances create "${VM_NAME_PREFIX}-1" \
        --project="${PROJECT}" \
        --zone="${ZONE}" \
        --machine-type="${MACHINE_TYPE}" \
        --enable-nested-virtualization \
        --min-cpu-platform="Intel Ice Lake" \
        --network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default \
        --metadata="${METADATA}" \
        --metadata-from-file=startup-script=scripts/startup-script.sh \
        ${SCHEDULING} \
        --service-account=628944397724-compute@developer.gserviceaccount.com \
        --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/trace.append \
        --tags=http-server,https-server,lb-health-check \
        --create-disk=auto-delete=yes,boot=yes,image=projects/debian-cloud/global/images/debian-13-trixie-v20260817,mode=rw,size=250,type=pd-ssd \
        --no-shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring \
        --labels=goog-ops-agent-policy=v2-template-1-7-0,goog-ec-src=vm_add-gcloud \
        --reservation-affinity=none
else
    # Bulk create multiple instances
    gcloud beta compute instances bulk create \
        --name-pattern="${VM_NAME_PREFIX}-#" \
        --count="${COUNT}" \
        --project="${PROJECT}" \
        --zone="${ZONE}" \
        --machine-type="${MACHINE_TYPE}" \
        --enable-nested-virtualization \
        --min-cpu-platform="Intel Ice Lake" \
        --network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default \
        --metadata="${METADATA}" \
        --metadata-from-file=startup-script=scripts/startup-script.sh \
        ${SCHEDULING} \
        --service-account=628944397724-compute@developer.gserviceaccount.com \
        --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/trace.append \
        --tags=http-server,https-server,lb-health-check \
        --create-disk=auto-delete=yes,boot=yes,image=projects/debian-cloud/global/images/debian-13-trixie-v20260817,mode=rw,size=250,type=pd-ssd \
        --no-shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring \
        --labels=goog-ops-agent-policy=v2-template-1-7-0,goog-ec-src=vm_add-gcloud \
        --reservation-affinity=none
fi

echo "Successfully triggered VM creation. Applying Ops Agent policy..."

# Apply Ops Agent Policy for host-level monitoring
cat <<EOF > /tmp/ops-agent-config.yaml
agentsRule:
  packageState: installed
  version: latest
instanceFilter:
  inclusionLabels:
  - labels:
      goog-ops-agent-policy: v2-template-1-7-0
EOF

gcloud compute instances ops-agents policies create "goog-ops-agent-v2-template-1-7-0-${ZONE}" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --file=/tmp/ops-agent-config.yaml || echo "Warning: Ops Agent policy creation returned an error (it might already exist)."

echo ""
echo "Done! The VM ${VM_NAME} is booting. cloud-init is running in the background to install Firecracker, Go, and sam-box."
echo "You can view the cloud-init logs by SSHing into the VM and running:"
echo "  sudo tail -f /var/log/cloud-init-output.log"

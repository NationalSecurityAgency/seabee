#!/bin/bash
set -eu

### Notes ###
# This script is intended to run on a GitHub hosted ubuntu 24.04 runner

# Configuration
IMAGE_DIR="ci/qcow"
CLOUD_INIT="ci/ci-cloud-init.yml"
FEDORA_42="Fedora-Cloud-Base-Generic-42-1.1.x86_64.qcow2"
FEDORA_42_CHECKSUM="Fedora-Cloud-42-1.1-x86_64-CHECKSUM"
FEDORA_42_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/${FEDORA_42}"
FEDORA_42_CHECKSUM_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/${FEDORA_42_CHECKSUM}"

# Ensure root
if [ "$EUID" -ne 0 ]; then
  printf "Please run this script as root or sudo\n"
  exit
fi

# Install packages
apt-get update -y
apt-get install -y wget

# Download f42 if missing
mkdir -p $IMAGE_DIR
if [ ! -f "${IMAGE_DIR}/${FEDORA_42}" ]; then
  echo "Downloading ${FEDORA_42} ..."
  wget -c $FEDORA_42_URL
  wget $FEDORA_42_CHECKSUM_URL

  # Verify f42 image
  wget https://fedoraproject.org/fedora.gpg
  gpgv --keyring ./fedora.gpg $FEDORA_42_CHECKSUM
  sha256sum  --ignore-missing -c $FEDORA_42_CHECKSUM
  echo "${FEDORA_42} verified successfully!"

  # Cleanup
  mv $FEDORA_42 "${IMAGE_DIR}/${FEDORA_42}"
  rm $FEDORA_42_CHECKSUM
  rm fedora.gpg
else
  echo "Skipping download due to existing: ${FEDORA_42}"
fi

FEDORA_42="${IMAGE_DIR}/${FEDORA_42}"
###########################################

# Install QEMU deps
apt-get install -y --no-install-recommends \
  libguestfs-tools qemu-utils

# https://libguestfs.org/virt-customize.1.html#options
# install dependencies on the image, this may take 10+ minutes
virt-customize -a $FEDORA_42 --verbose --copy-in ./scripts:/ --run-command "bash -c 'DOCKER=1 /scripts/update_dependencies.sh'"
# export the image
qemu-img convert -O qcow2 $FEDORA_42 fedora-42.qcow2


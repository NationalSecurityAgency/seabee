#!/bin/bash
set -e

USE_APT=0
USE_DNF=0

if [ "$EUID" -ne 0 ]; then
  printf "Please run this script as root or sudo\n"
  exit
fi

# https://unix.stackexchange.com/a/577608
os_check() {
  ID=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d "\"")
  case $ID in
  ubuntu)
    USE_APT=1
    ;;
  fedora | rocky)
    USE_DNF=1
    ;;&
  *) ;;
  esac
}

install_system_packages() {
  printf "Installing tools and libraries needed for testing\n"
  local common_deps
  common_deps=(gcc make)
  if [ "$USE_APT" -eq 1 ]; then
    apt-get update
    apt-get --no-install-recommends -y install \
      "${common_deps[@]}" \
      libc-dev \
      linux-headers-generic \
      linux-tools-generic \
      xz-utils
  elif [ "$USE_DNF" -eq 1 ]; then
    dnf -y update
    dnf -y install \
      "${common_deps[@]}" \
      bpftool \
      kernel-devel-"$(uname -r)" \
      xz
  else
    printf "Your OS was not detected. Dependencies may not be installed.\n"
  fi
}

os_check
install_system_packages

printf "All test dependencies are up to date!\n"

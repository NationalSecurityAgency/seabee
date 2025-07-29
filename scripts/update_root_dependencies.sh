#!/bin/bash

TOP_DIR=$(dirname "$(dirname "$(realpath "$0" || true)")")

DOCKER_VERSION=24.0.7
DOCKER="${DOCKER:=0}"
USE_APT=0
USE_DNF=0
DISTRO="Unassigned"

if [ "$EUID" -ne 0 ]; then
  printf "Please run this script as root or sudo\n"
  exit
fi

# https://unix.stackexchange.com/a/567537
version_greater_equal() {
  printf '%s\n%s\n' "$2" "$1" | sort --check=quiet --version-sort
}

# https://unix.stackexchange.com/a/577608
os_check() {
  ID=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d "\"")
  case $ID in
  ubuntu)
    USE_APT=1
    DISTRO="ubuntu"
    ;;
  fedora)
    USE_DNF=1
    DISTRO="fedora"
    ;;
  rocky)
    USE_DNF=1
    DISTRO="rhel"
    # Install EPEL
    # https://www.redhat.com/en/blog/whats-epel-and-how-do-i-use-it
    dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
    ;;
  *) ;;
  esac
}

install_system_packages() {
  printf "Installing tools and libraries needed for development\n"
  # Warning: if one of 'common_deps' fails to install, they all fail to install
  local common_deps
  common_deps=(clang pipx python3 python3-pip strace)
  # depedencies necessary to build static libraries for libelf and zlib
  # which are dependencies of libbpf which is also built statically
  # openssl dependencies are also included
  local library_deps library_deps_deb library_deps_dnf
  library_deps=(autoconf automake bison flex gawk)
  library_deps_deb=("${library_deps[@]}" autopoint pkg-config perl)
  library_deps_dnf=("${library_deps[@]}" gettext-devel perl-core)
  if [ $USE_APT -eq 1 ]; then
    apt update
    apt install --no-install-recommends -y \
      "${common_deps[@]}" \
      "${library_deps_deb[@]}"
  elif [ $USE_DNF -eq 1 ]; then
    dnf update -y
    dnf install \
      "${common_deps[@]}" \
      "${library_deps_dnf[@]}"
  else
    printf "Your OS was not detected. Dependencies may not be installed.\n"
  fi
}

curl_check() {
  if ! command -v curl &>/dev/null; then
    printf "Attempting to install curl...\n"
    if [ $USE_APT -eq 1 ]; then
      apt install --no-install-recommends -y \
        ca-certificates \
        curl
    elif [ $USE_DNF -eq 1 ]; then
      dnf install curl
    else
      printf "Curl dependency cannot be satisfied with this script.\n"
    fi
  fi
}

docker_install() {
  printf "Attempting to install Docker...\n"
  if [ $USE_APT -eq 1 ]; then
    apt install --no-install-recommends -y ca-certificates gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl_check
    curl -fsSL https://download.docker.com/linux/"$DISTRO"/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    # shellcheck disable=SC1091
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO \
			$(. /etc/os-release && echo "$VERSION_CODENAME") stable" |
      tee /etc/apt/sources.list.d/docker.list >/dev/null
    apt update
    apt install --no-install-recommends -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif [ $USE_DNF -eq 1 ]; then
    dnf -y install dnf-plugins-core
    dnf config-manager --add-repo https://download.docker.com/linux/"$DISTRO"/docker-ce.repo
    dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl start docker
  else
    printf "Docker installation not supported for your OS.\n"
  fi
}

docker_check() {
  if [ "$DOCKER" -eq 1 ]; then
    return
  fi
  if ! command -v docker &>/dev/null; then
    docker_install
  elif ! version_greater_equal "$(docker --version | cut -d" " -f3 | cut -d"," -f1)" "$DOCKER_VERSION"; then
    printf "Attempting to uninstall distro provided Docker\n"
    if [ $USE_APT -eq 1 ]; then
      for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt remove $pkg; done
      docker_install
    elif [ $USE_DNF -eq 1 ]; then
      dnf remove docker \
        docker-client \
        docker-client-latest \
        docker-common \
        docker-latest \
        docker-latest-logrotate \
        docker-logrotate \
        docker-selinux \
        docker-engine-selinux \
        docker-engine
      docker_install
    else
      printf "Unable to uninstall distro-provided Docker\n"
    fi
  fi
  # if docker context ls | grep -q "rootless"; then
  # 	printf "Installing rootless docker...\n"
  # 	curl_check
  # 	curl -o rootless-install.sh -fsSL https://get.docker.com/rootless
  # 	FORCE_ROOTLESS_INSTALL=1 sh rootless-install.sh
  # 	rm rootless-install.sh
  # fi
}

os_check
install_system_packages
docker_check
curl_check
"$TOP_DIR"/scripts/update_test_dependencies.sh

printf "All root dependencies are up to date!\n"

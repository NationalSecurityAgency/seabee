#!/bin/bash

TOP_DIR=$(dirname "$(dirname "$(realpath "$0" || true)")")

ASCIINEMA_VERSION=2.4.0
POETRY_VERSION=1.8.3
PYTHON_VERSION=3.9

ASCIINEMA=asciinema
export DOCKER="${DOCKER:-0}"
POETRY=poetry
PYTHON=python3
RUSTUP="$HOME/.cargo/bin/rustup"

# Docker container doesn't have sudo
SUDO="sudo"
if [ "$DOCKER" -eq 1 ]; then
  SUDO=""
fi

if [ "$EUID" -eq 0 ] && [ "$DOCKER" -eq 0 ]; then
  printf "Please don't run this script as root or sudo\n"
  exit 1
fi

# https://unix.stackexchange.com/a/567537
version_greater_equal() {
  printf '%s\n%s\n' "$2" "$1" | sort --check=quiet --version-sort
}

python_check() {
  if ! command -v "$PYTHON" &>/dev/null || ! version_greater_equal "$($PYTHON --version | cut -d" " -f2)" $PYTHON_VERSION; then
    printf "Compatible Python version not detected\n"
    printf "Please install Python %s or newer\n" "$PYTHON_VERSION"
    exit
  fi
  if ! command -v "$POETRY" &>/dev/null || ! version_greater_equal "$($POETRY --version | cut -d" " -f3 | tr -d ')')" $POETRY_VERSION; then
    printf "Compatible version of Poetry not detected\n"
    pipx install --force poetry==$POETRY_VERSION
    pipx ensurepath
    # shellcheck disable=SC1091
    source "$HOME/.bashrc" && poetry completions bash >>~/.bash_completion
  fi
  if [ "$DOCKER" -eq 0 ] && ! command -v "$ASCIINEMA" &>/dev/null || ! version_greater_equal "$($ASCIINEMA --version | cut -d" " -f2)" $ASCIINEMA_VERSION; then
    printf "Compatible version of Asciinema not detected\n"
    pipx install --force asciinema==$ASCIINEMA_VERSION
    pipx ensurepath
  fi
  # shellcheck disable=SC1091
  source "$HOME/.bashrc" && poetry install
}

# install the latest stable verison of rust
rust_check() {
  if ! command -V "$RUSTUP" &>/dev/null; then
    printf "Rustup not detected. Installing...\n"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile default -y
  fi
  # Install rust lints
  rustup component add rustfmt clippy
}

autocast_check() {
  if [ "$DOCKER" -eq 0 ] && ! command -v autocast &>/dev/null; then
    cargo install --locked autocast
  fi
}

$SUDO "$TOP_DIR"/scripts/update_root_dependencies.sh
python_check
rust_check
autocast_check

printf "All dependencies are up to date!\n"

#!/bin/sh
# install.sh — install dependencies for ECIES + ECDSA project
#
# Usage:
#   ./install.sh          # auto-detect and install Docker (recommended)
#   ./install.sh --docker # install Docker explicitly
#   ./install.sh --native # install native build tools (GMP, OpenSSL, CMake, etc.)

set -e

MODE="docker"
if [ "$1" = "--native" ]; then
    MODE="native"
elif [ "$1" = "--docker" ]; then
    MODE="docker"
elif [ -n "$1" ]; then
    echo "Usage: $0 [--docker|--native]"
    exit 1
fi

# ── detect OS ─────────────────────────────────────────────────────────────────

detect_os() {
    if [ "$(uname)" = "Darwin" ]; then
        echo "macos"
    elif uname -r | grep -qi microsoft; then
        echo "wsl"
    elif [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)

# ── Docker install ────────────────────────────────────────────────────────────

install_docker() {
    if command -v docker >/dev/null 2>&1; then
        echo "Docker is already installed: $(docker --version)"
        exit 0
    fi

    case "$OS" in
        macos)
            echo "On macOS, install Docker Desktop from: https://www.docker.com/products/docker-desktop"
            echo "Or via Homebrew: brew install --cask docker"
            exit 0
            ;;
        wsl)
            curl -fsSL https://get.docker.com | sh
            ;;
        alpine)
            apk add --no-cache docker
            rc-update add docker default
            service docker start
            ;;
        debian)
            curl -fsSL https://get.docker.com | sh
            ;;
        *)
            echo "Unsupported OS. Install Docker manually: https://docs.docker.com/get-docker/"
            exit 1
            ;;
    esac

    echo "Docker installed: $(docker --version)"
}

# ── Native install ────────────────────────────────────────────────────────────

install_native() {
    case "$OS" in
        macos)
            if ! command -v brew >/dev/null 2>&1; then
                echo "Homebrew is required for native install on macOS."
                echo "Install it from: https://brew.sh"
                exit 1
            fi
            brew install cmake ninja gmp openssl
            ;;
        wsl)
            apt-get update
            apt-get install -y cmake ninja-build g++ git libgmp-dev libssl-dev
            ;;
        alpine)
            apk add --no-cache cmake ninja g++ git gmp-dev openssl-dev
            ;;
        debian)
            apt-get update
            apt-get install -y cmake ninja-build g++ git libgmp-dev libssl-dev
            ;;
        *)
            echo "Unsupported OS. Install manually: cmake ninja g++ git libgmp-dev libssl-dev"
            exit 1
            ;;
    esac

    echo "Native dependencies installed."
    echo "Build with: cmake -S . -B build -G Ninja && cmake --build build"
}

# ── run ───────────────────────────────────────────────────────────────────────

if [ "$MODE" = "docker" ]; then
    echo "Installing Docker on $OS..."
    install_docker
else
    echo "Installing native build dependencies on $OS..."
    install_native
fi

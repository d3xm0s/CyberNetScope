#!/usr/bin/env bash
# cybernetscope - one-shot setup: installs build deps, compiles, optionally installs.
#
#   ./install.sh            install deps and build into ./build
#   ./install.sh --install  also install system-wide (needs sudo)

set -euo pipefail

cd "$(dirname "$0")"

DO_INSTALL=0
[ "${1:-}" = "--install" ] && DO_INSTALL=1

say() { printf '[*] %s\n' "$1"; }
die() { printf '[!] %s\n' "$1" >&2; exit 1; }

install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        say "apt detected - installing build-essential cmake libssl-dev"
        sudo apt-get update -qq
        sudo apt-get install -y build-essential cmake libssl-dev
    elif command -v dnf >/dev/null 2>&1; then
        say "dnf detected - installing gcc-c++ cmake openssl-devel"
        sudo dnf install -y gcc-c++ cmake openssl-devel
    elif command -v yum >/dev/null 2>&1; then
        say "yum detected - installing gcc-c++ cmake openssl-devel"
        sudo yum install -y gcc-c++ cmake openssl-devel
    elif command -v pacman >/dev/null 2>&1; then
        say "pacman detected - installing base-devel cmake openssl"
        sudo pacman -Sy --needed --noconfirm base-devel cmake openssl
    elif command -v zypper >/dev/null 2>&1; then
        say "zypper detected - installing gcc-c++ cmake libopenssl-devel"
        sudo zypper install -y gcc-c++ cmake libopenssl-devel
    elif command -v brew >/dev/null 2>&1; then
        say "brew detected - installing cmake openssl"
        brew install cmake openssl
    elif command -v cmake >/dev/null 2>&1 && command -v g++ >/dev/null 2>&1; then
        say "no known package manager, but cmake and g++ already exist - skipping deps"
    else
        die "no supported package manager found (apt/dnf/yum/pacman/zypper/brew)"
    fi
}

install_deps

say "building"
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

if [ "$DO_INSTALL" -eq 1 ]; then
    say "installing to /usr/local (sudo)"
    sudo cmake --install build
    say "done - run: cybernetscope -u https://target"
else
    say "done - run: ./build/cybernetscope -u https://target"
fi

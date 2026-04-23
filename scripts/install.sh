# shellcheck shell=bash
# Shared binary installation helpers for UDS Maru tasks.
# Source this file -- do not execute it directly.
# Usage: source scripts/install.sh

# get_os: prints "linux" or "darwin"
get_os() {
  case "$(uname -s)" in
    Linux)  echo "linux" ;;
    Darwin) echo "darwin" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; return 1 ;;
  esac
}

# get_arch: prints "amd64" or "arm64"
get_arch() {
  case "$(uname -m)" in
    x86_64)        echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; return 1 ;;
  esac
}

# install_binary <name> <url>: downloads a single binary to $HOME/.local/bin
install_binary() {
  local name="$1" url="$2"
  mkdir -p "$HOME/.local/bin"
  curl -fSL "$url" -o "$HOME/.local/bin/$name"
  chmod +x "$HOME/.local/bin/$name"
  echo "$name installed to \$HOME/.local/bin/$name"
}

# install_from_tarball <name> <url> [inner_name]:
# extracts one binary from a .tar.gz and installs it to $HOME/.local/bin.
# inner_name defaults to <name> when omitted.
install_from_tarball() {
  local name="$1" url="$2" inner="${3:-$1}"
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  curl -fSL "$url" | tar -xz -C "$tmp" "$inner"
  mkdir -p "$HOME/.local/bin"
  mv "$tmp/$inner" "$HOME/.local/bin/$name"
  chmod +x "$HOME/.local/bin/$name"
  echo "$name installed to \$HOME/.local/bin/$name"
}

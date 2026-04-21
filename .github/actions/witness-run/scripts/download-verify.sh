#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Downloads the witness binary for the current platform, verifies it with
# cosign, writes the binary to $WITNESS_CACHE_DIR, and records its SHA256
# sidecar at $WITNESS_CACHE_DIR/witness.sha256.
#
# Required environment variables (all passed from action.yml env: blocks):
#   WITNESS_VERSION
#   WITNESS_CACHE_DIR
#   WITNESS_CERT_IDENTITY      (optional, defaults to official release workflow)
#   WITNESS_CERT_OIDC_ISSUER   (optional, defaults to actions issuer)

: "${WITNESS_VERSION:?WITNESS_VERSION is required}"
: "${WITNESS_CACHE_DIR:?WITNESS_CACHE_DIR is required}"

CERT_IDENTITY="${WITNESS_CERT_IDENTITY:-}"
CERT_ISSUER="${WITNESS_CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

# Validate version format
if ! [[ "$WITNESS_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::Invalid version format '$WITNESS_VERSION'. Expected MAJOR.MINOR.PATCH with no v prefix."
  exit 1
fi

# Default cert identity derived from version
if [[ -z "$CERT_IDENTITY" ]]; then
  CERT_IDENTITY="https://github.com/in-toto/witness/.github/workflows/release.yml@refs/tags/v${WITNESS_VERSION}"
fi

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="darwin" ;;
  *)
    echo "::error::Unsupported OS: $OS"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)  ARCH_NAME="amd64" ;;
  aarch64) ARCH_NAME="arm64" ;;
  arm64)   ARCH_NAME="arm64" ;;
  *)
    echo "::error::Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

ARTIFACT="witness_${WITNESS_VERSION}_${PLATFORM}_${ARCH_NAME}.tar.gz"
RELEASE_BASE="https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}"

TEMP_DIR="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TEMP_DIR'" EXIT

echo "Downloading witness ${WITNESS_VERSION} (${PLATFORM}/${ARCH_NAME})"

curl --fail --silent --show-error --location --max-time 60 \
  -o "$TEMP_DIR/$ARTIFACT" \
  "${RELEASE_BASE}/${ARTIFACT}"

curl --fail --silent --show-error --location --max-time 30 \
  -o "$TEMP_DIR/${ARTIFACT}.pem" \
  "${RELEASE_BASE}/${ARTIFACT}.pem"

curl --fail --silent --show-error --location --max-time 30 \
  -o "$TEMP_DIR/${ARTIFACT}.sig" \
  "${RELEASE_BASE}/${ARTIFACT}.sig"

echo "Verifying Sigstore signature with cosign"
cosign verify-blob \
  --certificate       "$TEMP_DIR/${ARTIFACT}.pem" \
  --signature         "$TEMP_DIR/${ARTIFACT}.sig" \
  --certificate-identity "$CERT_IDENTITY" \
  --certificate-oidc-issuer "$CERT_ISSUER" \
  "$TEMP_DIR/${ARTIFACT}"

echo "Sigstore verification passed"

mkdir -p "$WITNESS_CACHE_DIR"
tar -xzf "$TEMP_DIR/$ARTIFACT" -C "$WITNESS_CACHE_DIR"

# Write SHA256 sidecar so the cache-integrity check can re-verify without
# a network round-trip on subsequent runs.
sha256sum "$WITNESS_CACHE_DIR/witness" | awk '{print $1}' > "$WITNESS_CACHE_DIR/witness.sha256"

echo "Witness binary installed to $WITNESS_CACHE_DIR"

#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Downloads the witness binary to $WITNESS_BIN_DIR/witness and verifies its
# checksum. Optionally verifies the Sigstore signature if cosign is available.
#
# Optional env vars:
#   WITNESS_VERSION   — default: 0.9.2
#   WITNESS_BIN_DIR   — default: .bin (relative to the project root)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WITNESS_VERSION="${WITNESS_VERSION:-0.9.2}"
WITNESS_BIN_DIR="${WITNESS_BIN_DIR:-$PROJECT_ROOT/.bin}"

# Validate version format
if ! [[ "$WITNESS_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid WITNESS_VERSION '$WITNESS_VERSION'. Expected MAJOR.MINOR.PATCH with no v prefix." >&2
  exit 1
fi

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="darwin" ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)  ARCH_NAME="amd64" ;;
  aarch64) ARCH_NAME="arm64" ;;
  arm64)   ARCH_NAME="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

ARTIFACT="witness_${WITNESS_VERSION}_${PLATFORM}_${ARCH_NAME}.tar.gz"
RELEASE_BASE="https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}"

TEMP_DIR="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TEMP_DIR'" EXIT

echo "Downloading witness ${WITNESS_VERSION} (${PLATFORM}/${ARCH_NAME})"
echo "URL IS ${RELEASE_BASE}/${ARTIFACT}"
curl --fail --silent --show-error --location --max-time 60 \
  -o "$TEMP_DIR/$ARTIFACT" \
  "${RELEASE_BASE}/${ARTIFACT}"

CHECKSUMS_FILE="witness_${WITNESS_VERSION}_checksums.txt"
curl --fail --silent --show-error --location --max-time 30 \
  -o "$TEMP_DIR/$CHECKSUMS_FILE" \
  "${RELEASE_BASE}/$CHECKSUMS_FILE"

echo "Verifying checksum"
EXPECTED_SHA="$(grep "[[:space:]]${ARTIFACT}$" "$TEMP_DIR/$CHECKSUMS_FILE" | awk '{print $1}')"
ACTUAL_SHA="$(sha256sum "$TEMP_DIR/$ARTIFACT" | awk '{print $1}')"
if [[ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]]; then
  echo "Checksum mismatch for $ARTIFACT" >&2
  echo "  expected: $EXPECTED_SHA" >&2
  echo "  actual:   $ACTUAL_SHA" >&2
  exit 1
fi
echo "Checksum verified"

# Optionally verify Sigstore signature if cosign is available
if command -v cosign &>/dev/null; then
  echo "cosign found — verifying Sigstore signature"
  curl --fail --silent --show-error --location --max-time 30 \
    -o "$TEMP_DIR/${ARTIFACT}.pem" \
    "${RELEASE_BASE}/${ARTIFACT}.pem"
  curl --fail --silent --show-error --location --max-time 30 \
    -o "$TEMP_DIR/${ARTIFACT}.sig" \
    "${RELEASE_BASE}/${ARTIFACT}.sig"
  CERT_IDENTITY="https://github.com/in-toto/witness/.github/workflows/release.yml@refs/tags/v${WITNESS_VERSION}"
  cosign verify-blob \
    --certificate       "$TEMP_DIR/${ARTIFACT}.pem" \
    --signature         "$TEMP_DIR/${ARTIFACT}.sig" \
    --certificate-identity "$CERT_IDENTITY" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$TEMP_DIR/$ARTIFACT"
  echo "Sigstore verification passed"
else
  echo "cosign not found — skipping Sigstore verification (checksum only)"
fi

mkdir -p "$WITNESS_BIN_DIR"
tar -xzf "$TEMP_DIR/$ARTIFACT" -C "$WITNESS_BIN_DIR" witness
chmod +x "$WITNESS_BIN_DIR/witness"

echo "Witness ${WITNESS_VERSION} installed to $WITNESS_BIN_DIR/witness"

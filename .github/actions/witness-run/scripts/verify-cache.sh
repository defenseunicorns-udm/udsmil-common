#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Re-verifies a cached witness binary against its SHA256 sidecar written by
# download-verify.sh. Exits non-zero if the binary is missing, the sidecar is
# missing, or the hashes don't match — signalling potential cache tampering.
#
# Required environment variable:
#   WITNESS_CACHE_DIR

: "${WITNESS_CACHE_DIR:?WITNESS_CACHE_DIR is required}"

BINARY="$WITNESS_CACHE_DIR/witness"
SIDECAR="$WITNESS_CACHE_DIR/witness.sha256"

if [[ ! -f "$BINARY" ]]; then
  echo "::error::Cached witness binary not found at $BINARY"
  exit 1
fi

if [[ ! -f "$SIDECAR" ]]; then
  # Cache entry predates SHA sidecar — treat as untrusted and fail so
  # the caller can fall back to a fresh download.
  echo "::error::Cached witness has no SHA256 sidecar ($SIDECAR). Cache must be re-populated."
  exit 1
fi

STORED_SHA="$(cat "$SIDECAR")"
ACTUAL_SHA="$(sha256sum "$BINARY" | awk '{print $1}')"

if [[ "$STORED_SHA" != "$ACTUAL_SHA" ]]; then
  echo "::error::Cached witness binary failed SHA256 verification. Expected: $STORED_SHA, Got: $ACTUAL_SHA. The runner cache may have been tampered with."
  exit 1
fi

echo "Cached witness binary SHA256 verified"

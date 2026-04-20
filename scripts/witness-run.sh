#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Portable witness runner — works locally and in any CI provider.
# All inputs come via WITNESS_* env vars; no GHA-specific variables required.
#
# Required:
#   WITNESS_STEP     — step name (used for attestation and default outfile name)
#   WITNESS_COMMAND  — command to run under attestation
#
# Optional (with local-friendly defaults):
#   WITNESS_BIN                    — path to witness binary; auto-detected if unset
#   WITNESS_OUTFILE                — output JSON file (default: ${WITNESS_STEP}-witness.json)
#   WITNESS_ATTESTATIONS           — space-separated (default: "environment git")
#   WITNESS_ENABLE_SIGSTORE        — (default: false)
#   WITNESS_ENABLE_ARCHIVISTA      — (default: false)
#   WITNESS_ARCHIVISTA_SERVER      — (default: https://archivista.testifysec.io)
#   WITNESS_ARCHIVISTA_HEADERS     — newline-separated headers
#   WITNESS_CERTIFICATE            — path to signing certificate
#   WITNESS_KEY                    — path to signing key
#   WITNESS_INTERMEDIATES          — space-separated intermediate cert paths
#   WITNESS_FULCIO                 — Fulcio URL (auto-set when WITNESS_ENABLE_SIGSTORE=true)
#   WITNESS_FULCIO_OIDC_CLIENT_ID  — (auto-set when WITNESS_ENABLE_SIGSTORE=true)
#   WITNESS_FULCIO_OIDC_ISSUER     — (auto-set when WITNESS_ENABLE_SIGSTORE=true)
#   WITNESS_FULCIO_TOKEN           — raw Fulcio token
#   WITNESS_TIMESTAMP_SERVERS      — space-separated (auto-set when WITNESS_ENABLE_SIGSTORE=true)
#   WITNESS_PRODUCT_EXCLUDE_GLOB   — pattern for files to exclude as subjects
#   WITNESS_PRODUCT_INCLUDE_GLOB   — pattern for files to include as subjects
#   WITNESS_SPIFFE_SOCKET          — path to SPIFFE workload API socket
#   WITNESS_TRACE                  — enable tracing (default: false)
#   WITNESS_EXPORT_LINK            — export link predicate (default: false)
#   WITNESS_EXPORT_SBOM            — export SBOM predicate (default: false)
#   WITNESS_EXPORT_SLSA            — export SLSA predicate (default: false)
#   WITNESS_MAVEN_POM              — path to Maven POM file

: "${WITNESS_STEP:?WITNESS_STEP is required}"
: "${WITNESS_COMMAND:?WITNESS_COMMAND is required}"

# ── Defaults ──────────────────────────────────────────────────────────────────
WITNESS_BIN="${WITNESS_BIN:-}"
WITNESS_OUTFILE="${WITNESS_OUTFILE:-${WITNESS_STEP}-witness.json}"
WITNESS_ATTESTATIONS="${WITNESS_ATTESTATIONS:-environment git}"
WITNESS_ENABLE_ARCHIVISTA="${WITNESS_ENABLE_ARCHIVISTA:-false}"
WITNESS_ARCHIVISTA_SERVER="${WITNESS_ARCHIVISTA_SERVER:-https://archivista.testifysec.io}"
WITNESS_ARCHIVISTA_HEADERS="${WITNESS_ARCHIVISTA_HEADERS:-}"
WITNESS_CERTIFICATE="${WITNESS_CERTIFICATE:-}"
WITNESS_ENABLE_SIGSTORE="${WITNESS_ENABLE_SIGSTORE:-false}"
WITNESS_FULCIO="${WITNESS_FULCIO:-}"
WITNESS_FULCIO_OIDC_CLIENT_ID="${WITNESS_FULCIO_OIDC_CLIENT_ID:-}"
WITNESS_FULCIO_OIDC_ISSUER="${WITNESS_FULCIO_OIDC_ISSUER:-}"
WITNESS_FULCIO_TOKEN="${WITNESS_FULCIO_TOKEN:-}"
WITNESS_INTERMEDIATES="${WITNESS_INTERMEDIATES:-}"
WITNESS_KEY="${WITNESS_KEY:-}"
WITNESS_PRODUCT_EXCLUDE_GLOB="${WITNESS_PRODUCT_EXCLUDE_GLOB:-}"
WITNESS_PRODUCT_INCLUDE_GLOB="${WITNESS_PRODUCT_INCLUDE_GLOB:-}"
WITNESS_SPIFFE_SOCKET="${WITNESS_SPIFFE_SOCKET:-}"
WITNESS_TIMESTAMP_SERVERS="${WITNESS_TIMESTAMP_SERVERS:-}"
WITNESS_TRACE="${WITNESS_TRACE:-false}"
WITNESS_EXPORT_LINK="${WITNESS_EXPORT_LINK:-false}"
WITNESS_EXPORT_SBOM="${WITNESS_EXPORT_SBOM:-false}"
WITNESS_EXPORT_SLSA="${WITNESS_EXPORT_SLSA:-false}"
WITNESS_MAVEN_POM="${WITNESS_MAVEN_POM:-}"

# ── Resolve witness binary ────────────────────────────────────────────────────
if [[ -z "$WITNESS_BIN" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
  LOCAL_BIN="$PROJECT_ROOT/.bin/witness"
  if [[ -x "$LOCAL_BIN" ]]; then
    WITNESS_BIN="$LOCAL_BIN"
  elif command -v witness &>/dev/null; then
    WITNESS_BIN="witness"
  else
    echo "witness binary not found. Run 'uds run setup:witness' to install it." >&2
    exit 1
  fi
fi

# ── Validate command ──────────────────────────────────────────────────────────
if [[ -z "${WITNESS_COMMAND// /}" ]]; then
  echo "WITNESS_COMMAND is required and cannot be empty" >&2
  exit 1
fi

# ── Apply sigstore defaults ───────────────────────────────────────────────────
if [[ "$WITNESS_ENABLE_SIGSTORE" == "true" ]]; then
  WITNESS_FULCIO="${WITNESS_FULCIO:-https://fulcio.sigstore.dev}"
  WITNESS_FULCIO_OIDC_CLIENT_ID="${WITNESS_FULCIO_OIDC_CLIENT_ID:-sigstore}"
  WITNESS_FULCIO_OIDC_ISSUER="${WITNESS_FULCIO_OIDC_ISSUER:-https://oauth2.sigstore.dev/auth}"
  WITNESS_TIMESTAMP_SERVERS="${WITNESS_TIMESTAMP_SERVERS:-https://timestamp.sigstore.dev/api/v1/timestamp}"
fi

# ── Build witness argument array (never string-interpolated) ─────────────────
declare -a WITNESS_ARGS=("run")

# Attestations (space-separated)
IFS=' ' read -ra ATTEST_LIST <<< "$WITNESS_ATTESTATIONS"
for a in "${ATTEST_LIST[@]}"; do
  a="${a#"${a%%[![:space:]]*}"}"
  a="${a%"${a##*[![:space:]]}"}"
  [[ -n "$a" ]] && WITNESS_ARGS+=("-a=$a")
done

[[ "$WITNESS_EXPORT_LINK" == "true" ]] && WITNESS_ARGS+=("--attestor-link-export")
[[ "$WITNESS_EXPORT_SBOM"  == "true" ]] && WITNESS_ARGS+=("--attestor-sbom-export")
[[ "$WITNESS_EXPORT_SLSA"  == "true" ]] && WITNESS_ARGS+=("--attestor-slsa-export")
[[ -n "$WITNESS_MAVEN_POM" ]]           && WITNESS_ARGS+=("--attestor-maven-pom-path=$WITNESS_MAVEN_POM")

[[ -n "$WITNESS_CERTIFICATE" ]]         && WITNESS_ARGS+=("--signer-file-cert-path=$WITNESS_CERTIFICATE")
WITNESS_ARGS+=("--enable-archivista=$WITNESS_ENABLE_ARCHIVISTA")
[[ -n "$WITNESS_ARCHIVISTA_SERVER" ]]   && WITNESS_ARGS+=("--archivista-server=$WITNESS_ARCHIVISTA_SERVER")

# Archivista headers (newline-separated)
while IFS= read -r header; do
  header="${header#"${header%%[![:space:]]*}"}"
  header="${header%"${header##*[![:space:]]}"}"
  [[ -n "$header" ]] && WITNESS_ARGS+=("--archivista-headers=$header")
done <<< "$WITNESS_ARCHIVISTA_HEADERS"

[[ -n "$WITNESS_FULCIO" ]]                && WITNESS_ARGS+=("--signer-fulcio-url=$WITNESS_FULCIO")
[[ -n "$WITNESS_FULCIO_OIDC_CLIENT_ID" ]] && WITNESS_ARGS+=("--signer-fulcio-oidc-client-id=$WITNESS_FULCIO_OIDC_CLIENT_ID")
[[ -n "$WITNESS_FULCIO_OIDC_ISSUER" ]]    && WITNESS_ARGS+=("--signer-fulcio-oidc-issuer=$WITNESS_FULCIO_OIDC_ISSUER")
[[ -n "$WITNESS_FULCIO_TOKEN" ]]          && WITNESS_ARGS+=("--signer-fulcio-token=$WITNESS_FULCIO_TOKEN")

# Intermediates (space-separated)
IFS=' ' read -ra INTER_LIST <<< "$WITNESS_INTERMEDIATES"
for i in "${INTER_LIST[@]}"; do
  i="${i#"${i%%[![:space:]]*}"}"
  i="${i%"${i##*[![:space:]]}"}"
  [[ -n "$i" ]] && WITNESS_ARGS+=("--signer-file-intermediate-paths=$i")
done

[[ -n "$WITNESS_KEY" ]]                   && WITNESS_ARGS+=("--signer-file-key-path=$WITNESS_KEY")
[[ -n "$WITNESS_PRODUCT_EXCLUDE_GLOB" ]]  && WITNESS_ARGS+=("--attestor-product-exclude-glob=$WITNESS_PRODUCT_EXCLUDE_GLOB")
[[ -n "$WITNESS_PRODUCT_INCLUDE_GLOB" ]]  && WITNESS_ARGS+=("--attestor-product-include-glob=$WITNESS_PRODUCT_INCLUDE_GLOB")
[[ -n "$WITNESS_SPIFFE_SOCKET" ]]         && WITNESS_ARGS+=("--signer-spiffe-socket-path=$WITNESS_SPIFFE_SOCKET")
[[ -n "$WITNESS_STEP" ]]                  && WITNESS_ARGS+=("-s=$WITNESS_STEP")

# Timestamp servers (space-separated)
IFS=' ' read -ra TS_LIST <<< "$WITNESS_TIMESTAMP_SERVERS"
for ts in "${TS_LIST[@]}"; do
  ts="${ts#"${ts%%[![:space:]]*}"}"
  ts="${ts%"${ts##*[![:space:]]}"}"
  [[ -n "$ts" ]] && WITNESS_ARGS+=("--timestamp-servers=$ts")
done

[[ "$WITNESS_TRACE" == "true" ]] && WITNESS_ARGS+=("--trace=true")
WITNESS_ARGS+=("--outfile=$WITNESS_OUTFILE")

# ── Parse command into array ──────────────────────────────────────────────────
eval "declare -a CMD_ARRAY=($WITNESS_COMMAND)"

# ── Execute ───────────────────────────────────────────────────────────────────
echo "Running: witness ${WITNESS_ARGS[*]} -- ${CMD_ARRAY[*]}"

set +e
"$WITNESS_BIN" "${WITNESS_ARGS[@]}" -- "${CMD_ARRAY[@]}"
WITNESS_EXIT=$?
set -e

if [[ $WITNESS_EXIT -ne 0 ]]; then
  echo "witness run exited with code $WITNESS_EXIT" >&2
  exit "$WITNESS_EXIT"
fi

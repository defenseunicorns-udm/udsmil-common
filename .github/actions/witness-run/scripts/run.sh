#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Validates inputs, builds the witness argument array, runs the attested
# command, parses GitOIDs from output, and appends to GITHUB_STEP_SUMMARY.
#
# All inputs come from action.yml env: blocks so they are never shell-interpolated
# directly from ${{ inputs.* }}, preventing shell injection.

# ── Required ──────────────────────────────────────────────────────────────────
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${WITNESS_COMMAND:?WITNESS_COMMAND is required}"
: "${WITNESS_STEP:?WITNESS_STEP is required}"
: "${WITNESS_CACHE_DIR:?WITNESS_CACHE_DIR is required}"

# ── Optional with defaults (set by action.yml) ────────────────────────────────
WITNESS_VERSION="${WITNESS_VERSION:-0.9.2}"
WITNESS_WORKINGDIR="${WITNESS_WORKINGDIR:-}"
WITNESS_OUTFILE="${WITNESS_OUTFILE:-}"
WITNESS_ATTESTATIONS="${WITNESS_ATTESTATIONS:-environment git github}"
WITNESS_ENABLE_ARCHIVISTA="${WITNESS_ENABLE_ARCHIVISTA:-true}"
WITNESS_ARCHIVISTA_SERVER="${WITNESS_ARCHIVISTA_SERVER:-https://archivista.testifysec.io}"
WITNESS_ARCHIVISTA_HEADERS="${WITNESS_ARCHIVISTA_HEADERS:-}"
WITNESS_CERTIFICATE="${WITNESS_CERTIFICATE:-}"
WITNESS_ENABLE_SIGSTORE="${WITNESS_ENABLE_SIGSTORE:-true}"
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

# ── Input validation ──────────────────────────────────────────────────────────

# Version format
if ! [[ "$WITNESS_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::Invalid version format '$WITNESS_VERSION'. Expected MAJOR.MINOR.PATCH."
  exit 1
fi

# Path traversal check for workingdir (mirrors index.ts:200-204)
if [[ -n "$WITNESS_WORKINGDIR" ]]; then
  FULL_WORK_DIR="$(realpath -m "$GITHUB_WORKSPACE/$WITNESS_WORKINGDIR")"
  if [[ "$FULL_WORK_DIR" != "$GITHUB_WORKSPACE" && "$FULL_WORK_DIR" != "$GITHUB_WORKSPACE/"* ]]; then
    echo "::error::workingdir '$WITNESS_WORKINGDIR' resolves outside GITHUB_WORKSPACE"
    exit 1
  fi
  if [[ ! -d "$FULL_WORK_DIR" ]]; then
    echo "::error::workingdir '$WITNESS_WORKINGDIR' does not exist"
    exit 1
  fi
else
  FULL_WORK_DIR="$GITHUB_WORKSPACE"
fi

# Command must not be empty (check without modifying the value)
if [[ -z "${WITNESS_COMMAND// /}" ]]; then
  echo "::error::command input is required and cannot be empty"
  exit 1
fi

# ── Mask secrets before any logging ──────────────────────────────────────────
[[ -n "$WITNESS_FULCIO_TOKEN" ]] && echo "::add-mask::$WITNESS_FULCIO_TOKEN"

# ── Resolve outfile ───────────────────────────────────────────────────────────
if [[ -z "$WITNESS_OUTFILE" ]]; then
  WITNESS_OUTFILE="${TMPDIR:-/tmp}/${WITNESS_STEP}-attestation.json"
fi

# ── Apply sigstore defaults ───────────────────────────────────────────────────
if [[ "$WITNESS_ENABLE_SIGSTORE" == "true" ]]; then
  WITNESS_FULCIO="${WITNESS_FULCIO:-https://fulcio.sigstore.dev}"
  WITNESS_FULCIO_OIDC_CLIENT_ID="${WITNESS_FULCIO_OIDC_CLIENT_ID:-sigstore}"
  WITNESS_FULCIO_OIDC_ISSUER="${WITNESS_FULCIO_OIDC_ISSUER:-https://oauth2.sigstore.dev/auth}"
  WITNESS_TIMESTAMP_SERVERS="${WITNESS_TIMESTAMP_SERVERS:-https://timestamp.sigstore.dev/api/v1/timestamp}"
fi

# ── Add witness binary to PATH ────────────────────────────────────────────────
export PATH="$WITNESS_CACHE_DIR:$PATH"

# ── Build witness argument array (array-based, never string-interpolated) ────
declare -a WITNESS_ARGS=("run")

# Attestations (space-separated)
IFS=' ' read -ra ATTEST_LIST <<< "$WITNESS_ATTESTATIONS"
for a in "${ATTEST_LIST[@]}"; do
  a="${a#"${a%%[![:space:]]*}"}"  # ltrim
  a="${a%"${a##*[![:space:]]}"}"  # rtrim
  [[ -n "$a" ]] && WITNESS_ARGS+=("-a=$a")
done

[[ "$WITNESS_EXPORT_LINK" == "true" ]] && WITNESS_ARGS+=("--attestor-link-export")
[[ "$WITNESS_EXPORT_SBOM"  == "true" ]] && WITNESS_ARGS+=("--attestor-sbom-export")
[[ "$WITNESS_EXPORT_SLSA"  == "true" ]] && WITNESS_ARGS+=("--attestor-slsa-export")
[[ -n "$WITNESS_MAVEN_POM" ]]           && WITNESS_ARGS+=("--attestor-maven-pom-path=$WITNESS_MAVEN_POM")

[[ -n "$WITNESS_CERTIFICATE" ]]         && WITNESS_ARGS+=("--certificate=$WITNESS_CERTIFICATE")
WITNESS_ARGS+=("--enable-archivista=$WITNESS_ENABLE_ARCHIVISTA")
[[ -n "$WITNESS_ARCHIVISTA_SERVER" ]]   && WITNESS_ARGS+=("--archivista-server=$WITNESS_ARCHIVISTA_SERVER")

# Archivista headers (newline-separated)
while IFS= read -r header; do
  header="${header#"${header%%[![:space:]]*}"}"
  header="${header%"${header##*[![:space:]]}"}"
  [[ -n "$header" ]] && WITNESS_ARGS+=("--archivista-headers=$header")
done <<< "$WITNESS_ARCHIVISTA_HEADERS"

[[ -n "$WITNESS_FULCIO" ]]              && WITNESS_ARGS+=("--signer-fulcio-url=$WITNESS_FULCIO")
[[ -n "$WITNESS_FULCIO_OIDC_CLIENT_ID" ]] && WITNESS_ARGS+=("--signer-fulcio-oidc-client-id=$WITNESS_FULCIO_OIDC_CLIENT_ID")
[[ -n "$WITNESS_FULCIO_OIDC_ISSUER" ]]  && WITNESS_ARGS+=("--signer-fulcio-oidc-issuer=$WITNESS_FULCIO_OIDC_ISSUER")
[[ -n "$WITNESS_FULCIO_TOKEN" ]]        && WITNESS_ARGS+=("--signer-fulcio-token=$WITNESS_FULCIO_TOKEN")

# Intermediates (space-separated)
IFS=' ' read -ra INTER_LIST <<< "$WITNESS_INTERMEDIATES"
for i in "${INTER_LIST[@]}"; do
  i="${i#"${i%%[![:space:]]*}"}"
  i="${i%"${i##*[![:space:]]}"}"
  [[ -n "$i" ]] && WITNESS_ARGS+=("-i=$i")
done

[[ -n "$WITNESS_KEY" ]]                 && WITNESS_ARGS+=("--key=$WITNESS_KEY")
[[ -n "$WITNESS_PRODUCT_EXCLUDE_GLOB" ]] && WITNESS_ARGS+=("--attestor-product-exclude-glob=$WITNESS_PRODUCT_EXCLUDE_GLOB")
[[ -n "$WITNESS_PRODUCT_INCLUDE_GLOB" ]] && WITNESS_ARGS+=("--attestor-product-include-glob=$WITNESS_PRODUCT_INCLUDE_GLOB")
[[ -n "$WITNESS_SPIFFE_SOCKET" ]]       && WITNESS_ARGS+=("--spiffe-socket=$WITNESS_SPIFFE_SOCKET")
[[ -n "$WITNESS_STEP" ]]                && WITNESS_ARGS+=("-s=$WITNESS_STEP")

# Timestamp servers (space-separated)
IFS=' ' read -ra TS_LIST <<< "$WITNESS_TIMESTAMP_SERVERS"
for ts in "${TS_LIST[@]}"; do
  ts="${ts#"${ts%%[![:space:]]*}"}"
  ts="${ts%"${ts##*[![:space:]]}"}"
  [[ -n "$ts" ]] && WITNESS_ARGS+=("--timestamp-servers=$ts")
done

[[ "$WITNESS_TRACE" == "true" ]]        && WITNESS_ARGS+=("--trace=true")
WITNESS_ARGS+=("--outfile=$WITNESS_OUTFILE")

# ── Parse command into array ──────────────────────────────────────────────────
# eval is used here to split the command into an array, handling quoted args
# (e.g. "my step" --flag). This runs in the caller's own workflow context so
# the input is trusted to the same degree as any other step shell command.
eval "declare -a CMD_ARRAY=($WITNESS_COMMAND)"

# ── Execute ───────────────────────────────────────────────────────────────────
echo "Running witness in: $FULL_WORK_DIR"

# Stream output live (visible in CI) while also saving to a file for GitOID
# parsing. set -e is suspended around the execution so a non-zero exit from
# the attested command is handled explicitly rather than silently aborting the
# script before any output is printed.
WITNESS_OUTPUT_FILE="$(mktemp)"
trap 'rm -f "$WITNESS_OUTPUT_FILE"' EXIT

set +e
(cd "$FULL_WORK_DIR" && witness "${WITNESS_ARGS[@]}" -- "${CMD_ARRAY[@]}") 2>&1 | tee "$WITNESS_OUTPUT_FILE"
WITNESS_EXIT=${PIPESTATUS[0]}
set -e

if [[ $WITNESS_EXIT -ne 0 ]]; then
  echo "::error::witness run exited with code $WITNESS_EXIT"
  exit "$WITNESS_EXIT"
fi

# ── Extract GitOIDs and write outputs ─────────────────────────────────────────
declare -a GIT_OIDS=()
while IFS= read -r line; do
  if [[ "$line" == *"Stored in archivista as "* ]]; then
    if [[ "$line" =~ ([0-9a-fA-F]{64}) ]]; then
      GIT_OIDS+=("${BASH_REMATCH[1]}")
    fi
  fi
done < "$WITNESS_OUTPUT_FILE"

GIT_OID_CSV="$(IFS=','; echo "${GIT_OIDS[*]}")"
echo "git_oid=$GIT_OID_CSV" >> "$GITHUB_OUTPUT"

# ── Append step summary ───────────────────────────────────────────────────────
if [[ ${#GIT_OIDS[@]} -gt 0 ]]; then
  SUMMARY_HEADER="## Attestations Created"
  if ! grep -qF "$SUMMARY_HEADER" "$GITHUB_STEP_SUMMARY" 2>/dev/null; then
    printf '\n%s\n| Step | Attestors Run | Attestation GitOID |\n| --- | --- | --- |\n' \
      "$SUMMARY_HEADER" >> "$GITHUB_STEP_SUMMARY"
  fi

  # Escape markdown table metacharacters
  escape_md() { printf '%s' "${1//|/\\|}" | sed 's/</\&lt;/g; s/>/\&gt;/g'; }

  ESCAPED_STEP="$(escape_md "$WITNESS_STEP")"
  ESCAPED_ATTESTATIONS="$(escape_md "${WITNESS_ATTESTATIONS// /, }")"

  for oid in "${GIT_OIDS[@]}"; do
    printf '| %s | %s | [%s](%s/download/%s) |\n' \
      "$ESCAPED_STEP" \
      "$ESCAPED_ATTESTATIONS" \
      "$oid" \
      "$WITNESS_ARCHIVISTA_SERVER" \
      "$oid" >> "$GITHUB_STEP_SUMMARY"
  done
fi

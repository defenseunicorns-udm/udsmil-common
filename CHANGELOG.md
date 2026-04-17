# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] — 2026-04-17 · `<pin-sha-here>`

### Added

- **`uds-cli-setup`** — Installs the UDS CLI at a configurable version.
- **`olm-cli-setup`** — Authenticates with an OCI registry and installs the OLM CLI at a configurable version.
- **`security-scan`** — Runs Gitleaks secrets scanning and OpenGrep SAST with Witness attestation; outputs witness JSON and SARIF file lists for downstream actions.
- **`vouch`** — Builds a Zarf package with Witness attestation and vouches for it via OLM; supports monorepo layouts via `zarf-path` and `artifact-name` inputs.
- **`publish`** — Downloads a vouched Zarf package artifact and publishes it to an OCI registry.
- **`verify-permissions`** — Fails fast with a descriptive error if the calling job lacks `id-token: write` permission required for Sigstore signing.

### Notes

- Actions are referenced as `defenseunicorns-udm/actions/<action-name>@<sha>`.
- See [`examples/ci-example.yaml`](examples/ci-example.yaml) for a full lint → scan → vouch → publish pipeline.

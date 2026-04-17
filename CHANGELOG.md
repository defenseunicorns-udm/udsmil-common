# Changelog

All notable changes to this project will be documented in this file.

## 1.0.0 (2026-04-17)


### Features

* **actions/security-scan:** add monorepo path scoping, Docker Buildx, and fix vouch glob ([ac73870](https://github.com/defenseunicorns-udm/udm-common/commit/ac738708a175a288af24ac43146e4361e0fc1cd1))
* **actions:** add zarf-path and artifact-name inputs for monorepo support ([9bc6fd2](https://github.com/defenseunicorns-udm/udm-common/commit/9bc6fd24578e645e588856b9293ae7cc5fb71799))
* add basic nginx package for testing actions ([17b3369](https://github.com/defenseunicorns-udm/udm-common/commit/17b33691bc078978c9fa2f1ea09a891776e74faf))
* add README, examples, and clean up ci-example ([753aa3b](https://github.com/defenseunicorns-udm/udm-common/commit/753aa3bd1b1ef871fc8a953c689a2719f318589f))
* **examples:** add tasks.yaml with lint task variants ([5f4be19](https://github.com/defenseunicorns-udm/udm-common/commit/5f4be1956f2551910ed43dc7d436783235a49627))
* initial commit.  Existing scripts adapted from internal repo ([bb6f148](https://github.com/defenseunicorns-udm/udm-common/commit/bb6f1481f161631ca1c428bedb65849118b624e9))
* initialize release workflow and baseline v0.1.0 features ([5206ad4](https://github.com/defenseunicorns-udm/udm-common/commit/5206ad439a66c4c6c63c8460e8e63e528c86557c))
* initialize release workflow and baseline v0.1.0 features ([773bb3f](https://github.com/defenseunicorns-udm/udm-common/commit/773bb3f554a729e901156bb35e5c343effd1bd47))
* split security-scan into separate security-scan and vouch actions ([012f62f](https://github.com/defenseunicorns-udm/udm-common/commit/012f62f517f006049b24f66437c7d794e392cfbd))
* split security-scan into separate security-scan and vouch actions ([a273058](https://github.com/defenseunicorns-udm/udm-common/commit/a2730584fd64a583104d89594f315fd398f7dec0))

## [0.1.0] — 2026-04-17 · `773bb3f554a729e901156bb35e5c343effd1bd47`

### Added callable GitHub actions

- **`.github/actions/uds-cli-setup`** — Installs the UDS CLI at a configurable version.
- **`.github/actions/olm-cli-setup`** — Authenticates with an OCI registry and installs the OLM CLI at a configurable version.
- **`.github/actions/security-scan`** — Runs Gitleaks secrets scanning and OpenGrep SAST with Witness attestation; outputs witness JSON and SARIF file lists for downstream actions.
- **`.github/actions/vouch`** — Builds a Zarf package with Witness attestation and vouches for it via OLM; supports monorepo layouts via `zarf-path` and `artifact-name` inputs.
- **`.github/actions/publish`** — Downloads a vouched Zarf package artifact and publishes it to an OCI registry.
- **`.github/actions/verify-permissions`** — Fails fast with a descriptive error if the calling job lacks `id-token: write` permission required for Sigstore signing.

### Notes

- Actions are referenced as `defenseunicorns-udm/udm-common/<action-name>@773bb3f554a729e901156bb35e5c343effd1bd47`.
- See [`examples/ci-example.yaml`](examples/ci-example.yaml) for a full lint → scan → vouch → publish pipeline for GitHub.

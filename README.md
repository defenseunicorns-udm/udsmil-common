# actions

Shared GitHub Actions and reusable workflows for UDS MIL customers. Provides
a supply-chain-security pipeline that lints, scans, builds, vouches, and
publishes Zarf packages to the UDS MIL registry.

## Available Actions

| Action | Description |
|--------|-------------|
| [`uds-cli-setup`](uds-cli-setup/action.yaml) | Installs the UDS CLI |
| [`olm-cli-setup`](olm-cli-setup/action.yaml) | Authenticates with the UDS registry and installs the OLM CLI |
| [`security-scan`](security-scan/action.yaml) | Runs Gitleaks secrets scanning and OpenGrep SAST; outputs witness JSON and SARIF file lists |
| [`vouch`](vouch/action.yaml) | Builds a Zarf package with Witness attestation and vouches for it via OLM |
| [`publish`](publish/action.yaml) | Publishes a vouched Zarf package to the UDS registry |
| [`verify-permissions`](verify-permissions/action.yaml) | Validates required GitHub Actions OIDC permissions are present |

## Quickstart

Reference actions from this repo using the action name and a pinned SHA:

```yaml
# TODO: Replace <pin-sha-here> with the SHA from CHANGELOG.md after release.
uses: defenseunicorns-udm/actions/security-scan@<pin-sha-here>
```

### Minimal CI workflow

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/actions/uds-cli-setup@<pin-sha-here>
      - uses: testifysec/witness-run-action@7aa15e327829f1f2a523365c564c948d5dde69dd
        with:
          step: lint
          enable-archivista: false
          enable-sigstore: true
          command: uds run lint        # defined in your tasks.yaml
          outfile: lint-witness.json
      - uses: actions/upload-artifact@v7.0.1
        with:
          name: lint-artifacts
          path: lint-witness.json

  scan-and-vouch:
    needs: lint
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
    steps:
      - uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/actions/uds-cli-setup@<pin-sha-here>
      - uses: actions/download-artifact@v8.0.1
        with:
          name: lint-artifacts
          path: .
      - id: scan
        uses: defenseunicorns-udm/actions/security-scan@<pin-sha-here>
      - uses: defenseunicorns-udm/actions/vouch@<pin-sha-here>
        with:
          attestations: "${{ steps.scan.outputs.witness-files }},lint-witness.json"
          sarif-files: "${{ steps.scan.outputs.sarif-files }}"
          olm-catalog: cat-api.uds-mil.us
          olm-org: <your-org-name>
          olm-user-id: ${{ secrets.OLM_USER_ID }}
          olm-password: ${{ secrets.OLM_PASSWORD }}

  publish:
    needs: scan-and-vouch
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/actions/uds-cli-setup@<pin-sha-here>
      - uses: defenseunicorns-udm/actions/publish@<pin-sha-here>
        with:
          registry: registry.uds-mil.us
          registry-org: <your-org-name>
          registry-user-id: ${{ secrets.REGISTRY_USER_ID }}
          registry-password: ${{ secrets.REGISTRY_PASSWORD }}
```

### Monorepo

Use `zarf-path` and `artifact-name` to build multiple services in a matrix:

```yaml
jobs:
  scan-and-vouch:
    strategy:
      matrix:
        service: [api, worker, frontend]
    steps:
      - id: scan
        uses: defenseunicorns-udm/actions/security-scan@<pin-sha-here>
        with:
          opengrep-scan-path: services/${{ matrix.service }}
      - uses: defenseunicorns-udm/actions/vouch@<pin-sha-here>
        with:
          attestations: "${{ steps.scan.outputs.witness-files }}"
          sarif-files: "${{ steps.scan.outputs.sarif-files }}"
          zarf-path: services/${{ matrix.service }}
          artifact-name: zarf-package-${{ matrix.service }}
          olm-catalog: cat-api.uds-mil.us
          olm-org: <your-org-name>
          olm-user-id: ${{ secrets.OLM_USER_ID }}
          olm-password: ${{ secrets.OLM_PASSWORD }}
```

## Required Secrets

| Secret | Used By | Description |
|--------|---------|-------------|
| `OLM_USER_ID` | `vouch` | Username for OLM catalog authentication |
| `OLM_PASSWORD` | `vouch` | Password for OLM catalog authentication |
| `REGISTRY_USER_ID` | `publish` | Username for publishing to `registry.uds-mil.us` |
| `REGISTRY_PASSWORD` | `publish` | Password for publishing to `registry.uds-mil.us` |

## Lint Task

The example CI workflow calls `uds run lint` — you must define a `lint`
task in your repo's `tasks.yaml`. See [`examples/tasks.yaml`](examples/tasks.yaml)
for patterns covering Python, Go, TypeScript, and monorepos.

## Examples

See the [`examples/`](examples/) directory for copy-paste starting points.

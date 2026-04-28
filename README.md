# udm-common

Shared GitHub Actions and reusable workflows for UDS MIL customers. Provides
a supply-chain-security pipeline that lints, scans, builds, vouches, and
publishes Zarf packages to the UDS MIL registry.

## Available Actions

| Action | Description |
|--------|-------------|
| [`uds-cli-setup`](.github/actions/uds-cli-setup/action.yaml) | Installs the UDS CLI |
| [`olm-cli-setup`](.github/actions/olm-cli-setup/action.yaml) | Authenticates with GHCR and installs the OLM CLI |
| [`security-scan`](.github/actions/security-scan/action.yaml) | Runs Gitleaks secrets scanning and OpenGrep SAST; outputs witness JSON and SARIF file lists |
| [`vouch`](.github/actions/vouch/action.yaml) | Builds a Zarf package with Witness attestation and vouches for it via OLM |
| [`publish`](.github/actions/publish/action.yaml) | Publishes a vouched Zarf package to the UDS registry |
| [`verify-permissions`](.github/actions/verify-permissions/action.yaml) | Validates required GitHub Actions OIDC permissions are present |

## Quickstart

Reference actions and workflows from this repo using the full path and a ref:

```yaml
uses: defenseunicorns-udm/udm-common/.github/actions/security-scan@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
```

### Minimal CI workflow (GitHub example)

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
        uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/udm-common/.github/actions/uds-cli-setup@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
      - uses: testifysec/witness-run-action@7aa15e327829f1f2a523365c564c948d5dde69dd
        with:
          step: lint
          command: uds run lint        # defined in your tasks.yaml
          outfile: lint-witness.json
        uses: actions/upload-artifact@v7.0.1
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
        uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/udm-common/.github/actions/uds-cli-setup@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
      - uses: actions/download-artifact@v8.0.1
        with:
          name: lint-artifacts
          path: .
      - id: scan
        uses: defenseunicorns-udm/udm-common/.github/actions/security-scan@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
      - uses: defenseunicorns-udm/udm-common/.github/actions/vouch@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
        with:
          attestations: "${{ steps.scan.outputs.witness-files }},lint-witness.json"
          sarif-files: "${{ steps.scan.outputs.sarif-files }}"
          olm-catalog: cat-api.uds-mil.us
          olm-org: <your-org-name>
          github-token: ${{ secrets.GITHUB_TOKEN }}

  publish:
    needs: scan-and-vouch
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
        uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/udm-common/.github/actions/uds-cli-setup@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
      - uses: defenseunicorns-udm/udm-common/.github/actions/publish@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
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
        uses: defenseunicorns-udm/udm-common/.github/actions/security-scan@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
        with:
          opengrep-scan-path: services/${{ matrix.service }}
      - uses: defenseunicorns-udm/udm-common/.github/actions/vouch@313297d92b3b10e1d86b18c5861a3099b46b7377 # v0.6.0
        with:
          attestations: "${{ steps.scan.outputs.witness-files }}"
          sarif-files: "${{ steps.scan.outputs.sarif-files }}"
          zarf-path: services/${{ matrix.service }}
          artifact-name: zarf-package-${{ matrix.service }}
          olm-catalog: cat-api.uds-mil.us
          olm-org: <your-org-name>
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Required Secrets

| Secret | Used By | Description |
|--------|---------|-------------|
| `REGISTRY_USER_ID` | `publish` | Username for publishing to `registry.uds-mil.us` |
| `REGISTRY_PASSWORD` | `publish` | Password for publishing to `registry.uds-mil.us` |

## Lint Task

The example CI workflow calls `uds run lint` — you must define a `lint`
task in your repo's `tasks.yaml`. See [`examples/tasks.yaml`](examples/tasks.yaml)
for patterns covering Python, Go, TypeScript, and monorepos.

## Examples

See the [`examples/`](examples/) directory for copy-paste starting points.
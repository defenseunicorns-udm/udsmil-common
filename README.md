# udsmil-common

Shared GitHub Actions and reusable workflows for UDS MIL customers. Provides
a supply-chain-security pipeline that lints, scans, builds, vouches, and
publishes Zarf packages to the UDS MIL registry.

## Available Actions

| Action | Description |
|--------|-------------|
| [`uds-cli-setup`](.github/actions/uds-cli-setup/action.yaml) | Installs the UDS CLI |
| [`olm-cli-setup`](.github/actions/olm-cli-setup/action.yaml) | Authenticates with the UDS registry and installs the OLM CLI |
| [`security-scan`](.github/actions/security-scan/action.yaml) | Runs Gitleaks + OpenGrep, builds and vouches a Zarf package |
| [`publish`](.github/actions/publish/action.yaml) | Publishes a vouched Zarf package to the UDS registry |
| [`verify-permissions`](.github/actions/verify-permissions/action.yaml) | Validates required GitHub Actions OIDC permissions are present |

## Quickstart

Reference actions and workflows from this repo using the full path and a ref:

```yaml
uses: defenseunicorns-udm/udsmil-common/.github/actions/security-scan@609a8ab12a0c5d82271c84591476ff14e4653df3
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
        uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/udsmil-common/.github/actions/uds-cli-setup@609a8ab12a0c5d82271c84591476ff14e4653df3
      - uses: testifysec/witness-run-action@7aa15e327829f1f2a523365c564c948d5dde69dd
        with:
          step: lint
          enable-archivista: false
          enable-sigstore: true
          command: uds run lint        # defined in your tasks.yaml
          outfile: lint-witness.json
        uses: actions/upload-artifact@v7.0.1
        with:
          name: lint-artifacts
          path: lint-witness.json

  security-scan:
    needs: lint
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
    steps:
        uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/udsmil-common/.github/actions/uds-cli-setup@609a8ab12a0c5d82271c84591476ff14e4653df3
      - uses: actions/download-artifact@v4
        with:
          name: lint-artifacts
          path: .
      - uses: defenseunicorns-udm/udsmil-common/.github/actions/security-scan@609a8ab12a0c5d82271c84591476ff14e4653df3
        with:
          external-attestations: "lint-witness.json"
          olm-catalog: cat-api.uds-mil.us
          olm-org: <your-org-name>
          olm-user-id: ${{ secrets.OLM_USER_ID }}
          olm-password: ${{ secrets.OLM_PASSWORD }}

  publish:
    needs: security-scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
        uses: actions/checkout@v6.0.2
      - uses: defenseunicorns-udm/udsmil-common/.github/actions/uds-cli-setup@609a8ab12a0c5d82271c84591476ff14e4653df3
      - uses: defenseunicorns-udm/udsmil-common/.github/actions/publish@609a8ab12a0c5d82271c84591476ff14e4653df3
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
  security-scan:
    strategy:
      matrix:
        service: [api, worker, frontend]
    steps:
      - uses: defenseunicorns-udm/udsmil-common/.github/actions/security-scan@609a8ab12a0c5d82271c84591476ff14e4653df3
        with:
          zarf-path: services/${{ matrix.service }}
          opengrep-scan-path: services/${{ matrix.service }}
          artifact-name: zarf-package-${{ matrix.service }}
          olm-catalog: cat-api.uds-mil.us
          olm-org: <your-org-name>
          olm-user-id: ${{ secrets.OLM_USER_ID }}
          olm-password: ${{ secrets.OLM_PASSWORD }}
```

## Required Secrets

| Secret | Used By | Description |
|--------|---------|-------------|
| `OLM_USER_ID` | `security-scan` | Username for OLM catalog authentication |
| `OLM_PASSWORD` | `security-scan` | Password for OLM catalog authentication |
| `REGISTRY_USER_ID` | `publish` | Username for publishing to `registry.uds-mil.us` |
| `REGISTRY_PASSWORD` | `publish` | Password for publishing to `registry.uds-mil.us` |

## Lint Task

The `security-scan` workflow calls `uds run lint` — you must define a `lint`
task in your repo's `tasks.yaml`. See [`examples/tasks.yaml`](examples/tasks.yaml)
for patterns covering Python, Go, TypeScript, and monorepos.

## Examples

See the [`examples/`](examples/) directory for copy-paste starting points.
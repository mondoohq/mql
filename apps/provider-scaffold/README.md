# Provider Scaffold

This tool generates a new provider skeleton and registers it in the build system.

## Usage

```shell
export PROVIDER=digitalocean
export PROVIDER_NAME="DigitalOcean"

go run apps/provider-scaffold/provider-scaffold.go \
  --provider-id $PROVIDER \
  --provider-name "$PROVIDER_NAME"

cd providers/$PROVIDER && go mod tidy && cd ../..

# Edit the resource schema
$EDITOR providers/$PROVIDER/resources/$PROVIDER.lr

# Generate resource code
make providers/mqlr && ./mqlr generate providers/$PROVIDER/resources/$PROVIDER.lr --dist providers/$PROVIDER/resources

# Build and install
make providers/build/$PROVIDER && make providers/install/$PROVIDER

# Test
mql shell $PROVIDER
```

The scaffold will:
1. Generate the provider skeleton at `providers/$PROVIDER/`
2. Add `$PROVIDER` to the `PROVIDERS` list in `Makefile`
3. Add `./mql/providers/$PROVIDER` to the `go.work` block in `DEVELOPMENT.md`

## Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--provider-id` | yes | | Provider identifier (e.g. `digitalocean`, `google-workspace`) |
| `--provider-name` | yes | | Human-readable name (e.g. `"DigitalOcean"`) |
| `--path` | no | `providers/{provider-id}` | Output directory |
| `--force` | no | `false` | Overwrite existing directory |

## Conventions

- **Provider ID**: `go.mondoo.com/mql/providers/{provider-id}` (no version number)
- **Go package**: `go.mondoo.com/mql/providers/{provider-id}` (derived automatically)
- **Go identifier**: Hyphen-separated IDs become CamelCase (e.g. `google-workspace` -> `GoogleWorkspaceConnection`)
- **Platform `Runtime`**: When you customize `asset.Platform` in `provider/provider.go`, keep `Runtime` set to the provider ID (the scaffold does this for you). Downstream consumers — most notably the mondoohq/server asset atlas — classify assets by matching on `Runtime`. Omitting it causes real assets to fall through to "Unrecognized Assets" in the Mondoo UI. Every other cloud provider (AWS, Azure, GCP, OCI, Proxmox, Hetzner, Tailscale, vSphere) follows this convention.

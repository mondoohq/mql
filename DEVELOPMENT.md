# Development

## Build

### Prerequisites

Before building from source, be sure to install:

- [Go 1.25.0+](https://go.dev/dl/)
- [Protocol Buffers v21+](https://github.com/protocolbuffers/protobuf/releases)

On macOS systems with Homebrew, run: `brew install go@1.25 protobuf`

## Install from source

1. Verify that you have Go 1.25+ installed:

   ```bash
   go version
   ```

If `go` is not installed or an older version exists, follow instructions on [the Go website](https://go.dev/doc/install).

2. Clone this repository:

   ```bash
   git clone https://github.com/mondoohq/mql.git
   cd mql
   ```

3. Build and install on Unix-like systems:

   ```bash
   # Build the pre-req tools
   make prep/tools

   # Build all providers
   make providers

   # To install mql using Go into the $GOBIN directory:
   make mql/install
   ```

## Develop mql, providers, or resources

Whenever you change resources, providers, or protos, you must generate files for the compiler. To do this, make sure you
have the necessary tools installed (such as protobuf):

```bash
make prep
```

Then, whenever you make changes, just run:

```bash
make mql/generate
```

This generates and updates all required files for the build. At this point you can `make mql/install` again as
outlined above.

If you make update to a provider's lr file, you can generate go files for that provider with this command: 
```bash
make providers/mqlr
./mqlr generate providers/aws/resources/aws.lr --dist providers/aws/resources
```
To quickly install the changed provider plugin run `make providers/build/aws && make providers/install/aws`.

## Run the tests

Some tests use mocks that `mockgen` writes. The generated files are not committed. A fresh clone therefore cannot build
the tests of `providers` and of `providers/os/connection/device/linux`. `go test ./...` stops with
`undefined: NewMockProviderPlugin` and `undefined: snapshot.MockVolumeMounter`.

Generate the mocks once after you clone:

```bash
make test/generate
```

The target installs `mockgen` and then runs `go generate ./providers/...`. It writes four files:

- `providers/mock_coordinator.go`
- `providers/mock_plugin_interface.go`
- `providers/mock_schema.go`
- `providers/os/connection/snapshot/mock_volumemounter.go`

Run the target again after you change one of the interfaces that these files mock. Every CI test job runs it before the
tests.

After that step `go test ./...` builds. To run the core suite the way CI does, use:

```bash
make test/go
```

## Debug providers

`mql` uses a plugin mechanism. Each provider has its own go modules. This ensures that dependencies are only used on
the appropriate provider. Since providers are their own binaries, debugging is more complex. To ease debugging, we wrote
a small tool that configures the provider accordingly so that it is compiled into the main binary.

To debug a provider locally with mql:

1. Modify the `providers.yaml` in the root folder and add providers you want to test to the `builtin` field. Example:
   ```yaml
   builtin: [aws]
   ```
2. Build and update everything:
   ```bash
   make providers/config
   ```
3. You can now use and debug your code. For example `make mql/install` or start a debugger.
4. Once done, please remember to restore `providers.yaml` (or just set back: `builtin: []`) and
   re-run `make providers/config`.

In your favorite IDE use `apps/mql/mql.go` as main entry point and set the following program
arguments `run aws -c "aws.ec2.instances"` to run the AWS provider with the `aws.ec2.instances` MQL query.

### Remote debug providers

Some providers need to run on specific VMs, e.g., GCP Snapshot scanning.
The `launch.json` already includes a debug target for remote debugging.
You only need to adjust the values to your setup.
Additionally, you need to set up the debugger on the remote VM:

1. Install Go.
2. Install Delve.
3. Change the local config to include the provider you want to debug as builtin (as described above).
4. Copy the source to the remote VM. (`rsync` makes multiple debug session easier.)
5. Allow ingress traffic to the debugger in the firewall.
6. Run the debugger on the remove VM:

  ```
  dlv debug <path>/apps/mql/mql.go --headless --listen=:12345 -- run gcp snapshot --project-id xyz-123 suse15 -c "asset{ name ids }" --verbose
  ```

To learn more, including other possible ways to remote debug, read:
https://github.com/golang/vscode-go/blob/master/docs/debugging.md

## Update provider versions

Each provider has its own version, which is based on [Semver](https://semver.org/).

It's often easy to forget to update them. We didn't want to auto-update versions and accidentally release them for now,
so you must update versions in order to get the new providers out.

Here's how to make this process as easy as 🥧 :

**Set up the version utility**

In the mql repo you can now find the version utility in `providers-sdk/v1/util/version`.

To make working with this utility easier, let's alias it:

```bash
alias version="go run providers-sdk/v1/util/version/version.go"
```

**Check provider versions**

The version utility can check if providers need upgrades. If you use it in `--fast` mode, it doesn't crawl the entire
Git change history but only looks for the first change.

```bash
version check providers/*/
```

```
...
crawling git history....
→ no changes provider=opcua version=9.0.1
crawling git history......
→ provider changed changes=2 provider=os version=9.0.1
...
```

The utility automatically detects if providers have no changes since their last version bump. It also counts changes to
all providers that have changed.

If you prefer not to wait, you can use the `--fast` option, which only looks for the first change.

**Update provider versions**

Once you are ready to release providers, you can use the `update` command.

Here is an example showing how the version tool increments and updates all provider versions:

```bash
version update providers/*/
```

Notable options include:

- `--increment` auto-increments either the patch or minor version for you (e.g., `--increment=patch`). Without this
  option you get the interactive CLI.
- `--fast` performs fast change detection (i.e., once a change is found it will create the update).
- `--commit` automatically generates the commit for you and pushes the branch to GitHub.

If you use the `--commit` option, the version utility creates the commit and pushes it back to `origin`:

```bash
version update providers/*/ --increment=patch --commit
```

```
...
→ committed changes for os-9.0.2, slack-9.0.1, terraform-9.0.1, vcd-9.0.1, vsphere-9.0.1
→ running: git push -u origin version/os-9.0.2+slack-9.0.1+terraform-9.0.1+vcd-9.0.1+vsphere-9.0.1
→ updates pushed successfully, open:
	https://github.com/mondoohq/mql/compare/version/os-9.0.2+slack-9.0.1+terraform-9.0.1+vcd-9.0.1+vsphere-9.0.1?expand=1
```

The final line of this message is the blueprint for the pull request.

## Use Go workspaces

If you want to develop mql, cnspec, and providers at the same time, you can use Go workspaces. This allows you
to use the latest updates from the different repos without having to commit and push changes.

Here is a sample config for `go.work` in the root folder of `mql` and `cnspec`:

```go
go 1.25

use (
   ./mql
   ./mql/providers/activedirectory
   ./mql/providers/alicloud
   ./mql/providers/ansible
   ./mql/providers/arista
   ./mql/providers/artifactory
   ./mql/providers/atlassian
   ./mql/providers/auth0
   ./mql/providers/aws
   ./mql/providers/azure
   ./mql/providers/bitwarden
   ./mql/providers/cassandra
   ./mql/providers/claude
   ./mql/providers/clickhousecloud
   ./mql/providers/clickhousedb
   ./mql/providers/cloudflare
   ./mql/providers/cloudformation
   ./mql/providers/databricks
   ./mql/providers/datadog
   ./mql/providers/depsdev
   ./mql/providers/digitalocean
   ./mql/providers/dropbox
   ./mql/providers/elasticsearch
   ./mql/providers/gcp
   ./mql/providers/github
   ./mql/providers/gitlab
   ./mql/providers/google-workspace
   ./mql/providers/grafana
   ./mql/providers/hcp
   ./mql/providers/hetzner
   ./mql/providers/huggingface
   ./mql/providers/ipinfo
   ./mql/providers/ipmi
   ./mql/providers/iru
   ./mql/providers/jumpcloud
   ./mql/providers/k8s
   ./mql/providers/keycloak
   ./mql/providers/mikrotik
   ./mql/providers/mistral
   ./mql/providers/mondoo
   ./mql/providers/mongo
   ./mql/providers/ms365
   ./mql/providers/mssql
   ./mql/providers/mysqldb
   ./mql/providers/neon
   ./mql/providers/netlify
   ./mql/providers/nextdns
   ./mql/providers/nmap
   ./mql/providers/nutanix
   ./mql/providers/oci
   ./mql/providers/okta
   ./mql/providers/ollama
   ./mql/providers/opcua
   ./mql/providers/openai
   ./mql/providers/opensearch
   ./mql/providers/openstack
   ./mql/providers/portainer
   ./mql/providers/postgresdb
   ./mql/providers/proxmox
   ./mql/providers/redfish
   ./mql/providers/redisdb
   ./mql/providers/shodan
   ./mql/providers/slack
   ./mql/providers/snowflake
   ./mql/providers/stackit
   ./mql/providers/tailscale
   ./mql/providers/terraform
   ./mql/providers/vcd
   ./mql/providers/vercel
   ./mql/providers/vllm
   ./mql/providers/vsphere
   ./mql/providers/weaviate
   ./cnspec
   ./mql/providers/zoom
)
```

## Creating a new provider

Use the scaffolding tool to generate the provider skeleton:

```bash
go run apps/provider-scaffold/provider-scaffold.go \
  --path providers/your-provider \
  --provider-id your-provider \
  --provider-name "Your Provider"
cd providers/your-provider && go mod tidy
```

The Go package path and the provider ID are both derived automatically as `go.mondoo.com/mql/providers/{provider-id}` (no version in either).

After scaffolding, register the provider in these files:

- **`providers/defaults.go`** — add a default entry (alphabetically) so the CLI discovers the provider before it's installed
- **`README.md`** — add a row to the provider table (alphabetically)
- **`DEVELOPMENT.md`** — add the provider path to the `go.work` provider list (alphabetically)
- **`Makefile`** — add the provider name to the `PROVIDERS` list (alphabetically)

The scaffold also emits a `providers/<provider-id>/README.md` from a shared template with the canonical structure (Prerequisites, Authentication, Usage, Discovery, Examples, Resources, Verification, Troubleshooting). Fill in its `TODO` sections — at minimum **Authentication** and **Examples** — with real flags and runnable `mql shell <provider-id>` queries and their output. Keep it developer-focused; do not hand-list every resource and field (the resource reference is generated from the `.lr` schema comments). Use the `snowflake` and `shodan` provider READMEs as models.

### Asset URL tree

Set `AssetUrlTrees` in `providers/<your-provider>/config/config.go` so assets discovered by the provider land under a stable technology bucket. This is what Mondoo Platform uses to group and filter assets across providers.

The convention is `technology=<bucket>` followed by one or more discriminants that match what the provider's connection scopes to (account, project, tenant, cluster, host, …). Match peer providers when the technology already exists (e.g. AWS uses `technology=aws/account=…/service=…`, GCP uses `technology=gcp/project=…/service=…`). Pick a new bucket only when none of the existing ones fit.

```go
AssetUrlTrees: []*inventory.AssetUrlBranch{
    {
        PathSegments: []string{"technology=<bucket>"},
        Key:          "<discriminant>",
        Title:        "<Discriminant Title>",
        Values: map[string]*inventory.AssetUrlBranch{
            "*": nil, // accept any discriminant value; nest further branches if the provider emits sub-assets
        },
    },
},
```

The build emits the tree into `providers/<your-provider>/dist/<your-provider>.json`; check it with `make providers/build/<your-provider>` and grep for `AssetUrlTrees` in the dist json. Mention the resulting URL shape in the provider's `README.md` so reviewers know what asset paths to expect.

## Providers development best practices

The more time we spend building providers, the more we learn how to do better in the future. Here we describe learnings
that will help you get started with providers development.

### Document every resource and field

Every resource and field declared in a `.lr` schema **must** have a `//`-comment immediately above it. These comments
are not just for code readers — the code generator emits them as the `title`/`desc` for each resource and field in the
generated `*.resources.json`, which is what powers our user-facing docs and IDE autocomplete. A field with no comment
ends up as an empty entry in the docs.

Write the comment for someone who has never seen the provider's Go code:

- **Describe what it represents, not how it's implemented.** "Static IP address reserved for a project" is useful;
  "Returned by the Compute API" is not.
- **Be specific.** A top-level provider resource is the worst place for a generic "X resource" comment, because that
  string is the heading of the entire provider's docs. Name what the provider exposes — for example, "GitHub — entry
  point for inspecting organizations, repositories, teams, users, packages, deploy keys, and security/governance
  settings" beats a bare "GitHub resource".
- **Match the SDK/API vocabulary** that someone reading docs would search for (e.g., "Amazon S3 bucket lifecycle rule",
  not "lifecycle entry on the bucket").
- **For deprecated fields**, prefix the comment with `DEPRECATED:` and name the replacement (see the `@maturity`
  section in `CLAUDE.md`).

```lr
// Snowflake Data Cloud — entry point for inspecting accounts, users, roles, grants, databases,
// warehouses, shares, and network/password/session policies
snowflake {
  // Role currently in use for this Snowflake session
  currentRole() string
}

// Snowflake user account, including authentication and session settings
snowflake.user @defaults("name") {
  // User name
  name string
  // Email address
  email string
  // Whether the user has an RSA public key configured for key-pair authentication
  hasRsaPublicKey bool
}
```

A quick way to find resources across all providers that are missing comments:

```bash
python3 - <<'EOF'
import glob, re
skip = ('import ', 'option ', 'alias ', 'extend ', 'embed ')
res_re = re.compile(r'^(private\s+)?[a-zA-Z][\w.]*\s*(@\w+\([^)]*\)\s*)*\{')
for path in sorted(glob.glob('providers/*/resources/*.lr')):
    with open(path) as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        s = line.lstrip()
        if any(s.startswith(p) for p in skip) or not res_re.match(s):
            continue
        j = i - 1
        while j >= 0 and not lines[j].strip():
            j -= 1
        if j < 0 or not lines[j].strip().startswith('//'):
            print(f'{path}:{i+1}: {line.rstrip()}')
EOF
```

### Referencing MQL resources

Often we have a top-level MQL resource, which we want to reference in another top-level resource.

For example, GCP networks can be retrieved for a project. That is a top-level resource:

```
// GCP Compute Engine
private gcp.project.computeService {
   // Google Compute Engine VPC network in a project
   networks() []gcp.project.computeService.network
}
```

However, we have a reference to a GCP network in a GCP Compute address. This allows us to quickly navigate to the
network in which an address is created:

```
private gcp.project.computeService.address {
  // Static IP address
  address string

  // Network in which to reserve the address
  network() gcp.project.computeService.network
}
```

The simple way to implement the reference would be to call the GCP API every
time `gcp.project.computeService.address.network` is executed. However, this would generate an excessive amount of API
calls when scanning large GCP projects. If we have 10 addresses, this would mean 10 separate API calls to get the
network, one for each of them.

MQL has powerful caching capabilities that let us achieve the same end result with a single (or fewer) API calls.

First, create an init function for `gcp.project.computeService.network`, which is the resource we are cross-referencing:

```go
func initGcpProjectComputeServiceNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Here we check that the resource isn't fully initialized yet
   if len(args) > 2 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

   // We create a gcp.project.computeService resource which would allow us to retrieve networks via MQL
	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}

   // Cast the resource to the appropriate type
	computeSvc := obj.(*mqlGcpProjectComputeService)
   // List the networks: equivalent to gcp.project.computeService.networks MQL query. This retrieves all networks in the project and caches them in the MQL cache. Consecutive calls to this retrieve the data from the cache and do not execute any API calls.
	networks := computeSvc.GetNetworks()
	if networks.Error != nil {
		return nil, nil, networks.Error
	}

   // Filter the networks in memory by comparing them with the input arguments
	for _, n := range networks.Data {
		network := n.(*mqlGcpProjectComputeServiceNetwork)
		name := network.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		projectId := network.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

      // return the resource if found
		if name.Data == args["name"].Value && projectId.Data == args["projectId"].Value {
			return args, network, nil
		}
	}
	return nil, nil, fmt.Errorf("not found")
}
```

Then, we implement the function for retrieving the network for a GCP compute address:

```go
func (g *mqlGcpProjectComputeServiceAddress) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.NetworkUrl.Error != nil {
		return nil, g.NetworkUrl.Error
	}
	networkUrl := g.NetworkUrl.Data

	// Format is https://www.googleapis.com/compute/v1/projects/project1/global/networks/net-1
	params := strings.TrimPrefix(networkUrl, "https://www.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	resId := resourceId{Project: parts[1], Region: parts[2], Name: parts[4]}

   // Use the init function for the resource to find the one that we need
	res, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.network", map[string]*llx.RawData{
		"name":      llx.StringData(resId.Name),
		"projectId": llx.StringData(resId.Project),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceNetwork), nil
}

```

## Profiling a provider

A provider runs as its own process. Its memory and CPU do not show up in a profile
of `mql` itself, so a provider needs its own pprof endpoint. Set
`MONDOO_PROVIDER_PROF` to expose one:

```bash
MONDOO_PROVIDER_PROF='enable,listen=localhost:0' mql run docker image ubuntu:24.04 -c "packages.length"
```

The provider logs the address it bound, for example
`profiler listening address=http://127.0.0.1:41234/debug/pprof/`. Port `0` picks a
free port, so several processes can profile at once. Then collect a profile while
the run is in flight:

```bash
curl -o heap.pprof http://127.0.0.1:41234/debug/pprof/heap
go tool pprof -inuse_space -top providers/os/dist/os heap.pprof
```

The value takes the same keys as `MONDOO_PROF`, which does the same for `mql`:
`enable`, `listen` and `memprofilerate`. Both are off when unset.

## Metrics (Prometheus + Grafana)

When debugging `mql`, you can monitor and profile memory and CPU usage using [Prometheus](https://prometheus.io/) and [Grafana](https://grafana.com/). The setup provides visibility into application performance metrics and allows us to diagnose bottlenecks, memory leaks, and high CPU usage.

**How it works?**

* Prometheus: Scrapes and stores time series metrics from your application.
* Grafana: Visualizes the metrics and allows creating dashboards and alerts.
* `mql` in `DEBUG` mode: Exposes basic metrics

### Setup

1. Install `prometheus` from https://prometheus.io/download/ (macOS: `brew install prometheus`)
1. Start both, Prometheus and Grafana with `make metrics/start`
1. **(one time only)** Create a Grafana Dashboard
    1. Open Grafana at <!-- markdown-link-check-disable --> http://localhost:3000 <!-- markdown-link-check-enable -->
    1. Add Prometheus as a data source (URL: `http://host.docker.internal:9009`)
    1. Use an existing Go profiling dashboard from [Grafana](https://grafana.com/grafana/dashboards/) dashboards e.g. [10826](https://grafana.com/grafana/dashboards/10826-go-metrics/)
1. Run `mql` with `DEBUG=1` e.g. `DEBUG=1 mql run local -c "asset { name }"`

You should start seeing data in Grafana!

![Grafana_dashboard](.github/images/Grafana-dashboard.png)

## Contribute changes

### Mark PRs with emojis

We love emojis in our commits. These are their meanings:

🛑 breaking 🐛 bugfix 🧹 cleanup/internals ⚡ speed 📄 docs
✨⭐🌟🌠 smaller or larger features 🐎 race condition
🌙 MQL 🌈 visual 🟢 fix tests 🎫 auth 🦅 falcon 🐳 container

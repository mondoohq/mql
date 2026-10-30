# ADR 045: The `iac` Meta-Target

## Status

Accepted

## Context

mql ships eight providers that read infrastructure as code from a file tree:
`terraform` (with its `opentofu` connector), `ansible`, `cloudformation`,
`bicep`, `helm`, `kustomize`, `k8s` (manifest mode), and the `docker-file`
connection type on `os`. Each is reached by naming it:

```
cnspec scan terraform ./infra
cnspec scan helm ./charts/api
cnspec scan ansible ./playbooks
```

That requires the user to already know what is in the directory, and to run one
command per tool per entry point. A repository with Terraform under `envs/`,
Helm charts under `charts/` and a Dockerfile at the root takes four commands and
four pieces of prior knowledge. What people ask for is one:

```
cnspec scan iac ./repo
```

### The fan-out mechanism already exists

A provider hands back discovered assets whose `inventory.Config.Type` names
*another* provider's connection type. The coordinator resolves it:
`Runtime.DetectProvider` calls `EnsureProvider(ProviderLookup{ConnType: …})`
(`providers/runtime.go:363`), which installs and starts that provider on demand.
Nothing about this is new, and nothing in the CLI needs to learn about it.

Two providers already fan out into IaC exactly this way:

- `providers/github/resources/discovery.go:520` — one recursive git-tree walk,
  classified into `terraform-hcl-git`, `k8s`, `bicep`, `helm`, `kustomize` and
  `docker-file` child assets.
- `providers/gitlab/provider/discovery.go:336` — the same set again, over the
  GitLab tree API.

### What is actually missing

Two things, and only two:

1. **A target that walks a tree** and emits those child assets. The two existing
   fan-outs are bound to a forge API.
2. **A way for a provider to say "that folder is mine"** without the discovering
   side hardcoding it. Today the knowledge is duplicated: the GitHub classifier
   (`classifyIacTree`, `discovery.go:607`) and the GitLab one
   (`discoverRepoTypes`, `discovery.go:476`) encode the same file patterns in two
   hand-ordered `switch` statements, and the GitHub one carries a comment saying
   it "mirrors the GitLab provider so the two behave identically". A third copy
   inside an `iac` provider is the wrong answer.

### The tree is not always a directory

A file tree is also a git repository, a tarball, a container image layer, a path
on a host reached over SSH. Everything the `iac` target does is the same for all
of them; only *getting* the tree differs. This ADR implements the local case, and
the phases name the rest so nothing here assumes a local path is the only
possibility.

### A meta-target has almost no code of its own

Everything `iac` knows how to do is wiring: walk a tree, ask other providers
whether they want a piece of it, hand back what they accepted, and expose a
small root resource describing what was found. It reads no cloud API and parses
no format. Shipping that as a separately built, separately released plugin
binary would cost a registry entry, a download on first use and a version to
keep in step, for a component that has no dependency of its own to justify any
of it.

mql already has the shape for this: `sbom` (`providers/sbom.go`) and
`recording` (`providers/recording.go`) are providers with connectors that are
compiled into the binary, registered in `builtinProviders`
(`providers/builtin.go`), and reach the coordinator directly. `sbom` even calls
another provider's `Connect` in-process (`sbom.go`, `MockConnect` on `os`).
That is exactly the call `iac` needs.

## Decision

`iac` is a **builtin provider**, like `sbom`: compiled into mql, registered in
`builtinProviders`, with an `iac` connector that `cnspec scan iac ./repo` and
`mql shell iac ./repo` reach through the connector machinery every other
provider uses. It is a meta-target only in what it discovers, not in how it is
wired.

Six pieces:

1. Providers **opt in** to the target declaratively, in their config.
2. `iac` **walks the tree and probes**: for each candidate it calls the
   provider's `Connect` in-process, and only what a provider accepted lands in
   the inventory.
3. The child connection carries **what `iac` knows about the tree**; the
   connecting provider decides its own platform ID.
4. Each provider decides its own **scope**: not mine, mine and stop here, mine
   and keep looking below.
5. `iac` has a **real root resource**, like every other provider.
6. Every discovered asset is **anchored to the resource that found it**
   (ADR 030): `iac.detection` is the anchor, in both directions.

### 1. Providers opt into the target

A new field on `plugin.Provider`:

```go
// providers-sdk/v1/plugin/provider.go (new file; Provider itself stays in start.go)
type TargetOptIn struct {
    // Target is the meta-target this opt-in joins. "iac" today.
    Target string
    // Discovery is the name users pass to --discover. It is not the provider
    // name: one provider can join a target several times.
    Discovery string
    // ConnType is the connection type to give the child asset. The coordinator
    // resolves it to a provider and installs it.
    ConnType string
    // Match is what makes a path a candidate for this discovery.
    Match []Matcher
    // PerFile hands the provider the matching file itself. Off, it is handed
    // the folder the match was found in. A provider that reads one document
    // per asset (cloudformation, docker-file) sets it; one that reads a
    // directory (terraform, helm, kustomize, k8s, bicep) leaves it off.
    PerFile bool `json:",omitempty"`
    // Options are set on the child connection as-is. This is how one provider
    // tells two of its opt-ins apart at connect time (terraform's dialect).
    Options map[string]string `json:",omitempty"`
    // Auto puts this discovery in the set an unset --discover expands to. A
    // provider opts itself in, which is the same trust the Match patterns
    // already carry. Leave it off for a discovery that is noisy enough to be
    // worth asking for by name.
    Auto bool `json:",omitempty"`
}

type Matcher struct {
    // Glob matches the file's base name, or, when it contains a slash, the
    // tail of the path relative to the folder being considered.
    Glob string
}

// Match reports whether a tree-relative path matches, and the directory the
// match sites at: the file's own directory for a glob with no slash, and the
// directory the glob's segments hang below for one that has one. So
// `roles/*/tasks/main.yml` offers the project directory, not the task file.
func (m Matcher) Match(relPath string) (site string, ok bool)
```

`path.Match`, not `filepath.Match`. Every path here comes from an `fs.FS` walk
or a forge's tree API, both always slash-separated, and `filepath.Match` on
Windows takes the separator to be `\` — so `roles/*/tasks/main.yml` would never
match there, and there is a Windows CI job.

`PerFile` and `Options` are additions over the first draft of this ADR, each
forced by a provider that exists:

- `cloudformation` reads exactly one file
  (`providers/cloudformation/connection/connection.go:74`, `os.ReadFile(path)`),
  and `docker-file` handed a directory builds an asset named `"Dockerfile "`
  with `FileAbsSrc` pointing at the directory
  (`providers/os/connection/docker/docker_file_connection.go:83-122`). Both are
  one-document-per-asset providers, and that is also how the forges emit them
  today (`gitAsset("docker-file", repo, path, …)`, one per Dockerfile). So the
  unit offered has to be the opt-in's choice, not the walk's.
- `terraform` chooses its dialect from `Options["iac-tool"]`
  (`providers/terraform/connection/dialect.go:32`, `OptionDialect`), which the
  connector sets from its own name (`provider/provider.go:105`). Forced
  `terraform` ignores `.tofu` files (`dialect.go:189`); forced `opentofu` reads
  both with `.tofu` overriding. Without the option, both opt-ins would detect
  the same dialect from the same files and produce one asset twice.

The nine opt-ins, as they should be written. Globs are lifted from
`classifyIacTree` (`providers/github/resources/discovery.go:607`) and
`discoverRepoTypes` (`providers/gitlab/provider/discovery.go:476`) so phase 3
can delete those without changing behavior:

```go
// providers/terraform/config/config.go
Targets: []plugin.TargetOptIn{
    // Neither is Auto: the user names the dialect (see below).
    {Target: "iac", Discovery: "terraform", ConnType: provider.HclConnectionType,
     Match:   []plugin.Matcher{{Glob: "*.tf"}, {Glob: "*.tf.json"}},
     Options: map[string]string{connection.OptionDialect: string(connection.DialectTerraform)}},
    {Target: "iac", Discovery: "opentofu", ConnType: provider.HclConnectionType,
     Match:   []plugin.Matcher{{Glob: "*.tofu"}, {Glob: "*.tofu.json"}},
     Options: map[string]string{connection.OptionDialect: string(connection.DialectOpenTofu)}},
},

// providers/helm/config/config.go
{Target: "iac", Discovery: "helm", ConnType: provider.DefaultConnectionType, Auto: true,
 Match: []plugin.Matcher{{Glob: "Chart.yaml"}}},

// providers/kustomize/config/config.go
{Target: "iac", Discovery: "kustomize", ConnType: provider.DefaultConnectionType, Auto: true,
 Match: []plugin.Matcher{{Glob: "kustomization.yaml"}, {Glob: "kustomization.yml"}, {Glob: "Kustomization"}}},

// providers/bicep/config/config.go
{Target: "iac", Discovery: "bicep", ConnType: provider.DefaultConnectionType, Auto: true,
 Match: []plugin.Matcher{{Glob: "*.bicep"}, {Glob: "*.bicepparam"}}},

// providers/k8s/config/config.go
{Target: "iac", Discovery: "k8s", ConnType: provider.ConnectionType, Auto: true,
 Match: []plugin.Matcher{{Glob: "*.yaml"}, {Glob: "*.yml"}}},

// providers/cloudformation/config/config.go
{Target: "iac", Discovery: "cloudformation", ConnType: provider.DefaultConnectionType, Auto: true, PerFile: true,
 Match: []plugin.Matcher{{Glob: "*.yaml"}, {Glob: "*.yml"}, {Glob: "*.json"}, {Glob: "*.template"}}},

// providers/ansible/config/config.go
{Target: "iac", Discovery: "ansible", ConnType: provider.DefaultConnectionType, Auto: true,
 Match: []plugin.Matcher{{Glob: "ansible.cfg"}, {Glob: "roles/*/tasks/main.yml"},
                         {Glob: "roles/*/tasks/main.yaml"}, {Glob: "inventory"},
                         {Glob: "*.yml"}, {Glob: "*.yaml"}}},

// providers/os/config/config.go
{Target: "iac", Discovery: "dockerfile", ConnType: shared.Type_DockerFile.String(), Auto: true, PerFile: true,
 Match: []plugin.Matcher{{Glob: "Dockerfile"}, {Glob: "Dockerfile.*"},
                         {Glob: "*.Dockerfile"}, {Glob: "*.dockerfile"}}},
```

**Ansible is one opt-in, on folders.** An earlier draft gave it two, the second
`PerFile` on every `*.yml`, which is the only thing that would ever offer
`ansible/site.yml` as an asset of its own beside the `ansible/` project that
already contains it. The walk walks folders, so ansible takes folders:
`project.Load` reads a directory, and a directory holding nothing but a playbook
is a project holding one playbook. What it is not is recursive —
`loadPlaybooks` reads only the folder itself and its `playbooks/` subfolder — so
ansible answers `continue_exploration`, and a bare playbook further down is
still found. Two opt-ins *may* share a `Discovery` name, and `--discover` would
select both; no provider needs that today.

The discovery is named `dockerfile`, the thing a user asks for, while the
connection type it hands out stays `docker-file`, which is a wiring name
nobody types. The forges call the same discovery `dockerfiles`
(`providers/github/connection/platform.go:21`); phase 3 keeps accepting that
spelling on the `github` and `gitlab` connectors and maps it onto this opt-in.

`*.dockerfile` is the lowercase arm of `isDockerfile`. Both forges also exclude
`mql.yaml`/`mql.yml` from their YAML arm; a glob cannot express that and it
changes nothing, because every probe rejects a policy bundle anyway. Terraform's
real extension set also has `.tfvars`/`.tofuvars`, deliberately not matchers: a
vars-only folder is not an asset, and vars beside `.tf` files already match on
the `.tf`.

**Terraform and OpenTofu are named, not automatic.** The user says which
dialect they mean: `--discover terraform`, `--discover opentofu`, or both. When
both are named, both run, and a folder holding `.tf` and `.tofu` files yields
two assets, one per dialect, each read the way its own connector reads it
(forced `terraform` ignores the `.tofu` files, forced `opentofu` lets them
override). That is the same result as running the two connectors on the folder
today, and it is why the two opt-ins carry `Options` rather than relying on
detection: detection would pick one dialect for the folder and the two probes
would hand back the same asset twice.

Every other opt-in is `Auto`. The broad matchers (`k8s`, `cloudformation`,
`ansible` on `*.yaml`) will fire on every YAML in a repository, and that is the
design: the probe is what says no, and a probe against an already-running
provider is cheap (§2). Turning one off is a judgment to make against a real
monorepo in verification, not up front.

#### Overlapping matches all run; `Connect` decides

A glob cannot settle whether something truly belongs to a provider, and it never
will. A Helm chart directory is full of YAML, so helm, k8s, cloudformation and
ansible all match it; a CloudFormation template is a `.yaml` like any other.
There is no pattern language that resolves this, because the question is not
what the file is named but what it is.

So when several opt-ins match the same thing, **they are all probed**. `Connect`
is where a provider decides whether it actually wants what it was handed, and a
provider that does not want it says so and is dropped.

That needs an error the probing side can recognize as "not mine" and treat as a
non-event, while any other error — a malformed file, a permission problem, a
provider that crashed — is retained and reported, because those are real and
have nothing to do with matching.

That error is `plugin.ErrNoMatch`:

```go
// providers-sdk/v1/plugin/errors.go
// ErrNoMatch is returned by Connect when the target is not this provider's:
// the connection type was right, the files were not. Discovery drops the asset;
// every other error is retained and reported.
ErrNoMatch = errors.New("not a match for this provider")

func IsNoMatchError(e error) bool
```

```protobuf
// providers-sdk/v1/plugin/plugin.proto
enum ErrorKind {
  ERROR_KIND_UNSPECIFIED = 0;
  ERROR_KIND_NO_MATCH = 1;
}
message ErrorDetail { ErrorKind kind = 1; }
```

A new sentinel rather than a reuse, because the two that exist both mean *wrong
connection type*, which is a wiring bug: `ErrUnsupportedProvider` is the default
arm of the `Connect` type switch (`providers/os/provider/provider.go:532`,
`providers/terraform/provider/provider.go:187`) and
`ErrProviderTypeDoesNotMatch` is the same check in connection constructors
(`providers/gcp/connection/connection.go:86`, and `opcua`, `ssh`, `okta`).
A mismatch is the other kind of statement: the connection type was right, the
content was not. It is also the only one of the three that is a normal outcome.

Reusing `ErrUnsupportedProvider` would cost something concrete beyond the muddle:
`IsUnsupportedProviderError` is consumed by `cli/printer/mql.go` at four sites to
suppress output, so every discovery mismatch would inherit those display
semantics.

`IsNoMatchError` exists rather than callers using `errors.Is` because the child
providers are gRPC plugins: the error crosses the process boundary and arrives
as a status, which is why `IsUnsupportedProviderError` compares `st.Message()`
rather than error values.

**But it cannot copy that shape.** Eight of the nine providers *wrap*
`ErrNoMatch` with their own explanation, so the message on the wire is
`no Helm charts found at /x: not a match for this provider` and an exact
comparison never matches. And `status.FromError` reports `ok=false` for a status
reached through `errors.As` — any wrapped one — which is why
`IsUnsupportedProviderError` silently answers "no" for a wrapped
`ErrUnsupportedProvider` today.

So the kind rides a **status detail**, and the SDK puts it there:
`GRPCServer.Connect` and `MockConnect` call `NoMatchStatus` when
`errors.Is(err, ErrNoMatch)`. That runs inside the provider process, where
`errors.Is` still sees the sentinel the provider wrapped, so a provider's
wrapping order stops being load-bearing and the wire form is an SDK guarantee
rather than nine authors' discipline. `IsNoMatchError` checks, in order of
authority: the raw sentinel (a builtin child), the `ErrorDetail` on the status,
then the message text — the last for a provider binary built before the detail
existed. It uses `status.Convert`, not `status.FromError`.

`ErrorDetail` carries an enum rather than being a `NoMatch` message of its own,
so `ErrUnsupportedProvider` and `ErrProviderTypeDoesNotMatch` can move onto the
same carrier later without a second message.

**Every one of the nine providers has to return it.** "No code change beyond
the opt-in block" was the first draft's claim and it is false; each connection
constructor today either errors generically or, worse, connects empty. The exact
sites:

| provider | today, on a non-matching target | change |
|---|---|---|
| terraform | logs a warning and connects an empty configuration (`connection/hcl_manifest.go:175`) | return `ErrNoMatch` when `len(resolved.Configs) == 0`. The "path is not a valid file or directory" error at `:80` stays a real error. The OpenTofu-only error at `:157` becomes `ErrNoMatch` for the `terraform` opt-in, because the `opentofu` opt-in will take that folder |
| helm | `errors.New("no Helm charts found at …")` (`connection/connection.go:104`) | wrap `ErrNoMatch` |
| kustomize | `ErrNoKustomization` (`connection/connection.go:24`, raised at `:95`) | wrap `ErrNoMatch` |
| bicep | `errors.New("no .bicep, .bicepparam, or ARM template JSON files found at …")` (`connection/connection.go:175`) | wrap `ErrNoMatch` |
| cloudformation | `parse.Reader` on any YAML/JSON; a k8s manifest may parse into a template with no `Resources` and connect empty | Measured: `parse.Reader` accepts a k8s Deployment, plain YAML, a YAML list and an empty file alike, so the gate is a marker check. It runs **before** the parse, textually: this opt-in matches every `.yaml`, `.yml`, `.json` and `.template` in a tree, and a Helm template full of Go templating is not valid YAML at all, so a parse-first gate would report "invalid YAML" for every chart in a repository instead of simply not claiming it. Confirmed against the parsed document afterwards. The marker is CloudFormation's whole top-level vocabulary, not just `Resources`/`AWSTemplateFormatVersion`: a fragment carrying only `Parameters`, `Mappings` or `Outputs` is a real thing to scan, and SAM leads with `Transform`. Reading the section is hand-rolled, because `cft.Template.HasSection` indexes `Node.Content[0]` unguarded and an empty file parses to no content |
| ansible, project dir | `LoadProject` error (`connection/connection.go:64`) | `project.Load` is documented never to fail on absence, so it succeeds on any directory at all: `ErrNoMatch` when the loaded project has no config, no roles, no inventory **and no playbooks** — one statement about the model rather than a filesystem re-check |
| ansible, playbook file | a YAML map fails `DecodePlaybook` (`play/playbook.go:315`); a YAML list of unrelated dicts decodes into a playbook with empty plays and connects | `ErrNoMatch` for both, but only after asking whether the bytes are YAML at all: a file that does not parse is one of ours and broken, and stays a reported error. The "says nothing" test is `project.LooksLikePlaybook`, exported so the folder gate and the file gate cannot disagree about one file — `import_playbook` lives on `Task`, not `Play`, so a gate written against the decoded struct drops an import-only playbook |
| k8s manifest | walks the directory (`connection/shared/manifest_parser.go:294`); behavior on a folder of non-k8s YAML (Helm templates with Go templating, plain config YAML) must be checked | `ErrNoMatch` when zero Kubernetes objects were loaded. Measured: the walk already drops every file that does not decode as a Kubernetes object, so plain YAML and Go-templated Helm files arrive as an empty set. Plus a skip for kustomization filenames — a `kustomization.yaml` declares a `kind`, so it decodes as an object and would make every Kustomize directory emit a second asset beside the kustomize one |
| docker-file | a directory builds an asset named `"Dockerfile "` whose platform ID hashes the directory | `ErrNoMatch` on a directory. A tenth change, and the only one of these that failed *silently*. Both forges always pass a file, so no discovery path regresses |

#### One behavior, whoever asked

A provider returns `ErrNoMatch` from `Connect` whenever the target is not its
own, and it does not matter who is asking. So this changes the direct
connectors too: `mql run terraform ./repo-with-no-tf` goes from "warns, results
will be empty" to an error carrying the provider's own message, and likewise
`mql run k8s ./plain-yaml`, `mql run helm ./dir`, `mql run bicep ./dir`.

That is the point rather than a side effect. An empty connection passes every
policy on a project nothing was ever read from, which is the same failure the
OpenTofu-only message already refuses to produce. A provider that cannot tell a
probe from a person would need the walk to mark its connections, which is
mechanism this design does not have and does not want: the one place that
decides how loud a mismatch is, is the discovery layer, and it does that by
where the asset came from rather than by who asked.

#### Matching stays simple on purpose

`Match` is a glob and nothing else. Anything more is `Connect`'s job, per
above. A false positive costs one probe. A false negative silently drops an
asset from the scan, and nothing in the output says so. So matching is tuned to
be generous, and the provider that gets probed is the authority — it already
knows how to read a directory, because that is what `scan terraform ./infra`
does today.

This is also why richer matching is not worth building. Anything a smarter
predicate could decide, the real provider decides better, and by then it costs
nothing.

#### Resolving a discovery name to a provider, before anything is installed

This is the part that has to be right, and it is the same guarantee the CLI
already makes for connector names. On a machine with no providers at all,
`mql shell ssh user@host` works because `providers/defaults.go` — generated by
`make providers/defaults` — knows that the `ssh` connector belongs to the `os`
provider, so `EnsureProvider` can fetch it before cobra ever runs
(`cli/providers/providers.go:45`).

**`--discover` values are resolved the same way, from the same source.** `iac`
is just another connector, and its `--discover` list is how it directs
connections, so we know exactly which providers to pull.

The mechanism needs almost nothing new, because `EnsureProvider` already does
this shape of work (`providers/providers.go:430`): it looks in the installed set
first, falls back to `DefaultProviders.Lookup(search)`, and installs what it
finds there. Two additions:

```go
type ProviderLookup struct {
    ID           string
    ProviderName string
    ConnName     string
    ConnType     string
    // Target and Discovery resolve a meta-target's --discover value, e.g.
    // Target "iac", Discovery "k8s" -> the k8s provider.
    Target    string
    Discovery string
}
```

`Providers.Lookup` gains a clause matching `Targets` the way it already matches
`ConnectionTypes` and connector names (`providers/providers.go:185`), and
`String()` prints the two fields. The generator emits `Targets` into
`defaults.go` — today it emits only `Name`, `ID`, `ConnectionTypes` and a reduced
`Connectors` list (`providers-sdk/v1/util/defaults/defaults.go:110`). It reads
each provider's built `dist/<name>.json`, so the field propagates from
`config.go` with no further change. Installed providers get it the same way:
`ListAll` unmarshals `<name>.json` into `plugin.Provider`.

With that, `EnsureProvider(ProviderLookup{Target: "iac", Discovery: "k8s"}, …)`
installs the k8s provider on a clean machine, over the existing code path, with
its existing offline and auto-update semantics.

`iac` itself never needs resolving from `defaults.go`: it gets a clause in
`EnsureProvider` next to `sbom`, `mock` and `recording`
(`providers/providers.go:452-465`), matched on its ID, connector name and
connection type.

#### The resolution is per name, not all-or-nothing

`Providers.Lookup` searches the installed set and only then falls back to
`DefaultProviders`, so the union is resolved one discovery name at a time. That
is exactly the required behavior:

```
mql shell iac ./repo --discover terraform,k8s
  terraform  -> found installed        -> use it
  k8s        -> not installed          -> found in DefaultProviders -> install
```

An installed provider is authoritative for its own opt-ins, because its
`<name>.json` on disk is newer than whatever `DefaultProviders` recorded at
release time. `DefaultProviders` covers everything not installed. Neither is a
fallback for the other; they are one lookup with a defined order.

#### `--discover` decides the provider set, before anything is read

`iac` is a meta-provider, and `--discover` is not a filter it applies to what it
finds — it is the control surface for the fan-out. **The providers a run needs
are a function of the `--discover` value alone**, and that value is always known
before a single file is read:

| `--discover` | providers needed |
|---|---|
| explicit list (`terraform,k8s`) | the ones those names resolve to |
| `auto` — what an unset flag expands to | the declared default set |
| `all` | every enumerated opt-in |

`auto` is not a question the walk answers. It is a list we declare — the `Auto`
flag on each opt-in — the same way `auto` is a declared subset for `aws` and
`k8s` today (`providers/aws/resources/discovery.go:27`). We know which targets we
auto-discover, so we know which providers the default configuration will want to
call, and we simply set them.

The walk decides which of those providers get an asset. It never decides which
of them need to exist.

So resolution happens once, before connect, reading `Discover.Targets` off the
`iac` connection — whether that came from the CLI flag, an inventory file, or
the scan API. `detectConnectorName` (`cli/providers/providers.go:58`) already
parses `--discover` into a pflag set before cobra runs, so on the CLI path the
values are in hand at the moment the connector's own provider is being ensured,
and `AttachCLIs` (`:37`) is where the resolution step goes. `iac`'s own
`Connect` repeats it (cheaply, everything is installed by then) so the
inventory-file and API paths get the same guarantee.

#### What happens when a provider is missing

Two axes: whether the user named the discovery themselves, and whether automatic
provider installation is on.

| | auto-install on | auto-install off |
|---|---|---|
| `--discover` unset (`auto`) | fetch the default set | run with the installed subset, saying which discoveries were dropped |
| `--discover` explicit | fetch each named one | **error**, naming every provider that is missing |

The asymmetry is the point. An explicit `--discover k8s` is a statement that
those assets matter; quietly skipping them would produce a clean report that is
simply missing the thing the user asked about. An unset flag is a preference,
and degrading to what is installed is the reasonable reading of it.

This is the nature of a meta-provider: it controls fan-out through `--discover`,
so `--discover` is also where it owes the user an answer about what it could and
could not reach.

**An unknown value is an error, not an empty result.** `--discover terrafom`
fails and prints the valid names, for the same reason: a typo that silently
discovers nothing leaves a scan that succeeds with a report quietly missing
assets.

`iac` needs no new field to be recognized as a meta-target connector, and the
CLI needs no hardcoded list of which connectors are: the opt-ins name their
target, and the target is the connector. If any enumerated opt-in says
`Target: "iac"`, then `--discover` values under the `iac` connector are opt-in
names. That is also what supplies the `--discover` help text, so
`mql shell iac --help` lists what this machine can actually reach instead of the
connector's static `Discovery` slice.

#### Why not `Requires`

ADR 042 `Requires` entries are installed eagerly by `installDependencies`
(`providers/providers.go:639`). Declaring the IaC providers as requirements of
`iac` would therefore install all nine on first use, whatever the target
directory holds. `Requires` is for cross-provider *invocation*, which `iac`
never does. The target-opt-in lookup is deliberately a separate, demand-driven
path. `iac` declares `core` in `Requires` like every other root (ADR 042), and
nothing else.

#### What this inherits from the connector guarantee

The same limit connector names have, and no more: a provider published after the
current release is not in this binary's `defaults.go`, so its opt-in is
reachable only once that provider is installed. That is the existing, understood
contract for `mql shell <new-connector>`, not a new gap. A registry-published
target index would close it for both at once and is out of scope here.

### 2. `iac` walks the tree and probes

The first draft had `iac` emit every matching folder and left it to the
discovery layer to connect them and sort out the answers. That cannot honor §4:
the answer to "do you want this, and is there more below?" comes back from the
child's `Connect`, and a plugin that has already returned its inventory never
sees it. It also puts filesystem knowledge into `discovery/`, which has none
and should keep having none.

So `iac` asks during its own `Connect`. It is builtin, so it has the parent
`Runtime` (`runtimeFromCallback(callback)`, `providers/runtime.go:869`, the
same call `sbom` makes) and the coordinator. **One probe runtime serves the
whole walk**, and it never carries an asset:

```go
// providers/iac.go (package providers), sketch
type prober struct{ rt *Runtime }

func newProber(parent *Runtime) *prober {
    // NewRuntime, not NewRuntimeFrom: NewRuntimeFrom copies the parent's
    // *ConnectedProvider pointers, and tryShutdown disconnects every one of
    // them that carries a connection -- the parent's own. It also shares the
    // parent's recording, so Close would save it mid-walk.
    rt := parent.coordinator.NewRuntime()
    rt.AutoUpdate = parent.AutoUpdate
    return &prober{rt: rt}
}

// Close is called once, after the walk.
func (p *prober) Close() { p.rt.Close() }

func (p *prober) probe(child *inventory.Asset, req *plugin.ConnectReq) (*plugin.ConnectRes, error) {
    if err := p.rt.DetectProvider(child); err != nil { // installs and starts on demand, parent's AutoUpdate
        return nil, err
    }
    child.Connections[0].Id = Coordinator.NextConnectionId()
    callbacks := providerCallbacks{runtime: p.rt}
    // No Upstream: every provider's connect calls InitClient on it, which
    // parses a service-account key, and no provider needs upstream to decide
    // whether a folder is its own. The real connect in discovery/ supplies it.
    res, err := p.rt.Provider.Instance.Plugin.Connect(&plugin.ConnectReq{
        Asset: child, Features: req.Features,
    }, &callbacks)
    // Keyed off the connection id rather than off a nil error, because a
    // provider can hand back a live connection alongside a failure.
    if res != nil && res.Id != 0 {
        _, _ = p.rt.Provider.Instance.Plugin.Disconnect(&plugin.DisconnectReq{Connection: res.Id})
    }
    if err != nil {
        return nil, err // caller checks plugin.IsNoMatchError
    }
    return res, nil // asset, continue_exploration
}
```

Two properties of this shape are load-bearing, and both come from how the
coordinator accounts for runtimes:

- **One runtime, not one per candidate.** `Runtime.Close` ends in
  `coordinator.RemoveRuntime`, which stops every provider no runtime still
  references (`providers/coordinator.go:234-260`). A probe runtime is the only
  holder of the child provider it started, so closing one per candidate is a
  provider spawn and teardown per candidate, rejected candidates included,
  because `DetectProvider` starts the provider before `Connect` can say no. On
  a monorepo where every `*.yaml` is a candidate for `k8s`, `cloudformation`
  and `ansible`, that is hundreds of spawns. A single runtime keeps every
  provider it touched in `rt.providers` (`ConnectedProviderIDs` lists them
  whether or not a connection is open, `providers/runtime.go:264`), so the
  providers live for the walk and are stopped once at `Close`. What remains
  is one respawn per *accepting* provider between the end of the walk and
  `discovery/` reconnecting the children, which is the double connect
  accepted below.
- **Never through `Runtime.Connect`.** `Runtime.Connect` sets
  `Provider.Connection` (`setProviderConnection`, `runtime.go:275`), and
  `unsafeRefreshRuntimes` (`coordinator.go:177`), which runs under any
  `RuntimeFor` or `RemoveRuntime` from any goroutine, indexes a runtime under
  its current asset's platform IDs (`unsafeSetAssetRuntime`, `:207`). A
  reused probe runtime connected to child X at that moment would be indexed
  under X, the entry would outlive the `Disconnect` (`RemoveRuntime` deletes
  only the keys of the runtime's *current* asset, `:227`), and discovery's
  later `RuntimeFor(X)` would hand back the probe runtime instead of a fresh
  one: `createRuntimeForAsset` would see a foreign connection and drop X as a
  duplicate (`discovery/discovery.go:67`). Calling the plugin directly with the
  runtime's own `providerCallbacks` keeps `rt.asset()` nil for the runtime's
  whole life, so it is never indexed and `Close` leaves nothing stale.
  `Runtime.Connect` also registers the asset with the recording and runs the
  provider-switch stopgap, neither of which a probe wants. `providerCallbacks`
  is unexported, which is one more reason the service lives in package
  `providers` (§7).

`RuntimeForAsset` (`providers/asset_resolver.go`) is not the right tool
either: `connectedRuntime` keeps the sub-runtime on a failed connect, and
rejection is the normal outcome of a probe.

No new callback RPC, no JSON on the connection: the opt-in table is read
in-process from `Coordinator.Providers()` (installed, authoritative) and
`DefaultProviders` (everything else), which is the same union
`EnsureProvider` resolves against.

The walk:

1. Resolve `--discover` to a set of opt-ins (§1). `all` is every enumerated
   opt-in; `auto` is the `Auto` subset; names are matched against `Discovery`.
2. Read the tree once, pre-order, skipping the ignored directory names (§4).
3. For each directory, for each selected opt-in not already stopped on an
   ancestor: evaluate its matchers against the directory's own entries (a glob
   with no slash) or against paths below it (a glob with a slash). A hit
   yields one candidate: the directory, or with `PerFile` each matching file.
4. Probe each candidate with a child asset whose single connection has
   `Type: optIn.ConnType`, `Path` and `Options["path"]` both set to the
   absolute candidate path, and `Options` merged from `optIn.Options`. **No
   `Discover` on the probe**: of the nine providers only `k8s` discovers
   children inside `Connect`, and it skips that work when `Discover` is nil, so
   setting it only makes a k8s probe enumerate a manifest tree that is about to
   be thrown away. It goes on the *accepted* asset instead (step 5), where the
   discovery layer acts on it. Both path fields because the providers
   disagree: `docker-file` reads `Config.Path`
   (`docker_file_connection.go:67`), the rest read `Options["path"]`
   (terraform `hcl_manifest.go:46`, helm `render.go:12`, kustomize
   `connection.go:68`, bicep `connection.go:135`, cloudformation
   `connection.go:56`, ansible `connection.go:42`, k8s `shared/connection.go:21`).
5. `IsNoMatchError` → drop the candidate, nothing recorded. Any other error →
   record it on the root's `detections` with the error, log it, keep walking:
   a broken chart must not hide the terraform next to it. Success → the
   returned `ConnectRes.Asset` goes into the inventory (its name, platform IDs
   and platform were decided by the real provider) with two additions: the
   reverse edge of §6, an `inventory.AssetRelationship` naming the `iac` root
   asset and the `iac.detection` that found it, and `Discover: {Targets:
   ["auto"]}` when the provider did not set one itself, which is what makes the
   child's own children appear as they would under a direct scan.
   `ConnectRes.ContinueExploration` decides whether this opt-in is offered
   anything below this directory.
6. `--discover all` offers the root directory to every opt-in **whose `PerFile`
   is off**, without matching (the escape hatch for a matcher that is wrong),
   then continues by matching below wherever a provider asked to keep going. A
   `PerFile` opt-in reads one document per asset and can say nothing about a
   directory: `docker-file` handed one builds an asset describing nothing, and
   ansible's file branch would take the project branch and duplicate another
   opt-in's work.

`Connect` returns `ConnectRes{Inventory: <the accepted assets>}`. The discovery
layer then connects each of them the ordinary way (`createRuntimeForAsset`,
`discovery/discovery.go:51`), which is what makes the result visible to
`cnspec scan` and the asset explorer with no change on that side.

#### The probe connection is dropped, and the child connects twice

Each probe disconnects as soon as it has the answer, and the probe runtime is
closed after the walk. The discovery layer then connects the accepted asset
again, on a provider that was restarted once at that boundary if nothing else
held it. That is a double `Connect` per accepted candidate, and it is accepted
for this effort.

Measured before deciding, on this machine, whole-process wall time of
`mql run <connector> <path> -c asset.name`, three runs each, providers already
installed (the measurement is an upper bound on one `Connect`, since it also
includes CLI start, provider spawn, query and teardown):

| target | size | wall time |
|---|---|---|
| `local` (baseline, no IaC) | | 318–332 ms |
| `terraform` (`cs-agentic-mssp/mvs-operations/infra/terraform`) | 15 files, 919 lines | 234–235 ms |
| `k8s` manifest (`conference-demos/k8s-manifests/shippingservice.yaml`) | 1 file | 263–296 ms |
| `docker file` (`conference-demos/containers/src/recommendationservice/Dockerfile`) | 1 file | 313–334 ms |
| `ansible` (`samples/hack-lab/.../windows-exchange.yml`) | 1 file | 229–234 ms |

A `Connect` is a fraction of a number that is itself a fraction of a second,
against a scan whose policy evaluation runs for seconds. Adopting the probe's
live runtime instead would mean teaching `createRuntimeForAsset` to tell "this
runtime already holds a connection because a probe made it" from "this runtime
already holds a connection because the asset is a duplicate"
(`discovery/discovery.go:67`), which is surgery in the asset explorer's
identity handling. Out of scope; listed under follow-ups with the trigger for
revisiting it.

Verification re-measures on a real monorepo with `iac` in place: the reference
number is the wall time of `cnspec scan iac ./repo` versus the sum of the
per-connector scans it replaces. If the probes come to more than a quarter of
the total, the follow-up moves up.

### 3. `iac` passes what it knows; the provider decides its own identity

A child asset gets the connection options the provider it is aimed at already
reads: `Path` and `Options["path"]` for a local tree (§2 step 4), which is what
`github` and `gitlab` set today (`gitAsset`,
`providers/github/resources/discovery.go:640`), alongside `ssh-url` and
`http-url` for a repo.

Handing over a tree is a cross-provider call, and the connecting provider decides
its own platform ID, as it does today (`providers/kustomize/provider/provider.go:136`,
`providers/terraform/provider/detector.go:54`). `iac` takes no view on identity
and imposes no shared scheme: a provider that is handed a local path derives an
ID from the path, one handed a repo derives it from the repo, and a provider that
later needs to distinguish a new kind of source decides that then. Shipped asset
IDs are untouched.

Later source kinds add whatever options they need, in the phase that implements
them. Two ways to reach a non-local tree, both deferred:

- **Materialize.** `iac` fetches the tree once into a workspace and hands local
  paths. Needs no provider changes.
- **Serve a filesystem.** The connection exposes an `fs.FS` over the plugin
  channel and providers read through it. Needed where materializing is wrong — a
  40 GB image, a host we only have a shell on — and it is a migration for every
  IaC provider off `os.ReadFile`.

Materialize is the phase-4 default; the filesystem handoff is phase 5 and is
scoped per provider.

### 4. The provider decides its own scope

What gets probed is a folder, or with `PerFile` a file. The provider then says
what it wants:

- **not mine** — `ErrNoMatch`, dropped
- **mine, and stop descending here** — it has taken everything below
- **mine, keep descending** — more of the same may live further down

The walk descends from the top, probing wherever a matcher fires, and stops
descending a branch for an opt-in when the provider that claimed it said to.
*Strictly* below the claimed site: a provider that took a folder has said
nothing about that folder's own other candidates, so a `PerFile` sibling in the
same directory is still offered and a stop never retracts the site itself.

So scope is the provider's decision, not a rule of the walk. That is the only
place the answer can live, because the providers genuinely differ and each one
already knows its own answer:

| provider | what it does with a folder |
|---|---|
| terraform | takes the first matching folder and stops. `filepath.WalkDir` over everything below it, as one configuration (`providers/terraform/connection/hcl_manifest.go:93`) |
| helm | finds the chart it is in, or the charts below it, and stops (`providers/helm/connection/connection.go:176`) |
| k8s manifest | walks everything below (`manifest_parser.go:294`), one asset, stops |
| ansible | reads the folder it was given and its `playbooks/` subfolder, and nothing deeper; keeps descending, so a bare playbook further down is still found |
| docker-file, cloudformation | per file; keep descending, there is one asset per document |

Terraform taking a whole repository as one asset is deliberate. A user who wants
`envs/prod` and `envs/dev` as separate assets says so by pointing at
`envs/prod` — the scan target is how you narrow the scope, and it needs no
second mechanism.

The answer rides on `ConnectRes`, which a provider already returns from
`Connect`, and which the probe hands straight back to the walk:

```protobuf
// ConnectRes, providers-sdk/v1/plugin/plugin.proto (fields 1-5 are taken)
// Keep exploring below this folder for this provider. Default false: a
// provider that says nothing has taken everything it wants here, and the walk
// stops descending this branch for it. Other providers are unaffected.
bool continue_exploration = 6;
```

False by default, so a provider has to ask for more explicitly. Terraform and
helm say nothing and get one asset; `docker-file` and `cloudformation` set it
and get one per document. A provider that has not thought about it yet behaves
like terraform, which is the safe end: one asset too few is visible in a
report, where one per directory of a monorepo is noise.

**Ignored by default**, because these directories hold code that is not yours
and would emit assets nobody asked to audit:

```
.git  .terraform  .terragrunt-cache  .venv  node_modules  vendor  target  dist
```

`.terraform` is the load-bearing one: it caches downloaded modules, each a
directory full of `.tf` files. The terraform connection already skips it
(`hcl_manifest.go:105`), so this is about not offering the folder in the first
place. The list is a default, overridable with `--iac-ignore`, a list flag on
the `iac` connector.

### 5. `iac` has a real root resource

Every provider that accepts a connection declares a root (ADR 031,
`providers/roots_test.go`), and `iac` is no exception. Its root is the tree it
connected to and what was found in it:

```
// providers/iac/resources/iac.lr
option provider = "go.mondoo.com/mql/providers/iac"
option go_package = "go.mondoo.com/mql/providers/iac/resources"
option root = "iac"

// Infrastructure as code project
//
// The tree of infrastructure-as-code files reached by this connection, and the
// entry points found in it. Each detection names the tool, the directory or
// file it was found at, and the files that matched.
iac @root {
  // Where the tree was read from
  source() iac.source
  // Entry points found in the tree
  detections() []iac.detection
}

// Source an infrastructure-as-code tree was read from
//
// Private because a resource named `<parent>.<field>` queried by its dotted
// path compiles to an empty husk: `iac.source.kind` would resolve to a bare
// iac.source and read null. Private makes the dotted path go through the
// accessor.
private iac.source {
  // Kind of source: file, git, archive, container-image, ssh, or oci
  kind string
  // Coordinate of the source, such as a path or a repository URL
  origin string
  // Version of the source, such as a git ref or an image tag
  ref string
}

// Infrastructure-as-code entry point
//
// One place in the tree that a tool accepted as its own, and the asset that
// was made of it. `asset` is that asset: `iac.detections { tool path asset }`
// lists what a scan of this tree produces, with the same identity the scan
// reports. See ADR 030 and ADR 031.
iac.detection {
  // Tool the entry point belongs to, such as terraform or helm
  tool string
  // Path of the entry point, relative to the root of the tree
  path string
  // Files that matched
  files []string
  // Asset the tool made of this entry point
  //
  // Null when the tool reported an error instead of connecting.
  asset() asset
  // Error the tool reported for this entry point, empty when it connected
  error string
}
```

`error` and `asset` are the additions over the first draft. A probe that failed
for a reason other than `ErrNoMatch` (§2 step 5) has to be visible somewhere,
and the root is where the walk reports. `asset` is §6.

Queries it answers:

```
iac.detections.map(tool)
iac.detections.where(tool == "terraform").map(path)
iac.detections.where(error != "")
iac.detections { tool path asset }
iac.source.ref
```

Asset identity for the root: `iac` decides its own. For a local tree,
`//platformid.api.mondoo.app/runtime/iac/hash/<sha256 of the absolute path>`,
the scheme `kustomize` and `docker-file` use for a local path today.

### 6. Discovered assets are anchored to `iac.detection`

`iac` has a root, so the assets it discovers do not have to be a flat list
hanging off "the project". ADR 030 says what a discovered asset should carry
instead: a directed edge anchored to the resource node that produced it, so
that provenance is structured data rather than a guess, the platform can
correlate on it, and a query can resolve across it (ADR 031). `iac.detection`
is that node. It exists for exactly one accepted probe, and it is built from
the same `ConnectRes.Asset` the probe returned, so the asset the edge names and
the asset the scan connects are the same object rather than two descriptions
of one.

Both directions come from one function, which is ADR 030's one invariant:

- **Reverse (discovery).** Every asset in `iac`'s inventory carries
  `Relationships: [{Asset: <iac root stub>, ResourceType: "iac.detection",
  ResourceId: <detection id>}]`. The stub is the root's `Id`, `Mrn` and
  `PlatformIds`, which `iac` has computed before the walk starts (§5). This is
  `mcpServerAssetWith` + `hostRefOf` in
  `providers/os/resources/mcp_discovery.go:95-122`, and it is what
  `targetAssetForAnchor` reads back (`providers/asset_resolver.go:229`), so a
  recording of an `iac` scan resolves its children without reconnecting.
- **Forward (query).** `iac.detection.asset` returns the anchor
  `(iac.detection, <id>)` as an `asset` value, and `mqlIacDetection`
  implements `plugin.AssetSource` (`providers-sdk/v1/plugin/asset.go:28`),
  returning the accepted child asset with its connection (`Type`, `Path`,
  `Options`; a local tree has no credentials, and per ADR 031 reachability is
  asked for at connect time and never stored). `plugin.Service.ResolveAsset`
  answers from the resource cache with no further code
  (`asset.go:42`), which the builtin gets by embedding `plugin.Service` (§7).
  Precedent: `mqlDockerContainer.MqlAsset` (`providers/os/resources/docker.go:142`).

The detection's `__id` is the anchor id on both sides; it is the opt-in's
`Discovery` name plus the tree-relative path (`terraform\x00envs/prod`), which
is unique within one tree because the walk probes each opt-in at each path at
most once. Building the id, the relationship and the `AssetSource` answer from
one helper is what phase 2 tests for parity: the asset a `detection.asset` read
resolves to and the asset the inventory carried must compare equal.

**Typing, and its v14 limit.** The field is a bare `asset`, not `asset<root>`.
The nine opt-ins resolve to eight different roots (`terraform`, `helm`,
`kustomize`, `k8s`, `ansible`, `cloudformation.template`, `bicep`, `os.any`),
the set is open to any provider that opts in, and ADR 031 puts the root on the
*type*, decided at schema time, precisely so the value carries identity alone.
`iac` cannot name one root for a field whose target is chosen per probe. A bare
`asset` is legal (`types.AssetLike`, `types/types.go:121`) and does what the
relationship needs: identity, reachability through `AssetSource`, correlation
on the platform. What it does not do in v14 is chain: `iac.detections.first.asset.blocks`
is rejected at compile time (`mqlc/mqlc.go:1136`, `availableFields` offers
nothing for a rootless asset), and `ResolveAssetRoot` refuses a deref with no
root (`providers/asset_resolver.go:51`). Making a detection chain into its
tool's tree needs a construct ADR 031 does not have yet, and is a follow-up
with two candidate shapes named there. It is not a data-model gap: the edge,
the anchor and the resolver already carry everything a typed hop would use.

What this buys now: `cnspec scan iac ./repo` reports every child with a
structured edge to the project and the detection that found it, the same
join the MCP-server and docker-container assets already ship; a recorded scan
replays its children through the edge; and the project/asset hierarchy in
cnspec comes from ADR 030 data rather than only from `TrackedAsset.Parent`.

### 7. Builtin wiring

What "builtin like `sbom`" means in files. Everything here has a precedent in
the tree; nothing is a new kind of thing.

| piece | where | precedent |
|---|---|---|
| the service | `providers/iac.go`, package `providers`, `type iacProviderService struct{ *plugin.Service }` | `providers/sbom.go`; embedding `plugin.Service` the way `providers/core/provider/provider.go` does gives `GetData`, `StoreData`, `Disconnect`, `Heartbeat`, `Shutdown`, `Translations`, `ResolveAsset` for free |
| the `Provider` value | `var iacProvider = Provider{Provider: &iacconf.Config}` in `providers/iac.go` | `sbomProvider` |
| config | `providers/iac/config/config.go`, `Name: "iac"`, `ID: "go.mondoo.com/mql/providers/iac"`, `Version: mql.GetVersion()`, `Root: "iac"`, `ConnectionTypes: []string{"iac"}`, `Requires: core`, one connector `iac PATH` with flags `--iac-ignore` (list) and `Discovery: nil` (help text comes from the opt-ins, §1) | `providers/core/config/config.go` for the version, `providers/kustomize/config/config.go` for the rest |
| resources | `providers/iac/resources/iac.lr`, `.lr.versions`, generated `iac.lr.go`, `iac.resources.json` | `providers/core/resources/` |
| gen | `providers/iac/gen/main.go` calling `gen.CLI(&config.Config)` | `providers/core/gen/main.go` |
| registration | an entry in `builtinProviders` (`providers/builtin.go`) with `Schema: MustLoadSchema("iac", iacInfo)` and `//go:embed iac/resources/iac.resources.json`, **plus `Version`, `Root` and `Requires`** — only the plugin path in `unsafeStartProvider` copies those off the config, and a builtin is returned as-is, so without them `_` does not resolve for an iac asset and every `asset` read logs an undeclared cross-provider call | the `core` entry. The file header says it is generated by `make providers/config`; it is not, that target writes `builtin_dev.go` (`providers-sdk/v1/util/configure/configure.go:150`). Edit it by hand and fix the header while there |
| resolution | a clause in `EnsureProvider` on `iacProvider.ID`, `ConnName == "iac"`, `ConnType == "iac"` | the `sbom` clause, `providers/providers.go:456` |
| start | add the ID to the no-warn list in `unsafeStartProvider` (`providers/coordinator.go:329`) | `sbomProvider.ID` there |
| build | a `providers/build/iac` target that runs `./lr go`, `./lr versions --version 14.0.0` and `go run ./gen/main.go .` without compiling a binary; add it to `providers/build` and `mql/generate/core`, and keep `iac` out of `PROVIDERS` | `providers/build/mock` (`Makefile:299`) and `buildProvider` (`:83`). `--version` is not optional: the version detector regex-matches a *quoted* `Version:` in `config.go`, and `iac` tracks the binary through `mql.GetVersion()`, so without it every entry is silently stamped with the `9.0.0` fallback — which is why `core.lr.versions` is full of `9.0.0` |
| gitignore | `!providers/iac/resources/*.resources.json` | the `core` exception, `.gitignore:28` |
| roots test | satisfied by `Root:` in config and `option root` + `@root` in the `.lr`; `readProviderRootState` reads `providers/iac/config/config.go` | `providers/roots_test.go:59` |

**Experimental at every layer.** `Maturity: resources.MaturityExperimental`
on the provider is what `mql providers list` tags, and nothing inherits from
it: the schema carries only what the `.lr` says, so `iac`, `iac.source` and
`iac.detection` each carry `@maturity("experimental")` (the way `dropbox`,
`notion` and `bitwarden` mark their roots), which is what `mql shell`,
`mql providers resources`, the LSP and the generated docs read. Fields inherit
the resource's level through `EffectiveFieldMaturity`. `plugin.Connector`
has a `Maturity` field too, but nothing consumes it, so the connector says it
in its help text instead. Graduating the provider means removing all of these
together.

The resources package (`providers/iac/resources`) imports only `providers-sdk`,
so package `providers` can import it without a cycle. The service stays in
package `providers` because `runtimeFromCallback`, `Runtime.coordinator` and
`NewRuntimeFrom` are what the probe is made of and they are not exported; `sbom`
sits there for the same reason.

The `iac` connector reaches the CLI through `ListActive` → `ListAll`, which
already merges `builtinProviders` into the list `attachProvidersToCmd` walks
(`providers/providers.go:369`). `mql providers list` shows it the way it shows
`sbom`.

### 8. CLI surface

```
cnspec scan iac ./repo
cnspec scan iac ./repo --discover terraform,helm
cnspec scan iac ./main.tf
mql shell iac ./repo -c "iac.detections"
```

- `--discover` defaults to `auto`, the declared default set of discovery names.
  Those providers are fetched whether or not the tree turns out to contain them;
  probing then decides which produce an asset.
- `--discover all` is every enumerated opt-in, and skips matching at the root:
  each opt-in is probed with the tree and decides for itself. The escape hatch
  for a matcher that is wrong.
- Named values are discovery names, not provider names. `terraform` and
  `opentofu` are not in `auto` and are selected by name, separately or
  together; together, a folder holding both dialects yields both assets (§1).
- `--iac-ignore` replaces the default ignore list (§4).

The CLI changes are the two described under
[`--discover` decides the provider set](#--discover-decides-the-provider-set-before-anything-is-read):
`AttachCLIs` resolves `Discover.Targets`, and
`genBuiltinFlags(connector.Discovery...)` (`cli/providers/providers.go:234`,
called from `setConnector` at `:432`) builds the `--discover` help text from
the enumerated opt-ins when the connector's name is a target any opt-in
declares.

**Offline and air-gapped.** Every install happens before the tree is read and
before any child asset is connected, because the provider set follows from
`--discover` and nothing else. What a missing provider costs depends on whether
the user named it — see
[what happens when a provider is missing](#what-happens-when-a-provider-is-missing).

**Sub-provider flags are not forwarded.** `--ignore-dot-terraform` is a
`terraform` connector flag with no route through the `iac` connector; the direct
connector stays the way to set it.

## cnspec

`cnspec scan` and `cnspec shell` attach every connector — the
`SupportedConnectors` filter at `apps/cnspec/cmd/root.go:98` applies only to
`sbom`, `vuln` and `aibom` — so the `iac` connector appears in both with no
cnspec change, once cnspec builds against an mql that has it (a builtin ships
with the library, not through the provider registry).

What does need attention:

- **The `iac` platform is new**, so a bundle may have no filter matching the
  root asset, which reports as `asset doesn't support any policies`
  (`NewAssetMatchError`, `cnspec/policy/explorer_errors.go:35`, raised at
  `policy/resolver.go:460`). Worth seeing in a real run before deciding whether
  it needs anything; the per-tool children match the policies that already
  exist.
- **Asset tree.** `technology=iac` already exists
  (`providers/providers.go:1342`, key `category`), with `category=terraform`,
  `category=ansible`, `category=kustomize` and the rest under it. The `iac`
  root attaches as `technology=iac`, `category=project`, and
  `AssetUrlBranch.references` lets the per-tool subtrees hang beneath the
  project instead of beside it.
- **Parenting.** Children discovered through a connection are already tracked
  with their parent (`discovery/asset_explorer.go`, `TrackedAsset.Parent`), and
  each child also carries the ADR 030 edge to the project and its detection
  (§6). The platform correlates on the edge's platform IDs, the same join it
  uses for `related_assets`, so the hierarchy needs no new wiring on either
  side.

## What this does not change

- **No `Requires` entries** beyond `core`. `iac` emits assets; it never calls
  another provider's resources. ADR 042 declarations are for cross-provider
  *invocation*, and adding ten of them here would be wrong.
- **No new plugin RPC.** Nothing is added to `plugin.ProviderPlugin` or
  `plugin.ProviderCallback`; the probe is an in-process Go call, which is what
  builtin buys. The one proto addition is `ConnectRes.continue_exploration`
  (§4).
- **No new install path.** Target resolution is two fields on `ProviderLookup`
  and one clause in `Providers.Lookup`; fetching, auto-update, air-gapped
  behavior and the `DefaultProviders` fallback are the ones `EnsureProvider`
  already has.
- **Almost no changes to `discovery/`.** It connects what `iac` hands it, as it
  does for every other provider's inventory. It gains one sentinel,
  `discovery.ErrNoMatch`, and the handling is **asymmetric**. On a *child*
  (`asset_explorer.go:213`) a no-match is not an error to report and not an
  asset either, like `ErrDuplicateAsset`: whatever emitted the child already
  decided, and recording it would attribute that judgement to the user. On a
  *root* (`:127`) it stays a reported error carrying the provider's own message
  — there the user named that connector for that path, and swallowing it would
  produce a scan that succeeded having connected to nothing, which is exactly
  what §1 refuses for `--discover`. Signalling it as a nil runtime is not
  available: callers read that as `ErrDuplicateAsset`.
- **No platform IDs change.** §3 names the existing encodings; it does not
  replace them.
- **No `related_assets`.** `iac` writes only the ADR 030 edge (§6); the
  deprecated flat list is not populated for new producers.
- **No new provider binary, no registry release.** `iac` versions with mql.

## Phases

1. **Resolution.** `plugin.TargetOptIn` and `Matcher` (with a `Match(path)`
   helper and its unit tests, since both the walk and the CLI help text use
   it); `plugin.ErrNoMatch` and `IsNoMatchError` (tested for the raw sentinel
   and the gRPC status form); `ConnectRes.continue_exploration` and
   `go generate ./providers-sdk/v1/plugin`; `ProviderLookup.Target`/`Discovery`
   with the `Providers.Lookup` clause and a test in `providers/providers_test.go`;
   the `defaults.go` generator emitting `Targets` and `make providers/defaults`
   re-run; the `AttachCLIs` resolution step and the declared `auto` set. This
   is the out-of-the-box guarantee, and it is testable on its own: a clean
   machine, `--discover terraform,k8s`, both providers fetched before the walk
   starts. Nothing in this phase depends on `iac` existing.
2. **The builtin and the local walk.** Everything under §7; the walk and probe
   of §2 and the anchoring of §6, with unit tests for the walk over a fixture tree using a fake prober
   (accept / `ErrNoMatch` / other error / `continue_exploration` on and off,
   ignore list, `PerFile`, `all`); the root resource; the nine opt-in blocks
   and the nine `ErrNoMatch` changes from the table in §1, each with a test
   that hands the connection a folder it must reject. The ADR 030 parity test
   of §6: for every detection in the fixture, `detection.asset` resolved
   through `ResolveAsset` equals the inventory asset carrying that detection's
   reverse edge, and both carry the child's platform IDs after connect.

   **The fixture tree.** Phase 2 ships `providers/iac/testdata/project/`, one
   directory that holds every case this ADR names, so the behavior is tested
   end to end against one target rather than assembled from nine separate
   repos. It is what the walk's unit tests run over (with a fake prober), what
   `mql shell iac providers/iac/testdata/project` is run against by hand, and
   what phase 3 diffs the forge ports against. Contents, at minimum:

   | path | exercises |
   |---|---|
   | `terraform/` with `main.tf`, `variables.tf` | `terraform`, one asset, stop descending |
   | `terraform/modules/vpc/main.tf` | swallowed by the parent: no second terraform asset |
   | `opentofu/main.tofu` | `opentofu` alone |
   | `mixed/main.tf` + `mixed/main.tofu` | both named → **two detections, one asset**: terraform's platform ID is deliberately dialect-agnostic, so both probes return the same identity and the asset carries both anchors. `terraform` alone ignores `.tofu`; `opentofu` alone takes both with the override |
   | `charts/api/Chart.yaml` + `templates/*.yaml` | `helm` takes the chart; `k8s`, `cloudformation`, `ansible` probe the templates and reject |
   | `k8s/deployment.yaml`, `k8s/service.yaml` | `k8s` manifest mode, one asset for the folder |
   | `kustomize/base/kustomization.yaml`, `kustomize/overlays/prod/kustomization.yaml` | `kustomize`, one asset per kustomization |
   | `cloudformation/stack.yaml` (with `AWSTemplateFormatVersion`) | `cloudformation`, per file |
   | `ansible/ansible.cfg`, `ansible/roles/web/tasks/main.yml`, `ansible/site.yml` | `ansible` project dir, and the playbook inside it not emitted a second time |
   | `ansible/playbook-only/site.yml` | `ansible` bare playbook |
   | `bicep/main.bicep` | `bicep` |
   | `Dockerfile`, `services/api/Dockerfile`, `services/web/Dockerfile` | `dockerfile` per file, `continue_exploration` keeps descending. First iteration: only files named `Dockerfile`. Then add `Dockerfile.dev` and `api.Dockerfile` and widen the matcher |
   | `config/settings.yaml` (plain YAML, no `kind`, no `Resources`, not a play) | every YAML opt-in probes it and every one returns `ErrNoMatch`; nothing emitted, nothing in `detections` with an error |
   | `terraform/.terraform/modules/x/main.tf`, `node_modules/pkg/Dockerfile` | ignored by default; found with `--iac-ignore ""` |
   | `broken/Chart.yaml` (malformed) | a non-`ErrNoMatch` failure: recorded on `iac.detections` with `error`, the rest of the tree still scanned |

   The expected outcome of `mql shell iac providers/iac/testdata/project -c
   "iac.detections { tool path error }"` is checked into the test as the
   assertion. The asset side is asserted through `ResolveAsset` rather than
   through printed output, because a bare `asset` renders as the literal string
   `asset` and the column would prove nothing. The fixture files are real,
   minimal configurations that the
   direct connectors also accept (`mql run terraform
   providers/iac/testdata/project/terraform -c "terraform.blocks.length"` works
   too), so a fixture that drifts fails loudly on both sides.

   Verification beyond the fixture: a real monorepo holding at least terraform,
   a Helm chart, k8s manifests and a Dockerfile, `mql shell iac ./repo -c
   "iac.detections"` listing them, and `cnspec scan iac ./repo` producing the
   same assets as the direct scans with the same platform IDs. Record the
   probe-time share (§2).
3. **Deduplicate the forges.** Port `github` and `gitlab` onto the same opt-ins,
   deleting `classifyIacTree` and `discoverRepoTypes`. **No detection is lost**
   — not "behavior is identical": both forges use an *ordered exclusive* switch
   (a `Chart.yaml` never also counts as a k8s manifest) which §1 deliberately
   replaces with "every match is probed", GitHub detects Terraform through the
   languages API rather than a glob, GitLab matches `.tf` only, and neither has
   a `*.bicepparam` or an ansible arm. The port detects strictly more.
4. **Git and archive sources.** A fetched tree materialized once. The open
   engineering question is workspace lifetime: `NewGitClone`
   (`providers-sdk/v1/plugin/git.go:19`) clones per *connection*, so N children
   means N clones today, and a shared workspace needs an owner that outlives
   every child runtime. Candidates: a content-addressed cache under
   `~/.mondoo/cache` with a TTL sweep (robust to arbitrary close ordering), or
   keeping the parent connection alive via the `parent_connection_id` already on
   `inventory.Config` (`inventory.proto:152`).
5. **Remote and container trees.** The `fs.FS` handoff, unlocking
   `scan iac ssh://host:/srv/deploy` and `scan iac docker://image` without
   materializing.

Phases 1 and 2 are this effort.

## Alternatives considered

**A detection RPC.** `iac` hands a file list to every candidate provider and
each claims what is its own. Maximally expressive, and it puts the knowledge in
the right place — but every candidate must be downloaded and started just to be
asked, which makes the first `scan iac` on a clean machine install every IaC
provider. Rejected. Declared matchers plus an authoritative provider gets the
same accuracy at a fraction of the cost, because the expensive judgment happens
after the provider is already being started for real work.

**A standalone `iac` plugin.** The first draft. It would have needed a new
`ProviderCallback` RPC for the probe (the callback service carries only
`Collect`, `GetRecording`, `GetData`), a gRPC round trip per candidate, a
registry release for a binary with no dependencies of its own, and a JSON copy
of the opt-in table on the connection because the plugin cannot see
`DefaultProviders`. Rejected in favor of builtin, which needs none of it.

**Emit candidates, let discovery prune.** Also the first draft: `iac` emits
every matching folder, the discovery layer connects them and drops nested ones
when a parent said `continue_exploration = false`. Rejected because it teaches
`discovery/` about path nesting, and because it connects providers to folders
they will reject, in the layer that reports errors to the user.

**Hardcoding the matchers inside `iac`.** Simplest to ship and gives total control
over precedence, but it is a fourth copy of knowledge that already exists twice
too often, and third-party or enterprise providers could never join the target.
Rejected.

**One asset per provider per tree.** Fewer assets, and it matches what the
GitHub provider does for Terraform today. Rejected because it merges `envs/prod`
and `envs/dev` into one row, which is exactly the distinction an IaC audit
exists to make.

**A CLI-level meta-target.** Implementing `iac` as a concept in
`cli/providers` rather than as a provider. Rejected: it would need new machinery
in both mql and cnspec, would not be reachable from an inventory file, and
would not be queryable in `mql shell`. As a provider it is reachable everywhere
a connector is, for free.

## Follow-ups

Decided here, to be built where noted. None of these block phase 1.

### Adopt the probe's runtime instead of connecting twice

Out of scope for this effort; see §2 for the measurement that put it there. It
requires `createRuntimeForAsset` (`discovery/discovery.go:51`) to distinguish a
runtime a probe left connected from the duplicate-asset case it currently
infers from `runtime.Provider.Connection != nil` (`:67`), and the coordinator
to hand a probe's runtime to the asset explorer as the child's own. Revisit
when a real `scan iac` spends more than a quarter of its wall time in probes,
or when phase 4 makes a child connect expensive (a clone per connect).

### Typed traversal from a detection into its tool's tree

`iac.detection.asset` is a bare `asset` (§6), so
`iac.detections.where(tool == "terraform") { asset.blocks }` does not compile
in v14. Two candidate shapes, to be decided under ADR 031 rather than here:

- **A checked narrowing on asset values**, `asset` → `asset<terraform>`,
  verified at run time against the target's `ConnectRes.Root` (the probe
  already has it) and failing with a root mismatch the way `ErrRootMismatch`
  does. Keeps the root on the type and the value identity-only.
- **The tool provider extends the detection.** ADR 042 keeps "providers
  extending each other's resources with new fields" legal in v14 and v15, so
  `terraform` could declare `extend iac.detection { terraform() asset<terraform> }`,
  answering null for detections that are not its own. Typed by construction,
  but it requires `import iac` at codegen in every participating provider and
  puts a field per tool on a resource whose point is not knowing the tools.

Either way the data model is done: the edge, the anchor id and `AssetSource`
are what a typed hop resolves through.

### Ansible must reject on mismatch, not connect empty

Done, and folded into the §1 table. Kept here because it is the case that showed
why rejection has to be tested rather than assumed, and because writing it
turned up two things the first attempt got wrong. A YAML **list** of unrelated
dicts decodes into a playbook with empty plays
(`providers/ansible/play/playbook.go:315`), so the connect succeeded and the
asset reported nothing — but a gate written against the decoded struct also
drops an import-only playbook, since `import_playbook` lives on `Task` and not
on `Play`; and a gate that treats every decode failure as a mismatch silently
drops a genuinely malformed playbook. The shipped gate asks whether the bytes
are YAML at all first, then applies `project.LooksLikePlaybook`, which is the
rule the project loader already used.

### Workspace lifetime, for phase 4

`NewGitClone` (`providers-sdk/v1/plugin/git.go:19`) clones per connection, so N
children means N clones. A shared workspace needs an owner outliving every child
runtime, and the coordinator has no such hook. Two candidates, both stated in
phase 4: a content-addressed cache under `~/.mondoo/cache` with a TTL sweep, or
keeping the parent connection alive through the `parent_connection_id` already on
`inventory.Config` (`inventory.proto:152`). Decide when phase 4 starts, against
a real repository.

### Sub-provider flags

Not forwarded. `--ignore-dot-terraform` is a `terraform` connector flag with no
route through the `iac` connector; the direct connector stays the way to set it.

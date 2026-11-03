# ADR 052: Resource permissions

## Status

Proposed

## Context

`command` runs whatever string it is given, on every system mql can reach.
`command("id").stdout` is a harmless probe; `command("curl … | sh").exitcode`
is remote code execution, and the two are the same resource. Its sibling
`powershell` does the same with a script. Both are first-class MQL resources
(`providers/os/resources/os.lr:933`, `:952`), so any query that reaches a
scanner can use them: a query pack pulled from a registry, a policy enabled in a
space, a check written by anyone with write access to that space.

The scanner usually runs as root or SYSTEM. `cnspec serve` on a server is a
long-lived agent with full read access to the host, and on that host the
question "who can make this machine run a command?" has an uncomfortable
answer: everyone who can put a policy in front of the agent. Some operators
cannot accept that, and today the only answer we can give them is "do not run
the agent".

The ask is a switch on the scanning host, in `mondoo.yml`, that turns a
resource off. `command` is the reason for it, but nothing about the mechanism
is specific to `command`: an operator who does not want `file` reading
arbitrary paths, or who wants `aws.iam.credentialReport` kept out of every
scan, should be able to say so the same way. A query that touches a disabled
resource must fail visibly, with an error that names the resource and the
setting, on the CLI and on the platform. A disabled resource that silently reads
as null would be indistinguishable from a passing check, which is the failure
ADR 046 exists to remove.

### Where the switch can and cannot go

Four facts about the tree constrain the design.

**The compiler is not a security boundary.** A policy scanned through the
platform arrives as a resolved execution job whose queries are already compiled
`CodeBundle`s; the client executes the bytecode it is handed. A check in
`mqlc` would only see queries compiled locally (`mql run`, the shell, a local
bundle) and would be bypassed by everything the platform sends.

**The compiler must not depend on local configuration anyway.** A query's code
ID and checksum are computed from its compiled bundle, and the platform keys
results, scores and exceptions on them. If disabling a resource changed what
`mqlc` emitted, two agents running the same policy would disagree about what
the policy *is*. Compiled output has to stay a function of the query and the
schema, nothing else.

**Providers use `command` internally, and must keep doing so.** There are 70
`CreateResource(runtime, "command", …)` calls across 45 files in
`providers/os/resources` (`lsblk.go`, `yum.go`, `firewalld.go`, `selinux.go`,
`nftables.go`, …). These run fixed command lines chosen by provider code, not
by a policy author, and they are how `packages`, `mount`, `kernel.modules` and
dozens of other resources gather data. They are created inside the provider
process through the plugin runtime and never reach the coordinator. Disabling
the *resource* must not disable the *mechanism*; an operator who turns off
`command` still expects `packages` to work.

**Every query-originated resource passes through one function.** The executor
creates a resource with `runtime.CreateResource(name, args)`
(`llx/llx.go:826`), which is `Runtime.createResource`
(`providers/runtime.go:587`). Cross-provider requests (ADR 042) arrive through
`providerCallbacks.GetData` (`providers/runtime.go:1173`), which calls the same
function. Field reads go through `Runtime.watchAndUpdateContext`
(`providers/runtime.go:731`). Those are the coordinator's two doors, and a
provider-internal `CreateResource` uses neither.

There is one more trap. `command` is reachable under three names:
`alias os.base.command = command` (`os.lr:12`), and `powershell` likewise as
`os.windows.powershell` and `os.any.powershell` (`os.lr:129`, `:175`). A switch
that matched the name the author typed would be bypassed by the alias.
`createResource` already resolves every name to its canonical id
(`name = info.Id`, `providers/runtime.go:595`) before it does anything else.

## Decision

### 1. One setting: `permissions`, with `deny` now and `allow` reserved

```yaml
# /etc/opt/mondoo/mondoo.yml
permissions:
  deny:
    - command
    - powershell
```

A `permissions` block in `CommonOpts` (`cli/config/config.go`), beside
`strict` and `exceptions`, with two lists of resource names:

```go
// Permissions limits which resources this client will create or read on
// behalf of a query, whatever query asks for them (ADR 052).
// Provider-internal use is unaffected.
Permissions ResourcePermissions `json:"permissions,omitempty" mapstructure:"permissions"`

type ResourcePermissions struct {
	// Allow is reserved for an allow-list (§1, "allow"). It must be empty.
	Allow []string `json:"allow,omitempty" mapstructure:"allow"`
	// Deny names resources queries may not use. A denied resource is disabled.
	Deny []string `json:"deny,omitempty" mapstructure:"deny"`
}
```

The shape follows the allow/deny permission blocks operators know from other
tools. The default is **allow**: with no `permissions` block, or with only
`deny`, every resource not denied is available, as it is today. This ADR
implements `deny`. `allow` is part of the structure from the start so that an
allow-list can be added later without a second, differently shaped key.

**`allow` is reserved, and setting it fails closed.** A client that implements
only `deny` refuses to start when `permissions.allow` is non-empty, with
`permissions.allow is not supported by this version; remove it or upgrade`.
An operator who writes an allow-list expects everything else to be off;
ignoring the key would leave every resource on, which is the opposite of what
they asked for. The meaning a future ADR gives `allow` is constrained now, so
that configurations written for it stay valid:

- A non-empty `allow` flips the default to deny: only listed resources are
  available.
- `deny` wins over `allow`. A name in both lists is denied, so an operator can
  allow a broad set and still carve out exceptions.
- Provider-internal use (§3) stays unaffected either way.

The rules below apply to every entry in `deny`, and will apply to `allow`
entries the same way.

- **Names are full resource names**, the way they appear in the schema:
  `command`, `aws.iam.credentialReport`, `k8s.secret`. Matching is exact. An
  entry does not disable sub-resources by prefix: `aws.iam` disables the
  `aws.iam` resource, not `aws.iam.user`. A prefix rule would make a short
  entry disable far more than its author read, and a security setting should
  say exactly what it covers. A glob syntax can be added later without changing
  the meaning of any existing entry.
- **Aliases resolve to their target.** An entry is matched against the
  canonical id after schema lookup, so `command` also disables
  `os.base.command`, and an entry that names an alias disables the resource it
  points at.
- **Unknown names are kept and warned about.** A name that no loaded schema
  knows is not an error, because the provider that defines it may simply not be
  installed yet, and once it is, the entry applies. But a typo here fails
  *open*, so the client logs a warning at startup naming every entry the
  schemas do not resolve: `permissions.deny: no resource named "aws.iam.credentialsReport"`.
- **There is no CLI flag and nothing in a policy, bundle or server response can
  change it.** The setting belongs to whoever owns the scanning host's
  configuration, and the content it constrains must not be able to lift it.
  Like every viper key it can be set through the environment
  (`MONDOO_PERMISSIONS_DENY`); whoever controls the agent's environment
  already controls its configuration, so that adds no new principal.

### 2. Enforced in the coordinator's runtime, not in the compiler

The set lives on the **coordinator**, not on a `Runtime`. Runtimes are created
in several places (`NewRuntime`, `NewRuntimeFrom`, `RuntimeFor` for every
discovered and cross-asset runtime, ADR 031), and `NewRuntimeFrom` copies an
explicit list of fields from its parent (`providers/coordinator.go:163-170`).
A per-runtime setting is one forgotten copy away from a child asset that runs
`command` freely. A coordinator setting cannot be forgotten by a constructor:

```go
// providers/coordinator.go
// SetResourcePermissions installs the set of resources no runtime of this
// coordinator will create or read on behalf of a query (ADR 052).
func (c *coordinator) SetResourcePermissions(p ResourcePermissions) error
```

It is set once at startup by every binary that loads `mondoo.yml` (`mql`,
`cnspec`, `cnspec serve`) and by embedders through the mqlx API (ADR 027).
It returns an error for a non-empty `Allow` (§1), so an embedder cannot get
the fail-open behavior the CLI refuses. It is read on every resource creation,
so it is held behind an `atomic.Pointer` to an immutable decision (today a
denied set; later a denied set plus an optional allowed set), not a mutex. The
runtime asks one question, "is this resource disabled?", so adding `allow`
changes how the answer is computed and none of the call sites below.

The runtime checks it at both doors:

| path | function | check |
|---|---|---|
| resource creation, from a query or a cross-provider callback | `Runtime.createResource` | the canonical `info.Id`, right after `lookupResourceProvider` and **before** the bridging-resource early return, the crash check and the `GetData` call |
| field read | `Runtime.watchAndUpdateContext` | the resource the field belongs to, and the resource type the field returns (or its list element type) |
| clone | `Runtime.cloneResource` | the source resource |

Creation is the gate that matters for `command`: its `init` runs the command,
so the check has to precede the call into the provider, not follow it. The
field-read gate is what makes the setting mean "disabled" for resources a query
never creates by name. `aws.iam.users` returns `aws.iam.user` instances that the
provider created; with `aws.iam.user` disabled, `aws.iam.users` errors and so
does any field read on one of its elements.

`mqlc` is not changed. Compiled bundles, code IDs and checksums are identical
with and without the setting.

### 3. Provider-internal use is unaffected, on purpose

The check is in `providers.Runtime`, which is the coordinator's side of the
plugin boundary. A provider that creates `command` for its own use
(`lsblk.go`, `yum.go`, …) never calls it, so `packages`, `mount` and every other
resource built on a fixed command line keep working with `command` disabled.

That is the intended meaning, and the documentation has to say it plainly:
**`permissions.deny: [command]` stops queries from running commands of their
choosing. It does not stop mql from running commands.** The OS provider still
executes the command lines its resources are built from.

The setting is not sent to providers. They have nothing to do with it, and
keeping it out of `ConnectReq` means a provider release is never needed to
enforce it.

### 4. A tenth error kind: `ERROR_KIND_DISABLED`

A disabled resource is reported as an `*llx.Error` (ADR 046 §6) with a new
kind:

```proto
// llx/llx.proto, enum ErrorKind
  // The client's configuration disabled the resource this needed
  // (permissions, ADR 052). Raised by the runtime, never by a provider.
  ERROR_KIND_DISABLED = 11;
```

```proto
// llx/llx.proto, message ErrorDetail
  // The resource a DISABLED error names, in its canonical form.
  string resource = 6;
```

```go
// llx/errors.go
var ErrDisabled = ...
func Disabled(resource, setting, configPath string) *Error
```

The kind says what happened to the resource (the client disabled it), not which
list did it, so the same kind covers a `deny` entry today and a resource
missing from an `allow` list later. The `setting` argument carries which one.

**Not `forbidden`.** ADR 046 defines forbidden as "authenticated and not
permitted" by the *target*, and everything downstream of the kind is built on
that: `permissions` names a grant to add, and the coverage summary groups
forbidden failures into a list of IAM permissions to request. A disabled
resource has no grant that would fix it; the target was never asked. The
remedy is a local configuration change, made by a different person, and the
coverage line has to name that person's setting, not a cloud permission.
ADR 046's test for a kind is "name the user's action", and this kind's action
(remove the entry from `permissions.deny`, or stop running checks that need
it) is unlike every other kind's. The setting's name does not make it
`forbidden` either: these are the client's permissions, not the target's.

**Scope is the call**, never `ERROR_SCOPE_ASSET`. A disabled resource makes one
query fail; the rest of the asset scans normally.

The message names the resource, the setting and the file it came from, so a
user who has never seen the setting can find it:

```
resource "command" is disabled by permissions.deny in /etc/opt/mondoo/mondoo.yml
```

When the name the query used is an alias, the message names both:
`resource "os.base.command" (command) is disabled …`. The config path comes from
`viper.ConfigFileUsed()`; when the setting came from the environment the
message says `MONDOO_PERMISSIONS_DENY` instead.

### 5. Where the user sees it

**CLI.** `mql run` and the shell render the error under the query like any
other classified error (ADR 046 §7). The shell's completer and `help` omit
disabled resources, so a user is not offered a resource that cannot run.

```
$ mql run local -c 'command("id").stdout'
command.stdout: resource "command" is disabled by permissions.deny in /etc/opt/mondoo/mondoo.yml
```

**cnspec and the platform.** A check whose query used a disabled resource
scores `ScoreType_Error`, exactly as ADR 046 scores every classified failure.
Its message carries the text above, and `Score.error_details` (ADR 046, cnspec
section) carries the kind and the resource, so the platform can show it on the
check and group it. The coverage summary gains a line:

> 4 checks were not run: resource `command` is disabled on this system.

Not `Skip` and not `OutOfScope`. A check that could not run because the host
refused to run it has not passed and does not belong out of scope; the operator
who disabled the resource should see exactly which checks that cost them, and
the policy owner should see that their policy is not being assessed. If the
platform later wants a distinct presentation for this case, the kind is what
lets it build one without another protocol change.

**Old consumers.** `ErrorKind` is a proto3 enum, so a server or cnspec that
predates value 11 keeps it as an unknown value and treats the error as
unclassified. It still scores as an error and the message still names the
resource and the file.

### 6. What this protects against, and what it does not

It protects the scanning host from **queries**: content that arrives as a
policy or query pack, from the platform, a registry or a file, and from any
query an agent is told to run. With `command` and `powershell` disabled, no
such query can choose a command line or script to execute.

It does not protect against:

- **Whoever can edit `mondoo.yml`** or the agent's environment. They can remove
  the entry.
- **The commands providers run for themselves** (§3).
- **Argument injection into other resources.** Disabling the general-purpose
  execution primitive does not certify that no other resource ever builds a
  command line from an argument. Those are bugs to fix where they are, not a
  reason to widen this setting.
- **Other resources with the same power.** `command` alone leaves `powershell`
  enabled, and on a Linux host with `pwsh` installed that is the same
  capability. The documentation recommends the pair and says why. A named
  group ("all execution resources") is deliberately left out: it would need a
  maintained list whose omissions fail open, which is worse than an explicit
  list the operator can read.
- **Older clients.** A client that predates this ADR ignores the
  `permissions` block and runs `command`. The setting fails open on a
  downgrade, and the documentation has to state the minimum mql and cnspec
  versions that enforce it. (The same is true of `allow`: §1 makes the first
  client that knows the block refuse an `allow` it cannot enforce, but a client
  older than that cannot refuse a key it has never heard of.)

### 7. Disabling a resource the scan depends on

Nothing stops an operator from disabling `asset`, `os.base` or a provider's
root. The result is what the setting says: every query that needs it fails,
including the asset filters cnspec evaluates to select policies, so most of the
scan errors. That is accepted rather than guarded. A protected list would be a
judgment about which resources an operator may turn off, and the operator owns
that judgment. The startup log notes each disabled resource that is an asset
root or `asset`, so the cause is easy to find.

## Phases

1. **Kind and carrier.** `ERROR_KIND_DISABLED`, `ErrorDetail.resource`,
   `llx.Disabled`, `llx.ErrDisabled`, rendering. Regenerate `llx.pb.go`.
2. **Enforcement.** `coordinator.SetResourcePermissions`, alias resolution
   against the loaded schemas, the three runtime checks, the startup warnings,
   the refusal of a non-empty `allow`. Tests in
   `providers/runtime_test.go` with the mock provider: creating a disabled
   resource returns `ErrDisabled` and never reaches the provider; an alias is
   refused; a field returning a disabled type errors; a field on an enabled
   resource is untouched; a runtime from `NewRuntimeFrom` and from `RuntimeFor`
   enforces the same set; a cross-provider `GetData` callback is refused; a
   non-empty `allow` returns an error.
3. **Wiring.** `CommonOpts.Permissions`, read in `mql run`, `mql shell`,
   and cnspec's `scan` and `serve`; shell completion and help. `StoreConfig`
   preserves the key across `login` (it writes viper's merged state, which
   includes it; a test pins that).
4. **cnspec.** The coverage summary line for the new kind. No scoring change.
5. **Docs.** The `mondoo.yml` reference: the `permissions` block, that `allow`
   is reserved and refused, the `command` and
   `powershell` recommendation, §3's "it does not stop mql from running
   commands", §6's limits, and the minimum versions.

Phases 1 to 3 need only an mql client release. No provider changes, no
provider releases.

Verification beyond the unit tests: on a Linux host with
`permissions.deny: [command, powershell]`, `mql run local -c
'command("id").stdout'` and `os.base.command("id")` both fail with the message,
while `packages.length`, `mount.list` and `kernel.modules.length` (all built on
internal `command` use) return the same values as with the setting removed.

## Consequences

- Operators can run the agent on hosts where arbitrary command execution by
  policy content is unacceptable, with a three-line `permissions` block.
- A disabled resource is a visible, attributed error everywhere a result is
  shown. Nothing reads as passing that did not run.
- Compiled output and checksums do not depend on local configuration, so
  policies, results and exceptions stay comparable across agents.
- The runtime gains a lookup on every resource creation and every field read.
  It is a lock-free read of an immutable set, and a map miss when the set is
  empty.
- `ErrorKind` grows a tenth value, owned by the runtime rather than providers,
  like `ERROR_KIND_ASSET_VANISHED`.
- Policies that rely on `command` report errors on hosts that disable it.
  Content authors who want broad coverage have a reason to prefer typed
  resources over `command`, which is the direction the schema is already going.

## Alternatives considered

**Reject in the compiler.** Gives the earliest error in `mql run`, but sees
none of the bytecode the platform sends (it is compiled before it arrives), and
would make compiled output depend on local configuration, changing code IDs
and checksums per agent. Rejected as the enforcement point. A compile-time
diagnostic for local surfaces could be added on top later, as long as it does
not change the emitted bundle.

**Remove the resources from the schema the client loads.** Hiding `command`
from the schema makes every reference to it fail with "could not find resource
command", which ADR 046 classifies as `ERROR_KIND_ASSET_VANISHED` and cnspec
scores as unscored, the asset-went-away case. It would also break the
provider-internal use of the resource, which is created through the same
schema. Rejected.

**Enforce in the provider.** Send the set in `ConnectReq` and have the OS
provider refuse. Every provider would need the check and a release to enforce
it, and a provider cannot tell a query's `command` from its own internal one
without plumbing the caller through `CreateResource`. The coordinator already
sees exactly the requests that come from queries. Rejected.

**Reuse `ERROR_KIND_FORBIDDEN`.** Forbidden means the target refused, carries
permissions to grant, and is grouped into a permission list in the coverage
summary. A disabled resource fits none of that, and folding it in would make
"grant `ec2:DescribeInstances`" and "edit `mondoo.yml`" one category. Rejected
(§4).

**Score it `Skip`.** Quieter, but a skipped check reads as "does not apply",
and the policy owner would never learn their checks are not being assessed on
these hosts. The request was for an error. Rejected (§5).

**Implement the allow-list now.** An allow-list is the stronger posture, but
the schema has thousands of resources and a provider release adds more, so an
allow-list breaks every new check on every upgrade, and it needs answers this
ADR does not have yet (do sub-resources a provider returns count as allowed,
does `asset` have to be listed). A deny-list for the handful of resources an
operator actually objects to is the shape the request has. Deferred, with the
key reserved and its precedence fixed (§1) so it can land without a new shape.

**A flat `disabled_resources` list.** The first draft of this ADR. It says the
same thing as `permissions.deny` today, but an allow-list would then need a
second top-level key whose interaction with the first is defined by prose
rather than by structure. Rejected in favor of one block holding both lists.

**Ignore a non-empty `allow` until it is implemented.** Forward-compatible in
the usual sense, but it fails open in exactly the case where the operator asked
for the tightest setting. Rejected (§1).

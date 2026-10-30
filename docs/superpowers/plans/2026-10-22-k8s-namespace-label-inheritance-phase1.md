# K8s namespace label inheritance, Phase 1 (mql provider) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the k8s connection option `inherit-namespace-labels` lists label keys, every namespaced workload asset the provider discovers carries those labels copied from its namespace, unless the workload already has the key.

**Architecture:** A new option is parsed once per discovery path into a list of glob patterns. A pure helper copies matching namespace labels onto a slice of assets, skipping any the asset already has and skipping container-image assets. It is called once per namespace from the two places that already have the namespace in hand: the staged namespace stage (`discoverNamespaceStage`) and the legacy per-namespace loop (`discoverLegacy`). The legacy loop gets the namespace's own labels from `discoverNamespaces`, which now also returns them keyed by namespace name. A CLI flag maps to the option so `cnspec scan k8s` behaves like an inventory file.

**Tech Stack:** Go, `github.com/gobwas/glob` (already used by the k8s discovery filters), testify, the provider's existing fake connection in `discovery_test.go`.

**Spec:** `docs/superpowers/specs/2026-10-20-k8s-namespace-label-inheritance-design.md` (sections "What exists today", D1–D4, Phase 1).

## Global Constraints

- Work only inside `providers/k8s/` (its own Go module; run tests from that directory) plus `docs/adr/`. No other provider, no `discovery/`, no SDK change.
- Option key: `inherit-namespace-labels`; constant `OPTION_INHERIT_NAMESPACE_LABELS`; CLI flag `--inherit-namespace-labels`. Value: comma-separated label keys, globs allowed, same matcher as the `images`/`namespaces` filters (`gobwas/glob`, no separator, so `my.company.com/*` and `*` both match keys containing `/`).
- Collision policy (spec D3): the workload's own value wins; the namespace only fills keys the workload lacks; nothing is ever removed.
- Container-image assets (connection type `registry-image`) are **not** labeled in this phase (spec D5 is Phase 3). Namespace assets, the cluster asset and admission-review assets are untouched.
- Only the namespace's **own** labels are inherited, never the `k8s.mondoo.com/*` keys the provider adds to the namespace asset.
- No new Kubernetes API calls per asset. The namespace object already fetched (stage 2) or listed (legacy) is the only source.
- Option unset or empty → every discovered asset's labels are byte-identical to today.
- An invalid glob fails discovery with an error naming the option, like the existing filters.
- Files carry the repo's license header: the same two comment lines every Go file under `providers/k8s` starts with (holder and SPDX identifier); a new file names only the current year.
- Commits: emoji prefix (`✨`, `🧪`, `📄`), scoped `k8s:`; every commit GPG-signed (check `git config commit.gpgsign` is `true`, else `git commit -S`). No unrelated changes in the diff.
- Tests: `cd providers/k8s && go test ./resources -run '<Name>' -count=1`. Never `go build ./...` or `go vet ./...` from the repo root; vet only `./resources ./provider ./connection/shared ./config` inside `providers/k8s`.

## Review Focus

1. A workload that sets a listed key itself with a different value than its namespace → it keeps its own value. Pinned in Task 2 (helper) and Task 3 (`...KeepsWorkloadLabelOnCollision`).
2. `inherit-namespace-labels: ""` or a value of only commas/spaces → treated as unset, labels unchanged, no error. Pinned in Task 2 (`TestInheritedLabelKeys`).
3. The option set together with `container-images` discovery → the image asset still has no inherited key. Pinned in Task 3 (`...DoesNotLabelContainerImages`).
4. A manifest scan whose pod references a namespace the manifest never declares → the synthesized bare namespace yields nothing to inherit and discovery does not error. Pinned in Task 3 (`...ManifestUndeclaredNamespaceInheritsNothing`).
5. A pattern like `*` → copies every own label of the namespace, including Kubernetes' default `kubernetes.io/metadata.name`, but never a `k8s.mondoo.com/*` key. Pinned in Task 4 (`TestDiscoverNamespacesReturnsOwnLabels`) and Task 2 (glob case).

---

### Task 1: Option constant, CLI flag, ParseCLI mapping

**Files:**
- Modify: `providers/k8s/connection/shared/connection.go:21-34` (option constants block)
- Modify: `providers/k8s/config/config.go:76-130` (the `Flags` list of the `k8s` connector)
- Modify: `providers/k8s/provider/provider.go:53-123` (`ParseCLI`)
- Test: `providers/k8s/provider/provider_test.go` (next to `TestParseCLI`, l.218)

**Interfaces:**
- Produces: `shared.OPTION_INHERIT_NAMESPACE_LABELS = "inherit-namespace-labels"`, used by Tasks 2–4.

- [ ] **Step 1: Write the failing test**

```go
func TestParseCLIInheritNamespaceLabels(t *testing.T) {
	s := &Service{}
	res, err := s.ParseCLI(&plugin.ParseCLIReq{
		Connector: "k8s",
		Flags: map[string]*llx.Primitive{
			"inherit-namespace-labels": llx.StringPrimitive("my.company.com/team,my.company.com/*"),
		},
	})
	require.NoError(t, err)
	conf := res.Asset.Connections[0]
	assert.Equal(t, "my.company.com/team,my.company.com/*", conf.Options[shared.OPTION_INHERIT_NAMESPACE_LABELS])
}
```

Copy the `Service` construction and the `plugin.ParseCLIReq` shape from `TestParseCLI` in the same file if they differ from the above.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd providers/k8s && go test ./provider -run TestParseCLIInheritNamespaceLabels -count=1`
Expected: FAIL, undefined `shared.OPTION_INHERIT_NAMESPACE_LABELS`.

- [ ] **Step 3: Add the constant, the flag and the mapping**

- `connection.go`: `OPTION_INHERIT_NAMESPACE_LABELS = "inherit-namespace-labels"` in the const block, aligned with its neighbours.
- `config.go`: append to `Flags`:
  ```go
  {
      Long:    "inherit-namespace-labels",
      Type:    plugin.FlagType_String,
      Default: "",
      Desc:    "Copy the namespace labels whose keys match this comma-separated list (glob supported) onto every workload discovered in that namespace; a label the workload already carries is kept",
  },
  ```
- `provider.go` `ParseCLI`: after the `OPTION_OBJECT_LABEL_SELECTOR` block, the same three-line pattern for `shared.OPTION_INHERIT_NAMESPACE_LABELS` (`string(v.Value)`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd providers/k8s && go test ./provider -run 'TestParseCLI' -count=1`
Expected: PASS (both the new test and the existing `TestParseCLI`).

- [ ] **Step 5: Commit**

```bash
git add providers/k8s/connection/shared/connection.go providers/k8s/config/config.go providers/k8s/provider/provider.go providers/k8s/provider/provider_test.go
git commit -m "✨ k8s: add the inherit-namespace-labels connection option and flag"
```

---

### Task 2: Option parser and the pure inheritance helper

**Files:**
- Modify: `providers/k8s/resources/discovery.go` (new functions next to `labelSelectorFilters`, l.1619; new const next to the `Discovery*` consts, l.30-46)
- Test: `providers/k8s/resources/discovery_test.go`

**Interfaces:**
- Consumes: `shared.OPTION_INHERIT_NAMESPACE_LABELS` (Task 1); existing `validateGlobs([]string) error`, `matchesAny([]string, string) bool`, `shared.SplitFilterValues(string) []string`.
- Produces, used by Tasks 3 and 4:
  ```go
  // registryImageConnectionType is the connection type of the image assets
  // discoverContainerImages emits.
  const registryImageConnectionType = "registry-image"

  // inheritedLabelKeys returns the glob patterns from OPTION_INHERIT_NAMESPACE_LABELS,
  // nil when the option is unset or empty, an error naming the option for an invalid glob.
  func inheritedLabelKeys(cfg *inventory.Config) ([]string, error)

  // inheritNamespaceLabels copies every entry of nsLabels whose key matches one of
  // patterns onto each asset that does not already carry that key. Assets whose
  // first connection is registryImageConnectionType are left untouched.
  // A nil or empty patterns slice is a no-op.
  func inheritNamespaceLabels(assets []*inventory.Asset, nsLabels map[string]string, patterns []string)
  ```

- [ ] **Step 1: Write the failing tests**

```go
func TestInheritedLabelKeys(t *testing.T) {
	cases := []struct {
		name    string
		value   *string // nil = option absent
		want    []string
		wantErr string
	}{
		{name: "absent", value: nil, want: nil},
		{name: "empty", value: ptr(""), want: nil},
		{name: "only separators", value: ptr(" , ,"), want: nil},
		{name: "keys and globs", value: ptr("my.company.com/team, my.company.com/*"), want: []string{"my.company.com/team", "my.company.com/*"}},
		{name: "invalid glob", value: ptr("my.company.com/[team"), wantErr: "inherit-namespace-labels"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &inventory.Config{Options: map[string]string{}}
			if tc.value != nil {
				cfg.Options[shared.OPTION_INHERIT_NAMESPACE_LABELS] = *tc.value
			}
			got, err := inheritedLabelKeys(cfg)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestInheritNamespaceLabels(t *testing.T) {
	ns := map[string]string{
		"my.company.com/team":       "aaabbbccc",
		"my.company.com/department": "d-42",
		"kubernetes.io/metadata.name": "team-a",
	}
	workload := func(labels map[string]string) *inventory.Asset {
		return &inventory.Asset{
			PlatformIds: []string{"//platformid.api.mondoo.app/runtime/k8s/uid/c/namespace/team-a/pods/name/web"},
			Labels:      labels,
			Connections: []*inventory.Config{{Type: "k8s"}},
		}
	}
	image := &inventory.Asset{Connections: []*inventory.Config{{Type: registryImageConnectionType, Host: "nginx@sha256:abc"}}}

	t.Run("exact key is copied", func(t *testing.T) {
		a := workload(map[string]string{"app": "web"})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"my.company.com/team"})
		assert.Equal(t, map[string]string{"app": "web", "my.company.com/team": "aaabbbccc"}, a.Labels)
	})
	t.Run("glob copies every matching key", func(t *testing.T) {
		a := workload(map[string]string{})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"my.company.com/*"})
		assert.Equal(t, map[string]string{"my.company.com/team": "aaabbbccc", "my.company.com/department": "d-42"}, a.Labels)
	})
	t.Run("workload's own value wins", func(t *testing.T) {
		a := workload(map[string]string{"my.company.com/team": "zzz"})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"my.company.com/team"})
		assert.Equal(t, "zzz", a.Labels["my.company.com/team"])
	})
	t.Run("namespace lacking the key changes nothing", func(t *testing.T) {
		a := workload(map[string]string{"app": "web"})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"other.io/owner"})
		assert.Equal(t, map[string]string{"app": "web"}, a.Labels)
	})
	t.Run("nil labels map is initialised", func(t *testing.T) {
		a := workload(nil)
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, []string{"my.company.com/team"})
		assert.Equal(t, "aaabbbccc", a.Labels["my.company.com/team"])
	})
	t.Run("image assets are skipped", func(t *testing.T) {
		inheritNamespaceLabels([]*inventory.Asset{image}, ns, []string{"*"})
		assert.Nil(t, image.Labels)
	})
	t.Run("no patterns is a no-op", func(t *testing.T) {
		a := workload(map[string]string{"app": "web"})
		inheritNamespaceLabels([]*inventory.Asset{a}, ns, nil)
		assert.Equal(t, map[string]string{"app": "web"}, a.Labels)
	})
}
```

`ptr` is a one-line generic test helper (`func ptr[T any](v T) *T`); add it to the test file if none exists.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd providers/k8s && go test ./resources -run 'TestInheritedLabelKeys|TestInheritNamespaceLabels' -count=1`
Expected: FAIL to compile, undefined `inheritedLabelKeys`, `inheritNamespaceLabels`, `registryImageConnectionType`.

- [ ] **Step 3: Implement the const and both functions in `discovery.go`**

`inheritedLabelKeys`: `shared.SplitFilterValues` on the option value; return `nil, nil` when the result is empty; `validateGlobs` on the rest, wrapping its error as `fmt.Errorf("invalid %s: %w", shared.OPTION_INHERIT_NAMESPACE_LABELS, err)`.

`inheritNamespaceLabels`: return early when `len(patterns) == 0`; for each asset, skip when `len(a.Connections) > 0 && a.Connections[0].Type == registryImageConnectionType`; initialise `a.Labels` when nil; for each `k, v` in `nsLabels` with `matchesAny(patterns, k)`, set `a.Labels[k] = v` only when `k` is absent.

Also replace the literal `"registry-image"` in `discoverContainerImages` (l.1285) with `registryImageConnectionType`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd providers/k8s && go test ./resources -run 'TestInheritedLabelKeys|TestInheritNamespaceLabels' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add providers/k8s/resources/discovery.go providers/k8s/resources/discovery_test.go
git commit -m "✨ k8s: parse inherit-namespace-labels and copy namespace labels onto assets"
```

---

### Task 3: Wire inheritance into the staged namespace stage

**Files:**
- Modify: `providers/k8s/resources/discovery.go:348-402` (`discoverNamespaceStage`)
- Modify: `providers/k8s/resources/discovery_test.go` (fake connection `namespaceDiscoveryConnection`, l.95-157; new tests)
- Create: `providers/k8s/resources/testdata/inherit_namespace_labels_undeclared_ns.yaml`

**Interfaces:**
- Consumes: `inheritedLabelKeys`, `inheritNamespaceLabels` (Task 2).
- Produces for Task 4: the extended fake (`pods []corev1.Pod` field, `Resources` serving them) and `newTestPod`.

- [ ] **Step 1: Extend the fake connection to serve pods**

In `discovery_test.go`:
- Add `pods []corev1.Pod` to `namespaceDiscoveryConnection`.
- Change `Resources` to return `&shared.ResourceResult{Resources: objs}` where `objs` holds a pointer to each pod (`&c.pods[i]`) when `kind == gvkString(corev1.SchemeGroupVersion.WithKind("pods"))`, and an empty `ResourceResult` for any other kind (no error).
- Add
  ```go
  func newTestPod(namespace, name, uid string, labels map[string]string, images ...string) corev1.Pod
  ```
  returning a pod with `TypeMeta{APIVersion: "v1", Kind: "Pod"}`, the given `ObjectMeta` (no owner references), one container per image in `Spec.Containers` and a matching `Status.ContainerStatuses` entry with `ImageID: image` (images are only used by the container-image test).
- Add a helper that builds the runtime the way `TestDiscoverStagedDiscoveryWithCommaSeparatedNamespacesStartsClusterStage` does, but whose `CreateResource` callback returns `&mqlK8s{MqlRuntime: rt}` for `"k8s"` and otherwise delegates to the package-level `CreateResource(rt, name, args)`:
  ```go
  func newDiscoveryTestRuntime(conn *namespaceDiscoveryConnection) *plugin.Runtime
  ```

- [ ] **Step 2: Write the failing tests**

The first test in full; the next three are deltas of it.

```go
func TestDiscoverNamespaceStageInheritsNamespaceLabels(t *testing.T) {
	cfg := &inventory.Config{
		Type: "k8s",
		Options: map[string]string{
			plugin.OptionStagedDiscovery:          "",
			shared.OPTION_NAMESPACE:               "team-a",
			shared.OPTION_INHERIT_NAMESPACE_LABELS: "my.company.com/team",
		},
		Discover: &inventory.Discovery{Targets: []string{DiscoveryPods}},
	}
	asset := &inventory.Asset{Name: "K8s Cluster test", Connections: []*inventory.Config{cfg}}
	ns := newTestNamespace("team-a", "uid-team-a")
	ns.Labels = map[string]string{"my.company.com/team": "aaabbbccc", "other": "x"}
	conn := &namespaceDiscoveryConnection{
		Connection: plugin.NewConnection(1, asset),
		asset:      asset,
		namespaces: []corev1.Namespace{ns},
		pods:       []corev1.Pod{newTestPod("team-a", "web", "uid-web", map[string]string{"app": "web"})},
	}

	inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)
	got := inv.Spec.Assets[0]
	assert.Equal(t, "team-a/web", got.Name)
	assert.Equal(t, "aaabbbccc", got.Labels["my.company.com/team"])
	assert.Equal(t, "web", got.Labels["app"])
	assert.NotContains(t, got.Labels, "other")
}
```

- `TestDiscoverNamespaceStageKeepsWorkloadLabelOnCollision`: pod labels `{"my.company.com/team": "zzz"}`; assert `got.Labels["my.company.com/team"] == "zzz"`.
- `TestDiscoverNamespaceStageWithoutOptionLeavesLabelsUnchanged`: drop `OPTION_INHERIT_NAMESPACE_LABELS` from `Options`; assert `assert.NotContains(t, got.Labels, "my.company.com/team")`.
- `TestDiscoverNamespaceStageDoesNotLabelContainerImages`: `Targets: []string{DiscoveryPods, DiscoveryContainerImages}`; pod built with image `"docker.io/library/nginx@sha256:0123456789abcdef"`; expect `len(inv.Spec.Assets) == 2`; find the asset whose `Connections[0].Type == registryImageConnectionType` and assert `assert.NotContains(t, img.Labels, "my.company.com/team")`; the other asset has the key with value `"aaabbbccc"`.

Fifth test, through the manifest connection (pattern: `loadCrossRefRuntime` in `cross_references_test.go`, using `manifest.NewConnection(0, asset, manifest.WithManifestFile(path))` where `asset.Connections[0].Options` carries `plugin.OptionStagedDiscovery: ""`, `shared.OPTION_NAMESPACE: "undeclared"`, `shared.OPTION_INHERIT_NAMESPACE_LABELS: "*"`, and `Discover.Targets: []string{DiscoveryPods}`). The fixture `testdata/inherit_namespace_labels_undeclared_ns.yaml` holds one `v1/Pod` named `web` in namespace `undeclared` with label `app: web` and no `Namespace` object.

```go
func TestDiscoverManifestUndeclaredNamespaceInheritsNothing(t *testing.T) {
	// expect NoError, 1 asset, Labels == {"app": "web"} plus k8s.mondoo.com/* keys only
	//   (assert no key other than "app" lacks the "k8s.mondoo.com/" prefix)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd providers/k8s && go test ./resources -run 'TestDiscoverNamespaceStage|TestDiscoverManifestUndeclared' -count=1`
Expected: the first and fourth FAIL on the missing `my.company.com/team` key; the collision, no-option and manifest tests may already pass (they pin today's behaviour).

- [ ] **Step 4: Wire the call in `discoverNamespaceStage`**

After `labelFilters, err := labelSelectorFilters(invConfig)`: `inheritKeys, err := inheritedLabelKeys(invConfig)` with the same error handling. After `assets, err := discoverAssets(...)` (l.395) and before the append (l.400): `inheritNamespaceLabels(assets, nsObj.Labels, inheritKeys)`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd providers/k8s && go test ./resources -run 'TestDiscover' -count=1`
Expected: PASS, including the pre-existing `TestDiscoverStagedDiscoveryWithCommaSeparatedNamespacesStartsClusterStage`.

- [ ] **Step 6: Commit**

```bash
git add providers/k8s/resources/discovery.go providers/k8s/resources/discovery_test.go providers/k8s/resources/testdata/inherit_namespace_labels_undeclared_ns.yaml
git commit -m "✨ k8s: inherit namespace labels onto workloads in the namespace discovery stage"
```

---

### Task 4: Wire inheritance into the legacy single-pass path

**Files:**
- Modify: `providers/k8s/resources/discovery.go:170-249` (`discoverLegacy`), `:259-346` (`discoverClusterStage`, caller update only), `:1177-1244` (`discoverNamespaces`)
- Test: `providers/k8s/resources/discovery_test.go`

**Interfaces:**
- Consumes: Task 2 helpers; Task 3 fake and `newTestPod`.
- Produces:
  ```go
  // discoverNamespaces now also returns each discovered namespace's own labels
  // (a copy of ns.Labels, never nil) keyed by namespace name, so callers can
  // inherit from them without the k8s.mondoo.com/* keys the asset carries.
  func discoverNamespaces(conn shared.Connection, invConfig *inventory.Config, clusterId string, od *PlatformIdOwnershipIndex, nsFilter FilterOpts, labelFilters *LabelSelectorFilters) ([]*inventory.Asset, map[string]map[string]string, error)
  ```

- [ ] **Step 1: Write the failing tests**

```go
func TestDiscoverNamespacesReturnsOwnLabels(t *testing.T) {
	// fake with team-a labeled {"my.company.com/team": "aaabbbccc", "kubernetes.io/metadata.name": "team-a"}
	// nsFilter/labelFilters empty (newFilterOpts(nil, nil), &LabelSelectorFilters{})
	// assets, own, err := discoverNamespaces(conn, cfg, "", nil, nsFilter, labelFilters)
	// expect own["team-a"] == exactly those two keys (no "k8s.mondoo.com/" key),
	//   while assets[0].Labels["k8s.mondoo.com/kind"] == "Namespace"
}

func TestDiscoverLegacyInheritsNamespaceLabels(t *testing.T) {
	// same fake and pod as TestDiscoverNamespaceStageInheritsNamespaceLabels but
	// Options WITHOUT plugin.OptionStagedDiscovery and Targets {DiscoveryPods}
	// (so no cluster root and no namespace asset is emitted; nsFilter is set)
	// expect 1 asset "team-a/web" with Labels["my.company.com/team"] == "aaabbbccc"
	//   and no "other" key
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd providers/k8s && go test ./resources -run 'TestDiscoverNamespacesReturnsOwnLabels|TestDiscoverLegacyInheritsNamespaceLabels' -count=1`
Expected: FAIL to compile (wrong number of return values), then the legacy test fails on the missing key.

- [ ] **Step 3: Implement**

- `discoverNamespaces`: build `own := map[string]map[string]string{}`; for each namespace that passes the filters, `own[ns.Name] = maps.Clone(ns.Labels)` with a non-nil empty map when `ns.Labels` is nil; return it as the second value.
- `discoverClusterStage` (l.308): `nss, _, err := discoverNamespaces(...)`.
- `discoverLegacy`: parse `inheritKeys, err := inheritedLabelKeys(invConfig)` next to `labelFilters`; `nss, nsOwnLabels, err := discoverNamespaces(...)` (l.225); in the per-namespace loop, after `discoverAssets` (l.242) and before `setRelatedAssets`: `inheritNamespaceLabels(assets, nsOwnLabels[ns.Name], inheritKeys)`.

- [ ] **Step 4: Run the whole package**

Run: `cd providers/k8s && go test ./resources -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add providers/k8s/resources/discovery.go providers/k8s/resources/discovery_test.go
git commit -m "✨ k8s: inherit namespace labels onto workloads in legacy discovery"
```

---

### Task 5: ADR

**Files:**
- Create: `docs/adr/051-k8s-namespace-label-inheritance.md`

**Interfaces:** none.

- [ ] **Step 1: Write the ADR**

Follow the layout of `docs/adr/050-terraform-module-and-config-inventory.md`: title `# ADR 051: Kubernetes namespace label inheritance`, `**Status:** Accepted`, `**Date:** 2026-10-22`, then `## Context`, `## Decision`, `## Consequences`. Content, condensed from the spec (do not restate the whole spec; link it by path):

- Context: namespaces labeled with team ids; org-level asset routing (server ADR-020) matches each uploaded asset on its own incoming labels; today a workload asset carries only its own object labels plus `k8s.mondoo.com/*`; cross-asset label propagation on the client copies only `*mondoo.com/*` keys from the root; the server replaces labels on every sync and merges annotations.
- Decision: the option `inherit-namespace-labels` (keys, globs); values are labels, not annotations, and why (replace semantics are the right lifecycle, every scanner of a workload is this provider); the namespace fills gaps only, never overwrites or removes; applies to every namespaced workload kind, not to namespaces, the cluster, admission reviews; container images deferred to a follow-up with the unanimity rule and the `k8s.mondoo.com/namespace-label-conflict` marker (summarise D5 in four lines, mark it "planned, Phase 3").
- Consequences: a scanner path that does not pass the option strips the label on its next sync (the operator must pass it to the resource watcher); routing creates a new asset in the new space when a namespace is relabeled and leaves the old one stale; shared images in a single multi-cluster space will flip once Phase 3 lands (accepted caveat); Phase 4 Console parity is a follow-up.

- [ ] **Step 2: Commit**

```bash
git add docs/adr/051-k8s-namespace-label-inheritance.md
git commit -m "📄 ADR 051: Kubernetes namespace label inheritance"
```

---

### Task 6: Final verification

- [ ] **Step 1: Run the touched packages' tests and vet**

Run: `cd providers/k8s && go test ./resources ./provider ./connection/shared ./config -count=1 && go vet ./resources ./provider ./connection/shared ./config`
Expected: all PASS, vet silent.

- [ ] **Step 2: Check the diff is scoped and every commit is signed**

Run: `git diff main --stat && git log main..HEAD --format='%h %G? %s'`
Expected: only files under `providers/k8s/` and `docs/adr/`; every line shows `G`.

- [ ] **Step 3: Hand off**

Report the branch and the commit list. Phase 2 (operator) and Phase 3 (images) are separate plans; the operator plan should state that the provider version carrying this change is the floor for the CRD field.

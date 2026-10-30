# K8s namespace label inheritance, Phase 3 (container images) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** With `inherit-namespace-labels` set, a container-image asset gets each inherited key's value when every in-scope namespace that runs the image and carries the key agrees, and the marker label `k8s.mondoo.com/namespace-label-conflict` naming the keys they disagree on otherwise.

**Architecture:** A per-image *verdict* (`labels` to set, `conflicts` to mark) is folded once over the whole cluster from the namespaces' own labels and the images their pods run. Stage 1 (`discoverClusterStage`) lists pods once through the connection, computes the verdicts, and hands each namespace stage the verdicts for the images that namespace runs as an internal JSON option on its connection config; stage 2 decodes it and stamps the image assets it emits. Because the client uploads only the first copy of an image, every namespace carries the same verdict, so which namespace runs first does not matter. Stage 2 started directly (one literal namespace, no stage 1) folds over its own namespace alone. The legacy single-pass path folds in-process. An oversized payload degrades to a sentinel that makes stage 2 skip image labels with a warning rather than label them wrongly.

**Tech Stack:** Go, `encoding/json`, the k8s provider's existing discovery and the fake connection in `discovery_test.go`.

**Spec:** `docs/superpowers/specs/2026-10-20-k8s-namespace-label-inheritance-design.md` D5 (as settled) and Phase 3; `docs/adr/051-k8s-namespace-label-inheritance.md` "Container images (planned, Phase 3)". Phase 1 landed as mondoohq/mql#12086.

## Global Constraints

- Work only inside `providers/k8s/` plus `docs/adr/051-*.md`. Branch `claude/asset-label-inheritance-k8s-images` off `origin/main`.
- Rule, per inherited key (pattern-matched exactly like workloads), over the **in-scope** namespaces (those `discoverNamespaces` returns after the namespace and label-selector filters) that run the image and **carry the key**: all agree → `key=value` on the image; disagree → the key stays unset and the marker `k8s.mondoo.com/namespace-label-conflict` holds the conflicting keys, sorted, comma-joined; no voter → nothing. Namespaces without the key do not vote.
- "Runs the image" means: a pod in the namespace that passes `object-label-selector` references the image, resolved exactly as `discoverContainerImages` resolves it (status `imageID` first, spec image as fallback), and the image passes the `images`/`images-exclude` filters.
- Marker constant `LabelNamespaceLabelConflict = "k8s.mondoo.com/namespace-label-conflict"`. Internal option constant `OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS = "inherit-namespace-labels-verdicts"` in `connection/shared/connection.go`, commented as stage-1→stage-2 transport, never set by users. Payload: JSON object `{"<resolved image ref>": {"labels": {k: v}, "conflicts": [k]}}`, `{}` when the namespace runs no image; sentinel value `*` when the encoded payload for a namespace exceeds `imageLabelVerdictsMaxBytes` (a package `var`, default `256 << 10`, lowered in tests).
- Stage 2: option present → decode and apply; sentinel → apply nothing to images and log one warning naming the namespace; option absent (no stage 1 ran) → fold over this namespace alone and apply.
- Stage 1 computes verdicts only when the inherit option is set **and** `container-images` or `all` is a discovery target. It lists pods once with `conn.Resources(gvkString(corev1.SchemeGroupVersion.WithKind("pods")), "", "")`, the call the mql `pods` resource makes, and never fetches pull secrets (that is what `UniqueImagesForPod` adds; the index must not). Legacy discovery already listed every pod; stage 1 now does the same once, which is accepted.
- `inheritNamespaceLabels` keeps skipping image assets; images are labeled only through verdicts.
- Option unset → every asset, images included, byte-identical to today.
- License headers as in the repo; commits emoji-prefixed, `k8s:` scoped, GPG-signed. No unrelated changes.
- Tests: `cd providers/k8s && go test ./resources -run '<Name>' -count=1`; never `go build ./...`/`go vet ./...` from the repo root; vet only `./resources ./connection/shared`.

## Review Focus

1. An image run by a labeled namespace and by an unlabeled in-scope namespace whose stage runs first → the image still gets the label, because both stages carry the same verdict. Pinned in Task 3 (`TestDiscoverClusterStageAttachesImageVerdicts` asserts the labeled verdict in the unlabeled namespace's payload) and Task 5 (legacy end to end).
2. Two inherited keys where only one conflicts → the agreed key's value is set and the marker names only the conflicting key. Pinned in Task 2 (`TestImageLabelVerdicts`).
3. A namespace excluded by the namespace filter runs the image with a different value → it does not vote; the image gets the in-scope value. Pinned in Task 3 (`TestClusterImagesByNamespaceHonoursScope`).
4. A payload larger than the cap → sentinel, stage 2 labels no image and warns, workloads still inherit. Pinned in Task 4 (`TestDiscoverNamespaceStageSentinelSkipsImageLabels`).
5. The option unset with `container-images` targeted → image assets carry no labels at all, as today. Pinned in Task 4 (`TestDiscoverNamespaceStageWithoutOptionLeavesImagesUnchanged`).

---

### Task 1: Pod image resolution without pull secrets

**Files:**
- Modify: `providers/k8s/resources/container_utils.go:55-85` (`UniqueImagesForPod`)
- Test: `providers/k8s/resources/container_utils_test.go` (create)

**Interfaces:**
- Produces, used by Tasks 3 and 5:
  ```go
  // resolvePodImages is UniqueImagesForPod without the pull-secret lookups: the
  // same status-first, spec-fallback resolution, keyed by resolved reference.
  func resolvePodImages(pod *v1.Pod, pullSecrets []v1.Secret) map[string]ContainerImage

  // podImageRefs returns the sorted resolved references of the images a pod runs.
  func podImageRefs(pod *v1.Pod) []string
  ```
  `UniqueImagesForPod` becomes: fetch the pull secrets as today, then `return resolvePodImages(pod, pullSecrets)`.

- [ ] **Step 1: Write the failing test** (header, `package resources`)

```go
func TestPodImageRefs(t *testing.T) {
	t.Run("status wins over spec and refs are sorted and unique", func(t *testing.T) {
		pod := newTestPod("ns", "p", "u", nil, "nginx:1.25", "redis:7")
		pod.Status.ContainerStatuses[0].ImageID = "docker.io/library/nginx@sha256:aaa"
		pod.Status.ContainerStatuses[1].ImageID = "docker.io/library/redis@sha256:bbb"
		assert.Equal(t, []string{"docker.io/library/nginx@sha256:aaa", "docker.io/library/redis@sha256:bbb"}, podImageRefs(&pod))
	})
	t.Run("falls back to spec without status", func(t *testing.T) {
		pod := newTestPod("ns", "p", "u", nil, "nginx:1.25")
		pod.Status.ContainerStatuses = nil
		assert.Equal(t, []string{"nginx:1.25"}, podImageRefs(&pod))
	})
	t.Run("init containers count", func(t *testing.T) {
		pod := newTestPod("ns", "p", "u", nil)
		pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "busybox:1.36"}}
		assert.Equal(t, []string{"busybox:1.36"}, podImageRefs(&pod))
	})
}
```

`newTestPod` is the Phase 1 helper in `discovery_test.go` (same package).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd providers/k8s && go test ./resources -run TestPodImageRefs -count=1`
Expected: FAIL to compile, undefined `podImageRefs`.

- [ ] **Step 3: Implement** by moving the body of `UniqueImagesForPod` after the secret loop into `resolvePodImages`, and `podImageRefs` as the sorted keys of `resolvePodImages(pod, nil)`.

- [ ] **Step 4: Run tests**

Run: `cd providers/k8s && go test ./resources -run 'TestPodImageRefs|TestDiscover' -count=1`
Expected: PASS (existing discovery tests prove `UniqueImagesForPod` is unchanged).

- [ ] **Step 5: Commit**

```bash
git add providers/k8s/resources/container_utils.go providers/k8s/resources/container_utils_test.go
git commit -m "♻️ k8s: split pod image resolution from the pull-secret lookup"
```

---

### Task 2: Verdict fold, transport encoding, and application

**Files:**
- Create: `providers/k8s/resources/image_labels.go`
- Modify: `providers/k8s/connection/shared/connection.go:21-35` (option constants)
- Test: `providers/k8s/resources/image_labels_test.go` (create)

**Interfaces:**
- Consumes: `inheritedNamespaceLabels(nsLabels map[string]string, patterns []string) map[string]string` (Phase 1), `registryImageConnectionType`.
- Produces, used by Tasks 3–5:
  ```go
  const LabelNamespaceLabelConflict = "k8s.mondoo.com/namespace-label-conflict"

  // imageLabelVerdict is what the in-scope namespaces running an image agreed on.
  type imageLabelVerdict struct {
      Labels    map[string]string `json:"labels,omitempty"`
      Conflicts []string          `json:"conflicts,omitempty"` // sorted
  }

  // imageLabelVerdicts folds the votes. imagesByNamespace lists the images each
  // in-scope namespace runs; nsLabels holds each namespace's own labels; patterns are
  // the inherited keys. Only namespaces carrying a key vote on it.
  func imageLabelVerdicts(imagesByNamespace map[string][]string, nsLabels map[string]map[string]string, patterns []string) map[string]imageLabelVerdict

  // verdictsForImages returns the subset of verdicts for the given images.
  func verdictsForImages(verdicts map[string]imageLabelVerdict, images []string) map[string]imageLabelVerdict

  var imageLabelVerdictsMaxBytes = 256 << 10
  const imageLabelVerdictsSentinel = "*"

  // encodeImageLabelVerdicts marshals to JSON ("{}" for an empty map); when the
  // result is longer than imageLabelVerdictsMaxBytes it returns the sentinel.
  func encodeImageLabelVerdicts(verdicts map[string]imageLabelVerdict) string

  // decodeImageLabelVerdicts parses the option; skip is true for the sentinel.
  func decodeImageLabelVerdicts(raw string) (verdicts map[string]imageLabelVerdict, skip bool, err error)

  // applyImageLabelVerdicts stamps each registry-image asset in assets (matched by
  // Connections[0].Host) with its verdict's labels and, when it has conflicts, the
  // marker label. Assets without a verdict are left untouched.
  func applyImageLabelVerdicts(assets []*inventory.Asset, verdicts map[string]imageLabelVerdict)
  ```
  And `shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS = "inherit-namespace-labels-verdicts"`.

- [ ] **Step 1: Write the failing tests**

```go
func TestImageLabelVerdicts(t *testing.T) {
	nsLabels := map[string]map[string]string{
		"team-alpha":     {"my.company.com/team": "alpha", "my.company.com/department": "d-1"},
		"team-beta":      {"my.company.com/team": "beta", "my.company.com/department": "d-1"},
		"platform-tools": {"my.company.com/department": "d-0"},
	}
	images := map[string][]string{
		"team-alpha":     {"nginx@sha256:shared", "web@sha256:alpha-only", "busybox@sha256:tools"},
		"team-beta":      {"nginx@sha256:shared"},
		"platform-tools": {"busybox@sha256:tools"},
	}
	got := imageLabelVerdicts(images, nsLabels, []string{"my.company.com/*"})

	assert.Equal(t, imageLabelVerdict{Labels: map[string]string{"my.company.com/team": "alpha", "my.company.com/department": "d-1"}}, got["web@sha256:alpha-only"])
	// team disagrees, department agrees: one value, marker names only the conflicting key
	assert.Equal(t, imageLabelVerdict{Labels: map[string]string{"my.company.com/department": "d-1"}, Conflicts: []string{"my.company.com/team"}}, got["nginx@sha256:shared"])
	// platform-tools lacks the team key and does not vote on it; it does vote on department
	assert.Equal(t, imageLabelVerdict{Labels: map[string]string{"my.company.com/team": "alpha"}, Conflicts: []string{"my.company.com/department"}}, got["busybox@sha256:tools"])
}

func TestImageLabelVerdictsNoVoters(t *testing.T) {
	got := imageLabelVerdicts(map[string][]string{"ns": {"img"}}, map[string]map[string]string{"ns": {"other": "x"}}, []string{"my.company.com/team"})
	assert.NotContains(t, got, "img")
}

func TestImageLabelVerdictsEncoding(t *testing.T) {
	v := map[string]imageLabelVerdict{"img": {Labels: map[string]string{"k": "v"}, Conflicts: []string{"c"}}}
	raw := encodeImageLabelVerdicts(v)
	got, skip, err := decodeImageLabelVerdicts(raw)
	require.NoError(t, err)
	assert.False(t, skip)
	assert.Equal(t, v, got)

	assert.Equal(t, "{}", encodeImageLabelVerdicts(nil))

	old := imageLabelVerdictsMaxBytes
	imageLabelVerdictsMaxBytes = 8
	defer func() { imageLabelVerdictsMaxBytes = old }()
	assert.Equal(t, imageLabelVerdictsSentinel, encodeImageLabelVerdicts(v))
	_, skip, err = decodeImageLabelVerdicts(imageLabelVerdictsSentinel)
	require.NoError(t, err)
	assert.True(t, skip)
}

func TestVerdictsForImages(t *testing.T) {
	all := map[string]imageLabelVerdict{"a": {Labels: map[string]string{"k": "1"}}, "b": {Labels: map[string]string{"k": "2"}}}
	assert.Equal(t, map[string]imageLabelVerdict{"a": all["a"]}, verdictsForImages(all, []string{"a", "missing"}))
}

func TestApplyImageLabelVerdicts(t *testing.T) {
	image := func(host string) *inventory.Asset {
		return &inventory.Asset{Connections: []*inventory.Config{{Type: registryImageConnectionType, Host: host}}}
	}
	labeled, conflicted, unknown := image("a"), image("b"), image("c")
	workload := &inventory.Asset{Name: "ns/pod", Labels: map[string]string{"app": "x"}, Connections: []*inventory.Config{{Type: "k8s"}}}
	applyImageLabelVerdicts([]*inventory.Asset{labeled, conflicted, unknown, workload}, map[string]imageLabelVerdict{
		"a": {Labels: map[string]string{"my.company.com/team": "alpha"}},
		"b": {Labels: map[string]string{"my.company.com/department": "d-1"}, Conflicts: []string{"my.company.com/dept", "my.company.com/team"}},
	})
	assert.Equal(t, map[string]string{"my.company.com/team": "alpha"}, labeled.Labels)
	assert.Equal(t, map[string]string{"my.company.com/department": "d-1", LabelNamespaceLabelConflict: "my.company.com/dept,my.company.com/team"}, conflicted.Labels)
	assert.Nil(t, unknown.Labels)
	assert.Equal(t, map[string]string{"app": "x"}, workload.Labels)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd providers/k8s && go test ./resources -run 'TestImageLabelVerdicts|TestVerdictsForImages|TestApplyImageLabelVerdicts' -count=1`
Expected: FAIL to compile on the undefined symbols.

- [ ] **Step 3: Implement `image_labels.go` and the constant**

Fold: for each namespace, `inherited := inheritedNamespaceLabels(nsLabels[ns], patterns)`; for each image it runs, for each `k, v` in `inherited`, record `v` in `votes[image][k]` (a set). Then per image: keys with one distinct value → `Labels`; keys with more → `Conflicts` (sorted); drop images with neither. Marker value is `strings.Join(verdict.Conflicts, ",")`.

- [ ] **Step 4: Run tests**

Run: `cd providers/k8s && go test ./resources -run 'TestImageLabelVerdicts|TestVerdictsForImages|TestApplyImageLabelVerdicts' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add providers/k8s/resources/image_labels.go providers/k8s/resources/image_labels_test.go providers/k8s/connection/shared/connection.go
git commit -m "✨ k8s: fold namespace label votes into per-image verdicts"
```

---

### Task 3: Stage 1 computes verdicts and hands them to each namespace stage

**Files:**
- Modify: `providers/k8s/resources/image_labels.go` (add `clusterImagesByNamespace`)
- Modify: `providers/k8s/resources/discovery.go` (`discoverClusterStage`, between `nss, _, err := discoverNamespaces(...)` and the namespace loop, and inside the loop after `nsConfig.Options[shared.OPTION_NAMESPACE] = ns.Name`)
- Test: `providers/k8s/resources/image_labels_test.go`, `providers/k8s/resources/discovery_test.go`

**Interfaces:**
- Consumes: Task 1 `podImageRefs`; Task 2 fold/encode; `discoverNamespaces` second return value (own labels, Phase 1); `inheritedLabelKeys`, `setImageFilters`, `labelSelectorFilters`.
- Produces, used by Task 5:
  ```go
  // clusterImagesByNamespace lists every pod once through conn and returns, for each
  // namespace in namespaces, the sorted unique images its pods run, counting only pods
  // that pass labelFilters.MatchObject and images that pass imgFilter.
  func clusterImagesByNamespace(conn shared.Connection, namespaces []string, labelFilters *LabelSelectorFilters, imgFilter FilterOpts) (map[string][]string, error)
  ```

- [ ] **Step 1: Write the failing tests**

```go
func TestClusterImagesByNamespaceHonoursScope(t *testing.T) {
	// fake conn with pods: team-alpha/web (nginx@sha256:shared), team-beta/proxy (nginx@sha256:shared),
	// excluded-ns/x (nginx@sha256:shared), team-alpha/skipme labeled {"scan": "no"} (other@sha256:1)
	// namespaces: []string{"team-alpha", "team-beta"} (excluded-ns not in scope)
	// labelFilters: object selector "scan!=no"; imgFilter: none
	// expect {"team-alpha": {"nginx@sha256:shared"}, "team-beta": {"nginx@sha256:shared"}} and no "excluded-ns" key
}

func TestDiscoverClusterStageAttachesImageVerdicts(t *testing.T) {
	// fake conn: namespaces team-alpha {team=alpha}, team-beta {team=beta}, platform-tools {} ;
	// pods: team-alpha/web (nginx@sha256:shared, web@sha256:alpha), team-beta/proxy (nginx@sha256:shared),
	//       platform-tools/agent (web@sha256:alpha)
	// config: staged-discovery, inherit-namespace-labels "my.company.com/team", Targets {container-images}
	// inv, err := Discover(newDiscoveryTestRuntime(conn), mql.Features{})
	// three namespace assets; for each, decode Connections[0].Options[shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS]:
	//   team-alpha payload: nginx → Conflicts ["my.company.com/team"], web → Labels {team: alpha}
	//   team-beta payload: nginx → Conflicts ["my.company.com/team"]; no "web" key
	//   platform-tools payload: web → Labels {team: alpha}   (review focus 1)
}

func TestDiscoverClusterStageWithoutImagesTargetAttachesNoVerdicts(t *testing.T) {
	// same, Targets {pods} → namespace assets have no OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS key
}
```

Extend `newTestNamespace`/the fake as needed (a helper taking labels). The fake's `Resources` already serves all pods for the pods kind.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd providers/k8s && go test ./resources -run 'TestClusterImagesByNamespace|TestDiscoverClusterStage' -count=1`
Expected: FAIL to compile (`clusterImagesByNamespace`), then the attach test fails on the missing option.

- [ ] **Step 3: Implement**

`clusterImagesByNamespace`: `conn.Resources(gvkString(corev1.SchemeGroupVersion.WithKind("pods")), "", "")`; for each `*corev1.Pod` (skip other types) whose namespace is in `namespaces` and which passes `labelFilters.MatchObject(pod)`, add `podImageRefs(pod)` minus `imgFilter.skip` matches to a per-namespace set; return sorted slices.

`discoverClusterStage`: after `nss` is known and only when `len(inheritKeys) > 0 && stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryContainerImages, DiscoveryAll)` (parse `inheritKeys` and `imgFilter` next to the other option parsers): `imagesByNs, err := clusterImagesByNamespace(conn, names(nss), labelFilters, imgFilter)`, `verdicts := imageLabelVerdicts(imagesByNs, nsOwnLabels, inheritKeys)` (use the second return value of `discoverNamespaces` instead of `_`). In the loop: `nsConfig.Options[shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS] = encodeImageLabelVerdicts(verdictsForImages(verdicts, imagesByNs[ns.Name]))`.

- [ ] **Step 4: Run tests**

Run: `cd providers/k8s && go test ./resources -run 'TestClusterImagesByNamespace|TestDiscoverClusterStage|TestDiscoverStagedDiscovery' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add providers/k8s/resources/image_labels.go providers/k8s/resources/image_labels_test.go providers/k8s/resources/discovery.go providers/k8s/resources/discovery_test.go
git commit -m "✨ k8s: compute image label verdicts in the cluster stage and pass them per namespace"
```

---

### Task 4: Stage 2 applies the verdicts (or folds its own namespace)

**Files:**
- Modify: `providers/k8s/resources/discovery.go:404-418` (`discoverNamespaceStage`, after `inheritNamespaceLabels(assets, nsObj.Labels, inheritKeys)`)
- Test: `providers/k8s/resources/discovery_test.go` (replace `TestDiscoverNamespaceStageDoesNotLabelContainerImages`)

**Interfaces:**
- Consumes: Task 2 decode/apply/fold; `inheritKeys` already parsed in stage 2.
- Produces: none new.

- [ ] **Step 1: Write the failing tests** (all use `inheritanceTestConn` from Phase 1 with `Targets {DiscoveryPods, DiscoveryContainerImages}`; find the image asset by `Connections[0].Type == registryImageConnectionType`)

```go
func TestDiscoverNamespaceStageLabelsImagesFromVerdicts(t *testing.T) {
	// option OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS preset to encodeImageLabelVerdicts of
	//   {"docker.io/library/nginx@sha256:0123456789abcdef": {Labels: {team: "aaabbbccc"}, Conflicts: ["my.company.com/department"]}}
	// pod web runs that image → image asset Labels == {team: aaabbbccc, LabelNamespaceLabelConflict: "my.company.com/department"}
	// the pod asset still has team aaabbbccc (workload path untouched)
}

func TestDiscoverNamespaceStageStandaloneFoldsOwnNamespace(t *testing.T) {
	// no verdict option (direct stage 2) → image gets {team: aaabbbccc} from the namespace's own labels, no marker
}

func TestDiscoverNamespaceStageSentinelSkipsImageLabels(t *testing.T) {
	// option set to imageLabelVerdictsSentinel → image asset Labels nil; pod asset still inherits (review focus 4)
}

func TestDiscoverNamespaceStageWithoutOptionLeavesImagesUnchanged(t *testing.T) {
	// no inherit option at all → image asset Labels nil (review focus 5)
}
```

Delete `TestDiscoverNamespaceStageDoesNotLabelContainerImages`: it pinned Phase 1's deliberate gap, which this task closes.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd providers/k8s && go test ./resources -run 'TestDiscoverNamespaceStage' -count=1`
Expected: the verdict and standalone tests FAIL on missing image labels; sentinel and without-option tests pass (pin today's output).

- [ ] **Step 3: Implement** in `discoverNamespaceStage` after the workload inheritance, only when `len(inheritKeys) > 0`:

```go
raw, ok := invConfig.Options[shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS]
switch {
case !ok:
    verdicts := imageLabelVerdicts(map[string][]string{nsName: imageRefs(assets)}, map[string]map[string]string{nsName: nsObj.Labels}, inheritKeys)
    applyImageLabelVerdicts(assets, verdicts)
default:
    verdicts, skip, err := decodeImageLabelVerdicts(raw)
    // err → return it (a corrupt internal option is a bug, not a user input);
    // skip → log.Warn().Str("namespace", nsName).Msg("too many images with namespace label verdicts; leaving container images unlabeled")
    // else applyImageLabelVerdicts(assets, verdicts)
}
```

`imageRefs(assets)` is a small helper in `image_labels.go` returning the `Connections[0].Host` of the registry-image assets.

- [ ] **Step 4: Run tests**

Run: `cd providers/k8s && go test ./resources -run 'TestDiscover' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add providers/k8s/resources/discovery.go providers/k8s/resources/discovery_test.go providers/k8s/resources/image_labels.go
git commit -m "✨ k8s: label container images from namespace label verdicts in the namespace stage"
```

---

### Task 5: Legacy single-pass discovery

**Files:**
- Modify: `providers/k8s/resources/discovery.go:244-262` (`discoverLegacy` namespace loop) and the option parsing above it
- Test: `providers/k8s/resources/discovery_test.go`

**Interfaces:**
- Consumes: Task 3 `clusterImagesByNamespace`, Task 2 fold/apply.

- [ ] **Step 1: Write the failing test**

```go
func TestDiscoverLegacyLabelsImagesAcrossNamespaces(t *testing.T) {
	// fake: team-alpha {team=alpha}, team-beta {team=beta}, platform-tools {} ;
	// pods: team-alpha/web (nginx@sha256:shared, web@sha256:alpha), team-beta/proxy (nginx@sha256:shared),
	//       platform-tools/agent (web@sha256:alpha)
	// config WITHOUT staged-discovery, namespaces "team-*,platform-tools", inherit "my.company.com/team",
	//   Targets {container-images}
	// Discover → image assets (one per ref per namespace emission; collect by Host, first occurrence):
	//   nginx → marker "my.company.com/team", no team key; web → team alpha (also on the copy emitted under platform-tools)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd providers/k8s && go test ./resources -run TestDiscoverLegacyLabelsImagesAcrossNamespaces -count=1`
Expected: FAIL on the missing labels.

- [ ] **Step 3: Implement**: in `discoverLegacy`, when `len(inheritKeys) > 0 && stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryContainerImages, DiscoveryAll)`, compute `imagesByNs` over the names of `nss` and `verdicts` once before the loop; in the loop after `inheritNamespaceLabels(...)`: `applyImageLabelVerdicts(assets, verdicts)`.

- [ ] **Step 4: Run the whole package**

Run: `cd providers/k8s && go test ./resources -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add providers/k8s/resources/discovery.go providers/k8s/resources/discovery_test.go
git commit -m "✨ k8s: label container images from namespace label verdicts in legacy discovery"
```

---

### Task 6: ADR 051 update and final verification

**Files:**
- Modify: `docs/adr/051-k8s-namespace-label-inheritance.md` ("Container images (planned, Phase 3)" section and the Consequences bullet about images)

- [ ] **Step 1: Update the ADR**: retitle the section "Container images", drop "planned", and state what shipped: the verdict fold, that stage 1 computes it once from a single pod list and hands each namespace stage the verdicts for its images through the internal option (name it), the sentinel degradation, standalone stage 2 folding its own namespace, and the marker constant. Keep the single-space caveat. Keep the file's layout.

- [ ] **Step 2: Verify**

Run: `cd providers/k8s && go test ./resources ./provider ./connection/shared -count=1 && go vet ./resources ./connection/shared && gofmt -l ./resources ./connection/shared`
Expected: all PASS, vet silent, gofmt prints nothing.
Run: `git diff origin/main --stat && git log origin/main..HEAD --format='%h %G? %s'`
Expected: only files under `providers/k8s/` and `docs/`; every commit `G`.

- [ ] **Step 3: Commit and hand off**

```bash
git add docs/adr/051-k8s-namespace-label-inheritance.md
git commit -m "📄 ADR 051: container images get namespace label verdicts"
```

Hand-off note for the end-to-end test: the minikube `label-routing` cluster already has the shared-image fixture (`nginx:1.25-alpine` in alpha and beta, `busybox` in alpha and platform-tools, `redis` only in gamma); expect redis → gamma's space, nginx 1.25 → the marker, busybox → alpha (platform-tools has no team label and does not vote).

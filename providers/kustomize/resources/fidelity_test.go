// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/kustomize/connection"
	kustomizeTypes "sigs.k8s.io/kustomize/api/types"
)

// newMultiFileTestRuntime is the multi-file sibling of newImageTestRuntime: it
// materializes every named file (relative paths, subdirectories allowed) into
// a temp directory and connects a real KustomizeConnection to it. Needed for
// the declarations that span more than one file, such as a replacement
// declared by `path:` or a patch pointing at a sibling YAML.
func newMultiFileTestRuntime(t *testing.T, files map[string]string) (*plugin.Runtime, string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}

	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": dir},
	}}}
	conn, err := connection.NewKustomizeConnection(1, asset, &inventory.Config{})
	require.NoError(t, err)
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil), dir
}

// onlyKustomization returns the single kustomization the runtime's connection
// loaded, already routed through newMqlKustomization.
func onlyKustomization(t *testing.T, rt *plugin.Runtime) *mqlKustomizeKustomization {
	t.Helper()
	conn := rt.Connection.(*connection.KustomizeConnection)
	entries := conn.Kustomizations()
	require.Len(t, entries, 1)
	k, err := newMqlKustomization(rt, entries[0])
	require.NoError(t, err)
	return k
}

// captureLogs redirects the global zerolog logger for the duration of the test
// and returns the accumulated output.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Logger
	log.Logger = zerolog.New(buf).Level(zerolog.WarnLevel)
	t.Cleanup(func() { log.Logger = prev })
	return buf
}

// BUG 1: the modern `labels:` syntax (what `kustomize edit fix` writes, and
// what the docs recommend) landed in types.Kustomization.Labels, which nothing
// in the provider read. commonLabels reported {} for an overlay that does
// label every rendered object, so a "must carry an owner label" policy failed
// on compliant input and a deny-list policy passed vacuously.
func TestCommonLabelsIncludesModernLabelsSyntax(t *testing.T) {
	rt, _ := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
labels:
- pairs:
    app: web
    env: prod
  includeSelectors: true
`,
	})

	k := onlyKustomization(t, rt)
	require.NotNil(t, k.CommonLabels.Data)
	assert.Equal(t, "web", k.CommonLabels.Data["app"])
	assert.Equal(t, "prod", k.CommonLabels.Data["env"])
}

// Both syntaxes may appear together (kustomize only rejects the overlap on a
// shared key). Neither may shadow the other.
func TestCommonLabelsMergesLegacyAndModernSyntax(t *testing.T) {
	rt, _ := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
commonLabels:
  legacy: "yes"
labels:
- pairs:
    modern: "yes"
`,
	})

	k := onlyKustomization(t, rt)
	assert.Equal(t, "yes", k.CommonLabels.Data["legacy"])
	assert.Equal(t, "yes", k.CommonLabels.Data["modern"])
}

const replacementFileKustomization = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
replacements:
- path: repl.yaml
`

const replacementFileBody = `source:
  kind: ConfigMap
  name: app-config
  fieldPath: data.version
targets:
- select:
    kind: Deployment
    name: web
  fieldPaths:
  - spec.template.spec.containers.0.image
`

// BUG 2: `replacements: - path: file.yaml` produced a completely blank row.
// types.ReplacementField carries the file reference in Path, and the provider
// only ever read the inline Source/Targets, so a replacement that rewrites a
// container image reported as injecting nothing, from nowhere, into nothing.
func TestReplacementDeclaredByFileIsResolved(t *testing.T) {
	rt, _ := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": replacementFileKustomization,
		"repl.yaml":          replacementFileBody,
	})

	k := onlyKustomization(t, rt)
	repls, err := k.replacements()
	require.NoError(t, err)
	require.Len(t, repls, 1)

	r := repls[0].(*mqlKustomizeReplacement)
	assert.Equal(t, "repl.yaml", r.Path.Data, "the file reference must stay visible")
	assert.Equal(t, "ConfigMap", r.SourceKind.Data)
	assert.Equal(t, "app-config", r.SourceName.Data)
	assert.Equal(t, "data.version", r.SourcePath.Data)

	targets, err := r.targets()
	require.NoError(t, err)
	require.Len(t, targets, 1)
	tgt := targets[0].(*mqlKustomizeReplacementTarget)
	assert.Equal(t, "Deployment", tgt.Kind.Data)
	assert.Equal(t, "web", tgt.Name.Data)
	assert.Equal(t, "spec.template.spec.containers.0.image", tgt.FieldPath.Data)
}

// A replacement file may hold a list of replacements rather than a single
// mapping (kustomize accepts both). Every entry must surface as its own row.
func TestReplacementFileWithListYieldsEveryEntry(t *testing.T) {
	rt, _ := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": replacementFileKustomization,
		"repl.yaml": `- source:
    kind: ConfigMap
    name: first
    fieldPath: data.a
  targets:
  - select:
      kind: Deployment
      name: web
    fieldPaths:
    - spec.a
- source:
    kind: ConfigMap
    name: second
    fieldPath: data.b
  targets:
  - select:
      kind: Deployment
      name: api
    fieldPaths:
    - spec.b
`,
	})

	k := onlyKustomization(t, rt)
	repls, err := k.replacements()
	require.NoError(t, err)
	require.Len(t, repls, 2)

	names := []string{
		repls[0].(*mqlKustomizeReplacement).SourceName.Data,
		repls[1].(*mqlKustomizeReplacement).SourceName.Data,
	}
	assert.ElementsMatch(t, []string{"first", "second"}, names)
	assert.NotEqual(t, repls[0].(*mqlKustomizeReplacement).__id, repls[1].(*mqlKustomizeReplacement).__id)
}

// The file read reuses the patch path-containment guard, so a replacement that
// points outside the kustomization directory is refused. The row still carries
// the path so the refusal is visible rather than looking like an empty
// replacement.
func TestReplacementFileEscapingKustomizationDirIsRefused(t *testing.T) {
	rt, dir := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
replacements:
- path: ../escape.yaml
`,
	})
	outside := filepath.Join(filepath.Dir(dir), "escape.yaml")
	require.NoError(t, os.WriteFile(outside, []byte(replacementFileBody), 0o600))
	defer os.Remove(outside)

	buf := captureLogs(t)
	k := onlyKustomization(t, rt)
	repls, err := k.replacements()
	require.NoError(t, err)
	require.Len(t, repls, 1)

	r := repls[0].(*mqlKustomizeReplacement)
	assert.Equal(t, "../escape.yaml", r.Path.Data)
	assert.Empty(t, r.SourceKind.Data, "an escaping path must not be read")
	assert.Contains(t, buf.String(), "escapes the kustomization directory")
}

// A replacement path that does not resolve still has to surface the path and
// warn rather than emitting a silent blank row.
func TestReplacementFileMissingSurfacesPathAndWarns(t *testing.T) {
	rt, _ := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
replacements:
- path: gone.yaml
`,
	})

	buf := captureLogs(t)
	k := onlyKustomization(t, rt)
	repls, err := k.replacements()
	require.NoError(t, err)
	require.Len(t, repls, 1)

	assert.Equal(t, "gone.yaml", repls[0].(*mqlKustomizeReplacement).Path.Data)
	assert.Contains(t, buf.String(), "gone.yaml")
}

// BUG 3: a lookup miss fell through to `args, nil, nil`, so the runtime built
// the resource from the partial `path` arg and left every other field UNSET,
// which surfaces client-side as "primitive with no type information" with no
// attribution. The sibling initKustomizeImage already returns a not-found
// error; this one has to as well.
func TestInitKustomizeKustomizationUnknownPathErrors(t *testing.T) {
	rt, _ := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
	})

	_, res, err := initKustomizeKustomization(rt, map[string]*llx.RawData{
		"path": llx.StringData("/nope/not/here"),
	})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "/nope/not/here")
}

// The bare-resource fast paths stay: no args, or an empty path, is a valid
// empty state rather than a miss.
func TestInitKustomizeKustomizationKeepsBareFastPaths(t *testing.T) {
	rt, _ := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
	})

	_, res, err := initKustomizeKustomization(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	assert.Nil(t, res)

	_, res, err = initKustomizeKustomization(rt, map[string]*llx.RawData{"path": llx.StringData("")})
	require.NoError(t, err)
	assert.Nil(t, res)
}

// BUG 4: types.Image has five fields and the provider surfaced four. A
// `tagSuffix:` override rewrites the tag, but the row read newName="",
// newTag="", digest="" — an entry that changes nothing. An "every image
// override must pin a digest" check sees a benign-looking no-op.
func TestImageTagSuffixIsSurfaced(t *testing.T) {
	rt, _ := newMultiFileTestRuntime(t, map[string]string{
		"kustomization.yaml": `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
images:
- name: nginx
  tagSuffix: -debian
`,
	})

	k := onlyKustomization(t, rt)
	images, err := k.images()
	require.NoError(t, err)
	require.Len(t, images, 1)

	img := images[0].(*mqlKustomizeImage)
	assert.Equal(t, "nginx", img.Name.Data)
	assert.Equal(t, "-debian", img.TagSuffix.Data, "a tagSuffix override is not a no-op")
}

// BUG 5: the doc comment on strategicMergePatchEntry promises "a genuine typo
// still reports as a missing patch file (with a warning from
// newMqlKustomizePatch)". No such warning existed; a typo'd patch path became
// an empty strategic-merge patch with no signal at all.
func TestMissingPatchFileWarns(t *testing.T) {
	dir := t.TempDir()
	buf := captureLogs(t)

	p, err := newMqlKustomizePatch(newTestRuntime(), dir, 0, &kustomizeTypes.Patch{Path: "does-not-exist.yaml"}, hintNone)
	require.NoError(t, err)
	assert.Equal(t, "does-not-exist.yaml", p.Path.Data)
	assert.Contains(t, buf.String(), "does-not-exist.yaml")
}

// BUG 6: the replacementTarget __id was built from the target index within its
// replacement plus kind/name/fieldPath, but never the parent replacement's own
// index. Two replacements whose first target shares those selectors produced
// the same __id, so CreateResource handed back the first instance for the
// second.
func TestReplacementTargetIDIncludesParentReplacement(t *testing.T) {
	rt := newTestRuntime()

	mk := func(index int, fieldPath string) *mqlKustomizeReplacement {
		r := &mqlKustomizeReplacement{MqlRuntime: rt}
		r.__id = "kustomize.replacement:kustomization.yaml:" + strconv.Itoa(index)
		r.kustPath = "kustomization.yaml"
		r.replacementTargets = []*kustomizeTypes.TargetSelector{{
			Select:     &kustomizeTypes.Selector{},
			FieldPaths: []string{fieldPath},
		}}
		return r
	}

	// Same kind (""), same name (""), same fieldPath, different parent.
	first, err := mk(0, "spec.replicas").targets()
	require.NoError(t, err)
	second, err := mk(1, "spec.replicas").targets()
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Len(t, second, 1)

	assert.NotEqual(t,
		first[0].(*mqlKustomizeReplacementTarget).__id,
		second[0].(*mqlKustomizeReplacementTarget).__id,
		"targets of different replacements must not alias in the resource cache")
}

// BUG 7: mqlKustomizePatch stamped its Internal state after CreateResource
// without a stampOnce, so a cached instance handed to a second goroutine was
// written while a concurrent operations() read it. Both sibling resources
// already guard this with a sync.Once. Detected by `go test -race`.
func TestPatchInternalStampIsRaceFree(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "patch.yaml"),
		[]byte("- op: replace\n  path: /spec/replicas\n  value: 3\n"), 0o600))
	rt := newTestRuntime()

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			p, err := newMqlKustomizePatch(rt, dir, 0, &kustomizeTypes.Patch{Path: "patch.yaml"}, hintNone)
			if err != nil {
				return
			}
			_, _ = p.operations()
		})
	}
	wg.Wait()
}

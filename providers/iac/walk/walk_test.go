// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package walk

import (
	"errors"
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/iac/connection"
)

// fakeProber answers scripted verdicts and records every candidate it was
// offered, so a test can assert on what was probed and not only on the result.
type fakeProber struct {
	// verdict answers for one connection type and path. A type with no entry
	// accepts and stops.
	verdict map[string]func(connType, path string) (*plugin.ConnectRes, error)
	seen    []string
	// platformIDs assigns an identity per probe; repeat an id to make two
	// probes resolve to one asset.
	platformIDs map[string]string
}

func (f *fakeProber) Probe(child *inventory.Asset) (*plugin.ConnectRes, error) {
	conf := child.Connections[0]
	key := conf.Type + " " + conf.Options["path"]
	f.seen = append(f.seen, key)

	if fn, ok := f.verdict[conf.Type]; ok {
		return fn(conf.Type, conf.Options["path"])
	}
	return accept(f.platformIDs[key]), nil
}

func accept(platformID string) *plugin.ConnectRes {
	if platformID == "" {
		platformID = "//platform/generated"
	}
	return &plugin.ConnectRes{Asset: &inventory.Asset{
		PlatformIds: []string{platformID},
		Connections: []*inventory.Config{{Type: "child"}},
	}}
}

func acceptAndContinue(platformID string) *plugin.ConnectRes {
	res := accept(platformID)
	res.ContinueExploration = true
	return res
}

func dirOptIn(discovery, connType string, globs ...string) plugin.TargetOptIn {
	optIn := plugin.TargetOptIn{Target: "iac", Discovery: discovery, ConnType: connType, Auto: true}
	for _, g := range globs {
		optIn.Match = append(optIn.Match, plugin.Matcher{Glob: g})
	}
	return optIn
}

func fileOptIn(discovery, connType string, globs ...string) plugin.TargetOptIn {
	optIn := dirOptIn(discovery, connType, globs...)
	optIn.PerFile = true
	return optIn
}

func rootAsset() *inventory.Asset {
	return &inventory.Asset{Id: "project", PlatformIds: []string{"//platform/project"}}
}

func detectionPaths(res *Result) []string {
	var out []string
	for _, d := range res.Detections {
		out = append(out, d.Tool+" "+d.Path)
	}
	return out
}

func runWalk(t *testing.T, files map[string]string, sel Selection, opts Options, prober Prober) *Result {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	res, err := Walk(Tree{FS: fsys, Root: "/tree"}, sel, opts, rootAsset(), prober)
	require.NoError(t, err)
	return res
}

func TestWalkSitesDirectoriesAndFiles(t *testing.T) {
	files := map[string]string{
		"terraform/main.tf":       "",
		"terraform/variables.tf":  "",
		"Dockerfile":              "",
		"services/api/Dockerfile": "",
	}
	prober := &fakeProber{verdict: map[string]func(string, string) (*plugin.ConnectRes, error){
		// docker-file keeps descending, so both Dockerfiles are probed.
		"docker-file": func(_, p string) (*plugin.ConnectRes, error) { return acceptAndContinue(p), nil },
		"terraform":   func(_, p string) (*plugin.ConnectRes, error) { return accept(p), nil },
	}}

	res := runWalk(t, files, Selection{OptIns: []plugin.TargetOptIn{
		dirOptIn("terraform", "terraform", "*.tf"),
		fileOptIn("docker-file", "docker-file", "Dockerfile"),
	}}, Options{}, prober)

	// A directory opt-in is offered the folder once, with both files recorded;
	// a PerFile one is offered each file.
	assert.ElementsMatch(t, []string{
		"terraform terraform",
		"docker-file Dockerfile",
		"docker-file services/api/Dockerfile",
	}, detectionPaths(res))

	for _, d := range res.Detections {
		if d.Tool == "terraform" {
			assert.Equal(t, []string{"terraform/main.tf", "terraform/variables.tf"}, d.Files)
		}
	}
}

func TestWalkStopsStrictlyBelowAClaimedSite(t *testing.T) {
	files := map[string]string{
		"terraform/main.tf":             "",
		"terraform/modules/vpc/main.tf": "",
		"other/main.tf":                 "",
	}
	prober := &fakeProber{}

	res := runWalk(t, files, Selection{OptIns: []plugin.TargetOptIn{
		dirOptIn("terraform", "terraform", "*.tf"),
	}}, Options{}, prober)

	// terraform took the folder and said nothing, so the nested module is
	// swallowed -- but a sibling folder is untouched.
	// Sites at the same depth are probed in path order, which is what makes
	// the detection list stable enough to assert on.
	assert.Equal(t, []string{"terraform other", "terraform terraform"}, detectionPaths(res))
	assert.NotContains(t, prober.seen, "terraform /tree/terraform/modules/vpc")
}

func TestWalkStopDoesNotAffectAnotherOptIn(t *testing.T) {
	files := map[string]string{
		"terraform/main.tf":                "",
		"terraform/modules/vpc/main.tf":    "",
		"terraform/modules/vpc/Dockerfile": "",
	}
	prober := &fakeProber{verdict: map[string]func(string, string) (*plugin.ConnectRes, error){
		"docker-file": func(_, p string) (*plugin.ConnectRes, error) { return acceptAndContinue(p), nil },
	}}

	res := runWalk(t, files, Selection{OptIns: []plugin.TargetOptIn{
		dirOptIn("terraform", "terraform", "*.tf"),
		fileOptIn("docker-file", "docker-file", "Dockerfile"),
	}}, Options{}, prober)

	// The terraform claim stops terraform below that folder and nothing else.
	assert.Contains(t, detectionPaths(res), "docker-file terraform/modules/vpc/Dockerfile")
}

func TestWalkContinueExplorationKeepsDescending(t *testing.T) {
	files := map[string]string{
		"Dockerfile":              "",
		"services/api/Dockerfile": "",
		"services/web/Dockerfile": "",
	}
	prober := &fakeProber{verdict: map[string]func(string, string) (*plugin.ConnectRes, error){
		"docker-file": func(_, p string) (*plugin.ConnectRes, error) { return acceptAndContinue(p), nil },
	}}

	res := runWalk(t, files, Selection{OptIns: []plugin.TargetOptIn{
		fileOptIn("docker-file", "docker-file", "Dockerfile"),
	}}, Options{}, prober)

	assert.Len(t, res.Detections, 3)
	assert.Len(t, res.Assets, 3)
}

func TestWalkNoMatchRecordsNothing(t *testing.T) {
	files := map[string]string{"config/settings.yaml": ""}
	prober := &fakeProber{verdict: map[string]func(string, string) (*plugin.ConnectRes, error){
		"k8s": func(_, _ string) (*plugin.ConnectRes, error) {
			return nil, fmt.Errorf("no Kubernetes objects found: %w", plugin.ErrNoMatch)
		},
	}}

	res := runWalk(t, files, Selection{OptIns: []plugin.TargetOptIn{
		dirOptIn("k8s", "k8s", "*.yaml"),
	}}, Options{}, prober)

	// The candidate was offered and refused. Nothing is emitted and nothing
	// appears in detections with an error: a rejection is not a failure.
	require.Contains(t, prober.seen, "k8s /tree/config")
	assert.Empty(t, res.Detections)
	assert.Empty(t, res.Assets)
}

func TestWalkRealErrorIsRecordedAndTheWalkContinues(t *testing.T) {
	files := map[string]string{
		"broken/Chart.yaml": "",
		"good/Chart.yaml":   "",
	}
	prober := &fakeProber{verdict: map[string]func(string, string) (*plugin.ConnectRes, error){
		"helm": func(_, p string) (*plugin.ConnectRes, error) {
			if p == "/tree/broken" {
				return nil, errors.New("chart is malformed")
			}
			return accept(p), nil
		},
	}}

	res := runWalk(t, files, Selection{OptIns: []plugin.TargetOptIn{
		dirOptIn("helm", "helm", "Chart.yaml"),
	}}, Options{}, prober)

	require.Len(t, res.Detections, 2)
	// The failure is visible with its message, and the good chart beside it is
	// still an asset.
	var broken, good *connection.Detection
	for _, d := range res.Detections {
		switch d.Path {
		case "broken":
			broken = d
		case "good":
			good = d
		}
	}
	require.NotNil(t, broken)
	require.NotNil(t, good)
	assert.Equal(t, "chart is malformed", broken.Err)
	assert.Nil(t, broken.Asset())
	assert.Empty(t, good.Err)
	assert.NotNil(t, good.Asset())
	assert.Len(t, res.Assets, 1)
}

func TestWalkIgnoreList(t *testing.T) {
	files := map[string]string{
		"main.tf":                                "",
		"terraform/.terraform/modules/x/main.tf": "",
		"node_modules/pkg/Dockerfile":            "",
	}
	optIns := []plugin.TargetOptIn{
		dirOptIn("terraform", "terraform", "*.tf"),
		fileOptIn("docker-file", "docker-file", "Dockerfile"),
	}

	withIgnore := runWalk(t, files, Selection{OptIns: optIns},
		Options{Ignore: connection.DefaultIgnore}, &fakeProber{})
	assert.Equal(t, []string{"terraform "}, detectionPaths(withIgnore))

	// An empty ignore list finds them, which is what --iac-ignore "" is for.
	withoutIgnore := runWalk(t, files, Selection{OptIns: optIns}, Options{}, &fakeProber{})
	assert.Contains(t, detectionPaths(withoutIgnore), "docker-file node_modules/pkg/Dockerfile")
}

func TestWalkAllOffersTheRootToDirectoryOptInsOnly(t *testing.T) {
	files := map[string]string{"README.md": ""}
	prober := &fakeProber{}

	runWalk(t, files, Selection{All: true, OptIns: []plugin.TargetOptIn{
		dirOptIn("terraform", "terraform", "*.tf"),
		fileOptIn("docker-file", "docker-file", "Dockerfile"),
	}}, Options{}, prober)

	// The escape hatch hands the tree to a provider that reads a directory.
	assert.Contains(t, prober.seen, "terraform /tree")
	// A PerFile opt-in reads one document per asset, so a directory says
	// nothing to it -- docker-file handed one builds an asset describing
	// nothing at all.
	assert.NotContains(t, prober.seen, "docker-file /tree")
}

func TestWalkTwoDetectionsOnOneIdentityShareAnAsset(t *testing.T) {
	files := map[string]string{
		"mixed/main.tf":   "",
		"mixed/main.tofu": "",
	}
	// Both dialects resolve to the same platform ID, because terraform's is
	// deliberately dialect-agnostic.
	prober := &fakeProber{verdict: map[string]func(string, string) (*plugin.ConnectRes, error){
		"terraform-hcl": func(_, p string) (*plugin.ConnectRes, error) { return accept("//platform/" + p), nil },
	}}

	res := runWalk(t, files, Selection{OptIns: []plugin.TargetOptIn{
		dirOptIn("terraform", "terraform-hcl", "*.tf"),
		dirOptIn("opentofu", "terraform-hcl", "*.tofu"),
	}}, Options{}, prober)

	require.Len(t, res.Detections, 2)
	// One asset, carrying both anchors, so either detection resolves into it.
	require.Len(t, res.Assets, 1)
	assert.Len(t, res.Assets[0].Relationships, 2)
	assert.Same(t, res.Assets[0], res.Detections[0].Asset())
	assert.Same(t, res.Assets[0], res.Detections[1].Asset())
}

func TestWalkSetsBothPathFieldsAndMergesOptions(t *testing.T) {
	var got *inventory.Config
	prober := probeFunc(func(child *inventory.Asset) (*plugin.ConnectRes, error) {
		got = child.Connections[0]
		return accept(""), nil
	})

	optIn := dirOptIn("terraform", "terraform-hcl", "*.tf")
	optIn.Options = map[string]string{"iac-tool": "terraform"}

	runWalk(t, map[string]string{"envs/prod/main.tf": ""},
		Selection{OptIns: []plugin.TargetOptIn{optIn}}, Options{}, prober)

	require.NotNil(t, got)
	// docker-file reads Config.Path, everything else reads Options["path"], so
	// both carry the candidate. k8s in particular falls through to a live
	// cluster connect when the path option is missing.
	assert.Equal(t, "/tree/envs/prod", got.Path)
	assert.Equal(t, "/tree/envs/prod", got.Options["path"])
	assert.Equal(t, "terraform", got.Options["iac-tool"])
	// A probe carries no Discover: it would make a k8s probe enumerate a tree
	// that is about to be thrown away.
	assert.Nil(t, got.Discover)
}

func TestWalkAcceptedAssetAsksForItsOwnDiscovery(t *testing.T) {
	res := runWalk(t, map[string]string{"k8s/deployment.yaml": ""},
		Selection{OptIns: []plugin.TargetOptIn{dirOptIn("k8s", "k8s", "*.yaml")}},
		Options{}, &fakeProber{})

	require.Len(t, res.Assets, 1)
	// The accepted asset is where Discover belongs, so the discovery layer
	// reproduces what a direct scan of that connector would find.
	require.NotNil(t, res.Assets[0].Connections[0].Discover)
	assert.Equal(t, []string{"auto"}, res.Assets[0].Connections[0].Discover.Targets)
}

func TestWalkProbesEachOptInAtEachPathOnce(t *testing.T) {
	files := map[string]string{
		"k8s/deployment.yaml": "",
		"k8s/service.yaml":    "",
		"k8s/ingress.yml":     "",
	}
	prober := &fakeProber{}

	runWalk(t, files, Selection{OptIns: []plugin.TargetOptIn{
		dirOptIn("k8s", "k8s", "*.yaml", "*.yml"),
	}}, Options{}, prober)

	// Three files, two globs, one candidate: the anchor id is the tool plus the
	// path, so a repeat would make two detections collide on one id.
	assert.Equal(t, []string{"k8s /tree/k8s"}, prober.seen)
}

func TestWalkAnchorsEveryAssetToItsDetection(t *testing.T) {
	res := runWalk(t, map[string]string{"charts/api/Chart.yaml": ""},
		Selection{OptIns: []plugin.TargetOptIn{dirOptIn("helm", "helm", "Chart.yaml")}},
		Options{}, &fakeProber{})

	require.Len(t, res.Detections, 1)
	require.Len(t, res.Assets, 1)

	rels := res.Assets[0].Relationships
	require.Len(t, rels, 1)
	assert.Equal(t, connection.DetectionResourceType, rels[0].ResourceType)
	assert.Equal(t, res.Detections[0].AnchorID(), rels[0].ResourceId)
	// The edge points back at the project by identity alone.
	assert.Equal(t, []string{"//platform/project"}, rels[0].Asset.PlatformIds)
}

// probeFunc adapts a function to the Prober interface.
type probeFunc func(child *inventory.Asset) (*plugin.ConnectRes, error)

func (f probeFunc) Probe(child *inventory.Asset) (*plugin.ConnectRes, error) { return f(child) }

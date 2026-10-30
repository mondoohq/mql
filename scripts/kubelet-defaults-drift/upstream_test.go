// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultsSrc = `package v1beta1

const (
	// DefaultIPTablesMasqueradeBit is the default.
	DefaultIPTablesMasqueradeBit = 14
	DefaultIPTablesDropBit = 15
)

func SetDefaults_KubeletConfiguration(obj *KubeletConfiguration) {
	if obj.SyncFrequency == zeroDuration {
		obj.SyncFrequency = metav1.Duration{Duration: 1 * time.Minute}
	}
}
`

// The same code, with the constants realigned, a comment changed and added,
// and blank lines moved: as when a release branch only reformats a file.
const defaultsSrcReformatted = `package v1beta1

const (
	DefaultIPTablesMasqueradeBit = 14 // the default
	DefaultIPTablesDropBit       = 15
)


func SetDefaults_KubeletConfiguration(obj *KubeletConfiguration) {
	// sync every minute

	if obj.SyncFrequency == zeroDuration {
		obj.SyncFrequency = metav1.Duration{Duration: 1 * time.Minute}
	}
}
`

func TestExtractIgnoresCommentsAndFormatting(t *testing.T) {
	it := item{Path: "pkg/kubelet/apis/config/v1beta1/defaults.go"}
	a, found, err := extract(defaultsSrc, it)
	require.NoError(t, err)
	require.True(t, found)
	b, _, err := extract(defaultsSrcReformatted, it)
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.NotContains(t, a, "default.")

	// a changed value is a change
	c, _, err := extract(strings.Replace(defaultsSrc, "1 * time.Minute", "1 * time.Hour", 1), it)
	require.NoError(t, err)
	assert.NotEqual(t, a, c)
}

// Removing a constant makes gofmt realign the rest of the block. Only the
// removed line differs.
func TestExtractRealignedBlock(t *testing.T) {
	before := "package p\n\nconst (\n\tA = 1\n\tB = 2\n\tLongerName = 3\n)\n"
	after := "package p\n\nconst (\n\tA = 1\n\tB = 2\n)\n"
	it := item{Path: "p.go"}
	a, _, err := extract(before, it)
	require.NoError(t, err)
	b, _, err := extract(after, it)
	require.NoError(t, err)
	assert.Equal(t, "package p\nconst (\n\tA = 1\n\tB = 2\n\tLongerName = 3\n)\n", a)
	assert.Equal(t, "package p\nconst (\n\tA = 1\n\tB = 2\n)\n", b)
}

func TestExtractDecl(t *testing.T) {
	src := `package options

func NewKubeletFlags() *KubeletFlags { return &KubeletFlags{} }

func applyLegacyDefaults(kc *KubeletConfiguration) {
	// --anonymous-auth
	kc.Authentication.Anonymous.Enabled = ptr.To(true)
}
`
	out, found, err := extract(src, item{Path: "options.go", Decl: "applyLegacyDefaults"})
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "func applyLegacyDefaults(kc *KubeletConfiguration) {\n\tkc.Authentication.Anonymous.Enabled = ptr.To(true)\n}\n", out)

	_, found, err = extract(src, item{Path: "options.go", Decl: "missing"})
	require.NoError(t, err)
	assert.False(t, found)
}

const featuresSrc = `package features

const (
	KubeletCrashLoopBackOffMax featuregate.Feature = "KubeletCrashLoopBackOffMax"
)

var defaultVersionedKubernetesFeatureGates = map[featuregate.Feature]featuregate.VersionedSpecs{
	KubeletCrashLoopBackOffMax: {
		{Version: version.MustParse("1.32"), Default: false, PreRelease: featuregate.Alpha},
		{Version: version.MustParse("1.35"), Default: true, PreRelease: featuregate.Beta},
	},
	genericfeatures.APIServerTracing: {
		{Version: version.MustParse("1.22"), Default: false, PreRelease: featuregate.Alpha},
	},
}

var defaultKubernetesFeatureGateDependencies = map[featuregate.Feature][]featuregate.Feature{
	KubeletCrashLoopBackOffMax: {},
}
`

func TestExtractGate(t *testing.T) {
	out, found, err := extract(featuresSrc, item{Path: featuresPath, Gate: "KubeletCrashLoopBackOffMax"})
	require.NoError(t, err)
	require.True(t, found)
	// the versioned spec, not the entry in the dependency map
	assert.Contains(t, out, `version.MustParse("1.35"), Default: true`)
	assert.NotContains(t, out, "{}")

	out, found, err = extract(featuresSrc, item{Path: featuresPath, Gate: "APIServerTracing"})
	require.NoError(t, err)
	require.True(t, found)
	assert.Contains(t, out, `version.MustParse("1.22")`)

	_, found, err = extract(featuresSrc, item{Path: featuresPath, Gate: "UserNamespacesSupport"})
	require.NoError(t, err)
	assert.False(t, found)
}

func TestExtractMalformed(t *testing.T) {
	_, _, err := extract("<html>rate limited</html>", item{Path: "defaults.go"})
	assert.Error(t, err)
}

func TestGatesFrom(t *testing.T) {
	src := `
	if featureGateEnabled(obj, "KubeletEnsureSecretPulledImages", minor, 35) {}
	if featureGateEnabled(obj, "KubeletCrashLoopBackOffMax", minor, 35) {}
	if featureGateEnabled(obj, "KubeletCrashLoopBackOffMax", minor, 35) {}
	func featureGateEnabled(obj *KubeletConfiguration, name string, minor, defaultOnSince int) bool {
	`
	assert.Equal(t, []string{"KubeletCrashLoopBackOffMax", "KubeletEnsureSecretPulledImages"}, gatesFrom(src))
	assert.Empty(t, gatesFrom(""))
}

func TestReleaseMinors(t *testing.T) {
	refs := map[string]string{
		"refs/heads/release-1.3":    "a",
		"refs/heads/release-1.33":   "b",
		"refs/heads/release-1.34":   "c",
		"refs/heads/release-1.38":   "d",
		"refs/heads/release-1.38.1": "e",
	}
	assert.Equal(t, map[int]string{34: "c", 38: "d"}, releaseMinors(refs, 34))
}

func TestBaselineOldest(t *testing.T) {
	b := Baseline{Minors: map[string]MinorBaseline{"1.36": {}, "1.34": {}, "1.37": {}}}
	assert.Equal(t, 34, b.oldest())
	assert.Equal(t, 0, Baseline{}.oldest())
}

func TestDrift(t *testing.T) {
	b := Baseline{Minors: map[string]MinorBaseline{
		"1.36": {Items: map[string]string{"defaults.go": "sha256:a", "options.go#applyLegacyDefaults": "sha256:b"}},
		"1.37": {Items: map[string]string{"defaults.go": "sha256:a", "options.go#applyLegacyDefaults": "sha256:b"}},
	}}
	same := map[string]string{"defaults.go": "sha256:a", "options.go#applyLegacyDefaults": "sha256:b"}

	assert.Empty(t, drift(b, map[int]map[string]string{36: same, 37: same}))

	got := drift(b, map[int]map[string]string{
		36: same,
		37: {"defaults.go": "sha256:c", "options.go#applyLegacyDefaults": "sha256:b", featuresPath + "#gate:NewGate": absent},
		38: same,
	})
	assert.Equal(t, []finding{
		{Minor: 37, Kind: changed, Item: "defaults.go"},
		{Minor: 37, Kind: newItem, Item: featuresPath + "#gate:NewGate"},
		{Minor: 38, Kind: newMinor},
	}, got)
}

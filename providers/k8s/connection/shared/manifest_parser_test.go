// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/core/v1"
)

type ManifestParserSuite struct {
	suite.Suite
	manifestParser ManifestParser
}

func (s *ManifestParserSuite) SetupSuite() {
	manifest, err := LoadManifestFile("./resources/testdata/mixed.yaml")
	s.Require().NoError(err)
	manP, err := NewManifestParser(manifest, "", "")
	s.Require().NoError(err)

	s.manifestParser = manP
}

func (s *ManifestParserSuite) TestNamespace() {
	ns, err := s.manifestParser.Namespace("default")
	s.Require().NoError(err)
	s.Equal("default", ns.Name)
	s.Equal("Namespace", ns.Kind)
}

func (s *ManifestParserSuite) TestNamespaces() {
	nss, err := s.manifestParser.Namespaces()
	s.Require().NoError(err)
	s.Len(nss, 2)

	nsNames := make([]string, 0, len(nss))
	for _, ns := range nss {
		nsNames = append(nsNames, ns.Name)
		s.Equal("Namespace", ns.Kind)
	}
	s.ElementsMatch([]string{"default", "custom"}, nsNames)
}

func TestManifestParserSuite(t *testing.T) {
	suite.Run(t, new(ManifestParserSuite))
}

func TestNamespaces_StandaloneObjectsCarryMetadata(t *testing.T) {
	manifest, err := LoadManifestFile("./resources/testdata/namespaces.yaml")
	require.NoError(t, err)
	parser, err := NewManifestParser(manifest, "", "")
	require.NoError(t, err)

	nss, err := parser.Namespaces()
	require.NoError(t, err)

	byName := map[string]v1.Namespace{}
	for _, ns := range nss {
		byName[ns.Name] = ns
		// every returned namespace must carry the Namespace kind
		require.Equal(t, "Namespace", ns.Kind, "namespace %q missing kind", ns.Name)
	}

	// standalone Namespace objects and a reference-only namespace are all present
	require.ElementsMatch(t, []string{"secured", "privileged-ns", "referenced-only"}, keysOf(byName))

	// standalone Namespace objects keep their full metadata
	secured := byName["secured"]
	require.Equal(t, "restricted", secured.Labels["pod-security.kubernetes.io/enforce"])
	require.Equal(t, "v1.30", secured.Labels["pod-security.kubernetes.io/enforce-version"])
	require.Equal(t, "baseline", secured.Labels["pod-security.kubernetes.io/warn"])
	require.Equal(t, "platform-team", secured.Annotations["owner"])
	require.Equal(t, "11111111-1111-1111-1111-111111111111", string(secured.UID))

	require.Equal(t, "privileged", byName["privileged-ns"].Labels["pod-security.kubernetes.io/enforce"])

	// reference-only namespaces are synthesized minimally (no labels)
	require.Empty(t, byName["referenced-only"].Labels)
}

func TestNamespace_StandaloneObjectLookup(t *testing.T) {
	manifest, err := LoadManifestFile("./resources/testdata/namespaces.yaml")
	require.NoError(t, err)
	parser, err := NewManifestParser(manifest, "", "")
	require.NoError(t, err)

	ns, err := parser.Namespace("secured")
	require.NoError(t, err)
	require.Equal(t, "secured", ns.Name)
	require.Equal(t, "restricted", ns.Labels["pod-security.kubernetes.io/enforce"])

	_, err = parser.Namespace("does-not-exist")
	require.Error(t, err)
}

func keysOf(m map[string]v1.Namespace) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRepositoryPath(t *testing.T) {
	root := filepath.Join("tmp", "mql-git-clone123")
	cases := []struct {
		name, path, want string
	}{
		{"a file in the root", filepath.Join(root, "deployment.yaml"), "deployment.yaml"},
		{"a nested file", filepath.Join(root, "scenarios", "hunger-check", "deployment.yaml"), "scenarios/hunger-check/deployment.yaml"},
		{"a dotted name is not the parent", filepath.Join(root, "..config.yaml"), "..config.yaml"},
		{"the root itself", root, root},
		{"the parent of the root", "tmp", "tmp"},
		{"a file outside the root", filepath.Join("tmp", "other", "a.yaml"), filepath.Join("tmp", "other", "a.yaml")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, RepositoryPath(root, tc.path))
		})
	}
}

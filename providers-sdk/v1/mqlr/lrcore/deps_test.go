// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
)

const depPeer = `
option provider = "go.mondoo.com/mql/providers/network"
option go_package = "go.mondoo.com/mql/providers/network/resources"

certificate {
  pem string
}

socket {
  port int
}
`

func resolveDepFixture(t *testing.T, src string) *LR {
	t.Helper()
	files := map[string]string{
		"providers/demo/resources/demo.lr":       src,
		"providers/network/resources/network.lr": depPeer,
	}
	res, err := Resolve("providers/demo/resources/demo.lr", func(path string) ([]byte, error) {
		raw, ok := files[path]
		require.Truef(t, ok, "unexpected read of %q", path)
		return []byte(raw), nil
	})
	require.NoError(t, err)
	return res
}

func TestSchemaRefs(t *testing.T) {
	ast := resolveDepFixture(t, `
import network

option provider = "go.mondoo.com/mql/providers/demo"
option go_package = "go.mondoo.com/mql/providers/demo/resources"

demo.bundle {
  []network.certificate(content)
  init(path string)
  path string
  content(path) string
}

demo.host {
  certs []network.certificate
  primary network.socket
  bymap map[string]network.socket
  local demo.part
  parts []demo.part
}

demo.part {
  id string
}
`)

	refs := SchemaRefs(ast)

	var got []string
	for _, r := range refs {
		got = append(got, r.Peer+"."+r.key())
	}

	assert.ElementsMatch(t, []string{
		"network.certificate", // the list-type resource, via its synthetic `list` field
		"network.certificate", // []network.certificate field
		"network.socket",      // singular field
		"network.socket",      // map value
	}, got)

	// `content` is a field of demo.bundle, not of network.certificate. Reading
	// the list args as peer fields asks for certificate.content, which does not
	// exist -- and would make every floor unresolvable.
	for _, r := range refs {
		assert.NotEqual(t, "content", r.Field, "list args are parent fields, not peer fields")
	}

	// local dotted names are not peer references
	for _, r := range refs {
		assert.NotEqual(t, "demo", r.Peer)
	}
}

func TestGoRefs(t *testing.T) {
	ast := resolveDepFixture(t, `
import network

option provider = "go.mondoo.com/mql/providers/demo"
option go_package = "go.mondoo.com/mql/providers/demo/resources"

demo.host {
  name string
}
`)

	src := []byte(`
		x, _ := runtime.CreateSharedResource("certificate", args)
		l, _ := runtime.GetSharedData("socket", x.MqlID(), "port")
		// not a peer: this provider's own resource
		y, _ := runtime.CreateSharedResource("demo.host", args)
	`)

	refs, unresolved := GoRefs(ast, "scan.go", src)
	assert.Empty(t, unresolved, "own and peer resources are both attributable")

	var got []string
	for _, r := range refs {
		got = append(got, r.Peer+"."+r.key())
	}
	assert.ElementsMatch(t, []string{"network.certificate", "network.socket.port"}, got)
}

func TestGoRefsReportsCallWithNoImport(t *testing.T) {
	// The "call with no import" half of the CI check: a shared-resource call
	// naming something that is neither ours nor a declared peer's. Dropping it
	// silently is how an undeclared cross-provider call stays invisible until
	// it hits the runtime gate.
	ast := resolveDepFixture(t, `
import network

option provider = "go.mondoo.com/mql/providers/demo"
option go_package = "go.mondoo.com/mql/providers/demo/resources"

demo.host {
  name string
}
`)

	refs, unresolved := GoRefs(ast, "scan.go", []byte(`
		a, _ := runtime.CreateSharedResource("certificate", args)   // declared peer
		b, _ := runtime.CreateSharedResource("demo.host", args)     // our own
		c, _ := runtime.CreateSharedResource("aws.s3.bucket", args) // neither
		d, _ := runtime.GetSharedData("cpe", x.MqlID(), "uri")      // neither
	`))

	assert.Len(t, refs, 1)
	require.Len(t, unresolved, 2)

	var names []string
	for _, u := range unresolved {
		names = append(names, u.Resource)
		assert.Equal(t, "scan.go", u.Origin)
	}
	assert.ElementsMatch(t, []string{"aws.s3.bucket", "cpe"}, names)
	assert.Equal(t, "uri", unresolved[1].Field)
}

func TestMinVersionsTakesTheMaximum(t *testing.T) {
	p := semver.Parser{}
	versions := map[string]LrVersions{
		"network": {
			"certificate":     "9.0.0",
			"certificate.pem": "13.2.0",
			"socket":          "9.0.0",
			"socket.port":     "9.4.1",
		},
	}

	refs := []PeerRef{
		{Peer: "network", Resource: "certificate", Origin: "a"},
		{Peer: "network", Resource: "socket", Field: "port", Origin: "b"},
		{Peer: "network", Resource: "certificate", Field: "pem", Origin: "c"},
	}

	mins, err := MinVersions(refs, versions, p.Compare)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"network": "13.2.0"}, mins)
}

func TestMinVersionsRejectsUnversionedReference(t *testing.T) {
	// A namespace-only root such as `openpgp` or `pkix` carries no version
	// because it has no fields. Treating that as version 0 would let a typo
	// like `network.pkix` validate instead of failing.
	p := semver.Parser{}
	versions := map[string]LrVersions{"network": {"certificate": "9.0.0"}}

	_, err := MinVersions([]PeerRef{
		{Peer: "network", Resource: "pkix", Origin: "demo.lr"},
	}, versions, p.Compare)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "network.pkix")
	assert.Contains(t, err.Error(), "no entry")
}

func TestParseDeclaredRequires(t *testing.T) {
	src := []byte(`package config

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

var Config = plugin.Provider{
	Name:    "os",
	ID:      "go.mondoo.com/mql/providers/os",
	Version: "13.40.9",
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "9.0.1"},
		{
			ID:         "go.mondoo.com/mql/providers/core",
			Name:       "core",
			MinVersion: "9.1.5",
			MaxVersion: "14.0.0",
		},
	},
}
`)

	deps, err := ParseDeclaredRequires("config.go", src)
	require.NoError(t, err)
	require.Len(t, deps, 2)

	assert.Equal(t, DeclaredDep{
		ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "9.0.1",
	}, deps[0])
	assert.Equal(t, DeclaredDep{
		ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "9.1.5", MaxVersion: "14.0.0",
	}, deps[1])
}

func TestParseDeclaredRequiresAbsent(t *testing.T) {
	// every provider today: no Requires block at all
	src := []byte(`package config

var Config = plugin.Provider{Name: "demo", ID: "go.mondoo.com/mql/providers/demo"}
`)
	deps, err := ParseDeclaredRequires("config.go", src)
	require.NoError(t, err)
	assert.Empty(t, deps)
}

func TestReconcile(t *testing.T) {
	p := semver.Parser{}

	detected := map[string]string{
		"network": "9.0.1",
		"core":    "9.1.5",
		"os":      "13.2.0",
	}
	declared := []DeclaredDep{
		{Name: "core", MinVersion: "9.1.5"},  // exact
		{Name: "os", MinVersion: "12.0.0"},   // too low
		{Name: "extra", MinVersion: "1.0.0"}, // declared, never referenced
	}
	// `extra` is imported but unreferenced; `network` is referenced with no
	// declaration at all
	imported := []string{"core", "extra", "network", "os"}

	got, err := Reconcile(detected, declared, imported, p.Compare)
	require.NoError(t, err)

	byPeer := map[string]Reconciliation{}
	for _, r := range got {
		byPeer[r.Peer] = r
	}

	assert.Equal(t, DepAccept, byPeer["core"].Action)
	assert.Equal(t, DepRaise, byPeer["os"].Action)
	assert.Equal(t, "12.0.0", byPeer["os"].Declared)
	assert.Equal(t, "13.2.0", byPeer["os"].Detected)
	assert.Equal(t, DepCreate, byPeer["network"].Action)
	assert.Equal(t, DepUnused, byPeer["extra"].Action)
}

func TestReconcileAcceptsOverConstraint(t *testing.T) {
	// Declaring a higher floor than the scan detects is legitimate: the author
	// may know something the scan does not. It must not be "fixed" downward.
	p := semver.Parser{}
	got, err := Reconcile(
		map[string]string{"network": "9.0.1"},
		[]DeclaredDep{{Name: "network", MinVersion: "13.5.0"}},
		[]string{"network"},
		p.Compare,
	)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, DepAccept, got[0].Action)
	assert.Equal(t, "13.5.0", got[0].Declared)
}

func TestRaiseToBaseline(t *testing.T) {
	p := semver.Parser{}

	got, err := RaiseToBaseline(map[string]string{
		"network": "9.0.1",   // historical introduction version, below the window
		"core":    "13.0.0",  // exactly at it
		"os":      "13.40.9", // above it, must be preserved
	}, SupportedBaseline, p.Compare)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"network": "13.0.0",
		"core":    "13.0.0",
		"os":      "13.40.9",
	}, got)
}

func TestRaiseToBaselineKeepsDetectionHonest(t *testing.T) {
	// MinVersions reports what the references actually need; the baseline is a
	// separate policy step. Conflating them would make a genuinely-new field's
	// floor indistinguishable from a floor that was merely raised.
	p := semver.Parser{}
	versions := map[string]LrVersions{"network": {"certificate": "9.0.0"}}

	detected, err := MinVersions([]PeerRef{
		{Peer: "network", Resource: "certificate", Origin: "demo.lr"},
	}, versions, p.Compare)
	require.NoError(t, err)
	assert.Equal(t, "9.0.0", detected["network"], "detection must report the real requirement")

	raised, err := RaiseToBaseline(detected, SupportedBaseline, p.Compare)
	require.NoError(t, err)
	assert.Equal(t, SupportedBaseline, raised["network"])
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cryptopolicies

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	cases := map[string]Config{
		"DEFAULT\n":                                 {Policy: "DEFAULT"},
		"# comment\n  default:no-sha1 # x\n":        {Policy: "DEFAULT", Subpolicies: []string{"NO-SHA1"}},
		"DEFAULT:NO-SHA1:NO-WEAKMAC\n":              {Policy: "DEFAULT", Subpolicies: []string{"NO-SHA1", "NO-WEAKMAC"}},
		"LEGACY\nAD-SUPPORT\n":                      {Policy: "LEGACY", Subpolicies: []string{"AD-SUPPORT"}},
		"FUTURE:\n":                                 {Policy: "FUTURE"},
		"# nothing configured\n":                    {},
		"DEFAULT:NO-CBC\nNO-SHA1:NO-WEAKMAC\n\n#\n": {Policy: "DEFAULT", Subpolicies: []string{"NO-CBC", "NO-SHA1", "NO-WEAKMAC"}},
	}
	for in, want := range cases {
		got, err := ParseConfig(strings.NewReader(in))
		require.NoError(t, err)
		assert.Equal(t, want, got, in)
	}
	assert.Equal(t, "DEFAULT:NO-SHA1:NO-WEAKMAC", Config{Policy: "DEFAULT", Subpolicies: []string{"NO-SHA1", "NO-WEAKMAC"}}.String())
}

func TestParsePolicy(t *testing.T) {
	f, err := os.Open("testdata/ol10-DEFAULT.pol")
	require.NoError(t, err)
	defer f.Close()

	p, err := ParsePolicy(f)
	require.NoError(t, err)
	assert.Equal(t, "DEFAULT", p.Name)
	assert.Equal(t, []any{}, p.Baseline["protocol"], "an empty list")
	assert.Equal(t, int64(2048), p.Baseline["min_rsa_size"])
	assert.Equal(t, "ANY", p.Baseline["etm"])
	assert.Contains(t, p.Baseline["cipher"], "AES-256-CBC")

	ssh := p.Resolve("openssh-server")
	assert.NotContains(t, ssh["cipher"], "AES-256-CBC", "openssh-server takes openssh's cipher list")
	assert.Equal(t, p.Baseline["mac"], ssh["mac"], "and the baseline for the rest")

	pkcs := p.Resolve("nss-pkcs12-import")
	assert.Contains(t, pkcs["cipher"], "RC2-CBC")
	assert.Contains(t, pkcs["hash"], "SHA1")

	assert.Equal(t, p.Baseline["cipher"], p.Resolve("bind")["cipher"], "a scope without lines is the baseline")
	assert.Contains(t, p.Scopes(), "openssh-client")
}

func TestParsePolicyScopesRelativeToParent(t *testing.T) {
	p, err := ParsePolicy(strings.NewReader(`# Policy DEFAULT:NO-CBC dump
cipher = AES-256-GCM AES-256-CBC
etm = ANY
# Scope-specific properties derived for select backends:
cipher@openssh = AES-256-GCM
etm@openssh-server = DISABLE_ETM
cipher@futurescope = X
`))
	require.NoError(t, err)
	assert.Equal(t, "DEFAULT:NO-CBC", p.Name)
	server := p.Resolve("OpenSSH-Server")
	assert.Equal(t, []any{"AES-256-GCM"}, server["cipher"])
	assert.Equal(t, "DISABLE_ETM", server["etm"])
	assert.Equal(t, "ANY", p.Resolve("openssh-client")["etm"])
	assert.Equal(t, []any{"X"}, p.Resolve("futurescope")["cipher"])
	assert.Contains(t, p.Scopes(), "futurescope")
}

func TestResolveRelativeToBaseline(t *testing.T) {
	// Before 2025, every scope's lines are relative to the baseline, so a
	// scope without lines has the baseline values even when its parent
	// differs.
	p, err := ParsePolicy(strings.NewReader(`cipher = AES-256-GCM AES-256-CBC
cipher@openssh = AES-256-GCM
`))
	require.NoError(t, err)
	p.RelativeToParent = false
	assert.Equal(t, []any{"AES-256-GCM", "AES-256-CBC"}, p.Resolve("openssh-server")["cipher"])
	assert.Equal(t, []any{"AES-256-GCM"}, p.Resolve("openssh")["cipher"])
}

func TestDumpsRelativeToParent(t *testing.T) {
	assert.True(t, DumpsRelativeToParent(`DUMPABLE_SCOPES = {
    'openssh': (None, {'openssh', 'ssh'}),
    'openssh-server': ('openssh', {'openssh-server', 'openssh', 'ssh'}),
}`))
	assert.False(t, DumpsRelativeToParent(`DUMPABLE_SCOPES = {  # TODO: fix duplication, backends specify same things
    'openssh': {'openssh', 'ssh'},
    'openssh-server': {'openssh-server', 'openssh', 'ssh'},
}`))
}

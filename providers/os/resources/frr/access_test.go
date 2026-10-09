// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyChains(t *testing.T) {
	cfg := parseFixture(t, "frr-access.conf")
	chains := cfg.KeyChains()
	require.Len(t, chains, 2)

	fabric := chains[0]
	assert.Equal(t, "FABRIC", fabric.Name)
	require.Len(t, fabric.Keys, 2)

	// A key reports that it is set and how it is hashed. The value stays out
	// of the resource.
	first := fabric.Keys[0]
	assert.Equal(t, "1", first.ID)
	assert.True(t, first.KeyStringSet)
	assert.Equal(t, "hmac-sha-256", first.Algorithm)
	assert.Equal(t, "00:00:00 Jan 1 2026 23:59:59 Dec 31 2026", first.SendLifetime)
	assert.Equal(t, "00:00:00 Jan 1 2026 23:59:59 Dec 31 2026", first.AcceptLifetime)

	// A key without a lifetime never rotates, which is the finding.
	second := fabric.Keys[1]
	assert.Equal(t, "2", second.ID)
	assert.Equal(t, "", second.SendLifetime)

	// A key without an algorithm falls back to plain text.
	legacy := chains[1]
	assert.Equal(t, "LEGACY", legacy.Name)
	require.Len(t, legacy.Keys, 1)
	assert.True(t, legacy.Keys[0].KeyStringSet)
	assert.Equal(t, "", legacy.Keys[0].Algorithm)
}

func TestVtyLines(t *testing.T) {
	cfg := parseFixture(t, "frr-access.conf")
	lines := cfg.VtyLines()
	require.Len(t, lines, 1)

	l := lines[0]
	assert.Equal(t, "acl_mgmt", l.AccessClass)
	assert.Equal(t, "acl_mgmt6", l.AccessClassIPv6)
	assert.Equal(t, "10 0", l.ExecTimeout)
	// FRR prompts for a password unless the line says otherwise.
	assert.True(t, l.LoginEnabled)
	assert.False(t, l.PasswordSet)
}

// TestVtyLines_Unrestricted covers the shape a policy has to catch: a line
// with no access class, no timeout and no password prompt.
func TestVtyLines_Unrestricted(t *testing.T) {
	src := `hostname x
line vty
 exec-timeout 0 0
 no login
exit
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	lines := cfg.VtyLines()
	require.Len(t, lines, 1)
	assert.Equal(t, "", lines[0].AccessClass)
	assert.Equal(t, "0 0", lines[0].ExecTimeout)
	assert.False(t, lines[0].LoginEnabled)
}

func TestRPKIBlock(t *testing.T) {
	cfg := parseFixture(t, "frr-access.conf")
	r := cfg.RPKIBlock()

	assert.True(t, r.Configured)
	assert.Equal(t, int64(300), r.PollingPeriod)
	assert.Equal(t, int64(7200), r.ExpireInterval)
	assert.Equal(t, int64(600), r.RetryInterval)
	require.Len(t, r.Caches, 2)

	assert.Equal(t, "192.0.2.100", r.Caches[0].Address)
	assert.Equal(t, "3323", r.Caches[0].Port)
	assert.Equal(t, "tcp", r.Caches[0].Transport)
	assert.Equal(t, int64(1), r.Caches[0].Preference)

	assert.Equal(t, "ssh", r.Caches[1].Transport)
	assert.Equal(t, "192.0.2.101", r.Caches[1].Address)
	assert.Equal(t, "22", r.Caches[1].Port)
	assert.Equal(t, "rpki-user", r.Caches[1].SSHUser)
	assert.Equal(t, int64(2), r.Caches[1].Preference)

	// A router without the block validates nothing, and that is a readable
	// answer rather than a missing resource.
	plain := parseFixture(t, "frr-bgp.conf")
	none := plain.RPKIBlock()
	assert.False(t, none.Configured)
	assert.Empty(t, none.Caches)
	assert.Equal(t, int64(-1), none.PollingPeriod)
}

// TestParse_KeyChainNesting pins that a key block stays inside its chain.
func TestParse_KeyChainNesting(t *testing.T) {
	cfg := parseFixture(t, "frr-access.conf")
	chain := findBlock(cfg, "key chain", "FABRIC")
	require.NotNil(t, chain)
	require.Len(t, chain.Blocks, 2)
	assert.Equal(t, "key", chain.Blocks[0].Type)
	assert.Equal(t, "1", chain.Blocks[0].Name)

	// The blocks that follow are still top-level blocks.
	assert.NotNil(t, findBlock(cfg, "line vty", ""))
	assert.NotNil(t, findBlock(cfg, "rpki", ""))
	assert.NotNil(t, findBlock(cfg, "router bgp", "65100"))
}

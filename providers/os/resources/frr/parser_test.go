// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseFixture(t *testing.T, name string) *Config {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	cfg, err := Parse(name, strings.NewReader(string(data)))
	require.NoError(t, err)
	require.NotNil(t, cfg)
	return cfg
}

func findBlock(cfg *Config, blockType, name string) *Block {
	for i := range cfg.Blocks {
		if cfg.Blocks[i].Type == blockType && cfg.Blocks[i].Name == name {
			return &cfg.Blocks[i]
		}
	}
	return nil
}

func TestParse_TopLevelDirectives(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")

	assert.Equal(t, "leaf1", cfg.Hostname())
	assert.Equal(t, "10.3.1", cfg.Version())
	assert.Equal(t, "datacenter", cfg.Defaults())
	assert.True(t, cfg.IntegratedVtyshConfig())

	// The `!` comment on line 1 must not become a directive.
	for i := range cfg.Directives {
		assert.NotEqual(t, "Plain", cfg.Directives[i].Name)
	}
}

func TestParse_BlockNesting(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")

	bgp := findBlock(cfg, "router bgp", "65500")
	require.NotNil(t, bgp)
	assert.Equal(t, "frr-bgp.conf", bgp.File)

	// Two address families nest under the router, and their neighbor lines
	// stay inside them rather than on the router block.
	require.Len(t, bgp.Blocks, 2)
	assert.Equal(t, "address-family", bgp.Blocks[0].Type)
	assert.Equal(t, []string{"ipv4", "unicast"}, bgp.Blocks[0].Args)
	assert.Equal(t, []string{"ipv6", "unicast"}, bgp.Blocks[1].Args)

	for _, d := range bgp.Directives {
		assert.NotEqual(t, "network", d.Name, "address-family line leaked into the router block")
	}

	// The bfd profile is a nested block, not a sibling of bfd.
	bfd := findBlock(cfg, "bfd", "")
	require.NotNil(t, bfd)
	require.Len(t, bfd.Blocks, 1)
	assert.Equal(t, "profile", bfd.Blocks[0].Type)
	assert.Equal(t, "fabric", bfd.Blocks[0].Name)
}

func TestParse_NegatedDirectives(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")

	bgp := findBlock(cfg, "router bgp", "65500")
	require.NotNil(t, bgp)

	var found bool
	for _, d := range bgp.Directives {
		if d.Name == "bgp" && len(d.Args) > 0 && d.Args[0] == "ebgp-requires-policy" {
			assert.True(t, d.Negated)
			found = true
		}
	}
	assert.True(t, found, "no bgp ebgp-requires-policy was not parsed")
}

func TestParse_VNIBlockOnlyInsideAddressFamily(t *testing.T) {
	cfg := parseFixture(t, "frr-evpn-vrf.conf")

	// `vni 5000` inside a vrf block stays a directive.
	vrf := findBlock(cfg, "vrf", "cluster")
	require.NotNil(t, vrf)
	assert.Empty(t, vrf.Blocks)
	require.NotEmpty(t, vrf.Directives)
	assert.Equal(t, "vni", vrf.Directives[0].Name)

	// `vni 4001` inside address-family l2vpn evpn becomes a block.
	bgp := findBlock(cfg, "router bgp", "65100")
	require.NotNil(t, bgp)
	var evpn *Block
	for i := range bgp.Blocks {
		if bgp.Blocks[i].Args[0] == "l2vpn" {
			evpn = &bgp.Blocks[i]
		}
	}
	require.NotNil(t, evpn)
	require.Len(t, evpn.Blocks, 1)
	assert.Equal(t, "vni", evpn.Blocks[0].Type)
	assert.Equal(t, "4001", evpn.Blocks[0].Name)
}

func TestParse_RouterBlocksAreSeparatedByVRF(t *testing.T) {
	cfg := parseFixture(t, "frr-evpn-vrf.conf")

	var routers []string
	for i := range cfg.Blocks {
		if cfg.Blocks[i].Type == "router bgp" {
			routers = append(routers, argAfter(cfg.Blocks[i].Args, "vrf"))
		}
	}
	assert.Equal(t, []string{"", "cluster", "vr.mgmt", "t-blue", "t-green"}, routers)
}

func TestParse_MissingTerminators(t *testing.T) {
	// This shape comes from hand-written configs: no `exit` anywhere, the
	// next block header ends the previous block.
	src := `hostname leaf9
router bgp 65500
 bgp router-id 192.0.2.1
 address-family ipv4 unicast
  network 192.0.2.1/32
vrf tenant
 vni 100
interface lo
 ip address 192.0.2.1/32
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.Blocks, 3)

	assert.Equal(t, "router bgp", cfg.Blocks[0].Type)
	require.Len(t, cfg.Blocks[0].Blocks, 1)
	assert.Equal(t, "address-family", cfg.Blocks[0].Blocks[0].Type)
	assert.Equal(t, "vrf", cfg.Blocks[1].Type)
	assert.Equal(t, "tenant", cfg.Blocks[1].Name)
	assert.Equal(t, "interface", cfg.Blocks[2].Type)
}

func TestParse_EndClosesEveryBlock(t *testing.T) {
	src := `route-map rm_x permit 10
 match source-vrf cluster
end
hostname after-end
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, cfg.Blocks, 1)
	assert.Equal(t, "route-map", cfg.Blocks[0].Type)
	assert.Equal(t, "after-end", cfg.Hostname())
}

func TestParse_MismatchedTerminatorIsReported(t *testing.T) {
	src := `vrf tenant
 vni 100
exit-address-family
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.Error(t, err)
	require.Len(t, cfg.Errors, 1)
	assert.Contains(t, cfg.Errors[0].Msg, "does not match open block")
	// The vrf block is still returned so an audit keeps what it can read.
	require.Len(t, cfg.Blocks, 1)
	assert.Equal(t, "tenant", cfg.Blocks[0].Name)
}

func TestParse_RawKeepsSourceText(t *testing.T) {
	cfg := parseFixture(t, "frr-bgp.conf")
	vrfless := findBlock(cfg, "router bgp", "65500")
	require.NotNil(t, vrfless)
	assert.True(t, strings.HasPrefix(vrfless.Raw, "router bgp 65500"))
	assert.Contains(t, vrfless.Raw, "neighbor server peer-group")
	assert.Greater(t, vrfless.EndLine, vrfless.StartLine)
}

// TestParse_CommentMarkerInsideALine covers text that carries a comment
// marker. FRR starts a comment only at the beginning of a line, so a
// description keeps everything an operator wrote.
func TestParse_CommentMarkerInsideALine(t *testing.T) {
	src := `hostname leaf7
! a real comment
   ! an indented comment
interface swp1
 description Transit peer! Primary path #1
exit
`
	cfg, err := Parse("inline.conf", strings.NewReader(src))
	require.NoError(t, err)

	ifaces := cfg.Interfaces()
	require.Len(t, ifaces, 1)
	assert.Equal(t, "Transit peer! Primary path #1", ifaces[0].Description)

	// The comment lines are still dropped.
	for _, d := range cfg.Directives {
		assert.NotEqual(t, "a", d.Name)
		assert.NotEqual(t, "an", d.Name)
	}
}

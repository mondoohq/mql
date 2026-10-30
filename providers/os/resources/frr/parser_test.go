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
	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	defer f.Close()
	cfg, err := Parse(name, f)
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

func TestRedactSecrets(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"password zebra", "password <redacted>"},
		{"enable password zebra", "enable password <redacted>"},
		{"neighbor 10.0.0.1 password s3cret", "neighbor 10.0.0.1 password <redacted>"},
		// everything after the secret goes with it
		{"username alice password s3cret privilege 15", "username alice password <redacted>"},
		{"area-password md5 s3cret authenticate snp validate", "area-password md5 <redacted>"},
		// LINE arguments run to the end of the line and may hold spaces
		{"neighbor 10.0.0.1 password my s3cret phrase", "neighbor 10.0.0.1 password <redacted>"},
		{"key-string two words", "key-string <redacted>"},
		{"ip rip authentication string a b c", "ip rip authentication string <redacted>"},
		{"isis password md5 s3cret", "isis password md5 <redacted>"},
		{"area-password clear s3cret", "area-password clear <redacted>"},
		{"domain-password hmac-md5 s3cret", "domain-password hmac-md5 <redacted>"},
		{"ip ospf authentication-key s3cret", "ip ospf authentication-key <redacted>"},
		{"ip ospf message-digest-key 1 md5 s3cret", "ip ospf message-digest-key 1 md5 <redacted>"},
		{"key-string s3cret", "key-string <redacted>"},
		{"ip rip authentication string s3cret", "ip rip authentication string <redacted>"},
		{"ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key s3cret", "ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key <redacted>"},
		{"ip nhrp authentication s3cret", "ip nhrp authentication <redacted>"},
		// service password-encryption writes the encrypted form after an 8
		{"password 8 Cpu5Ryrx5Mtc", "password 8 <redacted>"},
		{"enable password 8 Cpu5Ryrx5Mtc", "enable password 8 <redacted>"},
		// a type token with nothing after it is the password itself
		{"password md5", "password <redacted>"},
		{"password 8", "password <redacted>"},
		// nothing to redact
		{"username alice nopassword", "username alice nopassword"},
		{"neighbor 10.0.0.1 password", "neighbor 10.0.0.1 password"},
		{"key chain ospf-keys", "key chain ospf-keys"},
		{"ip ospf authentication message-digest", "ip ospf authentication message-digest"},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got, redacted := redactSecrets(strings.Fields(tt.line))
			assert.Equal(t, tt.want, strings.Join(got, " "))
			assert.Equal(t, tt.want != tt.line, redacted)
		})
	}
}

// No password or key in the config is readable through the parsed config,
// neither in a block's raw text, a directive, nor a neighbor's params.
func TestParse_SecretsAreRedacted(t *testing.T) {
	conf := `password vty-s3cret
enable password enable-s3cret
username alice nopassword
interface eth0
 ! ip ospf authentication-key old-s3cret
 ip ospf authentication-key ospf-s3cret
 ip ospf message-digest-key 1 md5 md5-s3cret
exit
key chain k
 key 1
  key-string chain-s3cret
 exit
exit
router bgp 65000
 neighbor 10.0.0.1 remote-as 65001
 neighbor 10.0.0.1 password bgp phrase with s3cret words
exit
`
	cfg, err := Parse("frr.conf", strings.NewReader(conf))
	require.NoError(t, err)

	var dump strings.Builder
	var walk func(blocks []Block)
	walk = func(blocks []Block) {
		for i := range blocks {
			dump.WriteString(blocks[i].Raw + "\n" + strings.Join(blocks[i].Args, " ") + "\n")
			for _, d := range blocks[i].Directives {
				dump.WriteString(d.Raw + "\n" + strings.Join(d.Args, " ") + "\n")
			}
			walk(blocks[i].Blocks)
		}
	}
	walk(cfg.Blocks)
	for _, d := range cfg.Directives {
		dump.WriteString(d.Raw + "\n" + strings.Join(d.Args, " ") + "\n")
	}
	for _, b := range cfg.BGPInstances() {
		dump.WriteString(b.Raw + "\n")
		for _, n := range b.Neighbors {
			for k, v := range n.Params {
				dump.WriteString(k + " " + v + "\n")
			}
		}
	}
	assert.NotContains(t, dump.String(), "s3cret")
	assert.Contains(t, dump.String(), "password <redacted>")

	// what the model reads from these lines still works
	instances := cfg.BGPInstances()
	require.Len(t, instances, 1)
	require.Len(t, instances[0].Neighbors, 1)
	assert.True(t, instances[0].Neighbors[0].PasswordSet)
	users := cfg.VtyshUsers()
	require.Len(t, users, 1)
	assert.True(t, users[0].NoPassword)
}

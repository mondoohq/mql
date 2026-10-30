// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package squid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The stock squid.conf that ships on Debian and RHEL annotates almost every
// line with a trailing comment. Before trailing comments were stripped at the
// token layer, those comment words became ACL values and access-rule ACL
// names.
func TestParse_StockConfigTrailingComments(t *testing.T) {
	cfg := Parse(`acl Safe_ports port 80		# http
acl Safe_ports port 21		# ftp
acl localnet src 10.0.0.0/8	# RFC1918 possible internal network
http_access allow localnet	# allow internal users
http_access deny all		# and nothing else
`)

	require.Len(t, cfg.ACLs, 2)

	safePorts := findACL(t, cfg, "Safe_ports")
	assert.Equal(t, "port", safePorts.Type)
	assert.Equal(t, []string{"80", "21"}, safePorts.Values)

	localnet := findACL(t, cfg, "localnet")
	assert.Equal(t, "src", localnet.Type)
	assert.Equal(t, []string{"10.0.0.0/8"}, localnet.Values)

	require.Len(t, cfg.AccessRules, 2)
	assert.Equal(t, "allow", cfg.AccessRules[0].Action)
	assert.Equal(t, []string{"localnet"}, cfg.AccessRules[0].ACLs)
	assert.Equal(t, "deny", cfg.AccessRules[1].Action)
	assert.Equal(t, []string{"all"}, cfg.AccessRules[1].ACLs)
}

// A commented-out option must not be read as an active one. `ssl-bump` in a
// trailing comment previously set TLS=true on a plaintext port — a comment
// turning a security flag on.
func TestParse_CommentedOptionDoesNotSetFlag(t *testing.T) {
	cfg := Parse(`http_port 3128   # TODO enable ssl-bump
http_port 3129 ssl-bump
`)

	require.Len(t, cfg.HTTPPorts, 2)
	assert.EqualValues(t, 3128, cfg.HTTPPorts[0].Port)
	assert.False(t, cfg.HTTPPorts[0].TLS, "a commented-out ssl-bump must not enable TLS")

	assert.EqualValues(t, 3129, cfg.HTTPPorts[1].Port)
	assert.True(t, cfg.HTTPPorts[1].TLS, "a real ssl-bump option must still enable TLS")
}

// Squid only treats `#` as a comment marker at a token boundary, so a `#`
// inside a value is data. A password or URL fragment must survive intact.
func TestTokenize_HashInsideTokenIsData(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "hash inside a value",
			line: `cache_peer parent.example.com parent 3128 0 login=user:p@ss#word`,
			want: []string{"cache_peer", "parent.example.com", "parent", "3128", "0", "login=user:p@ss#word"},
		},
		{
			name: "trailing comment after whitespace",
			line: `acl x port 80 # http`,
			want: []string{"acl", "x", "port", "80"},
		},
		{
			name: "tab before the comment",
			line: "acl x port 80\t# http",
			want: []string{"acl", "x", "port", "80"},
		},
		{
			name: "quoted hash is not a comment",
			line: `acl x note key "#literal"`,
			want: []string{"acl", "x", "note", "key", "#literal"},
		},
		{
			name: "comment immediately after the directive",
			line: `acl #everything after this is gone`,
			want: []string{"acl"},
		},
		{
			name: "no comment at all",
			line: `http_port 3128 ssl-bump`,
			want: []string{"http_port", "3128", "ssl-bump"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tokenize(tc.line))
		})
	}
}

// Squid strips trailing comments after joining continuations, so a comment on
// the tail of a continued directive must not swallow the tail's tokens.
func TestParse_TrailingCommentOnContinuedLine(t *testing.T) {
	cfg := Parse(`acl Safe_ports port \
	80 443   # http and https
`)

	require.Len(t, cfg.ACLs, 1)
	assert.Equal(t, []string{"80", "443"}, cfg.ACLs[0].Values)
}

// A line that is entirely a comment, and one that becomes empty once its
// trailing comment is stripped, must both yield no directive.
func TestParse_CommentOnlyLines(t *testing.T) {
	cfg := Parse(`# this whole line is a comment
   # so is this one, after indentation
http_port 3128
`)

	require.Len(t, cfg.HTTPPorts, 1)
	assert.EqualValues(t, 3128, cfg.HTTPPorts[0].Port)
}

func findACL(t *testing.T, cfg *Config, name string) ACL {
	t.Helper()
	for _, a := range cfg.ACLs {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("acl %q not found in %+v", name, cfg.ACLs)
	return ACL{}
}

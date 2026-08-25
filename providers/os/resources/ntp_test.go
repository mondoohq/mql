// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func anyLines(lines ...string) []any {
	out := make([]any, 0, len(lines))
	for _, l := range lines {
		out = append(out, l)
	}
	return out
}

// ntp.conf separates a keyword from its arguments with any run of whitespace.
// The old fixed-prefix match dropped tab-separated lines and kept the extra
// space from double-spaced ones.
func TestNtpConfDirectiveWhitespace(t *testing.T) {
	settings := anyLines(
		"server single.example.net iburst",
		"server  doublespace.example.net iburst",
		"server\ttabbed.example.net iburst",
		"server\t  mixed.example.net",
		"SERVER upper.example.net",
		"restrict default nomodify notrap",
		"restrict\t-6 ::1",
		"fudge  127.127.1.0 stratum 10",
		"serverfoo notadirective.example.net",
		"# server commented.example.net",
	)

	n := &mqlNtpConf{}

	servers, err := n.servers(settings)
	assert.NoError(t, err)
	assert.Equal(t, []any{
		"single.example.net iburst",
		"doublespace.example.net iburst",
		"tabbed.example.net iburst",
		"mixed.example.net",
		"upper.example.net",
	}, servers, "every server line is returned with its arguments cleanly separated")

	restrict, err := n.restrict(settings)
	assert.NoError(t, err)
	assert.Equal(t, []any{
		"default nomodify notrap",
		"-6 ::1",
	}, restrict)

	fudge, err := n.fudge(settings)
	assert.NoError(t, err)
	assert.Equal(t, []any{"127.127.1.0 stratum 10"}, fudge)
}

// A keyword that merely starts with the directive name is not that directive.
func TestNtpConfDoesNotMatchLongerKeywords(t *testing.T) {
	n := &mqlNtpConf{}
	servers, err := n.servers(anyLines("serverfoo host.example.net", "servers host2.example.net"))
	assert.NoError(t, err)
	assert.Empty(t, servers)
}

func TestNtpConfEmptyAndBareDirectives(t *testing.T) {
	n := &mqlNtpConf{}
	servers, err := n.servers(anyLines("server", "server   ", ""))
	assert.NoError(t, err)

	// A "server" line carrying no argument yields an empty value rather than
	// being skipped. chrony.conf shares the helper and behaves the same way, so
	// this pins the current behaviour rather than changing it; such a line is
	// malformed ntp.conf in the first place.
	assert.Equal(t, []any{"", ""}, servers)
}

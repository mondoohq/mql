// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseExposePort(t *testing.T) {
	cases := []struct {
		spec  string
		ports []dockerfilePort
	}{
		{"80", []dockerfilePort{{80, "tcp"}}},
		{"53/UDP", []dockerfilePort{{53, "udp"}}},
		{"8080:80/tcp", []dockerfilePort{{80, "tcp"}}},
		{"127.0.0.1:8080:80", []dockerfilePort{{80, "tcp"}}},
		{"[::1]:8080:81/sctp", []dockerfilePort{{81, "sctp"}}},
		{"7-9", []dockerfilePort{{7, "tcp"}, {8, "tcp"}, {9, "tcp"}}},
		{"5-5", []dockerfilePort{{5, "tcp"}}},
	}
	for _, kase := range cases {
		t.Run(kase.spec, func(t *testing.T) {
			ports, err := parseExposePort(kase.spec)
			require.NoError(t, err)
			require.Equal(t, kase.ports, ports)
		})
	}
	for _, bad := range []string{"", "/tcp", "http", "70000", "9-7", "80/icmp", "80-x"} {
		t.Run("invalid "+bad, func(t *testing.T) {
			_, err := parseExposePort(bad)
			require.Error(t, err)
		})
	}
}

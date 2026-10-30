// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/tailscale/connection"
)

func TestHandleTargets(t *testing.T) {
	everything := []string{connection.DiscoveryDevices, connection.DiscoveryUsers}

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "all expands", in: []string{connection.DiscoveryAll}, want: everything},
		{name: "auto expands", in: []string{connection.DiscoveryAuto}, want: everything},
		{
			name: "all wins over a narrower sibling",
			in:   []string{connection.DiscoveryDevices, connection.DiscoveryAll},
			want: everything,
		},
		{
			name: "explicit targets pass through",
			in:   []string{connection.DiscoveryUsers},
			want: []string{connection.DiscoveryUsers},
		},
		{name: "empty stays empty", in: []string{}, want: []string{}},
		{name: "nil stays nil", in: nil, want: nil},
		{
			name: "unknown targets pass through and are ignored downstream",
			in:   []string{"nope"},
			want: []string{"nope"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, handleTargets(tc.in))
		})
	}
}

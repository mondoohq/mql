// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"sort"
	"testing"

	"go.mondoo.com/mql/providers/nutanix/connection"
)

func TestHandleTargets(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "all expands to clusters+nodes",
			in:   []string{connection.DiscoveryAll},
			want: []string{connection.DiscoveryClusters, connection.DiscoveryNodes},
		},
		{
			name: "auto expands to clusters+nodes",
			in:   []string{connection.DiscoveryAuto},
			want: []string{connection.DiscoveryClusters, connection.DiscoveryNodes},
		},
		{
			name: "explicit clusters passthrough",
			in:   []string{connection.DiscoveryClusters},
			want: []string{connection.DiscoveryClusters},
		},
		{
			name: "explicit nodes passthrough",
			in:   []string{connection.DiscoveryNodes},
			want: []string{connection.DiscoveryNodes},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := handleTargets(tc.in)
			sort.Strings(got)
			want := append([]string{}, tc.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("handleTargets(%v) = %v, want %v", tc.in, got, want)
			}
		})
	}
}

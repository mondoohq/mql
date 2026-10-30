// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDropletID(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantID int64
		wantOK bool
	}{
		{"bare numeric id", "12345", 12345, true},
		{"droplet urn", "do:droplet:678", 678, true},
		{"whitespace trimmed", "  99 ", 99, true},
		{"non-droplet urn", "do:loadbalancer:abc-123", 0, false},
		{"dbaas urn", "do:dbaas:uuid", 0, false},
		{"empty", "", 0, false},
		{"non-numeric", "abc", 0, false},
		{"droplet urn missing id", "do:droplet:", 0, false},
		{"malformed urn extra segment", "do:droplet:12:34", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := parseDropletID(tt.input)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

func TestDoURNId(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"load balancer urn", "do:loadbalancer:abc-123", "abc-123"},
		{"dbaas urn", "do:dbaas:cluster-uuid", "cluster-uuid"},
		{"kubernetes urn", "do:kubernetes:k8s-uuid", "k8s-uuid"},
		{"bare id passes through", "plain-id", "plain-id"},
		{"whitespace trimmed", "  x ", "x"},
		{"empty", "", ""},
		{"prefix only yields empty tail", "do:", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, doURNId(tt.input))
		})
	}
}

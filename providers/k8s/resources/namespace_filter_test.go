// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSkipNamespace pins the include/exclude precedence and glob behavior of
// the namespace filter, which governs exactly which namespaces become assets.
// It is a small, inverted-condition-prone function with no prior coverage.
func TestSkipNamespace(t *testing.T) {
	tests := []struct {
		name      string
		include   []string
		exclude   []string
		namespace string
		wantSkip  bool
	}{
		{name: "no filters accepts everything", namespace: "prod", wantSkip: false},
		{name: "include exact match is kept", include: []string{"prod"}, namespace: "prod", wantSkip: false},
		{name: "include non-match is skipped", include: []string{"prod"}, namespace: "dev", wantSkip: true},
		{name: "include glob match is kept", include: []string{"kube-*"}, namespace: "kube-system", wantSkip: false},
		{name: "include glob non-match is skipped", include: []string{"kube-*"}, namespace: "prod", wantSkip: true},
		{name: "exclude exact match is skipped", exclude: []string{"kube-system"}, namespace: "kube-system", wantSkip: true},
		{name: "exclude non-match is kept", exclude: []string{"kube-system"}, namespace: "prod", wantSkip: false},
		{name: "exclude glob match is skipped", exclude: []string{"kube-*"}, namespace: "kube-public", wantSkip: true},
		// include takes precedence: a namespace matched by include is kept even
		// if it would also match exclude.
		{name: "include wins over exclude (kept)", include: []string{"prod"}, exclude: []string{"prod"}, namespace: "prod", wantSkip: false},
		// with include set, a namespace not in include is skipped regardless of exclude.
		{name: "include set skips non-included even when not excluded", include: []string{"prod"}, exclude: []string{"dev"}, namespace: "staging", wantSkip: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &FilterOpts{include: tt.include, exclude: tt.exclude}
			assert.Equal(t, tt.wantSkip, f.skip(tt.namespace))
		})
	}
}

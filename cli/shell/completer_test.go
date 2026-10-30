// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shell

import (
	"testing"

	"go.mondoo.com/mql/llx"
)

func TestByProviderSortFn(t *testing.T) {
	connectedProviders := []string{"go.mondoo.com/mql/v9/providers/aws"}
	sortFn := byProviderSortFn(connectedProviders)

	tests := []struct {
		docA     *llx.Documentation
		docB     *llx.Documentation
		expected int
	}{
		{
			docA:     &llx.Documentation{Provider: "go.mondoo.com/mql/v9/providers/aws", Field: "a"},
			docB:     &llx.Documentation{Provider: "gcp", Field: "b"},
			expected: -1,
		},
		{
			docA:     &llx.Documentation{Provider: "go.mondoo.com/mql/v9/providers/azure", Field: "a"},
			docB:     &llx.Documentation{Provider: "go.mondoo.com/mql/v9/providers/aws", Field: "a"},
			expected: 1,
		},
		{
			docA:     &llx.Documentation{Provider: "go.mondoo.com/mql/v9/providers/gcp", Field: "b"},
			docB:     &llx.Documentation{Provider: "go.mondoo.com/mql/v9/providers/gcp", Field: "a"},
			expected: 0,
		},
	}

	for _, test := range tests {
		result := sortFn(test.docA, test.docB)
		if result != test.expected {
			t.Errorf("Expected %d, got %d for docs %+v and %+v", test.expected, result, test.docA, test.docB)
		}
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveSubnetRefs must never return nil: a nil slice from a list accessor
// renders as an empty array anyway, but an explicitly empty one keeps the
// "no subnets" and "nothing resolved" cases reading the same way to callers.
//
// These cases reach no NewResource call, so they exercise the skip logic without
// a runtime. Resolution itself is covered by live verification, since it is one
// NewResource call per id.
func TestResolveSubnetRefsWithNothingToResolve(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
	}{
		{name: "nil ids", ids: nil},
		{name: "no ids", ids: []string{}},
		{name: "only empty ids", ids: []string{"", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveSubnetRefs(nil, "us-east-2", "111122223333", tc.ids)

			require.NotNil(t, got, "must return an empty slice rather than nil")
			assert.Empty(t, got)
		})
	}
}

// An empty subnet id would build the ARN "arn:aws:ec2:<region>:<acct>:subnet/",
// which resolves to nothing and would log a warning for every such entry. Skip
// them before that.
func TestResolveSubnetRefsSkipsEmptyIdsWithoutResolving(t *testing.T) {
	// A nil runtime proves no resolution was attempted: any NewResource call
	// would dereference it.
	assert.NotPanics(t, func() {
		resolveSubnetRefs(nil, "us-east-2", "111122223333", []string{"", "", ""})
	}, "empty ids must be skipped before any resolution is attempted")
}

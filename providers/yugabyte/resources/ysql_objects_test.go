// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestRelationKind(t *testing.T) {
	for relkind, want := range map[string]string{"r": "table", "p": "partitioned table", "v": "view", "m": "materialized view", "S": "sequence", "x": "x"} {
		if got := relationKind(relkind); got != want {
			t.Errorf("relationKind(%q) = %q, want %q", relkind, got, want)
		}
	}
}

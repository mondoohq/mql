// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestNormalizeConstraintName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "prefixed form as documented for constraints",
			in:   "constraints/compute.requireOsLogin",
			want: "compute.requireOsLogin",
		},
		{
			name: "bare form as it appears in a policy path",
			in:   "compute.requireOsLogin",
			want: "compute.requireOsLogin",
		},
		{
			name: "custom constraint keeps its custom prefix",
			in:   "constraints/custom.myOrgConstraint",
			want: "custom.myOrgConstraint",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			// Only a leading prefix is stripped, so a constraint whose name
			// happens to contain the word is left intact.
			name: "prefix only stripped from the front",
			in:   "iam.constraints/foo",
			want: "iam.constraints/foo",
		},
	}
	for _, tt := range tests {
		if got := normalizeConstraintName(tt.in); got != tt.want {
			t.Errorf("%s: normalizeConstraintName(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
}

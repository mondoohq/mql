// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestIsPublicMember(t *testing.T) {
	cases := map[string]bool{
		"allUsers":               true,
		"allAuthenticatedUsers":  true,
		"user:alice@example.com": false,
		"serviceAccount:sa@p.iam.gserviceaccount.com": false,
		"":         false,
		"AllUsers": false, // case-sensitive
	}
	for in, want := range cases {
		if got := isPublicMember(in); got != want {
			t.Errorf("isPublicMember(%q) = %v, want %v", in, got, want)
		}
	}
}

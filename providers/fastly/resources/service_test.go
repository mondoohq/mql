// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// TestChildID composes the stable id of a per-version service child. Synthetic:
// the id keys the resource cache, so a separator or field-order change would
// collide or duplicate entries, and this pins the format.
func TestChildID(t *testing.T) {
	got := childID("SU1Z0isxPaozGVKXdv0eY", 7, "www.example.com")
	want := "SU1Z0isxPaozGVKXdv0eY/7/www.example.com"
	if got != want {
		t.Errorf("childID = %q, want %q", got, want)
	}

	// Different versions of the same service must not share an id.
	if childID("svc", 1, "n") == childID("svc", 2, "n") {
		t.Error("ids for different versions collided")
	}
}

// TestPtrStr maps a nil pointer to the empty string for id composition.
// Synthetic: covers the absent-name case.
func TestPtrStr(t *testing.T) {
	if got := ptrStr(nil); got != "" {
		t.Errorf("ptrStr(nil) = %q, want empty", got)
	}
	s := "value"
	if got := ptrStr(&s); got != "value" {
		t.Errorf("ptrStr(&s) = %q, want %q", got, s)
	}
}

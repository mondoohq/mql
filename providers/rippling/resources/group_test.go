// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/rippling/connection"
)

// resourceMap is the minimal plugin.Resources implementation the generated
// CreateResource needs: it is what makes the runtime hand back an existing
// instance for a repeated __id.
type resourceMap map[string]plugin.Resource

func (m resourceMap) Get(key string) (plugin.Resource, bool) {
	v, ok := m[key]
	return v, ok
}

func (m resourceMap) Set(key string, value plugin.Resource) { m[key] = value }

// TestNewMqlRipplingGroupIsIdempotent pins the membership list against the
// resource cache. CreateResource returns the already-built instance when the
// same group is constructed twice in one scan (rippling.groups followed by a
// rippling.group(id:) lookup, say), so building the member list by appending
// onto whatever the instance already held reported every member twice.
func TestNewMqlRipplingGroupIsIdempotent(t *testing.T) {
	runtime := &plugin.Runtime{Resources: resourceMap{}}
	g := &connection.Group{ID: "g-1", Name: "Admins", Version: "7", Users: []string{"emp-1", "emp-2"}}

	first, err := newMqlRipplingGroup(runtime, g)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	second, err := newMqlRipplingGroup(runtime, g)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}

	if first != second {
		t.Fatal("expected the cached instance back on the second build")
	}
	if len(second.memberIDs) != 2 {
		t.Fatalf("memberIDs = %v, want the 2 members reported once each", second.memberIDs)
	}
}

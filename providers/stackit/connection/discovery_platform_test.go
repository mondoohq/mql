// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestAssetObjectID(t *testing.T) {
	conn := &StackitConnection{
		asset: &inventory.Asset{
			PlatformIds: []string{MondooObjectID("proj-1", "postgres-flex", "eu01", "db-9")},
		},
	}

	// Matching service returns the trailing object id.
	if id, ok := conn.AssetObjectID("postgres-flex"); !ok || id != "db-9" {
		t.Fatalf("postgres-flex: got (%q,%v), want (db-9,true)", id, ok)
	}
	// A different service must not match (no cross-type leakage).
	if id, ok := conn.AssetObjectID("mongodb-flex"); ok {
		t.Fatalf("mongodb-flex should not match, got %q", id)
	}

	// The project root must never be treated as an object.
	proj := &StackitConnection{
		asset: &inventory.Asset{PlatformIds: []string{PlatformIdStackitProject + "proj-1"}},
	}
	if id, ok := proj.AssetObjectID("postgres-flex"); ok {
		t.Fatalf("project root should not match, got %q", id)
	}

	// No asset -> no id.
	if _, ok := (&StackitConnection{}).AssetObjectID("postgres-flex"); ok {
		t.Fatal("nil asset should not match")
	}
}

func TestMondooObjectID(t *testing.T) {
	got := MondooObjectID("proj-1", "postgres-flex", "eu01", "db-9")
	want := "//platformid.api.mondoo.app/runtime/stackit/postgres-flex/proj-1/eu01/db-9"
	if got != want {
		t.Fatalf("regional object id: got %q, want %q", got, want)
	}

	// A project-global service (no region) falls back to "global".
	got = MondooObjectID("proj-1", "secrets-manager", "", "sm-2")
	want = "//platformid.api.mondoo.app/runtime/stackit/secrets-manager/proj-1/global/sm-2"
	if got != want {
		t.Fatalf("global object id: got %q, want %q", got, want)
	}
}

func TestGetPlatformForObject(t *testing.T) {
	p := GetPlatformForObject("stackit-postgres-flex-instance", "proj-1", "postgres-flex")

	if p.Name != "stackit-postgres-flex-instance" {
		t.Fatalf("name: got %q", p.Name)
	}
	if p.Title != "STACKIT PostgreSQL Flex Instance" {
		t.Fatalf("title: got %q", p.Title)
	}
	if p.Kind != "stackit-object" {
		t.Fatalf("kind: got %q, want stackit-object", p.Kind)
	}
	if p.Runtime != "stackit" {
		t.Fatalf("runtime: got %q, want stackit", p.Runtime)
	}
	if len(p.Family) != 1 || p.Family[0] != "stackit" {
		t.Fatalf("family: got %v, want [stackit]", p.Family)
	}
	// Must match the provider's AssetUrlTrees (technology=stackit -> project -> service).
	want := []string{"stackit", "proj-1", "postgres-flex"}
	if len(p.TechnologyUrlSegments) != len(want) {
		t.Fatalf("segments: got %v, want %v", p.TechnologyUrlSegments, want)
	}
	for i := range want {
		if p.TechnologyUrlSegments[i] != want[i] {
			t.Fatalf("segments: got %v, want %v", p.TechnologyUrlSegments, want)
		}
	}
}

// All discoverable sub-asset platforms must share the "stackit" family and the
// "stackit-object" kind so they group with the project root the way aws/azure do.
func TestSubAssetPlatformsAreConsistent(t *testing.T) {
	for _, name := range []string{
		"stackit-server",
		"stackit-ske-cluster",
		"stackit-object-storage-bucket",
		"stackit-postgres-flex-instance",
		"stackit-mongodb-flex-instance",
		"stackit-sqlserver-flex-instance",
		"stackit-secrets-manager-instance",
	} {
		pi := PlatformByName(name)
		if pi == nil {
			t.Fatalf("platform %q missing from catalog", name)
		}
		if len(pi.Family) != 1 || pi.Family[0] != "stackit" {
			t.Errorf("platform %q family = %v, want [stackit]", name, pi.Family)
		}
		if len(pi.Kind) != 1 || pi.Kind[0] != "stackit-object" {
			t.Errorf("platform %q kind = %v, want [stackit-object]", name, pi.Kind)
		}
	}
}

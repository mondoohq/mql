// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// graphLookup builds a roleLookup over a static role graph and counts how many
// batches it served, so the tests can assert on both the result and the walk.
func graphLookup(graph map[roleRef][]roleRef, batches *int) roleLookup {
	return func(refs []roleRef) (map[roleRef][]roleRef, error) {
		if batches != nil {
			*batches++
		}
		out := make(map[roleRef][]roleRef, len(refs))
		for _, ref := range refs {
			out[ref] = graph[ref]
		}
		return out, nil
	}
}

func roleNames(refs []roleRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.db+"."+ref.role)
	}
	return out
}

func sameSet(got []roleRef, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]struct{}{}
	for _, n := range roleNames(got) {
		seen[n] = struct{}{}
	}
	for _, n := range want {
		if _, ok := seen[n]; !ok {
			return false
		}
	}
	return true
}

func TestResolveEffectiveRoles(t *testing.T) {
	appReadMetrics := roleRef{role: "appReadMetrics", db: "admin"}
	userAdminAny := roleRef{role: "userAdminAnyDatabase", db: "admin"}
	readApp := roleRef{role: "read", db: "appdb"}
	mid := roleRef{role: "midTier", db: "admin"}

	tests := []struct {
		name  string
		graph map[roleRef][]roleRef
		grant []roleRef
		want  []string
		priv  bool
	}{
		{
			name:  "direct grant only",
			graph: map[roleRef][]roleRef{},
			grant: []roleRef{readApp},
			want:  []string{"appdb.read"},
			priv:  false,
		},
		{
			name:  "custom role inheriting a superuser role",
			graph: map[roleRef][]roleRef{appReadMetrics: {userAdminAny}},
			grant: []roleRef{appReadMetrics},
			want:  []string{"admin.appReadMetrics", "admin.userAdminAnyDatabase"},
			priv:  true,
		},
		{
			name: "privilege reached two levels down",
			graph: map[roleRef][]roleRef{
				appReadMetrics: {mid},
				mid:            {userAdminAny},
			},
			grant: []roleRef{appReadMetrics},
			want:  []string{"admin.appReadMetrics", "admin.midTier", "admin.userAdminAnyDatabase"},
			priv:  true,
		},
		{
			name:  "unprivileged custom role stays unprivileged",
			graph: map[roleRef][]roleRef{appReadMetrics: {readApp}},
			grant: []roleRef{appReadMetrics},
			want:  []string{"admin.appReadMetrics", "appdb.read"},
			priv:  false,
		},
		{
			name:  "no grants at all",
			graph: map[roleRef][]roleRef{},
			grant: nil,
			want:  []string{},
			priv:  false,
		},
		{
			name:  "duplicate direct grants are collapsed",
			graph: map[roleRef][]roleRef{},
			grant: []roleRef{readApp, readApp},
			want:  []string{"appdb.read"},
			priv:  false,
		},
		{
			name: "same role name in a different database is distinct",
			graph: map[roleRef][]roleRef{
				{role: "reporter", db: "a"}: {userAdminAny},
			},
			grant: []roleRef{{role: "reporter", db: "a"}, {role: "reporter", db: "b"}},
			want:  []string{"a.reporter", "b.reporter", "admin.userAdminAnyDatabase"},
			priv:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveEffectiveRoles(tt.grant, graphLookup(tt.graph, nil))
			if err != nil {
				t.Fatalf("resolveEffectiveRoles: %v", err)
			}
			if !sameSet(got, tt.want) {
				t.Errorf("effective roles = %v, want %v", roleNames(got), tt.want)
			}
			if priv := hasPrivilegedRole(got); priv != tt.priv {
				t.Errorf("isPrivileged = %v, want %v", priv, tt.priv)
			}
		})
	}
}

// The graph can be cyclic: MongoDB lets role A inherit B while B inherits A.
// An unguarded walk would never terminate, so this must finish and report each
// role once.
func TestResolveEffectiveRolesCycles(t *testing.T) {
	a := roleRef{role: "a", db: "admin"}
	b := roleRef{role: "b", db: "admin"}
	c := roleRef{role: "c", db: "admin"}
	root := roleRef{role: "root", db: "admin"}

	t.Run("two role cycle", func(t *testing.T) {
		graph := map[roleRef][]roleRef{a: {b}, b: {a}}
		batches := 0
		got, err := resolveEffectiveRoles([]roleRef{a}, graphLookup(graph, &batches))
		if err != nil {
			t.Fatalf("resolveEffectiveRoles: %v", err)
		}
		if !sameSet(got, []string{"admin.a", "admin.b"}) {
			t.Errorf("effective roles = %v", roleNames(got))
		}
		if hasPrivilegedRole(got) {
			t.Error("a cycle of unprivileged roles must not read as privileged")
		}
		if batches != 2 {
			t.Errorf("expected the walk to stop after 2 levels, took %d", batches)
		}
	})

	t.Run("longer cycle that reaches a superuser role", func(t *testing.T) {
		graph := map[roleRef][]roleRef{a: {b}, b: {c}, c: {a, root}}
		got, err := resolveEffectiveRoles([]roleRef{a}, graphLookup(graph, nil))
		if err != nil {
			t.Fatalf("resolveEffectiveRoles: %v", err)
		}
		if !sameSet(got, []string{"admin.a", "admin.b", "admin.c", "admin.root"}) {
			t.Errorf("effective roles = %v", roleNames(got))
		}
		if !hasPrivilegedRole(got) {
			t.Error("root reached through a cycle must read as privileged")
		}
	})

	t.Run("self referencing role", func(t *testing.T) {
		graph := map[roleRef][]roleRef{a: {a}}
		got, err := resolveEffectiveRoles([]roleRef{a}, graphLookup(graph, nil))
		if err != nil {
			t.Fatalf("resolveEffectiveRoles: %v", err)
		}
		if !sameSet(got, []string{"admin.a"}) {
			t.Errorf("effective roles = %v", roleNames(got))
		}
	})
}

// A lookup failure must surface instead of silently downgrading the user to
// unprivileged, which is the false negative this whole path exists to avoid.
func TestResolveEffectiveRolesLookupError(t *testing.T) {
	boom := errors.New("rolesInfo failed")
	_, err := resolveEffectiveRoles([]roleRef{{role: "x", db: "admin"}}, func([]roleRef) (map[roleRef][]roleRef, error) {
		return nil, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("expected the lookup error to propagate, got %v", err)
	}
}

func TestInheritedRoleRefs(t *testing.T) {
	// showPrivileges reports inheritedRoles, which already spans indirect grants.
	doc := bson.M{
		"role":           "appReadMetrics",
		"db":             "admin",
		"roles":          bson.A{bson.D{{Key: "role", Value: "midTier"}, {Key: "db", Value: "admin"}}},
		"inheritedRoles": bson.A{bson.D{{Key: "role", Value: "midTier"}, {Key: "db", Value: "admin"}}, bson.D{{Key: "role", Value: "root"}, {Key: "db", Value: "admin"}}},
	}
	if got := inheritedRoleRefs(doc); !sameSet(got, []string{"admin.midTier", "admin.root"}) {
		t.Errorf("inheritedRoleRefs = %v, want the transitive list", roleNames(got))
	}

	// Without inheritedRoles the direct roles array is used instead.
	direct := bson.M{"roles": bson.A{bson.M{"role": "read", "db": "appdb"}}}
	if got := inheritedRoleRefs(direct); !sameSet(got, []string{"appdb.read"}) {
		t.Errorf("inheritedRoleRefs fallback = %v", roleNames(got))
	}

	// A role that inherits nothing yields nothing, and a malformed document
	// must not panic.
	if got := inheritedRoleRefs(bson.M{"role": "read", "db": "appdb"}); len(got) != 0 {
		t.Errorf("expected no inherited roles, got %v", roleNames(got))
	}
	if got := inheritedRoleRefs(bson.M{"inheritedRoles": "not-an-array"}); len(got) != 0 {
		t.Errorf("expected no inherited roles, got %v", roleNames(got))
	}
}

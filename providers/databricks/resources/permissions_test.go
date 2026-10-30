// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"reflect"
	"testing"

	"github.com/databricks/databricks-sdk-go/service/iam"
)

func TestFlattenObjectPermissions(t *testing.T) {
	t.Run("nil response yields no records", func(t *testing.T) {
		got := flattenObjectPermissions(permissionObjectCluster, "c-1", nil)
		if len(got) != 0 {
			t.Fatalf("flattenObjectPermissions() = %v, want empty", got)
		}
	})

	t.Run("splits a principal's levels into one record each", func(t *testing.T) {
		// The API groups a principal's levels under that principal, but each
		// level has its own inheritance. Grouping them the way databricks.grant
		// groups privileges would lose which right is direct and which is
		// inherited, which is the whole point of the ACL.
		got := flattenObjectPermissions(permissionObjectJob, "620813104278135", &iam.ObjectPermissions{
			AccessControlList: []iam.AccessControlResponse{{
				GroupName:   "data-eng",
				DisplayName: "Data Engineering",
				AllPermissions: []iam.Permission{
					{PermissionLevel: iam.PermissionLevelCanManage, Inherited: false},
					{PermissionLevel: iam.PermissionLevelCanView, Inherited: true, InheritedFromObject: []string{"/directories/123"}},
				},
			}},
		})

		if len(got) != 2 {
			t.Fatalf("got %d records, want 2", len(got))
		}
		if got[0].permissionLevel != "CAN_MANAGE" || got[0].inherited {
			t.Fatalf("first record = %+v, want a direct CAN_MANAGE", got[0])
		}
		if got[1].permissionLevel != "CAN_VIEW" || !got[1].inherited {
			t.Fatalf("second record = %+v, want an inherited CAN_VIEW", got[1])
		}
		if !reflect.DeepEqual(got[1].inheritedFromObject, []string{"/directories/123"}) {
			t.Fatalf("inheritedFromObject = %v, want the parent directory", got[1].inheritedFromObject)
		}
		for _, rec := range got {
			if rec.principal != "data-eng" || rec.principalType != principalKindGroup {
				t.Fatalf("record = %+v, want the group principal on every level", rec)
			}
			if rec.displayName != "Data Engineering" {
				t.Fatalf("displayName = %q, want it carried onto every level", rec.displayName)
			}
			if rec.objectType != permissionObjectJob || rec.objectId != "620813104278135" {
				t.Fatalf("record = %+v, want the object carried onto every level", rec)
			}
		}
	})

	t.Run("drops entries that name no principal", func(t *testing.T) {
		got := flattenObjectPermissions(permissionObjectCluster, "c-1", &iam.ObjectPermissions{
			AccessControlList: []iam.AccessControlResponse{{
				DisplayName:    "orphan",
				AllPermissions: []iam.Permission{{PermissionLevel: iam.PermissionLevelCanManage}},
			}},
		})
		if len(got) != 0 {
			t.Fatalf("got %v, want an unattributable entry to be dropped", got)
		}
	})

	t.Run("drops entries with no permission level", func(t *testing.T) {
		// An entry with no level grants nothing, and the level is what makes a
		// record's id unique. Two such entries for one principal would collide
		// in the resource cache and the second would disappear without a trace,
		// so they are dropped here where the choice is visible.
		got := flattenObjectPermissions(permissionObjectCluster, "c-1", &iam.ObjectPermissions{
			AccessControlList: []iam.AccessControlResponse{{
				UserName: "ada@example.com",
				AllPermissions: []iam.Permission{
					{PermissionLevel: ""},
					{PermissionLevel: ""},
					{PermissionLevel: iam.PermissionLevelCanAttachTo},
				},
			}},
		})
		if len(got) != 1 {
			t.Fatalf("got %d records, want only the one with a level", len(got))
		}
		if got[0].permissionLevel != "CAN_ATTACH_TO" {
			t.Fatalf("permissionLevel = %q, want CAN_ATTACH_TO", got[0].permissionLevel)
		}
	})

	t.Run("ids are unique across principals and levels", func(t *testing.T) {
		// A duplicate id silently collapses two rows into one in the resource
		// cache, so uniqueness is the property that keeps the ACL complete.
		got := flattenObjectPermissions(permissionObjectWarehouse, "w-1", &iam.ObjectPermissions{
			AccessControlList: []iam.AccessControlResponse{
				{
					UserName: "ada@example.com",
					AllPermissions: []iam.Permission{
						{PermissionLevel: iam.PermissionLevelCanManage},
						{PermissionLevel: iam.PermissionLevelCanUse},
					},
				},
				{
					GroupName: "data-eng",
					AllPermissions: []iam.Permission{
						{PermissionLevel: iam.PermissionLevelCanManage},
					},
				},
			},
		})

		if len(got) != 3 {
			t.Fatalf("got %d records, want 3", len(got))
		}
		seen := map[string]struct{}{}
		for _, rec := range got {
			if _, dup := seen[rec.id]; dup {
				t.Fatalf("duplicate id %q, the record would be lost in the resource cache", rec.id)
			}
			seen[rec.id] = struct{}{}
		}
	})

	t.Run("id embeds the object type so two object kinds never collide", func(t *testing.T) {
		// Object ids are only unique within their type: a cluster and a
		// warehouse can both be "abc". Without the type in the key their ACLs
		// would overwrite each other.
		acl := &iam.ObjectPermissions{
			AccessControlList: []iam.AccessControlResponse{{
				UserName:       "ada@example.com",
				AllPermissions: []iam.Permission{{PermissionLevel: iam.PermissionLevelCanManage}},
			}},
		}
		cluster := flattenObjectPermissions(permissionObjectCluster, "abc", acl)
		warehouse := flattenObjectPermissions(permissionObjectWarehouse, "abc", acl)
		if cluster[0].id == warehouse[0].id {
			t.Fatalf("cluster and warehouse ACLs share the id %q", cluster[0].id)
		}
	})
}

func TestPermissionObjectTypesAreDistinct(t *testing.T) {
	// These constants are path segments interpolated into
	// /api/2.0/permissions/{type}/{id}. Two resources sharing one would query
	// the wrong object and, worse, produce colliding permission ids.
	types := map[string]string{
		"cluster":         permissionObjectCluster,
		"clusterPolicy":   permissionObjectClusterPolicy,
		"warehouse":       permissionObjectWarehouse,
		"job":             permissionObjectJob,
		"pipeline":        permissionObjectPipeline,
		"servingEndpoint": permissionObjectServingEndpoint,
	}

	seen := map[string]string{}
	for name, segment := range types {
		if segment == "" {
			t.Fatalf("%s has an empty object type", name)
		}
		if other, dup := seen[segment]; dup {
			t.Fatalf("%s and %s share the object type %q", name, other, segment)
		}
		seen[segment] = name
	}
}

// An object with no id must be reported as unreadable rather than sent to the
// API, where the empty id makes the request path end in a bare slash and the
// 404 that comes back names no object. Foundation model serving endpoints are
// the real case: they carry no id at all.
func TestPermissionsRejectsEmptyObjectId(t *testing.T) {
	_, err := mqlDatabricksPermissions(nil, permissionObjectServingEndpoint, "")
	if !errors.Is(err, errNoObjectId) {
		t.Fatalf("expected errNoObjectId, got %v", err)
	}
}

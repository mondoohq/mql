// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFlattenOktaAssignedRoleCoversUnion walks the members of the role
// assignment union and fails when one of them is not classified.
//
// Without this, the next SDK release can add a member, the flattener keeps
// compiling, and every assignment of the new kind is dropped from the role
// collection with nothing to attribute the absence to.
func TestFlattenOktaAssignedRoleCoversUnion(t *testing.T) {
	t.Parallel()

	union := reflect.TypeFor[okta.ListGroupAssignedRoles200ResponseInner]()
	require.NotZero(t, union.NumField(), "the union type has no members to check")

	for i := 0; i < union.NumField(); i++ {
		field := union.Field(i)
		if !field.IsExported() || field.Type.Kind() != reflect.Pointer {
			continue
		}

		t.Run(field.Name, func(t *testing.T) {
			// Populate only this member, leaving the others nil.
			entry := &okta.ListGroupAssignedRoles200ResponseInner{}
			reflect.ValueOf(entry).Elem().Field(i).
				Set(reflect.New(field.Type.Elem()))

			flat := flattenOktaAssignedRole(entry)
			assert.True(t, flat.classified,
				"union member %s is not handled by flattenOktaAssignedRole, so "+
					"assignments of that kind would be dropped", field.Name)
			assert.NotNil(t, flat.role, "a classified member must yield a role")
		})
	}
}

// TestFlattenOktaAssignedRoleUnsetMember checks the empty union, which is what
// an unrecognized assignment kind decodes to. It must report unclassified
// rather than yielding a role with no id, since a role resource keyed on an
// empty id would collide in the cache with every other one.
func TestFlattenOktaAssignedRoleUnsetMember(t *testing.T) {
	t.Parallel()

	flat := flattenOktaAssignedRole(&okta.ListGroupAssignedRoles200ResponseInner{})
	assert.False(t, flat.classified)
	assert.Nil(t, flat.role)

	flat = flattenOktaAssignedRole(nil)
	assert.False(t, flat.classified)
}

// TestFlattenOktaAssignedRoleCarriesFields pins the values each member
// contributes. The custom-role member names its role and resource set in its
// own fields, and those ids are what the customRole and resourceSet references
// resolve through, so losing them would leave both references empty.
func TestFlattenOktaAssignedRoleCarriesFields(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	t.Run("standard role", func(t *testing.T) {
		id, label, status, assignment := "ra1", "Super Administrator", "ACTIVE", "USER"
		flat := flattenOktaAssignedRole(&okta.ListGroupAssignedRoles200ResponseInner{
			StandardRole: &okta.StandardRole{
				Id: &id, Label: &label, Status: &status,
				AssignmentType: &assignment, Created: &created,
				Type: "SUPER_ADMIN",
			},
		})

		require.True(t, flat.classified)
		assert.Equal(t, "ra1", oktaStr(flat.role.Id))
		assert.Equal(t, "SUPER_ADMIN", oktaStr(flat.role.Type))
		assert.Equal(t, "ACTIVE", oktaStr(flat.role.Status))
		assert.Equal(t, "USER", oktaStr(flat.role.AssignmentType))
		require.NotNil(t, flat.role.Created)
		assert.Equal(t, created, *flat.role.Created)
		// A standard role is not scoped by a resource set.
		assert.Empty(t, flat.customRoleID)
		assert.Empty(t, flat.resourceSetID)
	})

	t.Run("custom role carries its role and resource set", func(t *testing.T) {
		id, label, role, resourceSet := "rb2", "Helpdesk", "cr9", "iamzz1"
		flat := flattenOktaAssignedRole(&okta.ListGroupAssignedRoles200ResponseInner{
			CustomRole: &okta.CustomRole{
				Id: &id, Label: &label, Role: &role, ResourceSet: &resourceSet,
				Type: "CUSTOM",
			},
		})

		require.True(t, flat.classified)
		assert.Equal(t, "rb2", oktaStr(flat.role.Id))
		assert.Equal(t, "CUSTOM", oktaStr(flat.role.Type))
		assert.Equal(t, "cr9", flat.customRoleID)
		assert.Equal(t, "iamzz1", flat.resourceSetID)
	})
}

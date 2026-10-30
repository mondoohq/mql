// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups/v2"
	"github.com/stretchr/testify/assert"
)

func mgEntity(name string, parentID string, chain ...string) *armmanagementgroups.EntityInfo {
	e := &armmanagementgroups.EntityInfo{
		ID:   new(managementGroupIDPrefix + name),
		Name: new(name),
		Type: new("Microsoft.Management/managementGroups"),
		Properties: &armmanagementgroups.EntityInfoProperties{
			DisplayName: new(name + " display"),
			TenantID:    new("tenant-1"),
		},
	}
	if parentID != "" {
		e.Properties.Parent = &armmanagementgroups.EntityParentGroupInfo{ID: new(parentID)}
	}
	for _, c := range chain {
		e.Properties.ParentNameChain = append(e.Properties.ParentNameChain, new(c))
	}
	return e
}

func subEntity(subID string, parentName string, chain ...string) *armmanagementgroups.EntityInfo {
	e := &armmanagementgroups.EntityInfo{
		ID:   new("/subscriptions/" + subID),
		Name: new(subID),
		Type: new("/subscriptions"),
		Properties: &armmanagementgroups.EntityInfoProperties{
			DisplayName: new("sub " + subID),
			Parent:      &armmanagementgroups.EntityParentGroupInfo{ID: new(managementGroupIDPrefix + parentName)},
		},
	}
	for _, c := range chain {
		e.Properties.ParentNameChain = append(e.Properties.ParentNameChain, new(c))
	}
	return e
}

func TestIsManagementGroupEntity(t *testing.T) {
	assert.True(t, isManagementGroupEntity(mgEntity("root", "")))
	assert.False(t, isManagementGroupEntity(subEntity("sub-1", "root", "root")))
	assert.False(t, isManagementGroupEntity(nil))
	assert.False(t, isManagementGroupEntity(&armmanagementgroups.EntityInfo{}))

	t.Run("casing of the provider path is tolerated", func(t *testing.T) {
		e := &armmanagementgroups.EntityInfo{
			ID: new("/providers/microsoft.management/managementgroups/root"),
		}
		assert.True(t, isManagementGroupEntity(e))
	})
}

func TestIsSubscriptionEntity(t *testing.T) {
	assert.True(t, isSubscriptionEntity(subEntity("sub-1", "root", "root")))
	assert.False(t, isSubscriptionEntity(mgEntity("root", "")))
	assert.False(t, isSubscriptionEntity(nil))

	t.Run("classified by type when the id prefix is unexpected", func(t *testing.T) {
		e := &armmanagementgroups.EntityInfo{
			ID:   new("/Subscriptions/sub-2"),
			Type: new("Microsoft.Management/managementGroups/subscriptions"),
		}
		assert.True(t, isSubscriptionEntity(e))
	})
}

func TestEntityParentID(t *testing.T) {
	assert.Equal(t, managementGroupIDPrefix+"root", entityParentID(mgEntity("prod", managementGroupIDPrefix+"root", "root")))

	t.Run("root group has no parent", func(t *testing.T) {
		assert.Equal(t, "", entityParentID(mgEntity("root", "")))
	})
	t.Run("nil-safe", func(t *testing.T) {
		assert.Equal(t, "", entityParentID(nil))
		assert.Equal(t, "", entityParentID(&armmanagementgroups.EntityInfo{}))
	})
}

func TestEntityParentNameChain(t *testing.T) {
	assert.Equal(t, []string{"root", "platform"},
		entityParentNameChain(mgEntity("prod", managementGroupIDPrefix+"platform", "root", "platform")))

	t.Run("nil-safe and empty for the root", func(t *testing.T) {
		assert.Empty(t, entityParentNameChain(nil))
		assert.Empty(t, entityParentNameChain(mgEntity("root", "")))
	})

	t.Run("nil chain entries are dropped", func(t *testing.T) {
		e := mgEntity("prod", managementGroupIDPrefix+"root")
		e.Properties.ParentNameChain = []*string{new("root"), nil, new("platform")}
		assert.Equal(t, []string{"root", "platform"}, entityParentNameChain(e))
	})
}

func TestPrincipalTypeFromODataType(t *testing.T) {
	cases := []struct {
		odataType string
		want      string
	}{
		{"#microsoft.graph.servicePrincipal", "servicePrincipal"},
		{"microsoft.graph.servicePrincipal", "servicePrincipal"},
		{"#microsoft.graph.user", "user"},
		{"#microsoft.graph.group", "group"},
		{"#microsoft.graph.application", "application"},
		{"#microsoft.graph.device", "device"},
		// casing differences from Graph are normalized to our spelling
		{"#microsoft.graph.serviceprincipal", "servicePrincipal"},
		// types we do not model, and malformed input, yield ""
		{"#microsoft.graph.orgContact", ""},
		{"", ""},
		{"servicePrincipal", "servicePrincipal"},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, principalTypeFromODataType(c.odataType), "odata.type %q", c.odataType)
	}
}

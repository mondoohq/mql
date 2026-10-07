// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPCatalogMergesScopes(t *testing.T) {
	c := gcpCatalog(t)
	assert.True(t, c.hasExact("compute.instances.list"))
	assert.True(t, c.hasExact("iam.googleapis.com/workforcePools.list"), "the spelling Google reports as primary")
	assert.True(t, c.hasExact("iam.workforcePools.list"), "the alias is listed too")
	assert.True(t, c.hasService("iam.anything"))
	assert.Equal(t, "iam.googleapis.com/workforcePools.list", c.gcp["iam.workforcePools.list"].Primary)
	assert.Equal(t, "", c.gcp["compute.instances.list"].Primary, "a primary equal to the name is not an alias")
	assert.Equal(t, "NOT_SUPPORTED", c.gcp["domains.registrations.list"].Support)
	assert.Equal(t, []string{"project", "organization"}, c.gcp["compute.instances.get"].Scopes)
	assert.Equal(t, []string{"organization"}, c.gcp["resourcemanager.projects.list"].Scopes)
}

func TestCheckManifestGCPSaysWhy(t *testing.T) {
	m := manifest{
		Provider: "gcp",
		Permissions: []string{
			"compute.instances.list",         // right
			"compute.Instances.list",         // wrong case: GCP matches exactly, and this spelling exists nowhere
			"compute.instances.nope",         // not a permission
			"datastore.indexes.list",         // alias
			"container.bindings.list",        // deprecated
			"domains.registrations.list",     // real, custom roles refuse it
			"iam.workforcePools.list",        // organization-only, listed at project level
			"iam.workloadIdentityPools.list", // alias of the qualified spelling (BETA)
		},
		OrgLevelPermissions: []string{
			"resourcemanager.projects.list", // right, organization level
			"compute.instances.get",         // testable at both scopes: fine at either level
			"resourcemanager.projects.get",  // same
		},
	}
	r := checkManifest(m, gcpCatalog(t))
	assert.Equal(t, 11, r.Total)
	assert.Equal(t, 8, r.Valid, "everything a custom role at the listed scope accepts, aliases and the deprecated name included")

	notes := map[string]string{}
	for _, p := range r.Notes {
		notes[p.Permission] = p.Message
	}
	require.Len(t, notes, 4)
	assert.Equal(t, "usable, but IAM refuses it in a custom role: grantable only through a predefined role", notes["domains.registrations.list"])
	assert.Equal(t, "usable, but an alias of datastore.schemas.list", notes["datastore.indexes.list"])
	assert.Equal(t, "usable, but Google marks it DEPRECATED", notes["container.bindings.list"])
	assert.Equal(t, "usable, but an alias of iam.googleapis.com/workloadIdentityPools.list", notes["iam.workloadIdentityPools.list"])

	got := map[string]string{}
	for _, p := range r.Problems {
		got[p.Permission] = p.Message
	}
	require.Len(t, got, 3)
	assert.Contains(t, got["compute.Instances.list"], `spelled "compute.instances.list"`)
	assert.Equal(t, "not a known IAM permission", got["compute.instances.nope"])
	assert.Equal(t, "exists, but only at organization scope: move it to org_level_permissions", got["iam.workforcePools.list"])
	assert.False(t, r.ok())
}

func TestCheckManifestGCPOrgLevelMisplaced(t *testing.T) {
	m := manifest{Provider: "gcp", OrgLevelPermissions: []string{"compute.instances.list", "iam.googleapis.com/workforcePools.list"}}
	r := checkManifest(m, gcpCatalog(t))
	assert.Equal(t, 2, r.Valid, "a permission testable at both scopes may be listed at either level")
	assert.Empty(t, r.Problems)

	// A project-only permission at organization level is the mirror mistake.
	c := gcpCatalog(t)
	c.gcp["compute.instances.get"] = gcpPermission{Name: "compute.instances.get", Scopes: []string{"project"}}
	r = checkManifest(manifest{Provider: "gcp", OrgLevelPermissions: []string{"compute.instances.get"}}, c)
	require.Len(t, r.Problems, 1)
	assert.Equal(t, "exists, but only at project scope: it is not an organization-level permission", r.Problems[0].Message)
}

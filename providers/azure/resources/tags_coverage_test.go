// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Azure splits resources into two kinds. A *tracked* resource has its own
// location and carries tags; a *proxy* resource is a child of a tracked parent
// (a subnet, a firewall rule, a role assignment) and ARM rejects tags on it.
// Modeling `location` is the schema's own statement that a resource is
// tracked, which makes "declares location but not tags" a reliable signal that
// a taggable resource shipped without its tags -- and a tag field that is
// missing is invisible at query time: a governance policy filtering on
// `tags["env"]` just skips the resource instead of failing.
//
// Every entry below was checked against the pinned SDK struct and has no Tags
// field, so the absence is correct rather than an oversight.
var untaggableWithLocation = map[string]string{
	"azure.subscription.cacheService.redisInstance.patchSchedule":     "armredis.PatchSchedule is a proxy child of the cache",
	"azure.subscription.cloudDefenderService.jitNetworkAccessPolicy":  "armsecurity.JitNetworkAccessPolicy has no Tags",
	"azure.subscription.kustoService.cluster.database":                "armkusto.Database/ReadWriteDatabase have no Tags",
	"azure.subscription.kustoService.cluster.database.dataConnection": "armkusto data connections have no Tags",
	"azure.subscription.monitorService.workspace.replication":         "replication config is a proxy child of the workspace",
	"azure.subscription.networkService.backendAddressPool":            "armnetwork.BackendAddressPool is a proxy child of the load balancer; its Location is the regional scope of a global pool, not a tracked resource's region",
	"azure.subscription.networkService.routeFilter.rule":              "armnetwork.RouteFilterRule is a proxy child of the filter",
	"azure.subscription.policy.assignment":                            "armpolicy.Assignment has Location but no Tags; the location is only set when the assignment carries a managed identity",
	"azure.subscription.recoveryServicesService.deletedVault":         "armrecoveryservices.DeletedVault has neither Location nor Tags; location is derived from the per-region listing",
	"azure.subscription.sqlService.database.dataMaskingPolicy":        "armsql.DataMaskingPolicy is a proxy child of the database",
	"azure.subscription.sqlService.server.failoverGroup.partner":      "armsql.PartnerInfo is a descriptor of another server, not a tracked resource; its Location is that server's region and the server itself carries the tags",
}

// TestTrackedResourcesDeclareTags fails when a resource models `location`
// without `tags`. If the resource really is untaggable, add it to
// untaggableWithLocation with the SDK type you checked; otherwise add the tags
// field and populate it from the SDK struct.
//
// This catches half-modeled tracked resources, not unmodeled ones: a taggable
// resource that declares neither field looks the same as a proxy resource from
// here, so adding a tracked resource still means checking the SDK struct for
// Location and Tags by hand.
func TestTrackedResourcesDeclareTags(t *testing.T) {
	raw, err := os.ReadFile("azure.resources.json")
	require.NoError(t, err)

	var schema struct {
		Resources map[string]struct {
			Fields map[string]json.RawMessage `json:"fields"`
		} `json:"resources"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))
	require.NotEmpty(t, schema.Resources, "schema failed to load")

	for name, res := range schema.Resources {
		if _, tracked := res.Fields["location"]; !tracked {
			continue
		}
		if _, ok := res.Fields["tags"]; ok {
			continue
		}
		require.Containsf(t, untaggableWithLocation, name,
			"%s declares location but not tags -- add the tags field, or record here why the SDK type has none", name)
	}

	// Keep the allowlist honest: an entry that has since gained tags is stale
	// and would otherwise mask the next real gap on that resource.
	for name := range untaggableWithLocation {
		res, ok := schema.Resources[name]
		require.Truef(t, ok, "%s is allowlisted but no longer exists in the schema", name)
		require.NotContainsf(t, res.Fields, "tags",
			"%s now declares tags -- drop it from untaggableWithLocation", name)
	}
}

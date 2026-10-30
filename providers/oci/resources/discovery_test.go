// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"
	"strings"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestDiscoveryPlatformIDFormat pins the platform id every discovery target
// emits.
//
// A platform id is an asset's identity: change the format, the service segment,
// or the object-type segment and every previously discovered asset becomes a new
// asset upstream. Nothing else in this provider would notice, so the exact
// strings are written out here rather than derived.
func TestDiscoveryPlatformIDFormat(t *testing.T) {
	const tenant = "ocid1.tenancy.oc1..aaaaexample"

	want := map[string]string{
		DiscoverySecurityLists:         "//platformid.api.mondoo.app/runtime/oci/network/v1/tenancies/" + tenant + "/regions/IAD/securitylist/ocid1.securitylist.oc1..x",
		DiscoveryUsers:                 "//platformid.api.mondoo.app/runtime/oci/identity/v1/tenancies/" + tenant + "/regions/global/user/ocid1.user.oc1..x",
		DiscoveryPolicies:              "//platformid.api.mondoo.app/runtime/oci/identity/v1/tenancies/" + tenant + "/regions/global/policy/ocid1.policy.oc1..x",
		DiscoveryBuckets:               "//platformid.api.mondoo.app/runtime/oci/objectstorage/v1/tenancies/" + tenant + "/regions/IAD/bucket/mynamespace/mybucket",
		DiscoveryAPIGatewayDeployments: "//platformid.api.mondoo.app/runtime/oci/apigateway/v1/tenancies/" + tenant + "/regions/IAD/deployment/ocid1.apideployment.oc1..x",
		DiscoveryLoadBalancers:         "//platformid.api.mondoo.app/runtime/oci/loadbalancer/v1/tenancies/" + tenant + "/regions/IAD/loadBalancer/ocid1.loadbalancer.oc1..x",
		DiscoveryRedisClusters:         "//platformid.api.mondoo.app/runtime/oci/redis/v1/tenancies/" + tenant + "/regions/IAD/cluster/ocid1.rediscluster.oc1..x",
		DiscoveryVaultSecrets:          "//platformid.api.mondoo.app/runtime/oci/vault/v1/tenancies/" + tenant + "/regions/IAD/secret/ocid1.vaultsecret.oc1..x",
		DiscoveryOkeClusters:           "//platformid.api.mondoo.app/runtime/oci/oke/v1/tenancies/" + tenant + "/regions/IAD/cluster/ocid1.cluster.oc1..x",
		DiscoveryGenerativeAiEndpoints: "//platformid.api.mondoo.app/runtime/oci/generativeai/v1/tenancies/" + tenant + "/regions/IAD/endpoint/ocid1.generativeaiendpoint.oc1..x",
	}

	// ids that exercise the two id shapes: a plain OCID, and the bucket's
	// composite namespace/name.
	ids := map[string]string{
		DiscoverySecurityLists:         "ocid1.securitylist.oc1..x",
		DiscoveryUsers:                 "ocid1.user.oc1..x",
		DiscoveryPolicies:              "ocid1.policy.oc1..x",
		DiscoveryBuckets:               "mynamespace/mybucket",
		DiscoveryAPIGatewayDeployments: "ocid1.apideployment.oc1..x",
		DiscoveryLoadBalancers:         "ocid1.loadbalancer.oc1..x",
		DiscoveryRedisClusters:         "ocid1.rediscluster.oc1..x",
		DiscoveryVaultSecrets:          "ocid1.vaultsecret.oc1..x",
		DiscoveryOkeClusters:           "ocid1.cluster.oc1..x",
		DiscoveryGenerativeAiEndpoints: "ocid1.generativeaiendpoint.oc1..x",
	}

	for _, target := range ociDiscoveryTargets {
		t.Run(target.Target, func(t *testing.T) {
			// identity is global; everything else carries a region key.
			region := "IAD"
			if target.Service == "identity" {
				region = "global"
			}
			got := mondooOciObjectID(ociObject{
				tenantID:    tenant,
				compartment: "ocid1.compartment.oc1..c",
				region:      region,
				id:          ids[target.Target],
				service:     target.Service,
				objectType:  target.ObjectType,
			})
			if got != want[target.Target] {
				t.Errorf("platform id changed\n got: %s\nwant: %s", got, want[target.Target])
			}
		})
	}
}

// TestDiscoveryPlatformIDRoundTrips checks that every emitted platform id parses
// back into the parts it was built from. initOciIdentityUser and its siblings
// resolve a discovered asset by parsing its platform id, so a format that builds
// but does not parse leaves those inits unable to find their own resource.
func TestDiscoveryPlatformIDRoundTrips(t *testing.T) {
	const tenant = "ocid1.tenancy.oc1..aaaaexample"

	for _, target := range ociDiscoveryTargets {
		t.Run(target.Target, func(t *testing.T) {
			id := "ocid1.thing.oc1..x"
			if target.Target == DiscoveryBuckets {
				id = "mynamespace/mybucket"
			}
			platformID := mondooOciObjectID(ociObject{
				tenantID: tenant, region: "IAD", id: id,
				service: target.Service, objectType: target.ObjectType,
			})

			parsed, ok := parseOciObjectPlatformID(platformID)
			if !ok {
				t.Fatalf("%s did not parse", platformID)
			}
			if parsed.service != target.Service {
				t.Errorf("service = %q, want %q", parsed.service, target.Service)
			}
			if parsed.objectType != target.ObjectType {
				t.Errorf("objectType = %q, want %q", parsed.objectType, target.ObjectType)
			}
			if parsed.tenantID != tenant {
				t.Errorf("tenantID = %q, want %q", parsed.tenantID, tenant)
			}
			if parsed.id != id {
				t.Errorf("id = %q, want %q", parsed.id, id)
			}
		})
	}
}

// TestDiscoveryTargetsMatchPlatformCatalog is the check the old code could not
// make. The platform name used to be re-derived from (service, objectType) by a
// second switch, so a target whose pair was missing from it emitted no asset at
// all - an unmapped pair returns "" and the caller skips it, silently. With one
// row per target the two sides can be compared directly, in both directions.
func TestDiscoveryTargetsMatchPlatformCatalog(t *testing.T) {
	for _, target := range ociDiscoveryTargets {
		if PlatformByName(target.Platform) == nil {
			t.Errorf("target %q names platform %q, which is not in the Platforms catalog",
				target.Target, target.Platform)
		}
	}

	// And no orphans the other way: a platform in the catalog that no target
	// emits is either a dropped target or a typo.
	claimed := make(map[string]string, len(ociDiscoveryTargets))
	for _, target := range ociDiscoveryTargets {
		if prev, dup := claimed[target.Platform]; dup {
			t.Errorf("platform %q is claimed by both %q and %q",
				target.Platform, prev, target.Target)
		}
		claimed[target.Platform] = target.Target
	}

	for _, pi := range Platforms {
		if pi.Name == "oci" {
			continue // the tenancy root, not a discovery target
		}
		if _, ok := claimed[pi.Name]; !ok {
			t.Errorf("platform %q is in the catalog but no discovery target emits it", pi.Name)
		}
	}
}

// TestDiscoveryTargetRowsAreWellFormed guards the fields a row cannot be useful
// without. A nil List or Extract would panic during a scan rather than at build.
func TestDiscoveryTargetRowsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, target := range ociDiscoveryTargets {
		if target.Target == "" || target.Platform == "" ||
			target.Service == "" || target.ObjectType == "" {
			t.Errorf("row %+v has an empty required field", target.Target)
		}
		if target.List == nil {
			t.Errorf("target %q has no List", target.Target)
		}
		if target.Extract == nil {
			t.Errorf("target %q has no Extract", target.Target)
		}
		if seen[target.Target] {
			t.Errorf("target %q is registered twice", target.Target)
		}
		seen[target.Target] = true

		// The service and object type land in a platform id path, so a "/" in
		// either would make the id unparseable.
		if strings.ContainsAny(target.Service+target.ObjectType, "/ ") {
			t.Errorf("target %q has a slash or space in service/objectType", target.Target)
		}
	}
}

// TestDiscoveryTargetConstantsAreRegistered keeps a declared constant from being
// unreachable. A constant with no row is accepted on the command line and then
// silently discovers nothing.
func TestDiscoveryTargetConstantsAreRegistered(t *testing.T) {
	constants := []string{
		DiscoverySecurityLists, DiscoveryUsers, DiscoveryPolicies,
		DiscoveryBuckets, DiscoveryAPIGatewayDeployments, DiscoveryLoadBalancers,
		DiscoveryRedisClusters, DiscoveryVaultSecrets, DiscoveryOkeClusters,
		DiscoveryGenerativeAiEndpoints,
	}
	for _, c := range constants {
		if _, ok := ociDiscoveryTargetsByName[c]; !ok {
			t.Errorf("discovery constant %q has no registry row", c)
		}
	}
	if len(constants) != len(ociDiscoveryTargets) {
		t.Errorf("%d constants but %d rows; one side gained an entry",
			len(constants), len(ociDiscoveryTargets))
	}
}

// TestAllAPIResourcesIsSorted pins the ordering the old hand-maintained slice
// documented as "keep sorted alphabetically for diff stability".
func TestAllAPIResourcesIsSorted(t *testing.T) {
	if !slices.IsSorted(AllAPIResources) {
		t.Errorf("AllAPIResources is not sorted: %v", AllAPIResources)
	}
	if len(AllAPIResources) != len(ociDiscoveryTargets) {
		t.Errorf("AllAPIResources has %d entries, registry has %d",
			len(AllAPIResources), len(ociDiscoveryTargets))
	}
}

// TestAutoPutsTenancyFirst pins the ordering `cnspec scan` output depends on:
// the tenancy asset should appear before any of its sub-assets.
func TestAutoPutsTenancyFirst(t *testing.T) {
	if len(Auto) == 0 || Auto[0] != DiscoveryTenancy {
		t.Fatalf("Auto must start with %q, got %v", DiscoveryTenancy, Auto)
	}
	if len(Auto) != len(AllAPIResources)+1 {
		t.Errorf("Auto has %d entries, want %d", len(Auto), len(AllAPIResources)+1)
	}
	if !slices.Equal(All, Auto) {
		t.Errorf("All and Auto have diverged:\n All: %v\nAuto: %v", All, Auto)
	}
}

// TestGetDiscoveryTargetsResolvesAliases covers the alias expansion and dedup
// that decide which targets actually run.
func TestGetDiscoveryTargetsResolvesAliases(t *testing.T) {
	conf := func(targets ...string) *inventory.Config {
		return &inventory.Config{Discover: &inventory.Discovery{Targets: targets}}
	}

	t.Run("all wins outright", func(t *testing.T) {
		got := getDiscoveryTargets(conf(DiscoveryAll, DiscoveryUsers))
		if !slices.Equal(got, All) {
			t.Errorf("got %v, want All", got)
		}
	})

	t.Run("auto expands to the same set", func(t *testing.T) {
		got := getDiscoveryTargets(conf(DiscoveryAuto))

		// Set equality, not slice equality: everything except the `all` path
		// goes through stringx.DedupStringArray, which collects into a map and
		// so returns the targets in a random order. That means `--discover auto`
		// does NOT preserve Auto's tenancy-first ordering, despite what Auto's
		// name and its former comment implied. Asserting order here would be a
		// flaky test against a real pre-existing defect; see the note on Auto.
		wantSet := slices.Clone(Auto)
		gotSet := slices.Clone(got)
		slices.Sort(wantSet)
		slices.Sort(gotSet)
		if !slices.Equal(gotSet, wantSet) {
			t.Errorf("got %v, want the same set as Auto %v", got, Auto)
		}
	})

	t.Run("all preserves tenancy-first ordering", func(t *testing.T) {
		// The `all` path returns All directly, without the dedup, so this is
		// the one path where the ordering Auto documents actually holds.
		got := getDiscoveryTargets(conf(DiscoveryAll))
		if len(got) == 0 || got[0] != DiscoveryTenancy {
			t.Errorf("got %v, want tenancy first", got)
		}
	})

	t.Run("explicit targets pass through", func(t *testing.T) {
		// Set equality, for the same reason the auto case above uses it: this
		// path also ends in stringx.DedupStringArray, whose result comes out of
		// a map and so has no stable order. Asserting the slice order made this
		// subtest a coin flip on two elements rather than a check of anything.
		got := getDiscoveryTargets(conf(DiscoveryUsers, DiscoveryBuckets))
		want := []string{DiscoveryUsers, DiscoveryBuckets}
		gotSet := slices.Clone(got)
		slices.Sort(gotSet)
		slices.Sort(want)
		if !slices.Equal(gotSet, want) {
			t.Errorf("got %v, want the same set as %v", got, want)
		}
	})

	t.Run("duplicates are collapsed", func(t *testing.T) {
		got := getDiscoveryTargets(conf(DiscoveryUsers, DiscoveryUsers, DiscoveryAuto))
		if len(got) != len(Auto) {
			t.Errorf("got %d targets, want %d: %v", len(got), len(Auto), got)
		}
	})
}

// TestFallbackRegion pins the placeholder that keeps a platform id valid when a
// resource did not expose a region at enumeration time.
func TestFallbackRegion(t *testing.T) {
	if got := fallbackRegion(""); got != "unknown" {
		t.Errorf("fallbackRegion(\"\") = %q, want \"unknown\"", got)
	}
	if got := fallbackRegion("IAD"); got != "IAD" {
		t.Errorf("fallbackRegion(\"IAD\") = %q, want \"IAD\"", got)
	}
}

// TestTagsToLabels covers the conversion discovery applies to freeform tags,
// including the non-string values the MQL dict path can carry.
func TestTagsToLabels(t *testing.T) {
	if got := tagsToLabels(nil); len(got) != 0 {
		t.Errorf("nil tags produced %v, want an empty map", got)
	}
	got := tagsToLabels(map[string]any{"env": "prod", "count": 3})
	if len(got) != 1 || got["env"] != "prod" {
		t.Errorf("got %v, want only the string-valued tag", got)
	}
}

// TestDiscoveryGone pins which lifecycle states discovery skips: those of a
// resource that is deleted or being deleted, in any case OCI spells them, and
// not those of one that still exists (an inactive user, a secret scheduled
// for deletion, a resource that failed to provision) or that has no state.
func TestDiscoveryGone(t *testing.T) {
	for _, s := range []string{"DELETED", "DELETING", "TERMINATED", "TERMINATING", "deleted"} {
		if !ociDiscoveryGone(s) {
			t.Errorf("ociDiscoveryGone(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "ACTIVE", "AVAILABLE", "INACTIVE", "CREATING", "UPDATING", "FAILED", "PENDING_DELETION", "SCHEDULING_DELETION"} {
		if ociDiscoveryGone(s) {
			t.Errorf("ociDiscoveryGone(%q) = true, want false", s)
		}
	}
}

// TestDiscoveryExtractCarriesState checks that a target's extractor hands the
// lifecycle state to discover(), which skips the resource on it: a deleted OCI
// Cache cluster keeps its tags, so a tag filter alone would still pick it.
func TestDiscoveryExtractCarriesState(t *testing.T) {
	target := ociDiscoveryTargetsByName[DiscoveryRedisClusters]
	obj, ok := target.Extract(&mqlOciRedisCluster{
		Id:           plugin.TValue[string]{Data: "ocid1.rediscluster.oc1..example", State: plugin.StateIsSet},
		Name:         plugin.TValue[string]{Data: "cache", State: plugin.StateIsSet},
		State:        plugin.TValue[string]{Data: "DELETED", State: plugin.StateIsSet},
		FreeformTags: plugin.TValue[map[string]any]{Data: map[string]any{"env": "prod"}, State: plugin.StateIsSet},
	})
	if !ok {
		t.Fatal("the redis-clusters extractor rejected an oci.redis.cluster")
	}
	if obj.state != "DELETED" || !ociDiscoveryGone(obj.state) {
		t.Errorf("extracted state %q, want DELETED, which discovery skips", obj.state)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discovery target constants. `auto` covers the tenancy plus every listed
// fine-grained API resource; `all` is currently identical to `auto`. Users
// may also pass any individual target directly (e.g. `--discover identity-users`).
const (
	DiscoveryAuto    = "auto"
	DiscoveryAll     = "all"
	DiscoveryTenancy = "tenancy"

	DiscoverySecurityLists         = "network-securitylists"
	DiscoveryUsers                 = "identity-users"
	DiscoveryPolicies              = "identity-policies"
	DiscoveryBuckets               = "objectstorage-buckets"
	DiscoveryAPIGatewayDeployments = "apigateway-deployments"
	DiscoveryLoadBalancers         = "loadbalancer-loadbalancers"
	DiscoveryRedisClusters         = "redis-clusters"
	DiscoveryVaultSecrets          = "vault-secrets"
	DiscoveryOkeClusters           = "oke-clusters"
	DiscoveryGenerativeAiEndpoints = "generativeai-endpoints"
)

// A discovery target used to be spread across four places: the constant above, a
// `case` in discover(), an entry in AllAPIResources, and an arm of a
// getPlatformName switch that re-derived the platform name from the service and
// object type the `case` had just written. The two switches encoded the same
// facts, so they could disagree - and a target whose pair was missing from
// getPlatformName silently emitted no asset at all, because an unmapped pair
// returns "" and the caller skips it.
//
// One row per target instead. The tuple that composes the platform id and the
// platform name that cnspec policy filters match on now live together, and
// TestDiscoveryTargetsMatchPlatformCatalog checks the row set against the
// platform catalog in both directions, so neither side can grow an entry the
// other lacks.

// ociDiscovered is what a target's extractor pulls off one resource: the parts
// that vary per object type, where everything else about the asset is uniform.
type ociDiscovered struct {
	id          string // OCID, or a composite id (e.g. namespace/name for buckets)
	name        string
	compartment string
	region      string
	labels      map[string]string
}

// ociDiscoveryTarget describes one fine-grained discovery target end to end.
type ociDiscoveryTarget struct {
	// Target is the --discover value.
	Target string
	// Platform is the platform name cnspec policy filters match on. It must
	// exist in the Platforms catalog.
	Platform string
	// Service and ObjectType compose the asset's platform id. Changing either
	// changes the identity of every asset the target emits.
	Service    string
	ObjectType string
	// List reaches the MQL collection the target iterates.
	List func(runtime *plugin.Runtime) ([]any, error)
	// Extract pulls the per-object asset fields. Returning false skips an entry
	// whose type does not match, rather than panicking on the assertion.
	Extract func(item any) (ociDiscovered, bool)
}

// ociDiscoveryList initializes a resource and reads one of its collection
// fields, which is what every target's List does.
func ociDiscoveryList[T plugin.Resource](runtime *plugin.Runtime, name string, field func(T) *plugin.TValue[[]any]) ([]any, error) {
	res, err := NewResource(runtime, name, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	typed, ok := res.(T)
	if !ok {
		return nil, fmt.Errorf("oci discovery: %s did not resolve to a %T", name, typed)
	}
	list := field(typed)
	if list.Error != nil {
		return nil, list.Error
	}
	return list.Data, nil
}

// ociDiscoveryTargets is the registry. Adding a discoverable object type means
// adding a row here, a constant above, and a platform to the Platforms catalog.
var ociDiscoveryTargets = []ociDiscoveryTarget{
	{
		Target: DiscoverySecurityLists, Platform: "oci-network-securitylist",
		Service: "network", ObjectType: "securitylist",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.network", (*mqlOciNetwork).GetSecurityLists)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			sl, ok := item.(*mqlOciNetworkSecurityList)
			if !ok {
				return ociDiscovered{}, false
			}
			// cacheRegion was populated when the security list was enumerated;
			// empty only when the enumeration didn't hit a region.
			return ociDiscovered{
				id: sl.Id.Data, name: sl.Name.Data,
				compartment: sl.cacheCompartmentID, region: sl.cacheRegion,
				labels: tagsToLabels(sl.FreeformTags.Data),
			}, true
		},
	},
	{
		Target: DiscoveryUsers, Platform: "oci-identity-user",
		Service: "identity", ObjectType: "user",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.identity", (*mqlOciIdentity).GetUsers)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			u, ok := item.(*mqlOciIdentityUser)
			if !ok {
				return ociDiscovered{}, false
			}
			// OCI IAM is global (single realm per tenancy); mark users as such
			// so the platform id stays stable regardless of which region the
			// scan connects to.
			return ociDiscovered{
				id: u.Id.Data, name: u.Name.Data,
				compartment: u.cacheCompartmentID, region: "global",
				labels: tagsToLabels(u.FreeformTags.Data),
			}, true
		},
	},
	{
		Target: DiscoveryPolicies, Platform: "oci-identity-policy",
		Service: "identity", ObjectType: "policy",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.identity", (*mqlOciIdentity).GetPolicies)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			p, ok := item.(*mqlOciIdentityPolicy)
			if !ok {
				return ociDiscovered{}, false
			}
			return ociDiscovered{
				id: p.Id.Data, name: p.Name.Data,
				compartment: p.cacheCompartmentID, region: "global",
				labels: tagsToLabels(p.FreeformTags.Data),
			}, true
		},
	},
	{
		Target: DiscoveryBuckets, Platform: "oci-objectstorage-bucket",
		Service: "objectstorage", ObjectType: "bucket",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.objectStorage", (*mqlOciObjectStorage).GetBuckets)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			b, ok := item.(*mqlOciObjectStorageBucket)
			if !ok {
				return ociDiscovered{}, false
			}
			// Region is exposed as a typed oci.region resource on the bucket;
			// pull its id (region key) for the platform id.
			regionKey := ""
			if region := b.GetRegion(); region.Error == nil && region.Data != nil {
				regionKey = region.Data.Id.Data
			}
			return ociDiscovered{
				// Buckets aren't globally unique by name alone - namespace
				// qualifies them - so use namespace/name to match the __id.
				id: b.Namespace.Data + "/" + b.Name.Data, name: b.Name.Data,
				compartment: b.cacheCompartmentID, region: regionKey,
				// Listed with the bucket (fields=tags), so no GetBucket.
				labels: tagsToLabels(b.GetFreeformTags().Data),
			}, true
		},
	},
	{
		Target: DiscoveryAPIGatewayDeployments, Platform: "oci-apigateway-deployment",
		Service: "apigateway", ObjectType: "deployment",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.apigateway", (*mqlOciApigateway).GetDeployments)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			d, ok := item.(*mqlOciApigatewayDeployment)
			if !ok {
				return ociDiscovered{}, false
			}
			return ociDiscovered{
				id: d.Id.Data, name: d.Name.Data,
				compartment: d.cacheCompartmentID, region: d.cacheRegion,
				labels: tagsToLabels(d.FreeformTags.Data),
			}, true
		},
	},
	{
		Target: DiscoveryLoadBalancers, Platform: "oci-loadbalancer",
		Service: "loadbalancer", ObjectType: "loadBalancer",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.loadBalancer", (*mqlOciLoadBalancer).GetLoadBalancers)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			lb, ok := item.(*mqlOciLoadBalancerLoadBalancer)
			if !ok {
				return ociDiscovered{}, false
			}
			return ociDiscovered{
				id: lb.Id.Data, name: lb.Name.Data,
				compartment: lb.cacheCompartmentID, region: lb.cacheRegion,
				labels: tagsToLabels(lb.FreeformTags.Data),
			}, true
		},
	},
	{
		Target: DiscoveryRedisClusters, Platform: "oci-redis-cluster",
		Service: "redis", ObjectType: "cluster",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.redis", (*mqlOciRedis).GetClusters)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			c, ok := item.(*mqlOciRedisCluster)
			if !ok {
				return ociDiscovered{}, false
			}
			return ociDiscovered{
				id: c.Id.Data, name: c.Name.Data,
				compartment: c.cacheCompartmentID, region: c.cacheRegion,
				labels: tagsToLabels(c.FreeformTags.Data),
			}, true
		},
	},
	{
		Target: DiscoveryVaultSecrets, Platform: "oci-vault-secret",
		Service: "vault", ObjectType: "secret",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.vault", (*mqlOciVault).GetSecrets)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			s, ok := item.(*mqlOciVaultSecret)
			if !ok {
				return ociDiscovered{}, false
			}
			return ociDiscovered{
				id: s.Id.Data, name: s.Name.Data,
				compartment: s.cacheCompartmentID, region: s.cacheRegion,
				labels: tagsToLabels(s.FreeformTags.Data),
			}, true
		},
	},
	{
		Target: DiscoveryOkeClusters, Platform: "oci-oke-cluster",
		Service: "oke", ObjectType: "cluster",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.oke", (*mqlOciOke).GetClusters)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			c, ok := item.(*mqlOciOkeCluster)
			if !ok {
				return ociDiscovered{}, false
			}
			return ociDiscovered{
				id: c.Id.Data, name: c.Name.Data,
				compartment: c.cacheCompartmentID, region: c.cacheRegion,
				labels: tagsToLabels(c.FreeformTags.Data),
			}, true
		},
	},
	{
		Target: DiscoveryGenerativeAiEndpoints, Platform: "oci-ai-generativeai-endpoint",
		Service: "generativeai", ObjectType: "endpoint",
		List: func(rt *plugin.Runtime) ([]any, error) {
			return ociDiscoveryList(rt, "oci.ai.generativeAi", (*mqlOciAiGenerativeAi).GetEndpoints)
		},
		Extract: func(item any) (ociDiscovered, bool) {
			e, ok := item.(*mqlOciAiGenerativeAiEndpoint)
			if !ok {
				return ociDiscovered{}, false
			}
			return ociDiscovered{
				id: e.Id.Data, name: e.Name.Data,
				compartment: e.CompartmentID.Data, region: e.cacheRegion,
				labels: tagsToLabels(e.FreeformTags.Data),
			}, true
		},
	},
}

// ociDiscoveryTargetsByName indexes the registry for dispatch.
var ociDiscoveryTargetsByName = func() map[string]ociDiscoveryTarget {
	res := make(map[string]ociDiscoveryTarget, len(ociDiscoveryTargets))
	for _, t := range ociDiscoveryTargets {
		res[t.Target] = t
	}
	return res
}()

// AllAPIResources lists every fine-grained per-resource discovery target,
// sorted by target string for diff stability.
var AllAPIResources = func() []string {
	res := make([]string, 0, len(ociDiscoveryTargets))
	for _, t := range ociDiscoveryTargets {
		res = append(res, t.Target)
	}
	slices.Sort(res)
	return res
}()

// Auto expands to the tenancy plus all API resources, tenancy first.
//
// That ordering only survives on the `all` path. getDiscoveryTargets returns All
// directly, but it runs everything else through stringx.DedupStringArray, which
// collects into a map and therefore returns the targets in a random order - so
// `--discover auto`, the default, does not in fact list the tenancy first.
// Pre-existing; left alone here because this change is not meant to alter
// behavior, but it is a real defect rather than a quirk: the ordering is what
// puts the tenancy above its own sub-assets in scan output.
var Auto = append(
	[]string{DiscoveryTenancy},
	AllAPIResources...,
)

// All mirrors Auto today but is kept as a separate slice so `all` vs `auto`
// can diverge if we later add heavier-weight targets that shouldn't run by
// default.
var All = slices.Clone(Auto)

// Discover is the provider's discovery entry point. It iterates the configured
// discovery targets and emits one inventory.Asset per fine-grained resource so
// per-resource cnspec security checks can run against them.
func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.OciConnection)
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := getDiscoveryTargets(conn.Conf)
	var (
		discoveryErr error
		succeeded    int
	)
	for _, target := range targets {
		list, err := discover(runtime, conn, target)
		if err != nil {
			log.Error().Err(err).Str("target", target).Msg("error during OCI discovery")
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %w", target, err))
			continue
		}
		succeeded++
		in.Spec.Assets = append(in.Spec.Assets, list...)
	}

	// One failing target among several is a partial result worth keeping, but
	// every target failing means discovery learned nothing - almost always an
	// under-scoped token. Returning a clean empty inventory there reported a
	// successful scan that had silently discovered nothing.
	if succeeded == 0 && discoveryErr != nil {
		return nil, discoveryErr
	}

	return in, nil
}

// getDiscoveryTargets resolves aliases (`auto`, `all`) to concrete target
// strings and deduplicates the result.
func getDiscoveryTargets(config *inventory.Config) []string {
	targets := config.GetDiscover().GetTargets()

	if stringx.Contains(targets, DiscoveryAll) {
		return All
	}

	res := []string{}
	for _, target := range targets {
		switch target {
		case DiscoveryAuto:
			res = append(res, Auto...)
		default:
			res = append(res, target)
		}
	}
	return stringx.DedupStringArray(res)
}

func discover(runtime *plugin.Runtime, conn *connection.OciConnection, target string) ([]*inventory.Asset, error) {
	// The tenancy asset already exists in the request (the user connected to it
	// directly), so there is no work to do for it here.
	if target == DiscoveryTenancy {
		return nil, nil
	}

	t, ok := ociDiscoveryTargetsByName[target]
	if !ok {
		log.Warn().Str("target", target).Msg("oci discovery: unknown target; skipping")
		return nil, nil
	}

	items, err := t.List(runtime)
	if err != nil {
		return nil, err
	}

	tenantID := conn.TenantID()
	assetList := make([]*inventory.Asset, 0, len(items))
	for i := range items {
		obj, ok := t.Extract(items[i])
		if !ok {
			log.Warn().Str("target", target).
				Msgf("oci discovery: unexpected item type %T in the collection; skipping", items[i])
			continue
		}
		appendIfNotNil(&assetList, ociObjectToAsset(ociObject{
			tenantID:    tenantID,
			compartment: obj.compartment,
			region:      fallbackRegion(obj.region),
			id:          obj.id,
			service:     t.Service,
			objectType:  t.ObjectType,
		}, t.Platform, obj.name, obj.labels, conn))
	}
	return assetList, nil
}

// appendIfNotNil guards the common ociObjectToAsset call pattern against
// returning a nil asset (unknown platform name). Nil entries in the
// inventory list cause downstream panics when cnspec iterates.
func appendIfNotNil(list *[]*inventory.Asset, a *inventory.Asset) {
	if a == nil {
		return
	}
	*list = append(*list, a)
}

// ociObject is the fine-grained handle used to construct a discovery asset.
type ociObject struct {
	tenantID    string
	compartment string
	region      string
	id          string // OCID or composite id (e.g. namespace/name for buckets)
	service     string
	objectType  string
}

// mondooOciObjectID builds the canonical platform id for a fine-grained OCI
// resource. Format mirrors AWS/GCP:
//
//	//platformid.api.mondoo.app/runtime/oci/<service>/v1/tenancies/<tenant>/regions/<region>/<objectType>/<id>
func mondooOciObjectID(obj ociObject) string {
	return "//platformid.api.mondoo.app/runtime/oci/" + obj.service +
		"/v1/tenancies/" + obj.tenantID +
		"/regions/" + obj.region +
		"/" + obj.objectType + "/" + obj.id
}

// ociObjectToAsset wraps an ociObject into an inventory.Asset suitable for
// returning from Discover(). Returns nil if the platform name is not in the
// catalog (discovery then skips it rather than emitting a broken asset).
func ociObjectToAsset(obj ociObject, platformName string, name string, labels map[string]string, conn *connection.OciConnection) *inventory.Asset {
	descriptor := PlatformByName(platformName)
	if descriptor == nil {
		log.Warn().Str("platform", platformName).Str("service", obj.service).
			Str("objectType", obj.objectType).
			Msg("oci discovery: platform is not in the catalog; skipping asset")
		return nil
	}
	if name == "" {
		name = obj.id
	}
	platformID := mondooOciObjectID(obj)
	// Clone to avoid mutating the parent connection's config under concurrent
	// discovery, and strip the discovery options so the sub-asset doesn't
	// recursively trigger another pass.
	clonedConfig := conn.Conf.Clone(
		inventory.WithoutDiscovery(),
		inventory.WithParentConnectionId(conn.Conf.Id),
	)
	clonedConfig.PlatformId = platformID
	platform := &inventory.Platform{}
	descriptor.Apply(platform)
	return &inventory.Asset{
		PlatformIds: []string{platformID},
		Name:        name,
		Platform:    platform,
		Labels:      labels,
		Connections: []*inventory.Config{clonedConfig},
	}
}

// tagsToLabels converts an MQL freeformTags map (map[string]interface{}) to
// the plain string map the asset schema expects. Non-string values are
// skipped — OCI freeform tags are declared as strings, but the MQL layer
// types them as `any` because they flow through the dict path.
func tagsToLabels(in map[string]interface{}) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// fallbackRegion returns "unknown" when a resource didn't expose a region at
// enumeration time. Using a literal string here (rather than "") keeps the
// platform id valid while making the gap obvious in asset listings.
func fallbackRegion(r string) string {
	if r == "" {
		return "unknown"
	}
	return r
}

// ociArgString reads a string-valued arg, returning "" if the key is missing,
// nil-valued, or not a string. Used by init functions that need to tolerate
// sparsely-populated args maps.
func ociArgString(args map[string]*llx.RawData, key string) string {
	if args == nil {
		return ""
	}
	raw, ok := args[key]
	if !ok || raw == nil || raw.Value == nil {
		return ""
	}
	s, ok := raw.Value.(string)
	if !ok {
		return ""
	}
	return s
}

// parsedOciPlatformID captures the components extracted from a canonical OCI
// asset platform id. It mirrors the structure produced by mondooOciObjectID.
type parsedOciPlatformID struct {
	tenantID   string
	region     string
	service    string
	objectType string
	// id is the last path segment. For most resources this is the OCID; for
	// object-storage buckets it's the composite "<namespace>/<name>" we emit
	// from discovery, so callers that need one or the other must split further.
	id string
}

// parseOciObjectPlatformID extracts the fine-grained components from a
// discovered asset's platform id. Returns (nil, false) when the string is not
// a recognized per-resource OCI platform id (e.g. the parent tenancy platform,
// or an unrelated provider).
//
// Expected format (see mondooOciObjectID):
//
//	//platformid.api.mondoo.app/runtime/oci/<service>/v1/tenancies/<tenant>/regions/<region>/<objectType>/<id>
//
// The final `<id>` segment may itself contain "/" (bucket composite id).
func parseOciObjectPlatformID(platformID string) (*parsedOciPlatformID, bool) {
	const prefix = "//platformid.api.mondoo.app/runtime/oci/"
	if !strings.HasPrefix(platformID, prefix) {
		return nil, false
	}
	rest := platformID[len(prefix):]
	// After the prefix we expect:
	//   <service>/v1/tenancies/<tenant>/regions/<region>/<objectType>/<id...>
	// Splitting on "/" with a cap of 8 leaves everything after the 7th slash
	// (i.e. the id) in the final element untouched — important for buckets
	// whose id is "<namespace>/<name>".
	parts := strings.SplitN(rest, "/", 8)
	if len(parts) < 8 {
		return nil, false
	}
	if parts[1] != "v1" || parts[2] != "tenancies" || parts[4] != "regions" {
		return nil, false
	}
	return &parsedOciPlatformID{
		service:    parts[0],
		tenantID:   parts[3],
		region:     parts[5],
		objectType: parts[6],
		id:         parts[7],
	}, true
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// isDoForbidden reports whether err is a 403 from the DigitalOcean API.
//
// It exists to keep "the token may not read this" separate from "there is
// nothing here". A denied read that degrades to an empty list makes "no
// findings" and "not allowed to look" indistinguishable, so callers
// propagate a 403 instead of swallowing it. Like isDoNotFound it matches
// only a godo error response, never a transport error: a connection reset
// is not evidence about permissions.
func isDoForbidden(err error) bool {
	var er *godo.ErrorResponse
	if errors.As(err, &er) {
		return er.Response != nil && er.Response.StatusCode == http.StatusForbidden
	}
	return false
}

// urnResourceType returns the kind segment of a DigitalOcean URN.
//
// URNs are shaped "do:<type>:<id>", e.g. "do:droplet:12345" or
// "do:dbaas:<uuid>". Anything that does not match that shape yields an
// empty string rather than a guess.
func urnResourceType(urn string) string {
	parts := strings.SplitN(strings.TrimSpace(urn), ":", 3)
	if len(parts) < 3 || parts[0] != "do" {
		return ""
	}
	return parts[1]
}

// ----- VPC membership -----

// members lists the resources placed inside the VPC.
func (r *mqlDigitaloceanVpc) members() ([]interface{}, error) {
	vpcID := r.Id.Data
	if vpcID == "" {
		return nil, errors.New("cannot list VPC members without a VPC id")
	}

	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	members, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.VPCMember, *godo.Response, error) {
		return client.VPCs.ListMembers(c, vpcID, nil, o)
	})
	if err != nil {
		// A VPC that has been removed between the listing and this call
		// answers 404; that is genuinely an empty membership. Denied and
		// transient reads propagate.
		if isDoNotFound(err) {
			return []interface{}{}, nil
		}
		return nil, err
	}

	out := make([]interface{}, 0, len(members))
	for _, m := range members {
		// godo hands back a slice of pointers; a nil entry would panic the
		// provider and take the whole scan with it.
		if m == nil || m.URN == "" {
			continue
		}
		id, err := resourceID("digitalocean.vpc.member", vpcID, m.URN)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.vpc.member", map[string]*llx.RawData{
			"__id":         llx.StringData(id),
			"vpcId":        llx.StringData(vpcID),
			"urn":          llx.StringData(m.URN),
			"resourceType": llx.StringData(urnResourceType(m.URN)),
			"name":         llx.StringData(m.Name),
			// An absent join time stays null rather than becoming the zero
			// time, which would report 1 January year 1 as a real date.
			"createdAt": llx.TimeDataPtr(timePtr(m.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ----- VPC routes -----

// routes lists the routes directing traffic out of the VPC.
func (r *mqlDigitaloceanVpc) routes() ([]interface{}, error) {
	vpcID := r.Id.Data
	if vpcID == "" {
		return nil, errors.New("cannot list VPC routes without a VPC id")
	}

	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	routes, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.Route, *godo.Response, error) {
		return client.Routes.ListVPCRoutes(c, vpcID, o)
	})
	if err != nil {
		// A VPC removed between the listing and this call answers 404, which
		// is genuinely an empty route table. Denied and transient reads
		// propagate rather than being reported as "no routes".
		if isDoNotFound(err) {
			return []interface{}{}, nil
		}
		return nil, err
	}

	out := make([]interface{}, 0, len(routes))
	for _, rt := range routes {
		// godo hands back a slice of pointers; a nil entry would panic the
		// provider and take the whole scan with it.
		if rt == nil || rt.ID == "" {
			continue
		}
		args, err := vpcRouteArgs(vpcID, rt)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.vpc.route", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// vpcRouteArgs maps a godo route onto the resource arguments. The route ID is
// only unique within its VPC, so the cache key carries both.
func vpcRouteArgs(vpcID string, rt *godo.Route) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.vpc.route", vpcID, rt.ID)
	if err != nil {
		return nil, err
	}
	targets := make([]interface{}, len(rt.TargetURNs))
	for i, u := range rt.TargetURNs {
		targets[i] = u
	}
	return map[string]*llx.RawData{
		"__id":            llx.StringData(id),
		"id":              llx.StringData(rt.ID),
		"type":            llx.StringData(rt.Type),
		"destinationCidr": llx.StringData(rt.DestinationCIDR),
		"targetUrns":      llx.ArrayData(targets, types.String),
		"modifiable":      llx.BoolData(rt.Modifiable),
		// An absent creation time stays null rather than becoming the zero
		// time, which would report 1 January year 1 as a real date.
		"createdAt": llx.TimeDataPtr(timePtr(rt.CreatedAt)),
	}, nil
}

// ----- Kubernetes cluster identity -----

// kubeconfigUsername returns the RBAC subject the platform-issued
// kubeconfig authenticates as.
func (r *mqlDigitaloceanKubernetesCluster) kubeconfigUsername() (string, error) {
	user, err := r.clusterUser()
	if err != nil {
		return "", err
	}
	if user == nil {
		// Nothing was read, so the field is null rather than an empty
		// username, which would read as an identity that authenticates
		// as nobody.
		r.KubeconfigUsername.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return user.Username, nil
}

// kubeconfigGroups returns the groups the platform-issued kubeconfig
// identity belongs to.
func (r *mqlDigitaloceanKubernetesCluster) kubeconfigGroups() ([]interface{}, error) {
	user, err := r.clusterUser()
	if err != nil {
		return nil, err
	}
	if user == nil {
		// A list accessor that returns (nil, nil) still renders as an empty
		// list, which would claim the identity was read and belongs to no
		// groups. Mark it null so an unread identity stays unread.
		r.KubeconfigGroups.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return toStringSlice(user.Groups), nil
}

// clusterUser fetches the cluster's platform user once and memoizes it.
//
// Both kubeconfig fields come from the same call, so it runs at most once
// per cluster. A nil user with a nil error means the cluster user is not
// readable on this cluster and the callers null their fields; a denied or
// transient read returns an error instead, so it never passes for an
// identity that simply has no groups.
func (r *mqlDigitaloceanKubernetesCluster) clusterUser() (*godo.KubernetesClusterUser, error) {
	r.clusterUserOnce.Do(func() {
		clusterID := r.Id.Data
		if clusterID == "" {
			r.clusterUserErr = errors.New("cannot read the cluster user without a cluster id")
			return
		}
		conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
		user, _, err := conn.Client().Kubernetes.GetUser(context.Background(), clusterID)
		if err != nil {
			// A cluster that is still provisioning, or one whose control
			// plane has gone away, answers 404. Everything else, a denied
			// read included, is reported.
			if isDoNotFound(err) {
				return
			}
			r.clusterUserErr = err
			return
		}
		// godo returns (nil, nil) on a body it could not decode into a user.
		r.clusterUserValue = user
	})
	return r.clusterUserValue, r.clusterUserErr
}

// ----- Container registries -----

// registries lists every container registry on the account.
//
// The account-wide listing is what makes a second registry visible: the
// legacy single-registry endpoint reports only the default one, so a
// scan that consults it alone misses every other registry an account
// holds. Accounts that do not have the multi-registry endpoint answer
// 404, and those fall back to the legacy endpoint so a single-registry
// account still lists its registry.
func (r *mqlDigitalocean) registries() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	ctx := context.Background()

	// The multi-registry endpoint returns every registry in one response;
	// godo's List takes no list options because the API paginates nothing
	// here.
	regs, _, err := client.Registries.List(ctx)
	if err != nil {
		if !isDoNotFound(err) {
			return nil, err
		}
		// Fall back to the legacy single-registry endpoint.
		reg, _, legacyErr := client.Registry.Get(ctx)
		if legacyErr != nil {
			// No registry configured at all is an empty list, not a failure.
			if isDoNotFound(legacyErr) {
				return []interface{}{}, nil
			}
			return nil, legacyErr
		}
		if reg == nil {
			return []interface{}{}, nil
		}
		regs = []*godo.Registry{reg}
	}

	// The subscription is billed per account rather than per registry, so
	// it is read once and reported on each.
	tier, subDict := registrySubscription(client)

	out := make([]interface{}, 0, len(regs))
	for _, reg := range regs {
		if reg == nil || reg.Name == "" {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.registry", registryArgs(reg, tier, subDict))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// registryArgs maps a registry onto the resource's fields.
func registryArgs(reg *godo.Registry, tier string, subDict map[string]interface{}) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"name":              llx.StringData(reg.Name),
		"storageUsageBytes": llx.IntData(int64(reg.StorageUsageBytes)),
		// DigitalOcean recomputes storage asynchronously and leaves the
		// timestamp zero until it has, so an absent value stays null.
		"storageUsageBytesUpdatedAt": llx.TimeDataPtr(timePtr(reg.StorageUsageBytesUpdatedAt)),
		"region":                     llx.StringData(reg.Region),
		"createdAt":                  llx.TimeData(reg.CreatedAt),
		"subscriptionTier":           llx.StringData(tier),
		"subscription":               llx.DictData(subDict),
	}
}

// registrySubscription reads the account's registry subscription tier.
//
// The subscription is supplementary metadata rather than a posture
// verdict, so a failure to read it leaves the tier empty instead of
// failing the registry listing.
func registrySubscription(client *godo.Client) (string, map[string]interface{}) {
	subDict := map[string]interface{}{}
	sub, _, err := client.Registry.GetSubscription(context.Background())
	if err != nil || sub == nil {
		return "", subDict
	}
	subDict["createdAt"] = sub.CreatedAt.Format(time.RFC3339)
	subDict["updatedAt"] = sub.UpdatedAt.Format(time.RFC3339)
	if sub.Tier == nil {
		return "", subDict
	}
	subDict["tierName"] = sub.Tier.Name
	subDict["tierSlug"] = sub.Tier.Slug
	subDict["includedRepositories"] = int64(sub.Tier.IncludedRepositories)
	subDict["includedStorageBytes"] = int64(sub.Tier.IncludedStorageBytes)
	subDict["includedBandwidthBytes"] = int64(sub.Tier.IncludedBandwidthBytes)
	subDict["monthlyPriceInCents"] = int64(sub.Tier.MonthlyPriceInCents)
	subDict["allowStorageOverage"] = sub.Tier.AllowStorageOverage
	return sub.Tier.Slug, subDict
}

// ----- Partner Network Connect advertised routes -----

// routes lists the CIDRs the remote side advertises into the attachment.
func (r *mqlDigitaloceanPartnerAttachment) routes() ([]interface{}, error) {
	attachmentID := r.Id.Data
	if attachmentID == "" {
		return nil, errors.New("cannot list routes without a partner attachment id")
	}

	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	routes, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.RemoteRoute, *godo.Response, error) {
		return client.PartnerAttachment.ListRoutes(c, attachmentID, o)
	})
	if err != nil {
		// Partner Network Connect is not enabled on every account, and an
		// attachment torn down mid-scan answers 404. Both are genuinely no
		// routes. A denied read is not, and propagates.
		if isDoNotFound(err) {
			return []interface{}{}, nil
		}
		return nil, err
	}

	out := make([]interface{}, 0, len(routes))
	for _, rt := range routes {
		if rt == nil || rt.Cidr == "" {
			continue
		}
		out = append(out, rt.Cidr)
	}
	return out, nil
}

// ----- Spaces key grants -----

// bucketGrants resolves the key's permission bindings to grant resources.
func (r *mqlDigitaloceanSpacesKey) bucketGrants() ([]interface{}, error) {
	accessKey := r.AccessKey.Data
	if accessKey == "" {
		return nil, errors.New("cannot build spaces key grants without an access key id")
	}

	out := make([]interface{}, 0, len(r.Grants.Data))
	for i, raw := range r.Grants.Data {
		grant, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		bucketName, _ := grant["bucket"].(string)
		permission, _ := grant["permission"].(string)

		// A grant scoped to every bucket carries no bucket name, so the
		// index it repeats along is its position on the key.
		key := bucketName
		if key == "" {
			key = fmt.Sprintf("all/%d", i)
		}
		id, err := resourceID("digitalocean.spacesKey.grant", accessKey, key, permission)
		if err != nil {
			return nil, err
		}

		res, err := CreateResource(r.MqlRuntime, "digitalocean.spacesKey.grant", map[string]*llx.RawData{
			"__id":       llx.StringData(id),
			"accessKey":  llx.StringData(accessKey),
			"bucketName": llx.StringData(bucketName),
			"permission": llx.StringData(permission),
			"allBuckets": llx.BoolData(bucketName == ""),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// bucket resolves the grant to the bucket it applies to.
func (r *mqlDigitaloceanSpacesKeyGrant) bucket() (*mqlDigitaloceanSpacesBucket, error) {
	name := r.BucketName.Data
	if name == "" {
		// The grant covers every bucket, so it names none.
		r.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// Resolved through the account's bucket listing rather than a per-grant
	// lookup, so a key with many grants costs one listing rather than one
	// call per grant.
	bucket, err := parent.spacesBucketByName(name)
	if err != nil {
		return nil, err
	}
	if bucket == nil {
		// The listing was read and holds no bucket by that name. This is
		// also what a grant naming a bucket in another account looks like.
		r.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return bucket, nil
}

// spacesBucketByName resolves a Spaces bucket by name from the account's
// bucket listing, building the index once.
func (r *mqlDigitalocean) spacesBucketByName(name string) (*mqlDigitaloceanSpacesBucket, error) {
	r.spacesBucketIndexOnce.Do(func() {
		buckets := r.GetSpacesBuckets()
		if buckets.Error != nil {
			r.spacesBucketIndexErr = buckets.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanSpacesBucket, len(buckets.Data))
		for _, b := range buckets.Data {
			mb, ok := b.(*mqlDigitaloceanSpacesBucket)
			if !ok {
				continue
			}
			idx[mb.Name.Data] = mb
		}
		r.spacesBucketIndex = idx
	})
	if r.spacesBucketIndexErr != nil {
		return nil, r.spacesBucketIndexErr
	}
	return r.spacesBucketIndex[name], nil
}

// ----- App Platform log destinations -----

// logDestinations lists the third-party services the app forwards logs to.
func (r *mqlDigitaloceanApp) logDestinations() ([]interface{}, error) {
	appID := r.Id.Data
	if appID == "" {
		return nil, errors.New("cannot list log destinations without an app id")
	}

	out := []interface{}{}
	for _, d := range appLogDestinations(r.cacheSpec) {
		id, err := resourceID("digitalocean.app.logDestination", appID, d.component, d.spec.Name)
		if err != nil {
			return nil, err
		}

		provider, endpoint, os := logDestinationTarget(d.spec)

		args := map[string]*llx.RawData{
			"__id":      llx.StringData(id),
			"appId":     llx.StringData(appID),
			"component": llx.StringData(d.component),
			"name":      llx.StringData(d.spec.Name),
			"provider":  llx.StringData(provider),
			"endpoint":  llx.StringData(endpoint),
			// TLSInsecure is reported on every destination the spec
			// declares, so it is a read value rather than a default.
			"tlsInsecure":           llx.BoolData(d.spec.TLSInsecure),
			"headerKeys":            llx.ArrayData(logDestinationHeaderKeys(d.spec), types.String),
			"opensearchEndpoint":    llx.StringData(os.endpoint),
			"opensearchIndexName":   llx.StringData(os.indexName),
			"opensearchClusterName": llx.StringData(os.clusterName),
		}

		res, err := CreateResource(r.MqlRuntime, "digitalocean.app.logDestination", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// scopedLogDestination pairs a destination with the component that
// declares it.
type scopedLogDestination struct {
	component string
	spec      *godo.AppLogDestinationSpec
}

// appLogDestinations collects the destinations declared for the whole app
// and for each of its components.
func appLogDestinations(spec *godo.AppSpec) []scopedLogDestination {
	if spec == nil {
		return nil
	}

	var out []scopedLogDestination
	appendDests := func(component string, dests []*godo.AppLogDestinationSpec) {
		for _, d := range dests {
			if d == nil {
				continue
			}
			out = append(out, scopedLogDestination{component: component, spec: d})
		}
	}

	// App Platform declares log forwarding per component; AppSpec carries no
	// app-wide destination list, so every destination is named by the
	// component that ships to it.
	// ForEachAppComponentSpec never returns an error when the callback doesn't.
	_ = spec.ForEachAppComponentSpec(func(c godo.AppComponentSpec) error {
		appendDests(c.GetName(), componentLogDestinations(c))
		return nil
	})
	return out
}

// componentLogDestinations returns the log destinations declared on a
// component.
//
// AppComponentSpec exposes only the name and type, so this switches over
// the concrete specs that carry destinations. Static sites and database
// components declare none. TestAppComponentLogDestinationsCoverage fails
// if the SDK grows a component type this misses.
func componentLogDestinations(c godo.AppComponentSpec) []*godo.AppLogDestinationSpec {
	switch t := c.(type) {
	case *godo.AppServiceSpec:
		return t.LogDestinations
	case *godo.AppWorkerSpec:
		return t.LogDestinations
	case *godo.AppJobSpec:
		return t.LogDestinations
	case *godo.AppFunctionsSpec:
		return t.LogDestinations
	}
	return nil
}

// opensearchTarget holds the OpenSearch-specific fields of a destination.
type opensearchTarget struct {
	endpoint    string
	indexName   string
	clusterName string
}

// logDestinationTarget names the service a destination ships to and the
// address it ships to.
//
// Exactly one of the managed-service blocks is populated per destination;
// a destination with none is a self-hosted endpoint. API tokens on the
// managed blocks are deliberately not read: the point is where logs go,
// not the credential used to get them there.
func logDestinationTarget(d *godo.AppLogDestinationSpec) (provider, endpoint string, os opensearchTarget) {
	if d == nil {
		return "", "", os
	}
	// Endpoints are written as URLs that may embed a password in their
	// userinfo, so every endpoint goes through redactURLPassword.
	switch {
	case d.Papertrail != nil:
		return "papertrail", redactURLPassword(d.Papertrail.Endpoint), os
	case d.Datadog != nil:
		return "datadog", redactURLPassword(d.Datadog.Endpoint), os
	case d.Logtail != nil:
		return "logtail", "", os
	case d.OpenSearch != nil:
		ep := redactURLPassword(d.OpenSearch.Endpoint)
		os = opensearchTarget{
			endpoint:    ep,
			indexName:   d.OpenSearch.IndexName,
			clusterName: d.OpenSearch.ClusterName,
		}
		return "opensearch", ep, os
	}
	return "custom", redactURLPassword(d.Endpoint), os
}

// logDestinationHeaderKeys returns the names of the headers attached to
// each delivery.
//
// Only the names are read. Header values on a log destination routinely
// carry the receiving service's API token, so they are never surfaced.
func logDestinationHeaderKeys(d *godo.AppLogDestinationSpec) []interface{} {
	if d == nil {
		return []interface{}{}
	}
	keys := make([]interface{}, 0, len(d.Headers))
	for _, h := range d.Headers {
		if h == nil || h.Key == "" {
			continue
		}
		keys = append(keys, h.Key)
	}
	return keys
}

// opensearchCluster resolves an OpenSearch destination to the managed
// database cluster backing it.
func (r *mqlDigitaloceanAppLogDestination) opensearchCluster() (*mqlDigitaloceanDatabase, error) {
	name := r.OpensearchClusterName.Data
	if name == "" {
		// A self-hosted OpenSearch endpoint, or a destination that is not
		// OpenSearch at all, is backed by no managed cluster.
		r.OpensearchCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// App Platform names the destination cluster rather than keying it, so
	// this resolves by name through the account's database listing.
	cluster, err := parent.databaseByName(name)
	if err != nil {
		return nil, err
	}
	if cluster == nil {
		r.OpensearchCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return cluster, nil
}

// databaseByName resolves a managed database cluster by name from the
// account's database listing, building the index once.
func (r *mqlDigitalocean) databaseByName(name string) (*mqlDigitaloceanDatabase, error) {
	r.databaseByNameIndexOnce.Do(func() {
		databases := r.GetDatabases()
		if databases.Error != nil {
			r.databaseByNameIndexErr = databases.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanDatabase, len(databases.Data))
		for _, d := range databases.Data {
			md, ok := d.(*mqlDigitaloceanDatabase)
			if !ok {
				continue
			}
			idx[md.Name.Data] = md
		}
		r.databaseByNameIndex = idx
	})
	if r.databaseByNameIndexErr != nil {
		return nil, r.databaseByNameIndexErr
	}
	return r.databaseByNameIndex[name], nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	sfs "github.com/stackitcloud/stackit-sdk-go/services/sfs/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The SDK exposes a distinct struct for the single-resource GET responses
// (e.g. GetResourcePoolResponseResourcePool) versus the LIST element
// (ResourcePool), even though they carry identical getters and nested types.
// These interfaces let one mapper serve both code paths.

type sfsResourcePoolData interface {
	GetId() string
	GetName() string
	GetState() string
	GetPerformanceClass() sfs.ResourcePoolPerformanceClass
	GetSpace() sfs.ResourcePoolSpace
	GetSnapshotPolicyOk() (*sfs.ResourcePoolSnapshotPolicy, bool)
	GetAvailabilityZone() string
	GetMountPath() string
	GetCountShares() int32
	GetIpAcl() []string
	GetSnapshotsAreVisible() bool
	GetLabels() map[string]string
	GetCreatedAtOk() (*time.Time, bool)
}

type sfsExportPolicyData interface {
	GetId() string
	GetName() string
	GetSharesUsingExportPolicy() int32
	GetRulesOk() ([]sfs.ShareExportPolicyRule, bool)
	GetLabels() map[string]string
	GetCreatedAtOk() (*time.Time, bool)
}

// derefFloat returns the value behind a *float64, or 0 when nil. SFS reports
// the space-usage gauges as optional floats; an absent value reads as 0.
func derefFloat[T float64 | *float64](p T) float64 {
	switch v := any(p).(type) {
	case float64:
		return v
	case *float64:
		if v == nil {
			return 0
		}
		return *v
	}
	return 0
}

// ------------------------- SFS namespace -------------------------

func (r *mqlStackitSfs) resourcePools() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Sfs()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListResourcePools(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	pools, _ := resp.GetResourcePoolsOk()
	out := make([]any, 0, len(pools))
	for i := range pools {
		res, err := CreateResource(r.MqlRuntime, "stackit.sfs.resourcePool", sfsResourcePoolArgs(c.Region(), &pools[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitSfs) exportPolicies() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Sfs()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListShareExportPolicies(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	policies, _ := resp.GetShareExportPoliciesOk()
	out := make([]any, 0, len(policies))
	for i := range policies {
		res, err := newSfsExportPolicy(r.MqlRuntime, c.Region(), &policies[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitSfs) lockId() (string, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Sfs()
	if err != nil {
		return "", err
	}
	resp, err := client.DefaultAPI.GetLock(bgctx(), c.Region(), c.ProjectID()).Execute()
	if err != nil {
		if isNotFound(err) {
			return "", nil
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return "", nil
			}
			return "", refusal(err)
		}
		return "", err
	}
	return resp.GetLockId(), nil
}

// ------------------------- SFS resource pool -------------------------

// sfsResourcePoolArgs maps a pool onto the stackit.sfs.resourcePool fields.
// The three usage gauges (used, available, used by snapshots) are left out:
// the SDK documents them as "only available when retrieving a single Resource
// Pool by ID", so the list response carries zeros for every pool. They are
// read lazily through fetchSpace, which the init path pre-seeds from the
// single-pool response it already holds (see sfsResourcePoolSpaceArgs).
func sfsResourcePoolArgs(region string, rp sfsResourcePoolData) map[string]*llx.RawData {
	pc := rp.GetPerformanceClass()
	sp := rp.GetSpace()
	snapPolicyID, snapPolicyName := "", ""
	if v, ok := rp.GetSnapshotPolicyOk(); ok && v != nil {
		snapPolicyID = v.GetId()
		snapPolicyName = v.GetName()
	}
	return map[string]*llx.RawData{
		"id":                         llx.StringData(rp.GetId()),
		"name":                       llx.StringData(rp.GetName()),
		"state":                      llx.StringData(rp.GetState()),
		"region":                     llx.StringData(region),
		"performanceClass":           llx.StringData(pc.GetName()),
		"performanceClassPeakIops":   llx.IntData(pc.GetPeakIops()),
		"performanceClassThroughput": llx.IntData(pc.GetThroughput()),
		"availabilityZone":           llx.StringData(rp.GetAvailabilityZone()),
		"mountPath":                  llx.StringData(rp.GetMountPath()),
		"countShares":                llx.IntData(rp.GetCountShares()),
		"sizeGigabytes":              llx.IntData(sp.GetSizeGigabytes()),
		"ipAcl":                      strSliceData(rp.GetIpAcl()),
		"snapshotsAreVisible":        llx.BoolData(rp.GetSnapshotsAreVisible()),
		"snapshotPolicyId":           llx.StringData(snapPolicyID),
		"snapshotPolicyName":         llx.StringData(snapPolicyName),
		"labels":                     labelData(rp.GetLabels()),
		"createdAt":                  llx.TimeDataPtr(timeOrNil(rp.GetCreatedAtOk())),
	}
}

// sfsResourcePoolSpaceArgs adds the usage gauges to a pool's args. Only call
// it with a pool that came from GetResourcePool; on a list element the gauges
// are absent and would read as 0.
func sfsResourcePoolSpaceArgs(args map[string]*llx.RawData, sp sfs.ResourcePoolSpace) map[string]*llx.RawData {
	args["usedGigabytes"] = llx.FloatData(derefFloat(sp.GetUsedGigabytes()))
	args["availableGigabytes"] = llx.FloatData(derefFloat(sp.GetAvailableGigabytes()))
	args["usedBySnapshotsGigabytes"] = llx.FloatData(derefFloat(sp.GetUsedBySnapshotsGigabytes()))
	return args
}

type mqlStackitSfsResourcePoolInternal struct {
	spaceFetched atomic.Bool
	space        *sfs.ResourcePoolSpace
	spaceLock    sync.Mutex
}

// fetchSpace reads the pool's usage gauges through GetResourcePool once and
// caches them; the three gauge accessors share the call. A nil result with a
// nil error means the read was denied, and the gauges report null rather
// than a zero that would read as an empty pool.
func (r *mqlStackitSfsResourcePool) fetchSpace() (*sfs.ResourcePoolSpace, error) {
	if r.spaceFetched.Load() {
		return r.space, nil
	}
	r.spaceLock.Lock()
	defer r.spaceLock.Unlock()
	if r.spaceFetched.Load() {
		return r.space, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.Sfs()
	if err != nil {
		return nil, err
	}
	region := r.Region.Data
	if region == "" {
		region = c.Region()
	}
	resp, err := client.DefaultAPI.GetResourcePool(bgctx(), c.ProjectID(), region, r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.spaceFetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	if pool, ok := resp.GetResourcePoolOk(); ok && pool != nil {
		sp := pool.GetSpace()
		r.space = &sp
	}
	r.spaceFetched.Store(true)
	return r.space, nil
}

func (r *mqlStackitSfsResourcePool) usedGigabytes() (float64, error) {
	sp, err := r.fetchSpace()
	if err != nil {
		return 0, err
	}
	if sp == nil {
		r.UsedGigabytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return derefFloat(sp.GetUsedGigabytes()), nil
}

func (r *mqlStackitSfsResourcePool) availableGigabytes() (float64, error) {
	sp, err := r.fetchSpace()
	if err != nil {
		return 0, err
	}
	if sp == nil {
		r.AvailableGigabytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return derefFloat(sp.GetAvailableGigabytes()), nil
}

func (r *mqlStackitSfsResourcePool) usedBySnapshotsGigabytes() (float64, error) {
	sp, err := r.fetchSpace()
	if err != nil {
		return 0, err
	}
	if sp == nil {
		r.UsedBySnapshotsGigabytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return derefFloat(sp.GetUsedBySnapshotsGigabytes()), nil
}

func (r *mqlStackitSfsResourcePool) id() (string, error) {
	return "stackit.sfs.resourcePool/" + r.Id.Data, nil
}

func (r *mqlStackitSfsResourcePool) shares() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Sfs()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListShares(bgctx(), c.ProjectID(), r.Region.Data, r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	shares, _ := resp.GetSharesOk()
	out := make([]any, 0, len(shares))
	for i := range shares {
		sh := shares[i]
		// The share carries its export policy inline, rules included, so the
		// policy resource is built here rather than re-fetched by id later.
		var exportPolicy *mqlStackitSfsExportPolicy
		if v, ok := sh.GetExportPolicyOk(); ok && v != nil && v.GetId() != "" {
			exportPolicy, err = newSfsExportPolicy(r.MqlRuntime, r.Region.Data, v)
			if err != nil {
				return nil, err
			}
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.sfs.share", map[string]*llx.RawData{
			"id":                      llx.StringData(sh.GetId()),
			"name":                    llx.StringData(sh.GetName()),
			"state":                   llx.StringData(sh.GetState()),
			"mountPath":               llx.StringData(sh.GetMountPath()),
			"spaceHardLimitGigabytes": llx.IntData(sh.GetSpaceHardLimitGigabytes()),
			"labels":                  labelData(sh.GetLabels()),
			"createdAt":               llx.TimeDataPtr(timeOrNil(sh.GetCreatedAtOk())),
		})
		if err != nil {
			return nil, err
		}
		share := res.(*mqlStackitSfsShare)
		share.cacheExportPolicy = exportPolicy
		share.cacheRegion = r.Region.Data
		out = append(out, share)
	}
	return out, nil
}

func (r *mqlStackitSfsResourcePool) snapshots() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Sfs()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListResourcePoolSnapshots(bgctx(), c.ProjectID(), r.Region.Data, r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	snaps, _ := resp.GetResourcePoolSnapshotsOk()
	out := make([]any, 0, len(snaps))
	for i := range snaps {
		snap := snaps[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.sfs.snapshot", map[string]*llx.RawData{
			"__id":                 llx.StringData("stackit.sfs.snapshot/" + r.Id.Data + "/" + snap.GetSnapshotName()),
			"name":                 llx.StringData(snap.GetSnapshotName()),
			"sizeGigabytes":        llx.IntData(snap.GetSizeGigabytes()),
			"logicalSizeGigabytes": llx.IntData(snap.GetLogicalSizeGigabytes()),
			"comment":              llx.StringData(snap.GetComment()),
			"snaplockExpiryTime":   llx.TimeDataPtr(timeOrNil(snap.GetSnaplockExpiryTimeOk())),
			"createdAt":            llx.TimeDataPtr(timeOrNil(snap.GetCreatedAtOk())),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func initStackitSfsResourcePool(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.Sfs()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetResourcePool(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	pool, ok := resp.GetResourcePoolOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit.sfs.resourcePool with id %q not found", id)
	}
	// The single-pool response is the one place the usage gauges are
	// populated, so seed them here instead of paying fetchSpace later.
	args = sfsResourcePoolSpaceArgs(sfsResourcePoolArgs(c.Region(), pool), pool.GetSpace())
	res, err := CreateResource(runtime, "stackit.sfs.resourcePool", args)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// ------------------------- SFS share -------------------------

type mqlStackitSfsShareInternal struct {
	// cacheExportPolicy is the policy the share response carried inline,
	// already built as a resource; nil when the share has no policy.
	cacheExportPolicy *mqlStackitSfsExportPolicy
	cacheRegion       string
}

func (r *mqlStackitSfsShare) id() (string, error) {
	return "stackit.sfs.share/" + r.Id.Data, nil
}

func (r *mqlStackitSfsShare) exportPolicy() (*mqlStackitSfsExportPolicy, error) {
	if r.cacheExportPolicy == nil {
		r.ExportPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.cacheExportPolicy, nil
}

// ------------------------- SFS share export policy -------------------------

type mqlStackitSfsExportPolicyInternal struct {
	cacheRegion string
	// cacheRules holds the rules the policy response carried inline. Both
	// ListShareExportPolicies and the policy nested on a share return them,
	// so rules() only calls GetShareExportPolicy when the field was omitted.
	cacheRules    []sfs.ShareExportPolicyRule
	cacheRulesSet bool
}

func newSfsExportPolicy(runtime *plugin.Runtime, region string, p sfsExportPolicyData) (*mqlStackitSfsExportPolicy, error) {
	res, err := CreateResource(runtime, "stackit.sfs.exportPolicy", map[string]*llx.RawData{
		"id":                      llx.StringData(p.GetId()),
		"name":                    llx.StringData(p.GetName()),
		"sharesUsingExportPolicy": llx.IntData(p.GetSharesUsingExportPolicy()),
		"labels":                  labelData(p.GetLabels()),
		"createdAt":               llx.TimeDataPtr(timeOrNil(p.GetCreatedAtOk())),
	})
	if err != nil {
		return nil, err
	}
	ep := res.(*mqlStackitSfsExportPolicy)
	ep.cacheRegion = region
	if rules, ok := p.GetRulesOk(); ok {
		ep.cacheRules = rules
		ep.cacheRulesSet = true
	}
	return ep, nil
}

func (r *mqlStackitSfsExportPolicy) id() (string, error) {
	return "stackit.sfs.exportPolicy/" + r.Id.Data, nil
}

func (r *mqlStackitSfsExportPolicy) rules() ([]any, error) {
	rules := r.cacheRules
	if !r.cacheRulesSet {
		c := conn(r.MqlRuntime)
		client, err := c.Sfs()
		if err != nil {
			return nil, err
		}
		region := r.cacheRegion
		if region == "" {
			region = c.Region()
		}
		resp, err := client.DefaultAPI.GetShareExportPolicy(bgctx(), c.ProjectID(), region, r.Id.Data).Execute()
		if err != nil {
			if isAccessDenied(err) {
				return deniedList(err)
			}
			return nil, err
		}
		pol, ok := resp.GetShareExportPolicyOk()
		if !ok {
			return []any{}, nil
		}
		rules, _ = pol.GetRulesOk()
	}
	out := make([]any, 0, len(rules))
	for i := range rules {
		rule := rules[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.sfs.exportPolicy.rule", map[string]*llx.RawData{
			"id":          llx.StringData(rule.GetId()),
			"order":       llx.IntData(rule.GetOrder()),
			"ipAcl":       strSliceData(rule.GetIpAcl()),
			"description": llx.StringData(rule.GetDescription()),
			"readOnly":    llx.BoolDataPtr(optBool(rule.GetReadOnlyOk())),
			"superUser":   llx.BoolDataPtr(optBool(rule.GetSuperUserOk())),
			"setUuid":     llx.BoolDataPtr(optBool(rule.GetSetUuidOk())),
			"createdAt":   llx.TimeDataPtr(timeOrNil(rule.GetCreatedAtOk())),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitSfsExportPolicyRule) id() (string, error) {
	return "stackit.sfs.exportPolicy.rule/" + r.Id.Data, nil
}

func initStackitSfsExportPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.Sfs()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetShareExportPolicy(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	pol, ok := resp.GetShareExportPolicyOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit.sfs.exportPolicy with id %q not found", id)
	}
	res, err := newSfsExportPolicy(runtime, c.Region(), pol)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

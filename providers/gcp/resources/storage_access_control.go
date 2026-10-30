// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/storage/v1"
)

// bucketAccessControlEntry is the shape shared by BucketAccessControl and
// ObjectAccessControl. The two SDK types carry the same grant fields and differ
// only in the object-scoped extras, so one resource serves both lists.
type bucketAccessControlEntry struct {
	entity          string
	entityId        string
	role            string
	email           string
	domain          string
	projectTeamId   string
	projectTeamRole string
}

func bucketAclEntries(acl []*storage.BucketAccessControl) []bucketAccessControlEntry {
	res := make([]bucketAccessControlEntry, 0, len(acl))
	for _, a := range acl {
		if a == nil {
			continue
		}
		e := bucketAccessControlEntry{
			entity:   a.Entity,
			entityId: a.EntityId,
			role:     a.Role,
			email:    a.Email,
			domain:   a.Domain,
		}
		if a.ProjectTeam != nil {
			e.projectTeamId = a.ProjectTeam.ProjectNumber
			e.projectTeamRole = a.ProjectTeam.Team
		}
		res = append(res, e)
	}
	return res
}

func objectAclEntries(acl []*storage.ObjectAccessControl) []bucketAccessControlEntry {
	res := make([]bucketAccessControlEntry, 0, len(acl))
	for _, a := range acl {
		if a == nil {
			continue
		}
		e := bucketAccessControlEntry{
			entity:   a.Entity,
			entityId: a.EntityId,
			role:     a.Role,
			email:    a.Email,
			domain:   a.Domain,
		}
		if a.ProjectTeam != nil {
			e.projectTeamId = a.ProjectTeam.ProjectNumber
			e.projectTeamRole = a.ProjectTeam.Team
		}
		res = append(res, e)
	}
	return res
}

// newMqlBucketAccessControl builds the ACL resources for one of a bucket's two
// legacy lists.
//
// The list is scoped by which list it came from, because a bucket's own ACL and
// its default object ACL routinely name the same entity and would otherwise
// share a cache key.
func newMqlBucketAccessControl(runtime *plugin.Runtime, bucketID string, list string, entries []bucketAccessControlEntry) ([]any, error) {
	res := make([]any, 0, len(entries))
	for _, e := range entries {
		mqlEntry, err := CreateResource(runtime, "gcp.project.storageService.bucket.accessControl", map[string]*llx.RawData{
			"__id":            llx.StringData(bucketID + "/" + list + "/" + e.entity),
			"entity":          llx.StringData(e.entity),
			"entityId":        llx.StringData(e.entityId),
			"role":            llx.StringData(e.role),
			"email":           llx.StringData(e.email),
			"domain":          llx.StringData(e.domain),
			"projectTeamId":   llx.StringData(e.projectTeamId),
			"projectTeamRole": llx.StringData(e.projectTeamRole),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEntry)
	}
	return res, nil
}

func (g *mqlGcpProjectStorageServiceBucket) accessControl() ([]any, error) {
	if err := g.fetchAcls(); err != nil {
		return nil, err
	}
	// Uniform bucket-level access removes the legacy ACL outright, and GCS then
	// returns no list at all. Reporting an empty list would claim the bucket has
	// an ACL that grants nothing, which is a different fact and would let a
	// "no public entity in the ACL" check pass for the wrong reason.
	if g.cacheAcl == nil {
		g.AccessControl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlBucketAccessControl(g.MqlRuntime, g.__id, "acl", bucketAclEntries(g.cacheAcl))
}

func (g *mqlGcpProjectStorageServiceBucket) defaultObjectAccessControl() ([]any, error) {
	if err := g.fetchAcls(); err != nil {
		return nil, err
	}
	if g.cacheDefaultObjAcl == nil {
		g.DefaultObjectAccessControl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlBucketAccessControl(g.MqlRuntime, g.__id, "defaultObjectAcl", objectAclEntries(g.cacheDefaultObjAcl))
}

type mqlGcpProjectStorageServiceBucketIpFilterConfigVpcSourceInternal struct {
	cacheNetworkUrl string
}

func (g *mqlGcpProjectStorageServiceBucketIpFilterConfigVpcSource) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	net, err := getNetworkByUrl(g.cacheNetworkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return net, nil
}

// newMqlBucketIpFilterConfig promotes a bucket's IP filter. Returns llx.NilData
// when the bucket has no filter configured, which leaves it reachable from
// anywhere its IAM policy allows.
func newMqlBucketIpFilterConfig(runtime *plugin.Runtime, bucketID string, f *storage.BucketIpFilter) (*llx.RawData, error) {
	if f == nil {
		return llx.NilData, nil
	}

	publicRanges := []any{}
	if f.PublicNetworkSource != nil {
		for _, r := range f.PublicNetworkSource.AllowedIpCidrRanges {
			publicRanges = append(publicRanges, r)
		}
	}

	vpcSources := make([]any, 0, len(f.VpcNetworkSources))
	for i, v := range f.VpcNetworkSources {
		if v == nil {
			continue
		}
		ranges := []any{}
		for _, r := range v.AllowedIpCidrRanges {
			ranges = append(ranges, r)
		}
		// The network is keyed into the id because a filter may name the same
		// network twice with different ranges, and an index alone would not
		// survive a reordering of the list.
		mqlSource, err := CreateResource(runtime, "gcp.project.storageService.bucket.ipFilterConfig.vpcSource", map[string]*llx.RawData{
			"__id":                llx.StringData(bucketID + "/ipFilter/vpcSource/" + strconv.Itoa(i) + "/" + v.Network),
			"allowedIpCidrRanges": llx.ArrayData(ranges, types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlSource.(*mqlGcpProjectStorageServiceBucketIpFilterConfigVpcSource).cacheNetworkUrl = v.Network
		vpcSources = append(vpcSources, mqlSource)
	}

	res, err := CreateResource(runtime, "gcp.project.storageService.bucket.ipFilterConfig", map[string]*llx.RawData{
		"__id":                       llx.StringData(bucketID + "/ipFilterConfig"),
		"mode":                       llx.StringData(f.Mode),
		"allowAllServiceAgentAccess": llx.BoolData(f.AllowAllServiceAgentAccess),
		"allowCrossOrgVpcs":          llx.BoolData(f.AllowCrossOrgVpcs),
		"publicAllowedIpCidrRanges":  llx.ArrayData(publicRanges, types.String),
		"vpcSources":                 llx.ArrayData(vpcSources, types.Resource("gcp.project.storageService.bucket.ipFilterConfig.vpcSource")),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.project.storageService.bucket.ipFilterConfig"), nil
}

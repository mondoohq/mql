// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"
	"time"

	csclient "github.com/alibabacloud-go/cs-20151215/v8/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// csAllClusters is the resource id Container Service uses for a grant that
// covers every cluster in the account rather than a named one.
const csAllClusters = "all-clusters"

// csParseTime parses a cluster-check timestamp. The API returns RFC3339 with
// nanosecond precision; an unparseable or absent value stays null rather than
// becoming the zero time, which would report 1 January year 1 as a real run.
func csParseTime(s *string) *time.Time {
	v := tea.StringValue(s)
	if v == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			return &t
		}
	}
	return nil
}

// csGrantID builds the cache key for a grant. A principal can hold several
// grants, and the same principal can hold different roles on different
// namespaces of one cluster, so the key has to carry the principal, the scope
// it applies at, and the role it confers. Dropping any one of them would make
// two real grants share a key, and the second would be reported with the
// first one's values.
//
// The separator is llx.IDSeparator rather than a slash because resourceID
// legitimately contains slashes ("<clusterId>/<namespace>"). No component can
// contain it, so the joined key cannot be read two ways whatever the
// components hold.
func csGrantID(uid, resourceType, resourceID, roleType, roleName string) string {
	return strings.Join([]string{uid, resourceType, resourceID, roleType, roleName}, llx.IDSeparator)
}

// csGrantCoversCluster reports whether a grant reaches the given cluster. A
// grant is either scoped to one cluster (resourceId is the cluster id), to one
// namespace of a cluster (clusterId/namespace), or to every cluster in the
// account (the all-clusters sentinel), and the last of those reaches a cluster
// without naming it.
func csGrantCoversCluster(resourceID, clusterID string) bool {
	if clusterID == "" || resourceID == "" {
		return false
	}
	if resourceID == csAllClusters {
		return true
	}
	if resourceID == clusterID {
		return true
	}
	// namespace scope: "<clusterId>/<namespace>"
	return strings.HasPrefix(resourceID, clusterID+"/")
}

// mqlAlicloudCsClusterCheckInternal holds the id of the cluster the run belongs
// to, so the resource can rebuild its own cluster-qualified cache key.
type mqlAlicloudCsClusterCheckInternal struct {
	cacheClusterID string
}

// csClusterCheckID builds the cache key for an inspection run. The run id is
// qualified with the cluster because the API gives no guarantee that run ids are
// unique across clusters, and an id that repeated would make the second
// cluster's runs collide with the first's in the resource cache and report the
// first cluster's results.
func csClusterCheckID(clusterID, checkID string) string {
	return clusterID + "/" + checkID
}

// mqlAlicloudCsGrantInternal holds the principal and cluster id the grant was
// built from. The RAM user or role is kept as the resource the sweep already
// listed, so resolving user()/role() costs no further calls.
type mqlAlicloudCsGrantInternal struct {
	cacheClusterID string
	cacheUser      *mqlAlicloudRamUser
	cacheRole      *mqlAlicloudRamRole
}

// csPrincipal is one RAM identity to ask DescribeUserPermission about.
type csPrincipal struct {
	uid  string
	name string
	user *mqlAlicloudRamUser
	role *mqlAlicloudRamRole
}

// grants sweeps the account's RAM users and roles for their cluster access
// grants.
//
// Container Service reports grants per principal, not per cluster:
// DescribeUserPermission takes a RAM user or role id and there is no
// cluster-keyed listing, so answering "who can reach this cluster" costs one
// call per principal. The sweep is therefore memoized on this singleton and
// shared with every alicloud.cs.cluster.grants read, which is why the per
// cluster accessor resolves through here rather than fetching for itself.
func (r *mqlAlicloudCs) grants() ([]any, error) {
	return r.grantSweep()
}

func (r *mqlAlicloudCs) grantSweep() ([]any, error) {
	r.grantLock.Lock()
	defer r.grantLock.Unlock()
	if r.grantDone {
		return r.grantList, r.grantErr
	}
	r.grantDone = true

	principals, err := r.ramPrincipals()
	if err != nil {
		r.grantErr = err
		return nil, err
	}
	if len(principals) == 0 {
		r.grantList = []any{}
		return r.grantList, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		r.grantErr = err
		return nil, err
	}
	if len(regions) == 0 {
		r.grantList = []any{}
		return r.grantList, nil
	}
	// DescribeUserPermission is account-scoped; any enabled region's endpoint
	// answers for the whole account, so one client serves the sweep.
	client, err := conn.CsClient(regions[0])
	if err != nil {
		r.grantErr = err
		return nil, err
	}

	res := []any{}
	for _, principal := range principals {
		if principal.uid == "" {
			continue
		}
		resp, err := client.DescribeUserPermission(tea.String(principal.uid))
		if err != nil {
			// One principal that cannot be read must not blind the sweep: the
			// caller loses that principal's grants, not everybody's. Logged so
			// a partial answer leaves a trace rather than looking complete.
			log.Debug().Err(err).Str("principal", principal.name).
				Msg("alicloud> could not read ACK cluster permissions for principal")
			continue
		}
		if resp == nil {
			continue
		}
		for _, perm := range resp.Body {
			if perm == nil {
				continue
			}
			grant, err := newCsGrant(r.MqlRuntime, principal, perm)
			if err != nil {
				r.grantErr = err
				return nil, err
			}
			res = append(res, grant)
		}
	}

	r.grantList = res
	return r.grantList, nil
}

// ramPrincipals lists the RAM users and roles to ask about, reusing the
// alicloud.ram resources so the identities are the ones already modelled.
func (r *mqlAlicloudCs) ramPrincipals() ([]csPrincipal, error) {
	ram, err := CreateResource(r.MqlRuntime, "alicloud.ram", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	mqlRam := ram.(*mqlAlicloudRam)

	res := []csPrincipal{}

	users := mqlRam.GetUsers()
	if users.Error != nil {
		return nil, users.Error
	}
	for _, entry := range users.Data {
		user, ok := entry.(*mqlAlicloudRamUser)
		if !ok {
			continue
		}
		res = append(res, csPrincipal{
			uid:  user.UserId.Data,
			name: user.UserName.Data,
			user: user,
		})
	}

	roles := mqlRam.GetRoles()
	if roles.Error != nil {
		return nil, roles.Error
	}
	for _, entry := range roles.Data {
		role, ok := entry.(*mqlAlicloudRamRole)
		if !ok {
			continue
		}
		res = append(res, csPrincipal{
			uid:  role.RoleId.Data,
			name: role.RoleName.Data,
			role: role,
		})
	}

	return res, nil
}

func newCsGrant(runtime *plugin.Runtime, principal csPrincipal, perm *csclient.DescribeUserPermissionResponseBody) (*mqlAlicloudCsGrant, error) {
	resourceType := tea.StringValue(perm.ResourceType)
	resourceID := tea.StringValue(perm.ResourceId)
	roleType := tea.StringValue(perm.RoleType)
	roleName := tea.StringValue(perm.RoleName)

	// The cluster id is the resource id for a cluster-scoped grant and its
	// leading segment for a namespace-scoped one. A grant covering every
	// cluster names none, so it resolves to no cluster.
	clusterID := ""
	if resourceID != csAllClusters {
		clusterID, _, _ = strings.Cut(resourceID, "/")
	}

	resource, err := CreateResource(runtime, "alicloud.cs.grant", map[string]*llx.RawData{
		"__id":          llx.StringData(csGrantID(principal.uid, resourceType, resourceID, roleType, roleName)),
		"uid":           llx.StringData(principal.uid),
		"principalName": llx.StringData(principal.name),
		"ramRole":       llx.BoolData(tea.Int64Value(perm.IsRamRole) == 1),
		"resourceType":  llx.StringData(resourceType),
		"resourceId":    llx.StringData(resourceID),
		"roleType":      llx.StringData(roleType),
		"roleName":      llx.StringData(roleName),
		"owner":         llx.BoolData(tea.Int64Value(perm.IsOwner) == 1),
	})
	if err != nil {
		return nil, err
	}

	grant := resource.(*mqlAlicloudCsGrant)
	grant.cacheClusterID = clusterID
	grant.cacheUser = principal.user
	grant.cacheRole = principal.role
	return grant, nil
}

func (r *mqlAlicloudCsGrant) id() (string, error) {
	return csGrantID(r.Uid.Data, r.ResourceType.Data, r.ResourceId.Data, r.RoleType.Data, r.RoleName.Data), nil
}

// cluster resolves the cluster the grant names by scanning the memoized cluster
// list rather than through NewResource. The grant carries a cluster id but not
// its region, which the by-id init needs, and a per-grant init would cost one
// listing per grant because init runs before the resource cache is consulted.
//
// "No such cluster" and "could not read the clusters" are kept apart. A grant
// that names nothing (it covers every cluster) or names a cluster that has been
// deleted resolves to null, because neither should fail an account-wide query.
// A failure to read the listing propagates: reporting null there would state
// that the grant reaches no cluster, which is a claim nobody verified, and it
// would silently drop the grant from a filter on the cluster it does reach.
// The listing already tolerates a single unreachable region on its own, so an
// error reaching here is a hard failure rather than one bad region.
func (r *mqlAlicloudCsGrant) cluster() (*mqlAlicloudCsCluster, error) {
	if r.cacheClusterID == "" {
		r.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	cluster, err := resolveCsClusterByID(r.MqlRuntime, r.cacheClusterID)
	if err != nil {
		return nil, err
	}
	if cluster == nil {
		r.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return cluster, nil
}

func (r *mqlAlicloudCsGrant) user() (*mqlAlicloudRamUser, error) {
	if r.cacheUser == nil {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.cacheUser, nil
}

func (r *mqlAlicloudCsGrant) role() (*mqlAlicloudRamRole, error) {
	if r.cacheRole == nil {
		r.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.cacheRole, nil
}

// resolveCsClusterByID finds an already-listed cluster by its id, across every
// region. The listing is memoized by the runtime, so repeated lookups are free.
func resolveCsClusterByID(runtime *plugin.Runtime, clusterID string) (*mqlAlicloudCsCluster, error) {
	cs, err := CreateResource(runtime, "alicloud.cs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	clusters := cs.(*mqlAlicloudCs).GetClusters()
	if clusters.Error != nil {
		return nil, clusters.Error
	}
	for _, entry := range clusters.Data {
		cluster, ok := entry.(*mqlAlicloudCsCluster)
		if !ok {
			continue
		}
		if cluster.ClusterId.Data == clusterID {
			return cluster, nil
		}
	}
	return nil, nil
}

// grants returns the account's grants that reach this cluster. It reads the
// sweep memoized on the parent service, so asking every cluster costs one sweep
// between them rather than one each.
func (r *mqlAlicloudCsCluster) grants() ([]any, error) {
	cs, err := CreateResource(r.MqlRuntime, "alicloud.cs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all, err := cs.(*mqlAlicloudCs).grantSweep()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, entry := range all {
		grant, ok := entry.(*mqlAlicloudCsGrant)
		if !ok {
			continue
		}
		if csGrantCoversCluster(grant.ResourceId.Data, r.clusterId) {
			res = append(res, grant)
		}
	}
	return res, nil
}

// checks lists the cluster's inspection runs. ListClusterChecks returns the
// whole set in one response, so there is no paging to walk.
func (r *mqlAlicloudCsCluster) checks() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CsClient(r.region)
	if err != nil {
		return nil, err
	}

	resp, err := client.ListClusterChecks(tea.String(r.clusterId), &csclient.ListClusterChecksRequest{})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, check := range resp.Body.Checks {
		if check == nil {
			continue
		}
		checkID := tea.StringValue(check.CheckId)
		if checkID == "" {
			// the check id is the cache key; an entry without one would collide
			// with every other unnamed entry and report the first one's values
			log.Debug().Str("cluster", r.clusterId).
				Msg("alicloud> skipping ACK cluster check with no check id")
			continue
		}
		resource, err := CreateResource(r.MqlRuntime, "alicloud.cs.cluster.check", map[string]*llx.RawData{
			"__id":       llx.StringData(csClusterCheckID(r.clusterId, checkID)),
			"checkId":    llx.StringData(checkID),
			"type":       llx.StringDataPtr(check.Type),
			"status":     llx.StringDataPtr(check.Status),
			"message":    llx.StringDataPtr(check.Message),
			"createdAt":  llx.TimeDataPtr(csParseTime(check.CreatedAt)),
			"finishedAt": llx.TimeDataPtr(csParseTime(check.FinishedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlCheck := resource.(*mqlAlicloudCsClusterCheck)
		mqlCheck.cacheClusterID = r.clusterId
		res = append(res, mqlCheck)
	}
	return res, nil
}

func (r *mqlAlicloudCsClusterCheck) id() (string, error) {
	return csClusterCheckID(r.cacheClusterID, r.CheckId.Data), nil
}

// mqlAlicloudCsInternal memoizes the account-wide grant sweep so every cluster
// shares one pass over the account's RAM principals.
type mqlAlicloudCsInternal struct {
	grantLock sync.Mutex
	grantDone bool
	grantList []any
	grantErr  error
}

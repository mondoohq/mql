// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	crclient "github.com/alibabacloud-go/cr-20181201/v3/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// acrEpochMillis converts an epoch-milliseconds timestamp into a *time.Time,
// returning nil when the value is nil or zero so a record that has never
// carried the timestamp stays null rather than reporting the zero time.
func acrEpochMillis(v *int64) *time.Time {
	if v == nil || *v == 0 {
		return nil
	}
	t := time.UnixMilli(*v).UTC()
	return &t
}

// acrEpochMillisString converts an epoch-milliseconds timestamp that the
// registry returns as a string, which ListInstance does for its create and
// modify times. A value that is not a number yields nil rather than a
// fabricated date.
func acrEpochMillisString(v *string) *time.Time {
	if v == nil || *v == "" {
		return nil
	}
	ms, err := strconv.ParseInt(strings.TrimSpace(*v), 10, 64)
	if err != nil {
		return nil
	}
	return acrEpochMillis(&ms)
}

func (r *mqlAlicloudAcr) id() (string, error) {
	return "alicloud.acr", nil
}

func (r *mqlAlicloudAcr) instances() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.CrClient(region)
		if err != nil {
			return nil, err
		}

		pageNo := int32(1)
		pageSize := int32(100)
		firstPage := true
		for {
			resp, err := client.ListInstance(&crclient.ListInstanceRequest{
				PageNo:   new(pageNo),
				PageSize: new(pageSize),
			})
			if err != nil {
				// A first-page error means the region has no Container Registry
				// or the credential lacks access there; skip it. A later-page
				// error is real, so surface it rather than truncating the list.
				if firstPage {
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil {
				break
			}

			items := resp.Body.Instances
			for _, inst := range items {
				if inst == nil || inst.InstanceId == nil {
					continue
				}
				mqlInst, err := newAcrInstance(r.MqlRuntime, region, inst)
				if err != nil {
					return nil, err
				}
				// ListInstance returns tags inline, so the filter costs nothing
				// beyond the listing already made
				if filteredOutByTags(conn, mqlInst.Tags.Data) {
					continue
				}
				res = append(res, mqlInst)
			}

			total := tea.Int32Value(resp.Body.TotalCount)
			if len(items) < int(pageSize) || (total > 0 && pageNo*pageSize >= total) {
				break
			}
			pageNo++
		}
	}
	return res, nil
}

// mqlAlicloudAcrInstanceInternal caches the region needed to rebuild a
// region-scoped registry client, and memoizes the internet endpoint so the four
// endpoint accessors and every repository's isPublic share one read.
type mqlAlicloudAcrInstanceInternal struct {
	region string

	endpointLock    sync.Mutex
	endpointFetched atomic.Bool
	endpoint        *crclient.GetInstanceEndpointResponseBody
}

// newAcrInstance builds an alicloud.acr.instance from a ListInstance item.
func newAcrInstance(runtime *plugin.Runtime, region string, inst *crclient.ListInstanceResponseBodyInstances) (*mqlAlicloudAcrInstance, error) {
	tags := map[string]any{}
	for _, t := range inst.Tags {
		if t == nil || tea.StringValue(t.TagKey) == "" {
			continue
		}
		tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
	}

	resource, err := CreateResource(runtime, "alicloud.acr.instance", map[string]*llx.RawData{
		"__id":                  llx.StringDataPtr(inst.InstanceId),
		"instanceId":            llx.StringDataPtr(inst.InstanceId),
		"instanceName":          llx.StringDataPtr(inst.InstanceName),
		"instanceSpecification": llx.StringDataPtr(inst.InstanceSpecification),
		"instanceStatus":        llx.StringDataPtr(inst.InstanceStatus),
		"regionId":              llx.StringData(region),
		"resourceGroupId":       llx.StringDataPtr(inst.ResourceGroupId),
		"tags":                  llx.MapData(tags, types.String),
		"createTime":            llx.TimeDataPtr(acrEpochMillisString(inst.CreateTime)),
		"modifiedTime":          llx.TimeDataPtr(acrEpochMillisString(inst.ModifiedTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlInst := resource.(*mqlAlicloudAcrInstance)
	mqlInst.region = region
	return mqlInst, nil
}

// initAlicloudAcrInstance resolves a registry by its instance id within a
// region, reusing an already-listed instance from the resource cache. It also
// backs the discovered acr-instance asset, which scopes the connection to one
// registry.
func initAlicloudAcrInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// on a discovered registry asset, resolve the instance the asset is scoped to
	args = scopedInitArgs(runtime, args, connection.OptionAcrInstanceID, "instanceId")

	instanceID, err := requiredStringArg(args, "instanceId", "alicloud.acr.instance")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.acr.instance")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.acr.instance\x00" + instanceID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CrClient(region)
	if err != nil {
		return nil, nil, err
	}
	// ListInstance has no by-id filter, so the match is made over the region's
	// instances. The walk runs to the end rather than stopping at the first
	// page: a registry beyond the hundredth would otherwise report as not found
	// rather than as unmatched.
	pageNo := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.ListInstance(&crclient.ListInstanceRequest{
			PageNo:   new(pageNo),
			PageSize: new(pageSize),
		})
		if err != nil {
			return nil, nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		items := resp.Body.Instances
		for _, inst := range items {
			if inst == nil || tea.StringValue(inst.InstanceId) != instanceID {
				continue
			}
			res, err := newAcrInstance(runtime, region, inst)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if len(items) < int(pageSize) || (total > 0 && pageNo*pageSize >= total) {
			break
		}
		pageNo++
	}
	return nil, nil, fmt.Errorf("alicloud.acr.instance %q not found in region %q", instanceID, region)
}

func (r *mqlAlicloudAcrInstance) id() (string, error) {
	return r.InstanceId.Data, nil
}

func (r *mqlAlicloudAcrInstance) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// internetEndpointDetail lazily loads and memoizes the instance's internet
// endpoint. A transient error is not cached, so a later access retries rather
// than permanently reporting an unread endpoint as switched off.
func (r *mqlAlicloudAcrInstance) internetEndpointDetail() (*crclient.GetInstanceEndpointResponseBody, error) {
	if r.endpointFetched.Load() {
		return r.endpoint, nil
	}
	r.endpointLock.Lock()
	defer r.endpointLock.Unlock()
	if r.endpointFetched.Load() {
		return r.endpoint, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CrClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetInstanceEndpoint(&crclient.GetInstanceEndpointRequest{
		InstanceId:   new(r.InstanceId.Data),
		EndpointType: new("internet"),
	})
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.endpoint = resp.Body
	}
	r.endpointFetched.Store(true)
	return r.endpoint, nil
}

func (r *mqlAlicloudAcrInstance) internetEndpointEnabled() (bool, error) {
	d, err := r.internetEndpointDetail()
	if err != nil || d == nil {
		return false, err
	}
	return tea.BoolValue(d.Enable), nil
}

func (r *mqlAlicloudAcrInstance) internetEndpointAclEnabled() (bool, error) {
	d, err := r.internetEndpointDetail()
	if err != nil || d == nil {
		return false, err
	}
	return tea.BoolValue(d.AclEnable), nil
}

func (r *mqlAlicloudAcrInstance) internetEndpointAclEntries() ([]any, error) {
	d, err := r.internetEndpointDetail()
	if err != nil || d == nil {
		return nil, err
	}
	res := []any{}
	for _, e := range d.AclEntries {
		if e == nil || tea.StringValue(e.Entry) == "" {
			continue
		}
		res = append(res, tea.StringValue(e.Entry))
	}
	return res, nil
}

func (r *mqlAlicloudAcrInstance) internetEndpointDomains() ([]any, error) {
	d, err := r.internetEndpointDetail()
	if err != nil || d == nil {
		return nil, err
	}
	res := []any{}
	for _, dom := range d.Domains {
		if dom == nil || tea.StringValue(dom.Domain) == "" {
			continue
		}
		res = append(res, tea.StringValue(dom.Domain))
	}
	return res, nil
}

func (r *mqlAlicloudAcrInstance) namespaces() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CrClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNo := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.ListNamespace(&crclient.ListNamespaceRequest{
			InstanceId: new(r.InstanceId.Data),
			PageNo:     new(pageNo),
			PageSize:   new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		items := resp.Body.Namespaces
		for _, ns := range items {
			if ns == nil || ns.NamespaceName == nil {
				continue
			}
			mqlNs, err := newAcrNamespace(r.MqlRuntime, r, ns)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlNs)
		}

		// TotalCount arrives as a string here, unlike the sibling list calls, so
		// a page shorter than the page size is the reliable stop condition.
		if len(items) < int(pageSize) {
			break
		}
		pageNo++
	}
	return res, nil
}

// mqlAlicloudAcrNamespaceInternal holds the instance the namespace was listed
// from. A namespace exists only inside its registry, so carrying the parent
// resolves the repository listing without a second lookup.
type mqlAlicloudAcrNamespaceInternal struct {
	parentInstance *mqlAlicloudAcrInstance
}

// newAcrNamespace builds an alicloud.acr.namespace from a ListNamespace item.
//
// The visibility new repositories inherit is read from DefaultRepoConfiguration
// because the flat DefaultRepoType field is deprecated in the API. The
// deprecated field is still consulted when the configuration is absent: leaving
// the visibility empty would read as "unknown" on a namespace that does have a
// default.
func newAcrNamespace(runtime *plugin.Runtime, instance *mqlAlicloudAcrInstance, ns *crclient.ListNamespaceResponseBodyNamespaces) (*mqlAlicloudAcrNamespace, error) {
	instanceID := instance.InstanceId.Data
	name := tea.StringValue(ns.NamespaceName)

	defaultRepoType := ""
	defaultTagImmutability := false
	if cfg := ns.DefaultRepoConfiguration; cfg != nil {
		defaultRepoType = tea.StringValue(cfg.RepoType)
		defaultTagImmutability = tea.BoolValue(cfg.TagImmutability)
	}
	if defaultRepoType == "" {
		defaultRepoType = tea.StringValue(ns.DefaultRepoType)
	}

	resource, err := CreateResource(runtime, "alicloud.acr.namespace", map[string]*llx.RawData{
		"__id":                   llx.StringData(instanceID + "/" + name),
		"namespaceId":            llx.StringDataPtr(ns.NamespaceId),
		"namespaceName":          llx.StringData(name),
		"instanceId":             llx.StringData(instanceID),
		"autoCreateRepo":         llx.BoolData(tea.BoolValue(ns.AutoCreateRepo)),
		"defaultRepoType":        llx.StringData(defaultRepoType),
		"defaultTagImmutability": llx.BoolData(defaultTagImmutability),
		"namespaceStatus":        llx.StringDataPtr(ns.NamespaceStatus),
		"resourceGroupId":        llx.StringDataPtr(ns.ResourceGroupId),
	})
	if err != nil {
		return nil, err
	}
	mqlNs := resource.(*mqlAlicloudAcrNamespace)
	mqlNs.parentInstance = instance
	return mqlNs, nil
}

func (r *mqlAlicloudAcrNamespace) id() (string, error) {
	return r.InstanceId.Data + "/" + r.NamespaceName.Data, nil
}

func (r *mqlAlicloudAcrNamespace) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// repositories lists the repositories in this namespace only.
func (r *mqlAlicloudAcrNamespace) repositories() ([]any, error) {
	if r.parentInstance == nil {
		return nil, nil
	}
	return listAcrRepositories(r.MqlRuntime, r.parentInstance, r.NamespaceName.Data)
}

// repositories lists every repository in the instance, across all namespaces.
func (r *mqlAlicloudAcrInstance) repositories() ([]any, error) {
	return listAcrRepositories(r.MqlRuntime, r, "")
}

// listAcrRepositories walks ListRepository for an instance, optionally narrowed
// to one namespace. Every repository carries the instance it came from so
// isPublic can consult the instance's internet endpoint without refetching it
// per repository.
func listAcrRepositories(runtime *plugin.Runtime, instance *mqlAlicloudAcrInstance, namespaceName string) ([]any, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CrClient(instance.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNo := int32(1)
	pageSize := int32(100)
	for {
		req := &crclient.ListRepositoryRequest{
			InstanceId: new(instance.InstanceId.Data),
			PageNo:     new(pageNo),
			PageSize:   new(pageSize),
		}
		if namespaceName != "" {
			req.RepoNamespaceName = new(namespaceName)
		}
		resp, err := client.ListRepository(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		items := resp.Body.Repositories
		for _, repo := range items {
			if repo == nil || repo.RepoId == nil {
				continue
			}
			mqlRepo, err := newAcrRepository(runtime, instance, repo)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRepo)
		}

		// TotalCount arrives as a string here, so a short page is the stop
		// condition rather than a count comparison.
		if len(items) < int(pageSize) {
			break
		}
		pageNo++
	}
	return res, nil
}

// mqlAlicloudAcrRepositoryInternal holds the instance the repository was listed
// from, which isPublic needs in order to know whether the registry answers on
// the internet at all.
type mqlAlicloudAcrRepositoryInternal struct {
	parentInstance *mqlAlicloudAcrInstance
}

// newAcrRepository builds an alicloud.acr.repository from a ListRepository item.
func newAcrRepository(runtime *plugin.Runtime, instance *mqlAlicloudAcrInstance, repo *crclient.ListRepositoryResponseBodyRepositories) (*mqlAlicloudAcrRepository, error) {
	resource, err := CreateResource(runtime, "alicloud.acr.repository", map[string]*llx.RawData{
		"__id":              llx.StringDataPtr(repo.RepoId),
		"repoId":            llx.StringDataPtr(repo.RepoId),
		"repoName":          llx.StringDataPtr(repo.RepoName),
		"repoNamespaceName": llx.StringDataPtr(repo.RepoNamespaceName),
		"instanceId":        llx.StringData(instance.InstanceId.Data),
		"repoType":          llx.StringDataPtr(repo.RepoType),
		"tagImmutability":   llx.BoolData(tea.BoolValue(repo.TagImmutability)),
		"summary":           llx.StringDataPtr(repo.Summary),
		"repoStatus":        llx.StringDataPtr(repo.RepoStatus),
		"repoBuildType":     llx.StringDataPtr(repo.RepoBuildType),
		"resourceGroupId":   llx.StringDataPtr(repo.ResourceGroupId),
		"createTime":        llx.TimeDataPtr(acrEpochMillis(repo.CreateTime)),
		"modifiedTime":      llx.TimeDataPtr(acrEpochMillis(repo.ModifiedTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlRepo := resource.(*mqlAlicloudAcrRepository)
	mqlRepo.parentInstance = instance
	return mqlRepo, nil
}

func (r *mqlAlicloudAcrRepository) id() (string, error) {
	return r.RepoId.Data, nil
}

func (r *mqlAlicloudAcrRepository) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// acrRepoIsPublic reports whether a repository can be pulled anonymously from
// the internet. PUBLIC visibility alone is not enough: a public repository in an
// instance whose internet endpoint is switched off is still reachable only from
// a linked VPC.
func acrRepoIsPublic(repoType string, internetEnabled bool) bool {
	return strings.EqualFold(strings.TrimSpace(repoType), "PUBLIC") && internetEnabled
}

// isPublic combines the repository's visibility with its instance's internet
// endpoint. An unreadable endpoint is an error rather than a false: reporting a
// PUBLIC repository as not public because the endpoint could not be read would
// hide exactly the finding this field exists for.
func (r *mqlAlicloudAcrRepository) isPublic() (bool, error) {
	if r.parentInstance == nil {
		r.IsPublic.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	enabled := r.parentInstance.GetInternetEndpointEnabled()
	if enabled.Error != nil {
		return false, enabled.Error
	}
	return acrRepoIsPublic(r.RepoType.Data, enabled.Data), nil
}

// namespace resolves the namespace holding the repository. The namespace can be
// deleted while a repository listing is in flight, so a name that is no longer
// in the instance's namespace list resolves to null.
func (r *mqlAlicloudAcrRepository) namespace() (*mqlAlicloudAcrNamespace, error) {
	if r.parentInstance == nil || r.RepoNamespaceName.Data == "" {
		r.Namespace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	namespaces := r.parentInstance.GetNamespaces()
	if namespaces.Error != nil {
		return nil, namespaces.Error
	}
	for _, entry := range namespaces.Data {
		ns, ok := entry.(*mqlAlicloudAcrNamespace)
		if !ok {
			continue
		}
		if ns.NamespaceName.Data == r.RepoNamespaceName.Data {
			return ns, nil
		}
	}
	log.Debug().Str("namespace", r.RepoNamespaceName.Data).Str("repository", r.RepoName.Data).
		Msg("alicloud> repository names a namespace that is not in the instance namespace list")
	r.Namespace.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (r *mqlAlicloudAcrInstance) syncRules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CrClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNo := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.ListRepoSyncRule(&crclient.ListRepoSyncRuleRequest{
			InstanceId: new(r.InstanceId.Data),
			PageNo:     new(pageNo),
			PageSize:   new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		items := resp.Body.SyncRules
		for _, rule := range items {
			if rule == nil || rule.SyncRuleId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.acr.syncRule", map[string]*llx.RawData{
				"__id":                llx.StringDataPtr(rule.SyncRuleId),
				"syncRuleId":          llx.StringDataPtr(rule.SyncRuleId),
				"syncRuleName":        llx.StringDataPtr(rule.SyncRuleName),
				"crossUser":           llx.BoolData(tea.BoolValue(rule.CrossUser)),
				"syncDirection":       llx.StringDataPtr(rule.SyncDirection),
				"syncScope":           llx.StringDataPtr(rule.SyncScope),
				"syncTrigger":         llx.StringDataPtr(rule.SyncTrigger),
				"localInstanceId":     llx.StringDataPtr(rule.LocalInstanceId),
				"localRegionId":       llx.StringDataPtr(rule.LocalRegionId),
				"localNamespaceName":  llx.StringDataPtr(rule.LocalNamespaceName),
				"localRepoName":       llx.StringDataPtr(rule.LocalRepoName),
				"targetInstanceId":    llx.StringDataPtr(rule.TargetInstanceId),
				"targetRegionId":      llx.StringDataPtr(rule.TargetRegionId),
				"targetNamespaceName": llx.StringDataPtr(rule.TargetNamespaceName),
				"targetRepoName":      llx.StringDataPtr(rule.TargetRepoName),
				"namespaceNameFilter": llx.StringDataPtr(rule.NamespaceNameFilter),
				"repoNameFilter":      llx.StringDataPtr(rule.RepoNameFilter),
				"tagFilter":           llx.StringDataPtr(rule.TagFilter),
				"createTime":          llx.TimeDataPtr(acrEpochMillis(rule.CreateTime)),
				"modifiedTime":        llx.TimeDataPtr(acrEpochMillis(rule.ModifiedTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if len(items) < int(pageSize) || (total > 0 && pageNo*pageSize >= total) {
			break
		}
		pageNo++
	}
	return res, nil
}

func (r *mqlAlicloudAcrSyncRule) id() (string, error) {
	return r.SyncRuleId.Data, nil
}

func (r *mqlAlicloudAcrInstance) scanRules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CrClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNo := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.ListScanRule(&crclient.ListScanRuleRequest{
			InstanceId: new(r.InstanceId.Data),
			PageNo:     new(pageNo),
			PageSize:   new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		items := resp.Body.ScanRules
		for _, rule := range items {
			if rule == nil || rule.ScanRuleId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.acr.scanRule", map[string]*llx.RawData{
				"__id":                 llx.StringDataPtr(rule.ScanRuleId),
				"scanRuleId":           llx.StringDataPtr(rule.ScanRuleId),
				"ruleName":             llx.StringDataPtr(rule.RuleName),
				"instanceId":           llx.StringData(r.InstanceId.Data),
				"scanType":             llx.StringDataPtr(rule.ScanType),
				"scanScope":            llx.StringDataPtr(rule.ScanScope),
				"repoTagFilterPattern": llx.StringDataPtr(rule.RepoTagFilterPattern),
				"triggerType":          llx.StringDataPtr(rule.TriggerType),
				"createTime":           llx.TimeDataPtr(acrEpochMillis(rule.CreateTime)),
				"updateTime":           llx.TimeDataPtr(acrEpochMillis(rule.UpdateTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if len(items) < int(pageSize) || (total > 0 && pageNo*pageSize >= total) {
			break
		}
		pageNo++
	}
	return res, nil
}

func (r *mqlAlicloudAcrScanRule) id() (string, error) {
	return r.ScanRuleId.Data, nil
}

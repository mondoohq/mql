// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	rmclient "github.com/alibabacloud-go/resourcemanager-20200331/v3/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// rmPageDone reports whether a Resource Management listing has returned its
// last page. A short page ends the walk; so does reaching the reported total,
// which the API omits (as 0) on some listings. Both guards are needed: without
// the short-page check a listing whose total is absent would page forever.
func rmPageDone(itemCount int, pageNumber, pageSize, total int32) bool {
	if itemCount < int(pageSize) {
		return true
	}
	return total > 0 && pageNumber*pageSize >= total
}

// rmParseTime parses a Resource Management ISO-8601 timestamp, which may carry
// fractional seconds. Returns nil on a nil or unparseable input.
func rmParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, *s); err == nil {
			return &t
		}
	}
	return nil
}

// mqlAlicloudResourceManagerInternal memoizes the resource directory detail
// shared by the identity accessors, and the account's resource groups, which
// back the resourceGroup reference on every resource that carries a resource
// group id.
type mqlAlicloudResourceManagerInternal struct {
	dirLock    sync.Mutex
	dirFetched atomic.Bool
	dir        *rmclient.GetResourceDirectoryResponseBodyResourceDirectory

	groupsLock    sync.Mutex
	groupsFetched atomic.Bool
	groupsErr     error
	groups        []any
	groupsByID    map[string]*mqlAlicloudResourceManagerResourceGroup
}

func (r *mqlAlicloudResourceManager) id() (string, error) {
	return "alicloud.resourceManager", nil
}

// directory lazily fetches and caches the resource directory detail. A
// transient error is not cached and is returned so the identity accessors
// surface the failure rather than empty strings.
func (r *mqlAlicloudResourceManager) directory() (*rmclient.GetResourceDirectoryResponseBodyResourceDirectory, error) {
	if r.dirFetched.Load() {
		return r.dir, nil
	}
	r.dirLock.Lock()
	defer r.dirLock.Unlock()
	if r.dirFetched.Load() {
		return r.dir, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ResourceManagerClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetResourceDirectory()
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		r.dir = resp.Body.ResourceDirectory
	}
	r.dirFetched.Store(true)
	return r.dir, nil
}

func (r *mqlAlicloudResourceManager) resourceDirectoryId() (string, error) {
	d, err := r.directory()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.ResourceDirectoryId), nil
}

func (r *mqlAlicloudResourceManager) rootFolderId() (string, error) {
	d, err := r.directory()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.RootFolderId), nil
}

func (r *mqlAlicloudResourceManager) masterAccountId() (string, error) {
	d, err := r.directory()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.MasterAccountId), nil
}

func (r *mqlAlicloudResourceManager) masterAccountName() (string, error) {
	d, err := r.directory()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.MasterAccountName), nil
}

func (r *mqlAlicloudResourceManager) memberDeletionStatus() (string, error) {
	d, err := r.directory()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.MemberDeletionStatus), nil
}

func (r *mqlAlicloudResourceManager) controlPolicyStatus() (string, error) {
	d, err := r.directory()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.ControlPolicyStatus), nil
}

func (r *mqlAlicloudResourceManager) createTime() (*time.Time, error) {
	d, err := r.directory()
	if err != nil || d == nil {
		return nil, err
	}
	return rmParseTime(d.CreateTime), nil
}

// initAlicloudResourceManagerAccount resolves a member account from its ID.
//
// NewResource runs an init before it consults the resource cache, so the cache
// probe here keeps an account that the account listing already produced from
// costing another GetAccount call for every assignment that targets it.
func initAlicloudResourceManagerAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	accountID, err := requiredStringArg(args, "accountId", "alicloud.resourceManager.account")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.resourceManager.account\x00" + accountID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ResourceManagerClient()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetAccount(&rmclient.GetAccountRequest{AccountId: new(accountID)})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Account == nil {
		return nil, nil, fmt.Errorf("alicloud.resourceManager.account %q not found", accountID)
	}

	a := resp.Body.Account
	res, err := CreateResource(runtime, "alicloud.resourceManager.account", map[string]*llx.RawData{
		"__id":                llx.StringDataPtr(a.AccountId),
		"accountId":           llx.StringDataPtr(a.AccountId),
		"displayName":         llx.StringDataPtr(a.DisplayName),
		"status":              llx.StringDataPtr(a.Status),
		"type":                llx.StringDataPtr(a.Type),
		"folderId":            llx.StringDataPtr(a.FolderId),
		"resourceDirectoryId": llx.StringDataPtr(a.ResourceDirectoryId),
		"joinMethod":          llx.StringDataPtr(a.JoinMethod),
		"joinTime":            llx.TimeDataPtr(rmParseTime(a.JoinTime)),
		"modifyTime":          llx.TimeDataPtr(rmParseTime(a.ModifyTime)),
	})
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudResourceManager) accounts() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ResourceManagerClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.ListAccounts(&rmclient.ListAccountsRequest{
			PageNumber: new(pageNumber),
			PageSize:   new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.Accounts == nil {
			break
		}

		items := resp.Body.Accounts.Account
		for _, a := range items {
			if a == nil || a.AccountId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.resourceManager.account", map[string]*llx.RawData{
				"__id":                llx.StringDataPtr(a.AccountId),
				"accountId":           llx.StringDataPtr(a.AccountId),
				"displayName":         llx.StringDataPtr(a.DisplayName),
				"status":              llx.StringDataPtr(a.Status),
				"type":                llx.StringDataPtr(a.Type),
				"folderId":            llx.StringDataPtr(a.FolderId),
				"resourceDirectoryId": llx.StringDataPtr(a.ResourceDirectoryId),
				"joinMethod":          llx.StringDataPtr(a.JoinMethod),
				"joinTime":            llx.TimeDataPtr(rmParseTime(a.JoinTime)),
				"modifyTime":          llx.TimeDataPtr(rmParseTime(a.ModifyTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if rmPageDone(len(items), pageNumber, pageSize, total) {
			break
		}
		pageNumber++
	}
	return res, nil
}

func (r *mqlAlicloudResourceManager) folders() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ResourceManagerClient()
	if err != nil {
		return nil, err
	}

	rootFolderId, err := r.rootFolderId()
	if err != nil || rootFolderId == "" {
		return []any{}, nil
	}

	res := []any{}
	// Walk the folder tree breadth-first from the root, listing each parent's
	// children. The root folder itself is not returned by the API, only its
	// descendants. A visited set guards against a scan hanging if the API ever
	// returns a folder that re-references an ancestor.
	visited := map[string]struct{}{}
	queue := []string{rootFolderId}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		if _, seen := visited[parent]; seen {
			continue
		}
		visited[parent] = struct{}{}

		pageNumber := int32(1)
		pageSize := int32(100)
		for {
			resp, err := client.ListFoldersForParent(&rmclient.ListFoldersForParentRequest{
				ParentFolderId: new(parent),
				PageNumber:     new(pageNumber),
				PageSize:       new(pageSize),
			})
			if err != nil || resp == nil || resp.Body == nil || resp.Body.Folders == nil {
				break
			}
			items := resp.Body.Folders.Folder
			for _, f := range items {
				if f == nil || f.FolderId == nil {
					continue
				}
				resource, err := newResourceManagerFolder(r.MqlRuntime, f.FolderId, f.FolderName, new(parent), f.CreateTime)
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
				queue = append(queue, tea.StringValue(f.FolderId))
			}
			total := tea.Int32Value(resp.Body.TotalCount)
			if rmPageDone(len(items), pageNumber, pageSize, total) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

func (r *mqlAlicloudResourceManager) controlPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ResourceManagerClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, policyType := range []string{"System", "Custom"} {
		pageNumber := int32(1)
		pageSize := int32(100)
		for {
			resp, err := client.ListControlPolicies(&rmclient.ListControlPoliciesRequest{
				PolicyType: new(policyType),
				PageNumber: new(pageNumber),
				PageSize:   new(pageSize),
			})
			if err != nil || resp == nil || resp.Body == nil || resp.Body.ControlPolicies == nil {
				break
			}
			items := resp.Body.ControlPolicies.ControlPolicy
			for _, p := range items {
				if p == nil || p.PolicyId == nil {
					continue
				}
				attachmentCount := int64(0)
				if p.AttachmentCount != nil {
					if n, err := strconv.Atoi(*p.AttachmentCount); err == nil {
						attachmentCount = int64(n)
					}
				}
				resource, err := CreateResource(r.MqlRuntime, "alicloud.resourceManager.controlPolicy", map[string]*llx.RawData{
					"__id":            llx.StringDataPtr(p.PolicyId),
					"policyId":        llx.StringDataPtr(p.PolicyId),
					"policyName":      llx.StringDataPtr(p.PolicyName),
					"policyType":      llx.StringDataPtr(p.PolicyType),
					"description":     llx.StringDataPtr(p.Description),
					"effectScope":     llx.StringDataPtr(p.EffectScope),
					"attachmentCount": llx.IntData(attachmentCount),
					"createDate":      llx.TimeDataPtr(rmParseTime(p.CreateDate)),
					"updateDate":      llx.TimeDataPtr(rmParseTime(p.UpdateDate)),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			total := tea.Int32Value(resp.Body.TotalCount)
			if rmPageDone(len(items), pageNumber, pageSize, total) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

func (r *mqlAlicloudResourceManagerAccount) id() (string, error) {
	return r.AccountId.Data, nil
}

func (r *mqlAlicloudResourceManagerAccount) folder() (*mqlAlicloudResourceManagerFolder, error) {
	folderID := r.FolderId.Data
	if folderID == "" {
		r.Folder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.resourceManager.folder", map[string]*llx.RawData{
		"folderId": llx.StringData(folderID),
	})
	if err != nil {
		r.Folder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAlicloudResourceManagerFolder), nil
}

// newResourceManagerFolder builds a folder resource, carrying the parent id from
// the listing context since the list item does not include it.
func newResourceManagerFolder(runtime *plugin.Runtime, folderID, folderName, parentFolderID, createTime *string) (*mqlAlicloudResourceManagerFolder, error) {
	resource, err := CreateResource(runtime, "alicloud.resourceManager.folder", map[string]*llx.RawData{
		"__id":           llx.StringDataPtr(folderID),
		"folderId":       llx.StringDataPtr(folderID),
		"folderName":     llx.StringDataPtr(folderName),
		"parentFolderId": llx.StringDataPtr(parentFolderID),
		"createTime":     llx.TimeDataPtr(rmParseTime(createTime)),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudResourceManagerFolder), nil
}

// initAlicloudResourceManagerFolder resolves a folder by id, reusing an
// already-listed folder from the resource cache and otherwise fetching it via
// GetFolder.
func initAlicloudResourceManagerFolder(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	folderID, err := requiredStringArg(args, "folderId", "alicloud.resourceManager.folder")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.resourceManager.folder\x00" + folderID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ResourceManagerClient()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetFolder(&rmclient.GetFolderRequest{FolderId: new(folderID)})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Folder == nil {
		return nil, nil, fmt.Errorf("alicloud.resourceManager.folder %q not found", folderID)
	}
	f := resp.Body.Folder
	res, err := newResourceManagerFolder(runtime, f.FolderId, f.FolderName, f.ParentFolderId, f.CreateTime)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// parentFolder resolves the folder that contains this folder. The root folder
// has no parent and resolves to null; any other folder cannot outlive its
// parent, so a failure to read it is a real error.
func (r *mqlAlicloudResourceManagerFolder) parentFolder() (*mqlAlicloudResourceManagerFolder, error) {
	parentID := r.ParentFolderId.Data
	if parentID == "" {
		r.ParentFolder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.resourceManager.folder", map[string]*llx.RawData{
		"folderId": llx.StringData(parentID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudResourceManagerFolder), nil
}

func (r *mqlAlicloudResourceManagerFolder) id() (string, error) {
	return r.FolderId.Data, nil
}

// loadResourceGroups lists every resource group in the account once and indexes
// it by id.
//
// Unlike directory(), a failure is cached alongside the result. Resource groups
// are resolved from the resourceGroup reference of every ECS instance, bucket,
// cluster and load balancer in a scan, so an uncached error would turn one
// denied ListResourceGroups call into one call per resource.
func (r *mqlAlicloudResourceManager) loadResourceGroups() error {
	if r.groupsFetched.Load() {
		return r.groupsErr
	}
	r.groupsLock.Lock()
	defer r.groupsLock.Unlock()
	if r.groupsFetched.Load() {
		return r.groupsErr
	}

	groups := []any{}
	byID := map[string]*mqlAlicloudResourceManagerResourceGroup{}
	err := func() error {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.ResourceManagerClient()
		if err != nil {
			return err
		}

		pageNumber := int32(1)
		pageSize := int32(100)
		for {
			resp, err := client.ListResourceGroups(&rmclient.ListResourceGroupsRequest{
				IncludeTags: new(true),
				PageNumber:  new(pageNumber),
				PageSize:    new(pageSize),
			})
			if err != nil {
				return err
			}
			if resp == nil || resp.Body == nil || resp.Body.ResourceGroups == nil {
				break
			}

			items := resp.Body.ResourceGroups.ResourceGroup
			for _, g := range items {
				if g == nil {
					continue
				}
				// Id is the rg- identifier that every other resource reports as
				// its resourceGroupId, so it is the only usable key. Name is a
				// separate account-unique label and cannot stand in for it. A
				// group without an id can be neither keyed nor referenced, so
				// it is dropped, but not silently: the resources that belong to
				// it would otherwise report a null resource group with no
				// explanation.
				if tea.StringValue(g.Id) == "" {
					log.Warn().Str("name", tea.StringValue(g.Name)).
						Msg("alicloud> skipping resource group without an id")
					continue
				}
				resource, err := newResourceManagerResourceGroup(r.MqlRuntime, g)
				if err != nil {
					return err
				}
				groups = append(groups, resource)
				byID[tea.StringValue(g.Id)] = resource
			}

			total := tea.Int32Value(resp.Body.TotalCount)
			if rmPageDone(len(items), pageNumber, pageSize, total) {
				break
			}
			pageNumber++
		}
		return nil
	}()

	if err != nil {
		r.groupsErr = err
	} else {
		r.groups = groups
		r.groupsByID = byID
	}
	r.groupsFetched.Store(true)
	return r.groupsErr
}

func (r *mqlAlicloudResourceManager) resourceGroups() ([]any, error) {
	if err := r.loadResourceGroups(); err != nil {
		return nil, err
	}
	return r.groups, nil
}

// resourceGroupByID returns the resource group with the given id, or nil when
// the account has no such group.
func (r *mqlAlicloudResourceManager) resourceGroupByID(id string) (*mqlAlicloudResourceManagerResourceGroup, error) {
	if err := r.loadResourceGroups(); err != nil {
		return nil, err
	}
	return r.groupsByID[id], nil
}

// resourceGroupTagsToMap flattens the nested tag envelope ListResourceGroups
// returns. A tag with no key is dropped rather than creating an empty-string
// key, and a tag with no value maps to the empty string.
func resourceGroupTagsToMap(tags *rmclient.ListResourceGroupsResponseBodyResourceGroupsResourceGroupTags) map[string]any {
	res := map[string]any{}
	if tags == nil {
		return res
	}
	for _, t := range tags.Tag {
		if t == nil || tea.StringValue(t.TagKey) == "" {
			continue
		}
		res[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
	}
	return res
}

// newResourceManagerResourceGroup builds a resource group resource from a
// ListResourceGroups entry.
func newResourceManagerResourceGroup(runtime *plugin.Runtime, g *rmclient.ListResourceGroupsResponseBodyResourceGroupsResourceGroup) (*mqlAlicloudResourceManagerResourceGroup, error) {
	resource, err := CreateResource(runtime, "alicloud.resourceManager.resourceGroup", map[string]*llx.RawData{
		"__id":            llx.StringDataPtr(g.Id),
		"resourceGroupId": llx.StringDataPtr(g.Id),
		"name":            llx.StringDataPtr(g.Name),
		"displayName":     llx.StringDataPtr(g.DisplayName),
		"accountId":       llx.StringDataPtr(g.AccountId),
		"status":          llx.StringDataPtr(g.Status),
		"createDate":      llx.TimeDataPtr(rmParseTime(g.CreateDate)),
		"tags":            llx.MapData(resourceGroupTagsToMap(g.Tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudResourceManagerResourceGroup), nil
}

// initAlicloudResourceManagerResourceGroup resolves a resource group by id from
// the account's group listing, which is fetched once and shared with every
// resourceGroup reference in the scan.
func initAlicloudResourceManagerResourceGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	groupID, err := requiredStringArg(args, "resourceGroupId", "alicloud.resourceManager.resourceGroup")
	if err != nil {
		return nil, nil, err
	}

	rm, err := resourceManagerResource(runtime)
	if err != nil {
		return nil, nil, err
	}
	group, err := rm.resourceGroupByID(groupID)
	if err != nil {
		return nil, nil, err
	}
	if group == nil {
		return nil, nil, fmt.Errorf("alicloud.resourceManager.resourceGroup %q not found", groupID)
	}
	return nil, group, nil
}

func (r *mqlAlicloudResourceManagerResourceGroup) id() (string, error) {
	return r.ResourceGroupId.Data, nil
}

func (r *mqlAlicloudResourceManagerControlPolicy) id() (string, error) {
	return r.PolicyId.Data, nil
}

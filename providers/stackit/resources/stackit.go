// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	resourcemanager "github.com/stackitcloud/stackit-sdk-go/services/resourcemanager/v0api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/stackit/connection"
)

func (r *mqlStackit) id() (string, error) {
	return "stackit/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackit) region() (string, error) {
	return conn(r.MqlRuntime).Region(), nil
}

func conn(runtime *plugin.Runtime) *connection.StackitConnection {
	return runtime.Connection.(*connection.StackitConnection)
}

// mqlStackitProjectInternal caches the ancestry chain the project response
// carries when parents are requested, so organization() and folders() build
// their resources without another call.
type mqlStackitProjectInternal struct {
	cacheParents []resourcemanager.ParentListInner
}

// project fetches the project metadata from the resource-manager API. Parents
// are requested on the same call: that populates the ancestry chain up to the
// organization, which is the only way a project-scoped credential learns
// which organization owns it without organization-level read access.
func (r *mqlStackit) project() (*mqlStackitProject, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ResourceManager()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetProject(bgctx(), c.ProjectID()).IncludeParents(true).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return markNull[mqlStackitProject](&r.Project)
			}
			return nil, refusal(err)
		}
		return nil, err
	}

	lifecycle, _ := resp.GetLifecycleStateOk()
	labels, _ := resp.GetLabelsOk()
	createdAt, ok := resp.GetCreationTimeOk()
	updatedAt, okUpdated := resp.GetUpdateTimeOk()

	parentID, parentType := "", ""
	if p, hasParent := resp.GetParentOk(); hasParent {
		parentID = p.GetContainerId()
		if parentID == "" {
			parentID = p.GetId()
		}
		if t, ok := p.GetTypeOk(); ok && t != nil {
			parentType = string(*t)
		}
	}

	args := map[string]*llx.RawData{
		"id":             llx.StringData(resp.GetProjectId()),
		"containerId":    llx.StringData(resp.GetContainerId()),
		"name":           llx.StringData(resp.GetName()),
		"parent":         llx.StringData(parentID),
		"parentType":     llx.StringData(parentType),
		"lifecycleState": llx.StringData(ptrEnumStr(lifecycle)),
		"creationTime":   llx.TimeDataPtr(timeOrNil(createdAt, ok)),
		"updateTime":     llx.TimeDataPtr(timeOrNil(updatedAt, okUpdated)),
		"labels":         labelData(labels),
	}
	res, err := CreateResource(r.MqlRuntime, "stackit.project", args)
	if err != nil {
		return nil, err
	}
	project := res.(*mqlStackitProject)
	project.cacheParents = resp.GetParents()
	return project, nil
}

func (r *mqlStackitProject) id() (string, error) {
	return "stackit.project/" + r.Id.Data, nil
}

// folders lists the folders between the project and its organization,
// nearest first, from the ancestry chain on the project response. Each is
// built from the chain entry with no further call; a folder's labels and
// timestamps are read on demand. Empty when the project sits directly under
// the organization.
func (r *mqlStackitProject) folders() ([]any, error) {
	chain := orderedFolders(r.cacheParents, r.Parent.Data)
	out := make([]any, 0, len(chain))
	for i := range chain {
		f := chain[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.folder", map[string]*llx.RawData{
			"id":          llx.StringData(f.GetId()),
			"containerId": llx.StringData(f.GetContainerId()),
			"name":        llx.StringData(f.GetName()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// organization resolves the organization at the top of the ancestry chain.
// The resource is built from the chain entry (id, container id, name) with no
// further call; its lifecycle state, labels, and timestamps are read on
// demand and stay null when the credential cannot read the organization.
// Null when the chain names no organization.
func (r *mqlStackitProject) organization() (*mqlStackitOrganization, error) {
	org := projectOrganization(r.cacheParents)
	if org == nil {
		return markNull[mqlStackitOrganization](&r.Organization)
	}
	res, err := CreateResource(r.MqlRuntime, "stackit.organization", map[string]*llx.RawData{
		"id":          llx.StringData(org.GetId()),
		"containerId": llx.StringData(org.GetContainerId()),
		"name":        llx.StringData(org.GetName()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitOrganization), nil
}

// ------------------------- organization -------------------------

type mqlStackitOrganizationInternal struct {
	fetched atomic.Bool
	detail  *resourcemanager.OrganizationResponse
	lock    sync.Mutex
}

func (r *mqlStackitOrganization) id() (string, error) {
	return "stackit.organization/" + r.Id.Data, nil
}

// initStackitOrganization resolves an organization by id through
// GetOrganization, for `stackit.organization(id: "...")`. The response is
// kept so the detail accessors need no second call.
func initStackitOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.ResourceManager()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetOrganization(bgctx(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, fmt.Errorf("stackit.organization with id %q not found", id)
	}
	res, err := CreateResource(runtime, "stackit.organization", map[string]*llx.RawData{
		"id":          llx.StringData(resp.GetOrganizationId()),
		"containerId": llx.StringData(resp.GetContainerId()),
		"name":        llx.StringData(resp.GetName()),
	})
	if err != nil {
		return nil, nil, err
	}
	org := res.(*mqlStackitOrganization)
	org.detail = resp
	org.fetched.Store(true)
	return nil, res, nil
}

// fetchDetail reads the organization record once and caches it. A nil result
// with a nil error means the credential cannot read the organization (a
// project-scoped service account usually cannot), and the detail fields
// report null rather than a value that was never read.
func (r *mqlStackitOrganization) fetchDetail() (*resourcemanager.OrganizationResponse, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.ResourceManager()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetOrganization(bgctx(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			r.fetched.Store(true)
			return nil, nil
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	r.detail = resp
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitOrganization) lifecycleState() (string, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil {
		r.LifecycleState.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	state, _ := d.GetLifecycleStateOk()
	return ptrEnumStr(state), nil
}

func (r *mqlStackitOrganization) labels() (map[string]any, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil {
		r.Labels.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	labels, _ := d.GetLabelsOk()
	return labelData(labels).Value.(map[string]any), nil
}

func (r *mqlStackitOrganization) creationTime() (*time.Time, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil {
		r.CreationTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return timeOrNil(d.GetCreationTimeOk()), nil
}

func (r *mqlStackitOrganization) updateTime() (*time.Time, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil {
		r.UpdateTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return timeOrNil(d.GetUpdateTimeOk()), nil
}

// projectOrganization finds the organization in an ancestry chain by its
// type, not its position, since the API does not promise an ordering. Nil
// when the chain names no organization.
func projectOrganization(parents []resourcemanager.ParentListInner) *resourcemanager.ParentListInner {
	for i := range parents {
		if t, ok := parents[i].GetTypeOk(); ok && t != nil && *t == resourcemanager.PARENTLISTINNERTYPE_ORGANIZATION {
			return &parents[i]
		}
	}
	return nil
}

// orderedFolders returns the folder entries of an ancestry chain nearest
// first, by starting at the project's direct parent and following each
// folder's containerParentId upward. Folders the walk cannot reach (a chain
// with a gap) are appended in API order so none is lost.
func orderedFolders(parents []resourcemanager.ParentListInner, parentContainerID string) []resourcemanager.ParentListInner {
	byContainer := make(map[string]*resourcemanager.ParentListInner, len(parents))
	for i := range parents {
		if t, ok := parents[i].GetTypeOk(); ok && t != nil && *t == resourcemanager.PARENTLISTINNERTYPE_FOLDER {
			byContainer[parents[i].GetContainerId()] = &parents[i]
		}
	}
	out := make([]resourcemanager.ParentListInner, 0, len(byContainer))
	seen := map[string]struct{}{}
	for next := parentContainerID; next != ""; {
		f, ok := byContainer[next]
		if !ok {
			break
		}
		if _, dup := seen[next]; dup {
			break
		}
		seen[next] = struct{}{}
		out = append(out, *f)
		next = ""
		if v, ok := f.GetContainerParentIdOk(); ok && v != nil {
			next = *v
		}
	}
	for i := range parents {
		if _, isFolder := byContainer[parents[i].GetContainerId()]; !isFolder {
			continue
		}
		if _, done := seen[parents[i].GetContainerId()]; done {
			continue
		}
		out = append(out, parents[i])
	}
	return out
}

// ------------------------- folder -------------------------

type mqlStackitFolderInternal struct {
	fetched atomic.Bool
	detail  *resourcemanager.GetFolderDetailsResponse
	lock    sync.Mutex
}

func (r *mqlStackitFolder) id() (string, error) {
	return "stackit.folder/" + r.Id.Data, nil
}

// initStackitFolder resolves a folder by container id through
// GetFolderDetails, for `stackit.folder(containerId: "...")`.
func initStackitFolder(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	containerID, ok := idArg(args, "containerId")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.ResourceManager()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetFolderDetails(bgctx(), containerID).Execute()
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, fmt.Errorf("stackit.folder with containerId %q not found", containerID)
	}
	res, err := CreateResource(runtime, "stackit.folder", map[string]*llx.RawData{
		"id":          llx.StringData(resp.GetFolderId()),
		"containerId": llx.StringData(resp.GetContainerId()),
		"name":        llx.StringData(resp.GetName()),
	})
	if err != nil {
		return nil, nil, err
	}
	folder := res.(*mqlStackitFolder)
	folder.detail = resp
	folder.fetched.Store(true)
	return nil, res, nil
}

// fetchDetail reads the folder record once and caches it. A nil result with
// a nil error means the credential cannot read the folder, and the detail
// fields report null.
func (r *mqlStackitFolder) fetchDetail() (*resourcemanager.GetFolderDetailsResponse, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.ResourceManager()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetFolderDetails(bgctx(), r.ContainerId.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			r.fetched.Store(true)
			return nil, nil
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	r.detail = resp
	r.fetched.Store(true)
	return r.detail, nil
}

func (r *mqlStackitFolder) labels() (map[string]any, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil {
		r.Labels.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	labels, _ := d.GetLabelsOk()
	return labelData(labels).Value.(map[string]any), nil
}

func (r *mqlStackitFolder) creationTime() (*time.Time, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil {
		r.CreationTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return timeOrNil(d.GetCreationTimeOk()), nil
}

func (r *mqlStackitFolder) updateTime() (*time.Time, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil {
		r.UpdateTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return timeOrNil(d.GetUpdateTimeOk()), nil
}

// Each namespace resource has a stable id.

func (r *mqlStackitSke) id() (string, error) {
	return "stackit.ske/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitObjectStorage) id() (string, error) {
	return "stackit.objectStorage/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitDns) id() (string, error) {
	return "stackit.dns/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitPostgresFlex) id() (string, error) {
	return "stackit.postgresFlex/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitMongoDbFlex) id() (string, error) {
	return "stackit.mongoDbFlex/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitOpenSearch) id() (string, error) {
	return "stackit.openSearch/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitMariaDb) id() (string, error) {
	return "stackit.mariaDb/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitRedis) id() (string, error) {
	return "stackit.redis/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitRabbitMq) id() (string, error) {
	return "stackit.rabbitMq/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitSecretsManager) id() (string, error) {
	return "stackit.secretsManager/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitObservability) id() (string, error) {
	return "stackit.observability/" + conn(r.MqlRuntime).ProjectID(), nil
}

// Namespace getters on `stackit` just return the singleton namespace resource.

func (r *mqlStackit) ske() (*mqlStackitSke, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.ske")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSke), nil
}

func (r *mqlStackit) objectStorage() (*mqlStackitObjectStorage, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.objectStorage")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitObjectStorage), nil
}

func (r *mqlStackit) dns() (*mqlStackitDns, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.dns")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitDns), nil
}

func (r *mqlStackit) postgresFlex() (*mqlStackitPostgresFlex, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.postgresFlex")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitPostgresFlex), nil
}

func (r *mqlStackit) mongoDbFlex() (*mqlStackitMongoDbFlex, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.mongoDbFlex")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitMongoDbFlex), nil
}

func (r *mqlStackit) openSearch() (*mqlStackitOpenSearch, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.openSearch")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitOpenSearch), nil
}

func (r *mqlStackit) sqlServerFlex() (*mqlStackitSqlServerFlex, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.sqlServerFlex")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSqlServerFlex), nil
}

func (r *mqlStackit) logMe() (*mqlStackitLogMe, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.logMe")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitLogMe), nil
}

func (r *mqlStackit) mariaDb() (*mqlStackitMariaDb, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.mariaDb")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitMariaDb), nil
}

func (r *mqlStackit) redis() (*mqlStackitRedis, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.redis")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitRedis), nil
}

func (r *mqlStackit) rabbitMq() (*mqlStackitRabbitMq, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.rabbitMq")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitRabbitMq), nil
}

func (r *mqlStackit) secretsManager() (*mqlStackitSecretsManager, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.secretsManager")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSecretsManager), nil
}

func (r *mqlStackit) observability() (*mqlStackitObservability, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.observability")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitObservability), nil
}

func (r *mqlStackit) modelServing() (*mqlStackitModelServing, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.modelServing")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitModelServing), nil
}

func (r *mqlStackit) telemetry() (*mqlStackitTelemetry, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.telemetry")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitTelemetry), nil
}

func (r *mqlStackit) sfs() (*mqlStackitSfs, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.sfs")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSfs), nil
}

func (r *mqlStackit) kms() (*mqlStackitKms, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.kms")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitKms), nil
}

func (r *mqlStackit) iam() (*mqlStackitIam, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.iam")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitIam), nil
}

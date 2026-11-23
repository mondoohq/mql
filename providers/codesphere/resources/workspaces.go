// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strconv"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/codesphere/connection"
)

type mqlCodesphereWorkspaceInternal struct {
	resourceGroupID   int64
	userID            int64
	planID            int64
	dataCenterID      int64
	sourceWorkspaceID *int64
	baseImageID       *string
}

func workspaceArgs(w *cs.WorkspacesGetWorkspace200Response) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":             llx.IntData(w.Id),
		"name":           llx.StringData(w.Name),
		"createdAt":      llx.TimeData(w.CreatedAt),
		"replicas":       llx.IntData(w.Replicas),
		"gitUrl":         llx.StringDataPtr(redactGitURL(w.GitUrl.Get())),
		"initialBranch":  llx.StringDataPtr(w.InitialBranch.Get()),
		"isPrivateRepo":  llx.BoolData(w.IsPrivateRepo),
		"restricted":     llx.BoolData(w.Restricted),
		"devDomain":      llx.StringDataPtr(w.DevDomain),
		"hasVpnConfig":   llx.BoolData(w.VpnConfig.Get() != nil && *w.VpnConfig.Get() != ""),
		"collectTraces":  llx.BoolData(w.CollectTraces),
		"persistentLogs": llx.BoolData(w.PersistentLogs),
		"welcomeMessage": llx.StringDataPtr(w.WelcomeMessage.Get()),
	}
}

func newWorkspace(runtime *plugin.Runtime, w *cs.WorkspacesGetWorkspace200Response) (*mqlCodesphereWorkspace, error) {
	o, err := CreateResource(runtime, "codesphere.workspace", workspaceArgs(w))
	if err != nil {
		return nil, err
	}
	ws := o.(*mqlCodesphereWorkspace)
	ws.resourceGroupID = int64(w.TeamId)
	ws.userID = int64(w.UserId)
	ws.planID = int64(w.PlanId)
	ws.dataCenterID = int64(w.DataCenterId)
	if src := w.SourceWorkspaceId.Get(); src != nil {
		id := int64(*src)
		ws.sourceWorkspaceID = &id
	}
	ws.baseImageID = nonEmpty(w.BaseImage)
	return ws, nil
}

func (r *mqlCodesphere) workspaces() ([]any, error) {
	rgs := r.GetResourceGroups()
	if rgs.Error != nil {
		return nil, rgs.Error
	}
	res := []any{}
	for _, it := range rgs.Data {
		rg := it.(*mqlCodesphereResourceGroup)
		list := rg.GetWorkspaces()
		if list.Error != nil {
			// A refused resource group is a gap in that partition, not a failure
			// of the whole list (ADR 046 §8).
			log.Debug().Err(list.Error).Int64("resourceGroup", rg.Id.Data).Msg("codesphere> skipping workspaces of resource group")
			continue
		}
		res = append(res, list.Data...)
	}
	return res, nil
}

// initCodesphereWorkspace resolves a workspace by ID, from the scope of a
// discovered asset when no ID is given.
func initCodesphereWorkspace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.CodesphereConnection)

	id := int64(conn.ScopedWorkspace())
	if v, ok := args["id"]; ok {
		id, _ = v.Value.(int64)
	}
	if id == 0 {
		return nil, nil, errors.New("codesphere.workspace requires an id")
	}
	if res, ok := cachedResource(runtime, "codesphere.workspace", strconv.FormatInt(id, 10)); ok {
		return nil, res, nil
	}

	w, resp, err := conn.API().WorkspacesAPI.WorkspacesGetWorkspace(conn.Context(), int(id)).Execute()
	if err != nil {
		return nil, nil, connection.Classify(resp, err)
	}
	if w == nil {
		return nil, nil, llx.NotFound(fmt.Errorf("codesphere.workspace with id %d not found", id))
	}
	res, err := newWorkspace(runtime, w)
	return nil, res, err
}

func (r *mqlCodesphereWorkspace) id() (string, error) {
	return strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlCodesphereWorkspace) resourceGroup() (*mqlCodesphereResourceGroup, error) {
	res, err := NewResource(r.MqlRuntime, "codesphere.resourceGroup", map[string]*llx.RawData{
		"id": llx.IntData(r.resourceGroupID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCodesphereResourceGroup), nil
}

// creator resolves the creating user through the resource group's member
// list. A creator who has left the resource group is null.
func (r *mqlCodesphereWorkspace) creator() (*mqlCodesphereResourceGroupMember, error) {
	rg, err := r.resourceGroup()
	if err != nil {
		return nil, err
	}
	members := rg.GetMembers()
	if members.Error != nil {
		return nil, members.Error
	}
	for _, it := range members.Data {
		if m := it.(*mqlCodesphereResourceGroupMember); m.UserId.Data == r.userID {
			return m, nil
		}
	}
	r.Creator.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// sourceWorkspace is null when the workspace was not copied from another, or
// when its source was deleted.
func (r *mqlCodesphereWorkspace) sourceWorkspace() (*mqlCodesphereWorkspace, error) {
	if r.sourceWorkspaceID == nil {
		r.SourceWorkspace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "codesphere.workspace", map[string]*llx.RawData{
		"id": llx.IntData(*r.sourceWorkspaceID),
	})
	if err != nil {
		if errors.Is(err, llx.ErrNotFound) {
			r.SourceWorkspace.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlCodesphereWorkspace), nil
}

func (r *mqlCodesphereWorkspace) workspacePlan() (*mqlCodesphereWorkspacePlan, error) {
	p, err := findWorkspacePlan(r.MqlRuntime, r.planID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		r.WorkspacePlan.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return p, nil
}

func (r *mqlCodesphereWorkspace) dataCenter() (*mqlCodesphereDataCenter, error) {
	dc, err := findDataCenter(r.MqlRuntime, r.dataCenterID)
	if err != nil {
		return nil, err
	}
	if dc == nil {
		r.DataCenter.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return dc, nil
}

func (r *mqlCodesphereWorkspace) baseImage() (*mqlCodesphereBaseImage, error) {
	if r.baseImageID == nil {
		r.BaseImage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	img, err := findBaseImage(r.MqlRuntime, *r.baseImageID)
	if err != nil {
		return nil, err
	}
	if img == nil {
		r.BaseImage.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return img, nil
}

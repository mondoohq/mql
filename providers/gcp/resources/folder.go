// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

type mqlGcpFolderInternal struct {
	iamPolicyOnce  sync.Once
	iamPolicyCache *cloudresourcemanager.Policy
	iamPolicyErr   error
}

// folderResourceName normalizes a folder id (either "123" or "folders/123")
// into the canonical "folders/{id}" resource path expected by the
// cloudresourcemanager APIs.
func folderResourceName(id string) string {
	if strings.HasPrefix(id, "folders/") {
		return id
	}
	return "folders/" + id
}

func (g *mqlGcpFolders) id() (string, error) {
	if g.ParentId.Error != nil {
		return "", g.ParentId.Error
	}
	id := g.ParentId.Data
	return fmt.Sprintf("gcp.folders/%s", id), nil
}

func (g *mqlGcpFolder) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return fmt.Sprintf("gcp.folder/%s", id), nil
}

func initGcpFolder(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args == nil {
		args = make(map[string]*llx.RawData)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}

	folderId := conn.ResourceID()
	if args["id"] != nil {
		folderId, _ = args["id"].Value.(string)
	}

	folderPath := fmt.Sprintf("folders/%s", folderId)
	folder, err := svc.Folders.Get(folderPath).Do()
	if err != nil {
		return nil, nil, err
	}

	retrievedFolderID := strings.TrimPrefix(folder.Name, "folders/")
	args["id"] = llx.StringData(retrievedFolderID)
	args["name"] = llx.StringData(folder.DisplayName)
	args["created"] = llx.TimeDataPtr(parseTime(folder.CreateTime))
	args["updated"] = llx.TimeDataPtr(parseTime(folder.UpdateTime))
	args["parentId"] = llx.StringData(folder.Parent)
	args["state"] = llx.StringData(folder.State)
	args["managementProject"] = llx.StringData(folder.ManagementProject)
	return args, nil, nil
}

func (g *mqlGcpFolder) parentFolder() (*mqlGcpFolder, error) {
	parentId := g.GetParentId()
	if parentId.Error != nil {
		return nil, parentId.Error
	}
	f, err := parentFolderFromId(parentId.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if f == nil {
		g.ParentFolder.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return f, nil
}

func (g *mqlGcpFolder) parentOrganization() (*mqlGcpOrganization, error) {
	parentId := g.GetParentId()
	if parentId.Error != nil {
		return nil, parentId.Error
	}
	o, err := parentOrganizationFromId(parentId.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if o == nil {
		g.ParentOrganization.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return o, nil
}

func (g *mqlGcpFolder) managementProjectRef() (*mqlGcpProject, error) {
	mp := g.GetManagementProject()
	if mp.Error != nil {
		return nil, mp.Error
	}
	proj, err := projectRefById(g.MqlRuntime, projectFromResourceName(mp.Data))
	if err != nil {
		return nil, err
	}
	if proj == nil {
		g.ManagementProjectRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return proj, nil
}

func (g *mqlGcpFolders) children() ([]any, error) {
	if g.ParentId.Error != nil {
		return nil, g.ParentId.Error
	}
	parentId := g.ParentId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var mqlFolders []any
	if err := svc.Folders.List().Parent(parentId).Pages(ctx, func(page *cloudresourcemanager.ListFoldersResponse) error {
		for _, f := range page.Folders {
			mqlF, err := folderToMql(g.MqlRuntime, f)
			if err != nil {
				return err
			}
			mqlFolders = append(mqlFolders, mqlF)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return mqlFolders, nil
}

func (g *mqlGcpFolders) list() ([]any, error) {
	if g.ParentId.Error != nil {
		return nil, g.ParentId.Error
	}
	parentId := g.ParentId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var allFolders []*cloudresourcemanager.Folder
	if err := svc.Folders.Search().Pages(ctx, func(page *cloudresourcemanager.SearchFoldersResponse) error {
		allFolders = append(allFolders, page.Folders...)
		return nil
	}); err != nil {
		return nil, err
	}

	filteredFolders := getChildren(allFolders, parentId)
	mqlFolders := make([]any, 0, len(filteredFolders))
	for _, f := range filteredFolders {
		mqlF, err := folderToMql(g.MqlRuntime, f)
		if err != nil {
			return nil, err
		}
		mqlFolders = append(mqlFolders, mqlF)
	}
	return mqlFolders, nil
}

func getChildren(fs []*cloudresourcemanager.Folder, root string) []*cloudresourcemanager.Folder {
	var children []*cloudresourcemanager.Folder
	for _, f := range fs {
		if f.Parent == root {
			children = append(children, f)
			children = append(children, getChildren(fs, f.Name)...)
		}
	}
	return children
}

func (g *mqlGcpFolder) folders() (*mqlGcpFolders, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	folderId := "folders/" + g.Id.Data
	res, err := CreateResource(g.MqlRuntime, "gcp.folders", map[string]*llx.RawData{
		"parentId": llx.StringData(folderId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpFolders), nil
}

func (g *mqlGcpFolder) projects() (*mqlGcpProjects, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	folderId := "folders/" + g.Id.Data
	res, err := CreateResource(g.MqlRuntime, "gcp.projects", map[string]*llx.RawData{
		"parentId": llx.StringData(folderId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjects), nil
}

func folderToMql(runtime *plugin.Runtime, f *cloudresourcemanager.Folder) (any, error) {
	// Store the bare id ("123456"), matching initGcpFolder. folders()/projects()
	// re-prefix with "folders/", so storing the full "folders/123456" here would
	// double-prefix and silently break child traversal.
	return CreateResource(runtime, "gcp.folder", map[string]*llx.RawData{
		"id":                llx.StringData(strings.TrimPrefix(f.Name, "folders/")),
		"name":              llx.StringData(f.DisplayName),
		"created":           llx.TimeDataPtr(parseTime(f.CreateTime)),
		"updated":           llx.TimeDataPtr(parseTime(f.UpdateTime)),
		"parentId":          llx.StringData(f.Parent),
		"state":             llx.StringData(f.State),
		"deleteTime":        llx.TimeDataPtr(parseTime(f.DeleteTime)),
		"managementProject": llx.StringData(f.ManagementProject),
	})
}

func (g *mqlGcpFolder) fetchIamPolicy() (*cloudresourcemanager.Policy, error) {
	g.iamPolicyOnce.Do(func() {
		if g.Id.Error != nil {
			g.iamPolicyErr = g.Id.Error
			return
		}
		folderName := folderResourceName(g.Id.Data)

		conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
		client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
		if err != nil {
			g.iamPolicyErr = err
			return
		}

		ctx := context.Background()
		svc, err := cloudresourcemanager.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			g.iamPolicyErr = err
			return
		}

		g.iamPolicyCache, g.iamPolicyErr = svc.Folders.GetIamPolicy(folderName, &cloudresourcemanager.GetIamPolicyRequest{Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3}}).Do()
	})
	return g.iamPolicyCache, g.iamPolicyErr
}

func (g *mqlGcpFolder) iamPolicy() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	folderName := folderResourceName(g.Id.Data)

	policy, err := g.fetchIamPolicy()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(policy.Bindings))
	for i, b := range policy.Bindings {
		condTitle, condExpr, condDesc := "", "", ""
		if b.Condition != nil {
			condTitle = b.Condition.Title
			condExpr = b.Condition.Expression
			condDesc = b.Condition.Description
		}

		mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(folderName + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(condTitle),
			"conditionExpression":  llx.StringData(condExpr),
			"conditionDescription": llx.StringData(condDesc),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpFolder) auditConfig() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	folderName := folderResourceName(g.Id.Data)

	policy, err := g.fetchIamPolicy()
	if err != nil {
		return nil, err
	}

	return extractAuditConfigs(g.MqlRuntime, folderName, policy.AuditConfigs)
}

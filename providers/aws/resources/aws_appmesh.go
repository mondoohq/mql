// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	appmesh_types "github.com/aws/aws-sdk-go-v2/service/appmesh/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsAppmesh) id() (string, error) {
	return "aws.appmesh", nil
}

func (a *mqlAwsAppmesh) meshes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getMeshes(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsAppmesh) getMeshes(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("appmesh>getMeshes>calling aws with region %s", region)

			svc := conn.AppMesh(region)
			ctx := context.Background()
			res := []any{}

			paginator := appmesh.NewListMeshesPaginator(svc, &appmesh.ListMeshesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("App Mesh is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, mesh := range page.Meshes {
					mqlMesh, err := CreateResource(a.MqlRuntime, "aws.appmesh.mesh",
						map[string]*llx.RawData{
							"__id":      llx.StringDataPtr(mesh.Arn),
							"arn":       llx.StringDataPtr(mesh.Arn),
							"name":      llx.StringDataPtr(mesh.MeshName),
							"region":    llx.StringData(region),
							"meshOwner": llx.StringDataPtr(mesh.MeshOwner),
							"createdAt": llx.TimeDataPtr(mesh.CreatedAt),
						})
					if err != nil {
						return nil, err
					}
					internal := mqlMesh.(*mqlAwsAppmeshMesh)
					internal.cacheResourceOwner = mesh.ResourceOwner
					internal.cacheVersion = mesh.Version
					internal.cacheLastUpdatedAt = mesh.LastUpdatedAt
					res = append(res, mqlMesh)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsAppmeshMesh) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsAppmeshMeshInternal struct {
	fetched            bool
	lock               sync.Mutex
	descResp           *appmesh.DescribeMeshOutput
	cacheResourceOwner *string
	cacheVersion       *int64
	cacheLastUpdatedAt *time.Time
}

func (a *mqlAwsAppmeshMesh) fetchDetail() (*appmesh.DescribeMeshOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.AppMesh(region)
	ctx := context.Background()

	name := a.Name.Data
	resp, err := svc.DescribeMesh(ctx, &appmesh.DescribeMeshInput{
		MeshName: &name,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsAppmeshMesh) resourceOwner() (string, error) {
	if a.cacheResourceOwner != nil {
		return *a.cacheResourceOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Mesh == nil || resp.Mesh.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.Mesh.Metadata.ResourceOwner), nil
}

func (a *mqlAwsAppmeshMesh) version() (int64, error) {
	if a.cacheVersion != nil {
		return *a.cacheVersion, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if resp.Mesh == nil || resp.Mesh.Metadata == nil || resp.Mesh.Metadata.Version == nil {
		return 0, nil
	}
	return *resp.Mesh.Metadata.Version, nil
}

func (a *mqlAwsAppmeshMesh) lastUpdatedAt() (*time.Time, error) {
	if a.cacheLastUpdatedAt != nil {
		return a.cacheLastUpdatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Mesh == nil || resp.Mesh.Metadata == nil {
		return nil, nil
	}
	return resp.Mesh.Metadata.LastUpdatedAt, nil
}

func (a *mqlAwsAppmeshMesh) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Mesh == nil || resp.Mesh.Status == nil {
		return "", nil
	}
	return string(resp.Mesh.Status.Status), nil
}

func (a *mqlAwsAppmeshMesh) egressFilterType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Mesh == nil || resp.Mesh.Spec == nil || resp.Mesh.Spec.EgressFilter == nil {
		return "", nil
	}
	return string(resp.Mesh.Spec.EgressFilter.Type), nil
}

func (a *mqlAwsAppmeshMesh) serviceDiscoveryIpPreference() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Mesh == nil || resp.Mesh.Spec == nil || resp.Mesh.Spec.ServiceDiscovery == nil {
		return "", nil
	}
	return string(resp.Mesh.Spec.ServiceDiscovery.IpPreference), nil
}

func (a *mqlAwsAppmeshMesh) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.AppMesh(region)
	ctx := context.Background()

	arn := a.Arn.Data
	tags := make(map[string]any)
	paginator := appmesh.NewListTagsForResourcePaginator(svc, &appmesh.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, tag := range page.Tags {
			tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
		}
	}
	return tags, nil
}

func (a *mqlAwsAppmeshMesh) virtualServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.AppMesh(region)
	ctx := context.Background()

	meshName := a.Name.Data
	res := []any{}
	paginator := appmesh.NewListVirtualServicesPaginator(svc, &appmesh.ListVirtualServicesInput{
		MeshName: &meshName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vs := range page.VirtualServices {
			mqlVs, err := CreateResource(a.MqlRuntime, "aws.appmesh.virtualService",
				map[string]*llx.RawData{
					"__id":     llx.StringDataPtr(vs.Arn),
					"arn":      llx.StringDataPtr(vs.Arn),
					"name":     llx.StringDataPtr(vs.VirtualServiceName),
					"meshName": llx.StringData(meshName),
					"region":   llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			internal := mqlVs.(*mqlAwsAppmeshVirtualService)
			internal.region = region
			internal.meshName = meshName
			internal.cacheMeshOwner = vs.MeshOwner
			internal.cacheResourceOwner = vs.ResourceOwner
			internal.cacheVersion = vs.Version
			internal.cacheCreatedAt = vs.CreatedAt
			internal.cacheLastUpdatedAt = vs.LastUpdatedAt
			res = append(res, mqlVs)
		}
	}
	return res, nil
}

func (a *mqlAwsAppmeshMesh) virtualNodes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.AppMesh(region)
	ctx := context.Background()

	meshName := a.Name.Data
	res := []any{}
	paginator := appmesh.NewListVirtualNodesPaginator(svc, &appmesh.ListVirtualNodesInput{
		MeshName: &meshName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vn := range page.VirtualNodes {
			mqlVn, err := CreateResource(a.MqlRuntime, "aws.appmesh.virtualNode",
				map[string]*llx.RawData{
					"__id":     llx.StringDataPtr(vn.Arn),
					"arn":      llx.StringDataPtr(vn.Arn),
					"name":     llx.StringDataPtr(vn.VirtualNodeName),
					"meshName": llx.StringData(meshName),
					"region":   llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			internal := mqlVn.(*mqlAwsAppmeshVirtualNode)
			internal.region = region
			internal.meshName = meshName
			internal.cacheMeshOwner = vn.MeshOwner
			internal.cacheResourceOwner = vn.ResourceOwner
			internal.cacheVersion = vn.Version
			internal.cacheCreatedAt = vn.CreatedAt
			internal.cacheLastUpdatedAt = vn.LastUpdatedAt
			res = append(res, mqlVn)
		}
	}
	return res, nil
}

func (a *mqlAwsAppmeshVirtualService) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsAppmeshVirtualServiceInternal struct {
	lazyTags
	fetched            bool
	lock               sync.Mutex
	descResp           *appmesh.DescribeVirtualServiceOutput
	region             string
	meshName           string
	cacheMeshOwner     *string
	cacheResourceOwner *string
	cacheVersion       *int64
	cacheCreatedAt     *time.Time
	cacheLastUpdatedAt *time.Time
}

func (a *mqlAwsAppmeshVirtualService) fetchDetail() (*appmesh.DescribeVirtualServiceOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(a.region)
	ctx := context.Background()

	name := a.Name.Data
	meshName := a.meshName
	resp, err := svc.DescribeVirtualService(ctx, &appmesh.DescribeVirtualServiceInput{
		MeshName:           &meshName,
		VirtualServiceName: &name,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsAppmeshVirtualService) meshOwner() (string, error) {
	if a.cacheMeshOwner != nil {
		return *a.cacheMeshOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualService == nil || resp.VirtualService.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.VirtualService.Metadata.MeshOwner), nil
}

func (a *mqlAwsAppmeshVirtualService) resourceOwner() (string, error) {
	if a.cacheResourceOwner != nil {
		return *a.cacheResourceOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualService == nil || resp.VirtualService.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.VirtualService.Metadata.ResourceOwner), nil
}

func (a *mqlAwsAppmeshVirtualService) version() (int64, error) {
	if a.cacheVersion != nil {
		return *a.cacheVersion, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if resp.VirtualService == nil || resp.VirtualService.Metadata == nil || resp.VirtualService.Metadata.Version == nil {
		return 0, nil
	}
	return *resp.VirtualService.Metadata.Version, nil
}

func (a *mqlAwsAppmeshVirtualService) createdAt() (*time.Time, error) {
	if a.cacheCreatedAt != nil {
		return a.cacheCreatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualService == nil || resp.VirtualService.Metadata == nil {
		return nil, nil
	}
	return resp.VirtualService.Metadata.CreatedAt, nil
}

func (a *mqlAwsAppmeshVirtualService) lastUpdatedAt() (*time.Time, error) {
	if a.cacheLastUpdatedAt != nil {
		return a.cacheLastUpdatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualService == nil || resp.VirtualService.Metadata == nil {
		return nil, nil
	}
	return resp.VirtualService.Metadata.LastUpdatedAt, nil
}

func (a *mqlAwsAppmeshVirtualService) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualService == nil || resp.VirtualService.Status == nil {
		return "", nil
	}
	return string(resp.VirtualService.Status.Status), nil
}

func (a *mqlAwsAppmeshVirtualService) providerType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualService == nil || resp.VirtualService.Spec == nil || resp.VirtualService.Spec.Provider == nil {
		return "", nil
	}
	switch resp.VirtualService.Spec.Provider.(type) {
	case *appmesh_types.VirtualServiceProviderMemberVirtualNode:
		return "virtualNode", nil
	case *appmesh_types.VirtualServiceProviderMemberVirtualRouter:
		return "virtualRouter", nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualService) providerName() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualService == nil || resp.VirtualService.Spec == nil || resp.VirtualService.Spec.Provider == nil {
		return "", nil
	}
	switch p := resp.VirtualService.Spec.Provider.(type) {
	case *appmesh_types.VirtualServiceProviderMemberVirtualNode:
		return convert.ToValue(p.Value.VirtualNodeName), nil
	case *appmesh_types.VirtualServiceProviderMemberVirtualRouter:
		return convert.ToValue(p.Value.VirtualRouterName), nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualService) virtualNode() (*mqlAwsAppmeshVirtualNode, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualService == nil || resp.VirtualService.Spec == nil || resp.VirtualService.Spec.Provider == nil {
		a.VirtualNode.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	p, ok := resp.VirtualService.Spec.Provider.(*appmesh_types.VirtualServiceProviderMemberVirtualNode)
	if !ok || p.Value.VirtualNodeName == nil {
		a.VirtualNode.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	nodeName := *p.Value.VirtualNodeName
	nodeArn := buildAppmeshChildArn(a.Arn.Data, "virtualNode", nodeName)
	if nodeArn == "" {
		a.VirtualNode.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlNode, err := NewResource(a.MqlRuntime, "aws.appmesh.virtualNode",
		map[string]*llx.RawData{
			"arn": llx.StringData(nodeArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlNode.(*mqlAwsAppmeshVirtualNode), nil
}

func (a *mqlAwsAppmeshVirtualService) virtualRouter() (*mqlAwsAppmeshVirtualRouter, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualService == nil || resp.VirtualService.Spec == nil || resp.VirtualService.Spec.Provider == nil {
		a.VirtualRouter.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	p, ok := resp.VirtualService.Spec.Provider.(*appmesh_types.VirtualServiceProviderMemberVirtualRouter)
	if !ok || p.Value.VirtualRouterName == nil {
		a.VirtualRouter.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	routerName := *p.Value.VirtualRouterName
	routerArn := buildAppmeshChildArn(a.Arn.Data, "virtualRouter", routerName)
	if routerArn == "" {
		a.VirtualRouter.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRouter, err := NewResource(a.MqlRuntime, "aws.appmesh.virtualRouter",
		map[string]*llx.RawData{
			"arn": llx.StringData(routerArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlRouter.(*mqlAwsAppmeshVirtualRouter), nil
}

// buildAppmeshChildArn rewrites a sibling appmesh ARN to point at another
// resource type in the same mesh. Returns "" if the ARN can't be parsed.
// Example input:
//
//	arn:aws:appmesh:us-west-2:111:mesh/m1/virtualService/foo
//
// With kind="virtualNode" and name="bar" returns:
//
//	arn:aws:appmesh:us-west-2:111:mesh/m1/virtualNode/bar
func buildAppmeshChildArn(siblingArn, kind, name string) string {
	parsed, err := arn.Parse(siblingArn)
	if err != nil {
		return ""
	}
	// Resource is like "mesh/<mesh>/virtualService/<name>"
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) < 2 || parts[0] != "mesh" {
		return ""
	}
	parsed.Resource = "mesh/" + parts[1] + "/" + kind + "/" + name
	return parsed.String()
}

func initAwsAppmeshVirtualNode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	arnRaw, ok := args["arn"]
	if !ok || arnRaw == nil {
		return args, nil, nil
	}
	arnStr, ok := arnRaw.Value.(string)
	if !ok || arnStr == "" {
		return args, nil, nil
	}
	region, meshName, kind, name, err := parseAppmeshArn(arnStr)
	if err != nil {
		return nil, nil, err
	}
	if kind != "virtualNode" {
		return nil, nil, errors.New("ARN does not reference an aws.appmesh.virtualNode: " + arnStr)
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(region)
	ctx := context.Background()
	resp, err := svc.DescribeVirtualNode(ctx, &appmesh.DescribeVirtualNodeInput{
		MeshName:        &meshName,
		VirtualNodeName: &name,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.VirtualNode == nil {
		return args, nil, nil
	}
	args["__id"] = llx.StringData(arnStr)
	args["arn"] = llx.StringData(arnStr)
	args["name"] = llx.StringData(name)
	args["meshName"] = llx.StringData(meshName)
	args["region"] = llx.StringData(region)
	// Cache the Describe response on the resource so the next lazy-loaded
	// field (status, tags, etc.) doesn't re-fire the same RPC.
	res, err := CreateResource(runtime, "aws.appmesh.virtualNode", args)
	if err != nil {
		return nil, nil, err
	}
	node := res.(*mqlAwsAppmeshVirtualNode)
	node.descResp = resp
	node.fetched = true
	node.region = region
	node.meshName = meshName
	return args, res, nil
}

func initAwsAppmeshVirtualRouter(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	arnRaw, ok := args["arn"]
	if !ok || arnRaw == nil {
		return args, nil, nil
	}
	arnStr, ok := arnRaw.Value.(string)
	if !ok || arnStr == "" {
		return args, nil, nil
	}
	region, meshName, kind, name, err := parseAppmeshArn(arnStr)
	if err != nil {
		return nil, nil, err
	}
	if kind != "virtualRouter" {
		return nil, nil, errors.New("ARN does not reference an aws.appmesh.virtualRouter: " + arnStr)
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(region)
	ctx := context.Background()
	resp, err := svc.DescribeVirtualRouter(ctx, &appmesh.DescribeVirtualRouterInput{
		MeshName:          &meshName,
		VirtualRouterName: &name,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.VirtualRouter == nil {
		return args, nil, nil
	}
	args["__id"] = llx.StringData(arnStr)
	args["arn"] = llx.StringData(arnStr)
	args["name"] = llx.StringData(name)
	args["meshName"] = llx.StringData(meshName)
	args["region"] = llx.StringData(region)
	res, err := CreateResource(runtime, "aws.appmesh.virtualRouter", args)
	if err != nil {
		return nil, nil, err
	}
	router := res.(*mqlAwsAppmeshVirtualRouter)
	router.descResp = resp
	router.fetched = true
	router.region = region
	router.meshName = meshName
	return args, res, nil
}

// parseAppmeshArn extracts (region, meshName, childKind, childName) from an
// appmesh resource ARN of the form
// arn:aws:appmesh:<region>:<acct>:mesh/<mesh>/<kind>/<name>.
// For a bare mesh ARN, kind and name are returned as the empty string.
func parseAppmeshArn(arnStr string) (region, meshName, kind, name string, err error) {
	parsed, err := arn.Parse(arnStr)
	if err != nil {
		return "", "", "", "", err
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) < 2 || parts[0] != "mesh" {
		return "", "", "", "", errors.New("unexpected appmesh ARN: " + arnStr)
	}
	region = parsed.Region
	meshName = parts[1]
	if len(parts) >= 4 {
		kind = parts[2]
		name = parts[3]
	}
	return region, meshName, kind, name, nil
}

func (a *mqlAwsAppmeshVirtualNode) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsAppmeshVirtualNodeInternal struct {
	lazyTags
	fetched            bool
	lock               sync.Mutex
	descResp           *appmesh.DescribeVirtualNodeOutput
	region             string
	meshName           string
	cacheMeshOwner     *string
	cacheResourceOwner *string
	cacheVersion       *int64
	cacheCreatedAt     *time.Time
	cacheLastUpdatedAt *time.Time
}

func (a *mqlAwsAppmeshVirtualNode) fetchDetail() (*appmesh.DescribeVirtualNodeOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	region := a.region
	meshName := a.meshName
	if region == "" || meshName == "" {
		r, m, _, _, err := parseAppmeshArn(a.Arn.Data)
		if err != nil {
			return nil, err
		}
		if region == "" {
			region = r
			a.region = r
		}
		if meshName == "" {
			meshName = m
			a.meshName = m
		}
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(region)
	ctx := context.Background()

	nodeName := a.Name.Data
	resp, err := svc.DescribeVirtualNode(ctx, &appmesh.DescribeVirtualNodeInput{
		MeshName:        &meshName,
		VirtualNodeName: &nodeName,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsAppmeshVirtualNode) meshOwner() (string, error) {
	if a.cacheMeshOwner != nil {
		return *a.cacheMeshOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.VirtualNode.Metadata.MeshOwner), nil
}

func (a *mqlAwsAppmeshVirtualNode) resourceOwner() (string, error) {
	if a.cacheResourceOwner != nil {
		return *a.cacheResourceOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.VirtualNode.Metadata.ResourceOwner), nil
}

func (a *mqlAwsAppmeshVirtualNode) version() (int64, error) {
	if a.cacheVersion != nil {
		return *a.cacheVersion, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Metadata == nil || resp.VirtualNode.Metadata.Version == nil {
		return 0, nil
	}
	return *resp.VirtualNode.Metadata.Version, nil
}

func (a *mqlAwsAppmeshVirtualNode) createdAt() (*time.Time, error) {
	if a.cacheCreatedAt != nil {
		return a.cacheCreatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Metadata == nil {
		return nil, nil
	}
	return resp.VirtualNode.Metadata.CreatedAt, nil
}

func (a *mqlAwsAppmeshVirtualNode) lastUpdatedAt() (*time.Time, error) {
	if a.cacheLastUpdatedAt != nil {
		return a.cacheLastUpdatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Metadata == nil {
		return nil, nil
	}
	return resp.VirtualNode.Metadata.LastUpdatedAt, nil
}

func (a *mqlAwsAppmeshVirtualNode) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Status == nil {
		return "", nil
	}
	return string(resp.VirtualNode.Status.Status), nil
}

func (a *mqlAwsAppmeshVirtualNode) backendServices() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil {
		return []any{}, nil
	}
	res, err := convert.JsonToDictSlice(resp.VirtualNode.Spec.Backends)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (a *mqlAwsAppmeshVirtualNode) listeners() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil {
		return []any{}, nil
	}
	res, err := convert.JsonToDictSlice(resp.VirtualNode.Spec.Listeners)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (a *mqlAwsAppmeshVirtualNode) backendDefaults() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.BackendDefaults == nil {
		return []any{}, nil
	}
	d, err := convert.JsonToDict(resp.VirtualNode.Spec.BackendDefaults)
	if err != nil {
		return nil, err
	}
	return []any{d}, nil
}

func (a *mqlAwsAppmeshVirtualNode) serviceDiscoveryType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.ServiceDiscovery == nil {
		return "", nil
	}
	switch resp.VirtualNode.Spec.ServiceDiscovery.(type) {
	case *appmesh_types.ServiceDiscoveryMemberDns:
		return "DNS", nil
	case *appmesh_types.ServiceDiscoveryMemberAwsCloudMap:
		return "AWS_CLOUD_MAP", nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualNode) serviceDiscoveryDnsHostname() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.ServiceDiscovery == nil {
		return "", nil
	}
	if dns, ok := resp.VirtualNode.Spec.ServiceDiscovery.(*appmesh_types.ServiceDiscoveryMemberDns); ok {
		return convert.ToValue(dns.Value.Hostname), nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualNode) serviceDiscoveryDnsResponseType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.ServiceDiscovery == nil {
		return "", nil
	}
	if dns, ok := resp.VirtualNode.Spec.ServiceDiscovery.(*appmesh_types.ServiceDiscoveryMemberDns); ok {
		return string(dns.Value.ResponseType), nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualNode) serviceDiscoveryDnsIpPreference() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.ServiceDiscovery == nil {
		return "", nil
	}
	if dns, ok := resp.VirtualNode.Spec.ServiceDiscovery.(*appmesh_types.ServiceDiscoveryMemberDns); ok {
		return string(dns.Value.IpPreference), nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualNode) serviceDiscoveryCloudMapNamespaceName() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.ServiceDiscovery == nil {
		return "", nil
	}
	if cm, ok := resp.VirtualNode.Spec.ServiceDiscovery.(*appmesh_types.ServiceDiscoveryMemberAwsCloudMap); ok {
		return convert.ToValue(cm.Value.NamespaceName), nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualNode) serviceDiscoveryCloudMapServiceName() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.ServiceDiscovery == nil {
		return "", nil
	}
	if cm, ok := resp.VirtualNode.Spec.ServiceDiscovery.(*appmesh_types.ServiceDiscoveryMemberAwsCloudMap); ok {
		return convert.ToValue(cm.Value.ServiceName), nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualNode) serviceDiscoveryCloudMapAttributes() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.ServiceDiscovery == nil {
		return map[string]any{}, nil
	}
	cm, ok := resp.VirtualNode.Spec.ServiceDiscovery.(*appmesh_types.ServiceDiscoveryMemberAwsCloudMap)
	if !ok {
		return map[string]any{}, nil
	}
	out := make(map[string]any, len(cm.Value.Attributes))
	for _, attr := range cm.Value.Attributes {
		out[convert.ToValue(attr.Key)] = convert.ToValue(attr.Value)
	}
	return out, nil
}

func (a *mqlAwsAppmeshVirtualNode) serviceDiscoveryCloudMapIpPreference() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.ServiceDiscovery == nil {
		return "", nil
	}
	if cm, ok := resp.VirtualNode.Spec.ServiceDiscovery.(*appmesh_types.ServiceDiscoveryMemberAwsCloudMap); ok {
		return string(cm.Value.IpPreference), nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualNode) loggingAccessLogPath() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.Logging == nil || resp.VirtualNode.Spec.Logging.AccessLog == nil {
		return "", nil
	}
	if f, ok := resp.VirtualNode.Spec.Logging.AccessLog.(*appmesh_types.AccessLogMemberFile); ok {
		return convert.ToValue(f.Value.Path), nil
	}
	return "", nil
}

func (a *mqlAwsAppmeshVirtualNode) loggingAccessLogFormat() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualNode == nil || resp.VirtualNode.Spec == nil || resp.VirtualNode.Spec.Logging == nil || resp.VirtualNode.Spec.Logging.AccessLog == nil {
		return []any{}, nil
	}
	f, ok := resp.VirtualNode.Spec.Logging.AccessLog.(*appmesh_types.AccessLogMemberFile)
	if !ok || f.Value.Format == nil {
		return []any{}, nil
	}
	switch fmt := f.Value.Format.(type) {
	case *appmesh_types.LoggingFormatMemberJson:
		entries := []any{}
		for _, kv := range fmt.Value {
			entries = append(entries, map[string]any{
				"format": "json",
				"key":    convert.ToValue(kv.Key),
				"value":  convert.ToValue(kv.Value),
			})
		}
		return entries, nil
	case *appmesh_types.LoggingFormatMemberText:
		return []any{
			map[string]any{
				"format": "text",
				"value":  fmt.Value,
			},
		}, nil
	}
	return []any{}, nil
}

// ==================== Virtual Routers ====================

func (a *mqlAwsAppmeshMesh) virtualRouters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.AppMesh(region)
	ctx := context.Background()

	meshName := a.Name.Data
	res := []any{}
	paginator := appmesh.NewListVirtualRoutersPaginator(svc, &appmesh.ListVirtualRoutersInput{
		MeshName: &meshName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vr := range page.VirtualRouters {
			mqlVr, err := CreateResource(a.MqlRuntime, "aws.appmesh.virtualRouter",
				map[string]*llx.RawData{
					"__id":     llx.StringDataPtr(vr.Arn),
					"arn":      llx.StringDataPtr(vr.Arn),
					"name":     llx.StringDataPtr(vr.VirtualRouterName),
					"meshName": llx.StringData(meshName),
					"region":   llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			internal := mqlVr.(*mqlAwsAppmeshVirtualRouter)
			internal.region = region
			internal.meshName = meshName
			internal.cacheMeshOwner = vr.MeshOwner
			internal.cacheResourceOwner = vr.ResourceOwner
			internal.cacheVersion = vr.Version
			internal.cacheCreatedAt = vr.CreatedAt
			internal.cacheLastUpdatedAt = vr.LastUpdatedAt
			res = append(res, mqlVr)
		}
	}
	return res, nil
}

func (a *mqlAwsAppmeshVirtualRouter) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsAppmeshVirtualRouterInternal struct {
	fetched            bool
	lock               sync.Mutex
	descResp           *appmesh.DescribeVirtualRouterOutput
	region             string
	meshName           string
	cacheMeshOwner     *string
	cacheResourceOwner *string
	cacheVersion       *int64
	cacheCreatedAt     *time.Time
	cacheLastUpdatedAt *time.Time
}

func (a *mqlAwsAppmeshVirtualRouter) fetchDetail() (*appmesh.DescribeVirtualRouterOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	region := a.region
	meshName := a.meshName
	if region == "" || meshName == "" {
		r, m, _, _, err := parseAppmeshArn(a.Arn.Data)
		if err != nil {
			return nil, err
		}
		if region == "" {
			region = r
			a.region = r
		}
		if meshName == "" {
			meshName = m
			a.meshName = m
		}
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(region)
	ctx := context.Background()

	routerName := a.Name.Data
	resp, err := svc.DescribeVirtualRouter(ctx, &appmesh.DescribeVirtualRouterInput{
		MeshName:          &meshName,
		VirtualRouterName: &routerName,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsAppmeshVirtualRouter) meshOwner() (string, error) {
	if a.cacheMeshOwner != nil {
		return *a.cacheMeshOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualRouter == nil || resp.VirtualRouter.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.VirtualRouter.Metadata.MeshOwner), nil
}

func (a *mqlAwsAppmeshVirtualRouter) resourceOwner() (string, error) {
	if a.cacheResourceOwner != nil {
		return *a.cacheResourceOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualRouter == nil || resp.VirtualRouter.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.VirtualRouter.Metadata.ResourceOwner), nil
}

func (a *mqlAwsAppmeshVirtualRouter) version() (int64, error) {
	if a.cacheVersion != nil {
		return *a.cacheVersion, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if resp.VirtualRouter == nil || resp.VirtualRouter.Metadata == nil || resp.VirtualRouter.Metadata.Version == nil {
		return 0, nil
	}
	return *resp.VirtualRouter.Metadata.Version, nil
}

func (a *mqlAwsAppmeshVirtualRouter) createdAt() (*time.Time, error) {
	if a.cacheCreatedAt != nil {
		return a.cacheCreatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualRouter == nil || resp.VirtualRouter.Metadata == nil {
		return nil, nil
	}
	return resp.VirtualRouter.Metadata.CreatedAt, nil
}

func (a *mqlAwsAppmeshVirtualRouter) lastUpdatedAt() (*time.Time, error) {
	if a.cacheLastUpdatedAt != nil {
		return a.cacheLastUpdatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualRouter == nil || resp.VirtualRouter.Metadata == nil {
		return nil, nil
	}
	return resp.VirtualRouter.Metadata.LastUpdatedAt, nil
}

func (a *mqlAwsAppmeshVirtualRouter) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualRouter == nil || resp.VirtualRouter.Status == nil {
		return "", nil
	}
	return string(resp.VirtualRouter.Status.Status), nil
}

func (a *mqlAwsAppmeshVirtualRouter) listeners() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualRouter == nil || resp.VirtualRouter.Spec == nil {
		return []any{}, nil
	}
	listeners, err := convert.JsonToDictSlice(resp.VirtualRouter.Spec.Listeners)
	if err != nil {
		return nil, err
	}
	return listeners, nil
}

func (a *mqlAwsAppmeshVirtualRouter) routes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(a.region)
	ctx := context.Background()

	meshName := a.meshName
	routerName := a.Name.Data
	res := []any{}
	paginator := appmesh.NewListRoutesPaginator(svc, &appmesh.ListRoutesInput{
		MeshName:          &meshName,
		VirtualRouterName: &routerName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Routes {
			mqlRoute, err := CreateResource(a.MqlRuntime, "aws.appmesh.route",
				map[string]*llx.RawData{
					"__id":              llx.StringDataPtr(r.Arn),
					"arn":               llx.StringDataPtr(r.Arn),
					"name":              llx.StringDataPtr(r.RouteName),
					"meshName":          llx.StringData(meshName),
					"virtualRouterName": llx.StringData(routerName),
					"region":            llx.StringData(a.region),
				})
			if err != nil {
				return nil, err
			}
			internal := mqlRoute.(*mqlAwsAppmeshRoute)
			internal.region = a.region
			internal.meshName = meshName
			internal.virtualRouterName = routerName
			internal.cacheMeshOwner = r.MeshOwner
			internal.cacheResourceOwner = r.ResourceOwner
			internal.cacheVersion = r.Version
			internal.cacheCreatedAt = r.CreatedAt
			internal.cacheLastUpdatedAt = r.LastUpdatedAt
			res = append(res, mqlRoute)
		}
	}
	return res, nil
}

func (a *mqlAwsAppmeshVirtualRouter) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	// a.region is only populated when the resource was built via the parent
	// listing; via initAwsAppmeshVirtualRouter, only a.Region.Data is set.
	// Fall back to the schema field so the AppMesh client is constructed for
	// the correct region regardless of which path the caller took.
	region := a.region
	if region == "" {
		region = a.Region.Data
	}
	svc := conn.AppMesh(region)
	ctx := context.Background()

	arn := a.Arn.Data
	tags := make(map[string]any)
	paginator := appmesh.NewListTagsForResourcePaginator(svc, &appmesh.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, tag := range page.Tags {
			tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
		}
	}
	return tags, nil
}

// ==================== Routes ====================

func (a *mqlAwsAppmeshRoute) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsAppmeshRouteInternal struct {
	fetched            bool
	lock               sync.Mutex
	descResp           *appmesh.DescribeRouteOutput
	region             string
	meshName           string
	virtualRouterName  string
	cacheMeshOwner     *string
	cacheResourceOwner *string
	cacheVersion       *int64
	cacheCreatedAt     *time.Time
	cacheLastUpdatedAt *time.Time
}

func (a *mqlAwsAppmeshRoute) fetchDetail() (*appmesh.DescribeRouteOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(a.region)
	ctx := context.Background()

	routeName := a.Name.Data
	meshName := a.meshName
	routerName := a.virtualRouterName
	resp, err := svc.DescribeRoute(ctx, &appmesh.DescribeRouteInput{
		MeshName:          &meshName,
		VirtualRouterName: &routerName,
		RouteName:         &routeName,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsAppmeshRoute) meshOwner() (string, error) {
	if a.cacheMeshOwner != nil {
		return *a.cacheMeshOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Route == nil || resp.Route.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.Route.Metadata.MeshOwner), nil
}

func (a *mqlAwsAppmeshRoute) resourceOwner() (string, error) {
	if a.cacheResourceOwner != nil {
		return *a.cacheResourceOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Route == nil || resp.Route.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.Route.Metadata.ResourceOwner), nil
}

func (a *mqlAwsAppmeshRoute) version() (int64, error) {
	if a.cacheVersion != nil {
		return *a.cacheVersion, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if resp.Route == nil || resp.Route.Metadata == nil || resp.Route.Metadata.Version == nil {
		return 0, nil
	}
	return *resp.Route.Metadata.Version, nil
}

func (a *mqlAwsAppmeshRoute) createdAt() (*time.Time, error) {
	if a.cacheCreatedAt != nil {
		return a.cacheCreatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Route == nil || resp.Route.Metadata == nil {
		return nil, nil
	}
	return resp.Route.Metadata.CreatedAt, nil
}

func (a *mqlAwsAppmeshRoute) lastUpdatedAt() (*time.Time, error) {
	if a.cacheLastUpdatedAt != nil {
		return a.cacheLastUpdatedAt, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Route == nil || resp.Route.Metadata == nil {
		return nil, nil
	}
	return resp.Route.Metadata.LastUpdatedAt, nil
}

func (a *mqlAwsAppmeshRoute) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Route == nil || resp.Route.Status == nil {
		return "", nil
	}
	return string(resp.Route.Status.Status), nil
}

func (a *mqlAwsAppmeshRoute) priority() (int64, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if resp.Route == nil || resp.Route.Spec == nil || resp.Route.Spec.Priority == nil {
		return 0, nil
	}
	return int64(*resp.Route.Spec.Priority), nil
}

func (a *mqlAwsAppmeshRoute) spec() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Route == nil || resp.Route.Spec == nil {
		return map[string]any{}, nil
	}
	return convert.JsonToDict(resp.Route.Spec)
}

func (a *mqlAwsAppmeshRoute) httpRouteSpec() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Route == nil || resp.Route.Spec == nil || resp.Route.Spec.HttpRoute == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.Route.Spec.HttpRoute)
}

func (a *mqlAwsAppmeshRoute) http2RouteSpec() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Route == nil || resp.Route.Spec == nil || resp.Route.Spec.Http2Route == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.Route.Spec.Http2Route)
}

func (a *mqlAwsAppmeshRoute) tcpRouteSpec() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Route == nil || resp.Route.Spec == nil || resp.Route.Spec.TcpRoute == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.Route.Spec.TcpRoute)
}

func (a *mqlAwsAppmeshRoute) grpcRouteSpec() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Route == nil || resp.Route.Spec == nil || resp.Route.Spec.GrpcRoute == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.Route.Spec.GrpcRoute)
}

func (a *mqlAwsAppmeshRoute) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	// Same a.region vs a.Region.Data caveat as the sibling virtual* resources
	// — fall back so init-created Routes still tag-fetch from the right region.
	region := a.region
	if region == "" {
		region = a.Region.Data
	}
	svc := conn.AppMesh(region)
	ctx := context.Background()

	arn := a.Arn.Data
	tags := make(map[string]any)
	paginator := appmesh.NewListTagsForResourcePaginator(svc, &appmesh.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, tag := range page.Tags {
			tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
		}
	}
	return tags, nil
}

// ==================== Virtual Gateways ====================

func (a *mqlAwsAppmeshMesh) virtualGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.AppMesh(region)
	ctx := context.Background()

	meshName := a.Name.Data
	res := []any{}
	paginator := appmesh.NewListVirtualGatewaysPaginator(svc, &appmesh.ListVirtualGatewaysInput{
		MeshName: &meshName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vg := range page.VirtualGateways {
			args := map[string]*llx.RawData{
				"__id":          llx.StringDataPtr(vg.Arn),
				"arn":           llx.StringDataPtr(vg.Arn),
				"name":          llx.StringDataPtr(vg.VirtualGatewayName),
				"meshName":      llx.StringData(meshName),
				"region":        llx.StringData(region),
				"meshOwner":     llx.StringDataPtr(vg.MeshOwner),
				"createdAt":     llx.TimeDataPtr(vg.CreatedAt),
				"lastUpdatedAt": llx.TimeDataPtr(vg.LastUpdatedAt),
			}
			if vg.Version != nil {
				args["version"] = llx.IntData(*vg.Version)
			}
			mqlVg, err := CreateResource(a.MqlRuntime, "aws.appmesh.virtualGateway", args)
			if err != nil {
				return nil, err
			}
			internal := mqlVg.(*mqlAwsAppmeshVirtualGateway)
			internal.region = region
			internal.meshName = meshName
			internal.cacheResourceOwner = vg.ResourceOwner
			res = append(res, mqlVg)
		}
	}
	return res, nil
}

func (a *mqlAwsAppmeshVirtualGateway) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsAppmeshVirtualGatewayInternal struct {
	fetched            bool
	lock               sync.Mutex
	descResp           *appmesh.DescribeVirtualGatewayOutput
	region             string
	meshName           string
	cacheResourceOwner *string
}

func initAwsAppmeshVirtualGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	arnRaw, ok := args["arn"]
	if !ok || arnRaw == nil {
		return args, nil, nil
	}
	arnStr, ok := arnRaw.Value.(string)
	if !ok || arnStr == "" {
		return args, nil, nil
	}
	region, meshName, kind, name, err := parseAppmeshArn(arnStr)
	if err != nil {
		return nil, nil, err
	}
	if kind != "virtualGateway" {
		return nil, nil, errors.New("ARN does not reference an aws.appmesh.virtualGateway: " + arnStr)
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(region)
	ctx := context.Background()
	resp, err := svc.DescribeVirtualGateway(ctx, &appmesh.DescribeVirtualGatewayInput{
		MeshName:           &meshName,
		VirtualGatewayName: &name,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.VirtualGateway == nil {
		return args, nil, nil
	}
	vg := resp.VirtualGateway

	args["__id"] = llx.StringData(arnStr)
	args["arn"] = llx.StringData(arnStr)
	args["name"] = llx.StringData(name)
	args["meshName"] = llx.StringData(meshName)
	args["region"] = llx.StringData(region)
	if vg.Metadata != nil {
		if vg.Metadata.MeshOwner != nil {
			args["meshOwner"] = llx.StringData(*vg.Metadata.MeshOwner)
		}
		if vg.Metadata.Version != nil {
			args["version"] = llx.IntData(*vg.Metadata.Version)
		}
		args["createdAt"] = llx.TimeDataPtr(vg.Metadata.CreatedAt)
		args["lastUpdatedAt"] = llx.TimeDataPtr(vg.Metadata.LastUpdatedAt)
	}
	res, err := CreateResource(runtime, "aws.appmesh.virtualGateway", args)
	if err != nil {
		return nil, nil, err
	}
	gateway := res.(*mqlAwsAppmeshVirtualGateway)
	gateway.descResp = resp
	gateway.fetched = true
	gateway.region = region
	gateway.meshName = meshName
	return args, res, nil
}

func (a *mqlAwsAppmeshVirtualGateway) fetchDetail() (*appmesh.DescribeVirtualGatewayOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	region := a.region
	meshName := a.meshName
	if region == "" || meshName == "" {
		r, m, _, _, err := parseAppmeshArn(a.Arn.Data)
		if err != nil {
			return nil, err
		}
		if region == "" {
			region = r
			a.region = r
		}
		if meshName == "" {
			meshName = m
			a.meshName = m
		}
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(region)
	ctx := context.Background()

	gwName := a.Name.Data
	resp, err := svc.DescribeVirtualGateway(ctx, &appmesh.DescribeVirtualGatewayInput{
		MeshName:           &meshName,
		VirtualGatewayName: &gwName,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsAppmeshVirtualGateway) resourceOwner() (string, error) {
	if a.cacheResourceOwner != nil {
		return *a.cacheResourceOwner, nil
	}
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualGateway == nil || resp.VirtualGateway.Metadata == nil {
		return "", nil
	}
	return convert.ToValue(resp.VirtualGateway.Metadata.ResourceOwner), nil
}

func (a *mqlAwsAppmeshVirtualGateway) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.VirtualGateway == nil || resp.VirtualGateway.Status == nil {
		return "", nil
	}
	return string(resp.VirtualGateway.Status.Status), nil
}

func (a *mqlAwsAppmeshVirtualGateway) listeners() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualGateway == nil || resp.VirtualGateway.Spec == nil {
		return []any{}, nil
	}
	return convert.JsonToDictSlice(resp.VirtualGateway.Spec.Listeners)
}

func (a *mqlAwsAppmeshVirtualGateway) backendDefaults() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualGateway == nil || resp.VirtualGateway.Spec == nil || resp.VirtualGateway.Spec.BackendDefaults == nil {
		return []any{}, nil
	}
	d, err := convert.JsonToDict(resp.VirtualGateway.Spec.BackendDefaults)
	if err != nil {
		return nil, err
	}
	return []any{d}, nil
}

func (a *mqlAwsAppmeshVirtualGateway) logging() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.VirtualGateway == nil || resp.VirtualGateway.Spec == nil || resp.VirtualGateway.Spec.Logging == nil {
		return []any{}, nil
	}
	d, err := convert.JsonToDict(resp.VirtualGateway.Spec.Logging)
	if err != nil {
		return nil, err
	}
	return []any{d}, nil
}

func (a *mqlAwsAppmeshVirtualGateway) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	// a.region is only populated when the resource was built via the parent
	// listing; via initAwsAppmeshVirtualGateway, only a.Region.Data is set.
	// Fall back to the schema field so the AppMesh client is constructed for
	// the correct region regardless of which path the caller took.
	region := a.region
	if region == "" {
		region = a.Region.Data
	}
	svc := conn.AppMesh(region)
	ctx := context.Background()

	arn := a.Arn.Data
	tags := make(map[string]any)
	paginator := appmesh.NewListTagsForResourcePaginator(svc, &appmesh.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, tag := range page.Tags {
			tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
		}
	}
	return tags, nil
}

func (a *mqlAwsAppmeshVirtualService) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		region := a.region
		if region == "" {
			region = a.Region.Data
		}
		return appmeshTagsForArn(a.MqlRuntime, region, a.Arn.Data)
	})
}

func (a *mqlAwsAppmeshVirtualNode) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		region := a.region
		if region == "" {
			region = a.Region.Data
		}
		return appmeshTagsForArn(a.MqlRuntime, region, a.Arn.Data)
	})
}

// appmeshTagsForArn reads the tags of an App Mesh resource by ARN, following
// the paginated ListTagsForResource response to the end.
func appmeshTagsForArn(runtime *plugin.Runtime, region, resourceArn string) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppMesh(region)
	ctx := context.Background()
	tags := map[string]any{}
	paginator := appmesh.NewListTagsForResourcePaginator(svc, &appmesh.ListTagsForResourceInput{ResourceArn: &resourceArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				if plugin.StructuredErrors() {
					return nil, llx.Forbidden(err, llx.WithPermissions("appmesh:ListTagsForResource"))
				}
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		for k, v := range tagsToMap(page.Tags,
			func(t appmesh_types.TagRef) *string { return t.Key },
			func(t appmesh_types.TagRef) *string { return t.Value }) {
			tags[k] = v
		}
	}
	return tags, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
)

// The resources below are reachable two ways: through their gcp.project
// accessor (gcp.project.appEngine), which passes the project down, and by
// their own type name (gcp.project.appEngineService), which builds them from
// no arguments. On the second path the resource needs an init to fill in the
// project, otherwise every API call it makes targets "projects/" and fails
// with NotFound or InvalidArgument.

// initProjectScopedService sets projectId from the connection when the
// resource is built without arguments.
func initProjectScopedService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func initGcpProjectApiGatewayService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectAppEngineService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectCloudBuildService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectCloudDeployService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectCloudTasksService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectComposerService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectDataflowService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectHealthcareService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectIapService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectNotebooksService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectSourceRepositoriesService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectWorkbenchService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

func initGcpProjectWorkstationsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initProjectScopedService(runtime, args)
}

// initGcpProjectBinaryAuthorizationControl delegates to the gcp.project
// accessor. The resource carries no projectId: its policy is fetched up front
// by gcp.project.binaryAuthorization(), so built from no arguments it would
// have no policy at all.
func initGcpProjectBinaryAuthorizationControl(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	projectId := conn.ResourceID()

	proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(projectId),
	})
	if err != nil {
		return nil, nil, err
	}
	bauthz, err := proj.(*mqlGcpProject).binaryAuthorization()
	if err != nil {
		return nil, nil, err
	}
	if bauthz != nil {
		return nil, bauthz, nil
	}

	// The API is disabled or the policy is not readable: the accessor reports
	// null, so report the policy as null too.
	args["__id"] = llx.StringData(fmt.Sprintf("projects/%s/binaryAuthorizationControl", projectId))
	args["policy"] = llx.NilData
	return args, nil, nil
}

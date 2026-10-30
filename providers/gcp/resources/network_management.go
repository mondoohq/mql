// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	networkmanagement "cloud.google.com/go/networkmanagement/apiv1"
	"cloud.google.com/go/networkmanagement/apiv1/networkmanagementpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectNetworkManagementServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) networkManagement() (*mqlGcpProjectNetworkManagementService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.networkManagementService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_networkmanagement)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectNetworkManagementService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_networkmanagement).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectNetworkManagementService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	if args == nil {
		args = make(map[string]*llx.RawData)
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectNetworkManagementService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.networkManagementService", g.ProjectId.Data), nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectNetworkManagementService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_networkmanagement)
}

// networkManagementCredentials returns credentials scoped for the Network
// Management API. Only the credentials are shared, not the client: the
// permissions extractor tracks client variables per function, so a helper
// returning the client would hide the constructor and drop the permission from
// the manifest.
func (g *mqlGcpProjectNetworkManagementService) networkManagementCredentials() (*googleoauth.Credentials, error) {
	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return conn.Credentials(networkmanagement.DefaultAuthScopes()...)
}

func (g *mqlGcpProjectNetworkManagementServiceConnectivityTest) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// connectivityTests lists the project's reachability tests.
//
// The result and verify time are lifted out of reachabilityDetails onto the
// resource, because a test's verdict is the point of it and the verdict's age
// determines whether it still describes the network. The full details, including
// the per-hop trace naming every rule and route the analysis matched, stay
// available in the dict.
func (g *mqlGcpProjectNetworkManagementService) connectivityTests() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	creds, err := g.networkManagementCredentials()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := networkmanagement.NewReachabilityClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListConnectivityTests(ctx, &networkmanagementpb.ListConnectivityTestsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global", projectId),
	})

	res := []any{}
	for {
		test, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				// break rather than discard: keep the tests already returned.
				log.Warn().Err(err).Str("project", projectId).Msg("could not list all connectivity tests")
				break
			}
			return nil, err
		}

		source, err := protoToDict(test.GetSource())
		if err != nil {
			return nil, err
		}
		destination, err := protoToDict(test.GetDestination())
		if err != nil {
			return nil, err
		}
		reachabilityDetails, err := protoToDict(test.GetReachabilityDetails())
		if err != nil {
			return nil, err
		}
		probingDetails, err := protoToDict(test.GetProbingDetails())
		if err != nil {
			return nil, err
		}

		mqlTest, err := CreateResource(g.MqlRuntime, "gcp.project.networkManagementService.connectivityTest", map[string]*llx.RawData{
			"name":                 llx.StringData(test.GetName()),
			"displayName":          llx.StringData(test.GetDisplayName()),
			"description":          llx.StringData(test.GetDescription()),
			"result":               llx.StringData(test.GetReachabilityDetails().GetResult().String()),
			"verifyTime":           llx.TimeDataPtr(timestampAsTimePtr(test.GetReachabilityDetails().GetVerifyTime())),
			"protocol":             llx.StringData(test.GetProtocol()),
			"source":               llx.DictData(source),
			"destination":          llx.DictData(destination),
			"bypassFirewallChecks": llx.BoolData(test.GetBypassFirewallChecks()),
			"reachabilityDetails":  llx.DictData(reachabilityDetails),
			"probingDetails":       llx.DictData(probingDetails),
			"relatedProjects":      llx.ArrayData(convert.SliceAnyToInterface(test.GetRelatedProjects()), types.String),
			"labels":               llx.MapData(convert.MapToInterfaceMap(test.GetLabels()), types.String),
			"createTime":           llx.TimeDataPtr(timestampAsTimePtr(test.GetCreateTime())),
			"updateTime":           llx.TimeDataPtr(timestampAsTimePtr(test.GetUpdateTime())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTest)
	}

	return res, nil
}

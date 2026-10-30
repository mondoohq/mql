// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/option"
	workflows "google.golang.org/api/workflows/v1"
)

func (g *mqlGcpProjectWorkflowsService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.workflowsService", g.ProjectId.Data), nil
}

func (g *mqlGcpProject) workflows() (*mqlGcpProjectWorkflowsService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	serviceEnabled, err := g.isServiceEnabled(service_workflows)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_workflows).Msg("gcp service is not enabled, skipping")
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.workflowsService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"enabled":   llx.BoolData(serviceEnabled),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectWorkflowsService), nil
}

// Direct construction (e.g. `gcp.project.workflowsService.workflows`)
// bypasses gcp.project.workflows(), leaving projectId and enabled unset.
// Delegate to the parent project accessor so both are populated.
func initGcpProjectWorkflowsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["projectId"]; ok {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(conn.ResourceID()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc, err := proj.(*mqlGcpProject).workflows()
	if err != nil {
		return nil, nil, err
	}
	return nil, svc, nil
}

func (g *mqlGcpProjectWorkflowsService) workflows() ([]any, error) {
	if g.Enabled.Error != nil {
		return nil, g.Enabled.Error
	}
	if !g.Enabled.Data {
		return []any{}, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(workflows.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	workflowsSvc, err := workflows.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// The "-" location wildcard lists workflows across every location in a
	// single aggregated call, so there's no need to enumerate locations.
	parent := fmt.Sprintf("projects/%s/locations/-", projectId)
	var mqlWorkflows []any
	err = workflowsSvc.Projects.Locations.Workflows.List(parent).Pages(ctx, func(resp *workflows.ListWorkflowsResponse) error {
		for _, wf := range resp.Workflows {
			var stateError map[string]any
			if wf.StateError != nil {
				stateError, err = convert.JsonToDict(wf.StateError)
				if err != nil {
					log.Error().Err(err).Send()
				}
			}

			mqlWorkflow, err := CreateResource(g.MqlRuntime, "gcp.project.workflowsService.workflow", map[string]*llx.RawData{
				"__id":                  llx.StringData(wf.Name),
				"id":                    llx.StringData(wf.Name),
				"projectId":             llx.StringData(projectId),
				"location":              llx.StringData(workflowsLocation(wf.Name)),
				"name":                  llx.StringData(serviceName(wf.Name)),
				"description":           llx.StringData(wf.Description),
				"state":                 llx.StringData(wf.State),
				"stateError":            llx.DictData(stateError),
				"revisionId":            llx.StringData(wf.RevisionId),
				"created":               llx.TimeDataPtr(parseTime(wf.CreateTime)),
				"updated":               llx.TimeDataPtr(parseTime(wf.UpdateTime)),
				"revisionCreated":       llx.TimeDataPtr(parseTime(wf.RevisionCreateTime)),
				"labels":                llx.MapData(convert.MapToInterfaceMap(wf.Labels), types.String),
				"callLogLevel":          llx.StringData(wf.CallLogLevel),
				"executionHistoryLevel": llx.StringData(wf.ExecutionHistoryLevel),
				"cryptoKeyName":         llx.StringData(wf.CryptoKeyName),
				"allKmsKeys":            llx.ArrayData(convert.SliceAnyToInterface(wf.AllKmsKeys), types.String),
				"serviceAccountEmail":   llx.StringData(workflowsServiceAccountEmail(wf.ServiceAccount)),
				"sourceContents":        llx.StringData(wf.SourceContents),
				"userEnvVars":           llx.MapData(convert.MapToInterfaceMap(wf.UserEnvVars), types.String),
			})
			if err != nil {
				log.Error().Err(err).Send()
				continue
			}
			mqlWorkflows = append(mqlWorkflows, mqlWorkflow)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mqlWorkflows, nil
}

func (g *mqlGcpProjectWorkflowsServiceWorkflow) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" {
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// NewResource, not CreateResource: the service account has an init that
	// resolves the real account. CreateResource skips it, leaving a husk with
	// only projectId and email set -- and because that husk's id() falls back
	// to the email form while a listed account keys on uniqueId, the two never
	// share a cache entry, so it can't be repaired by a later lookup either.
	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(g.ProjectId.Data),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

// workflowsLocation extracts the location segment from a workflow resource
// name of the form projects/{project}/locations/{location}/workflows/{workflow}.
func workflowsLocation(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

// workflowsServiceAccountEmail normalizes a workflow's service account, which
// the API may return either as a bare email or as a
// projects/{project}/serviceAccounts/{email} resource path.
func workflowsServiceAccountEmail(sa string) string {
	if _, after, ok := strings.CutLast(sa, "/"); ok {
		return after
	}
	return sa
}

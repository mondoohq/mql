// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	waypoint_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-waypoint-service/preview/2024-11-22/client/waypoint_service"
	waypointmodels "github.com/hashicorp/hcp-sdk-go/clients/cloud-waypoint-service/preview/2024-11-22/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHcpWaypointApplicationInternal struct {
	cacheProjectID string
}

// waypointApplications lists the Waypoint applications in the project.
func (r *mqlHcpProject) waypointApplications() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return listMqlHcpWaypointApplications(r.MqlRuntime, oid, r.Id.Data)
}

func listMqlHcpWaypointApplications(runtime *plugin.Runtime, orgID, projectID string) ([]any, error) {
	conn := hcpConn(runtime)
	client := waypoint_service.New(conn.Transport(), nil)

	out := []any{}
	var nextToken *string
	for {
		params := waypoint_service.NewWaypointServiceListApplicationsParams()
		params.NamespaceLocationOrganizationID = orgID
		params.NamespaceLocationProjectID = projectID
		params.PaginationNextPageToken = nextToken
		resp, err := client.WaypointServiceListApplications(params, nil)
		if err != nil {
			// Waypoint is not activated in every project; degrade to no
			// applications rather than failing the whole project query.
			if isServiceUnavailable(err) {
				return out, nil
			}
			return nil, err
		}
		if resp.Payload == nil {
			break
		}
		for _, a := range resp.Payload.Applications {
			res, err := newMqlHcpWaypointApplication(runtime, projectID, a)
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if resp.Payload.Pagination == nil || resp.Payload.Pagination.NextPageToken == "" {
			break
		}
		token := resp.Payload.Pagination.NextPageToken
		nextToken = &token
	}
	return out, nil
}

func newMqlHcpWaypointApplication(runtime *plugin.Runtime, projectID string, a *waypointmodels.HashicorpCloudWaypointV20241122Application) (*mqlHcpWaypointApplication, error) {
	templateID := ""
	if a.ApplicationTemplate != nil {
		templateID = a.ApplicationTemplate.ID
	}
	res, err := CreateResource(runtime, "hcp.waypoint.application", map[string]*llx.RawData{
		"__id":           llx.StringData("hcp.waypoint.application/" + a.ID),
		"id":             llx.StringData(a.ID),
		"name":           llx.StringData(a.Name),
		"templateName":   llx.StringData(a.TemplateName),
		"templateId":     llx.StringData(templateID),
		"tfcWorkspaceId": llx.StringData(a.TfcWorkspaceID),
	})
	if err != nil {
		return nil, err
	}
	app := res.(*mqlHcpWaypointApplication)
	app.cacheProjectID = projectID
	return app, nil
}

// initHcpWaypointApplication hydrates a single Waypoint application, either from
// an explicit id argument or from the discovered asset the connection is scoped
// to.
func initHcpWaypointApplication(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	appID, projectID, err := scopedResourceIDs(runtime, args)
	if err != nil {
		return nil, nil, err
	}
	if appID == "" {
		return nil, nil, fmt.Errorf("hcp.waypoint.application requires an application id")
	}
	oid, err := orgID(runtime)
	if err != nil {
		return nil, nil, err
	}
	apps, err := listMqlHcpWaypointApplications(runtime, oid, projectID)
	if err != nil {
		return nil, nil, err
	}
	for _, a := range apps {
		app := a.(*mqlHcpWaypointApplication)
		if app.Id.Data == appID {
			return nil, app, nil
		}
	}
	return nil, nil, fmt.Errorf("hcp.waypoint.application %q not found in project %q", appID, projectID)
}

// project resolves the project the application belongs to.
func (r *mqlHcpWaypointApplication) project() (*mqlHcpProject, error) {
	return projectRef(r.MqlRuntime, &r.Project, r.cacheProjectID)
}

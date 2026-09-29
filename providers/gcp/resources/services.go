// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	serviceusage "cloud.google.com/go/serviceusage/apiv1"
	"cloud.google.com/go/serviceusage/apiv1/serviceusagepb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const (
	service_compute             = "compute.googleapis.com"
	service_gke                 = "container.googleapis.com"
	service_bigquery            = "bigquery.googleapis.com"
	service_essential_contacts  = "essentialcontacts.googleapis.com"
	service_dns                 = "dns.googleapis.com"
	service_accessapproval      = "accessapproval.googleapis.com"
	service_apikeys             = "apikeys.googleapis.com"
	service_dataproc            = "dataproc.googleapis.com"
	service_binaryauthorization = "binaryauthorization.googleapis.com"
	service_privateca           = "privateca.googleapis.com"
	service_certificatemanager  = "certificatemanager.googleapis.com"
	service_orgpolicy           = "orgpolicy.googleapis.com"
	service_securitycenter      = "securitycenter.googleapis.com"
	service_redis               = "redis.googleapis.com"
	service_secretmanager       = "secretmanager.googleapis.com"
	service_pubsub              = "pubsub.googleapis.com"
	service_cloudrun            = "run.googleapis.com"
	service_cloudfunctions      = "cloudfunctions.googleapis.com"
	service_logging             = "logging.googleapis.com"
	service_kms                 = "cloudkms.googleapis.com"
	service_kmsinventory        = "kmsinventory.googleapis.com"
	service_sqladmin            = "sqladmin.googleapis.com"
	service_storage             = "storage.googleapis.com"
	service_iam                 = "iam.googleapis.com"
	service_modelarmor          = "modelarmor.googleapis.com"
	service_identityplatform    = "identitytoolkit.googleapis.com"
	service_eventarc            = "eventarc.googleapis.com"
	service_dlp                 = "dlp.googleapis.com"
	service_batch               = "batch.googleapis.com"
	service_ids                 = "ids.googleapis.com"
	service_gkebackup           = "gkebackup.googleapis.com"
	service_containeranalysis   = "containeranalysis.googleapis.com"
	service_cloudbuild          = "cloudbuild.googleapis.com"
	service_iap                 = "iap.googleapis.com"
	service_sourcerepo          = "sourcerepo.googleapis.com"
	service_osconfig            = "osconfig.googleapis.com"
	service_cloudidentity       = "cloudidentity.googleapis.com"
	service_networksecurity     = "networksecurity.googleapis.com"
	service_dataplex            = "dataplex.googleapis.com"
	service_workflows           = "workflows.googleapis.com"
	service_cloudscheduler      = "cloudscheduler.googleapis.com"
	service_clouddomains        = "domains.googleapis.com"
	service_cloudasset          = "cloudasset.googleapis.com"
	service_pam                 = "privilegedaccessmanager.googleapis.com"
	service_networkconnectivity = "networkconnectivity.googleapis.com"
	service_networkmanagement   = "networkmanagement.googleapis.com"
	service_memcache            = "memcache.googleapis.com"
	service_monitoring          = "monitoring.googleapis.com"
	service_aiplatform          = "aiplatform.googleapis.com"
	service_datastream          = "datastream.googleapis.com"
	service_memorystore         = "memorystore.googleapis.com"
	service_documentai          = "documentai.googleapis.com"
	service_firebaserules       = "firebaserules.googleapis.com"
)

func serviceName(name string) string {
	entries := strings.Split(name, "/")
	return entries[len(entries)-1]
}

func (g *mqlGcpProject) services() ([]any, error) {
	return g.fetchServices("")
}

// fetches the gcp services with a filter, e.g. "state:ENABLED"
func (g *mqlGcpProject) fetchServices(filter string) ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	credentials, err := conn.Credentials(serviceusage.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	c, err := serviceusage.NewClient(ctx, option.WithCredentials(credentials), connection.GRPCClientTraceOption())
	if err != nil {
		log.Info().Err(err).Msg("could not create client")
		return nil, err
	}

	// projects/123/services/serviceusage.googleapis.com
	//service, err := c.GetService(ctx, &serviceusagepb.GetServiceRequest{
	//	Name: name,
	//})
	//service.Config.Title

	it := c.ListServices(ctx, &serviceusagepb.ListServicesRequest{
		Parent:   `projects/` + projectId,
		Filter:   filter,
		PageSize: 200,
	})

	res := []any{}
	for {
		item, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		title := ""
		if item.Config != nil {
			title = item.Config.Title
		}

		mqlService, err := CreateResource(g.MqlRuntime, "gcp.service", map[string]*llx.RawData{
			"projectId":  llx.StringData(projectId),
			"name":       llx.StringData(serviceName(item.Name)),
			"parentName": llx.StringData(item.Parent),
			"state":      llx.StringData(item.State.String()),
			"title":      llx.StringData(title),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlService)
	}

	return res, nil
}

func (g *mqlGcpService) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	parent := g.GetParentName()
	if parent.Error != nil {
		return "", parent.Error
	}

	return "gcp.service/" + parent.Data + "/" + name, nil
}

func initGcpService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.service requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.service requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Check the arguments before building credentials, so an unusable one is
	// reported as itself rather than as whatever the credential lookup says.
	projectId := conn.ResourceID()
	if projectIdRaw := args["projectId"]; projectIdRaw != nil {
		projectId, ok = projectIdRaw.Value.(string)
		if !ok || projectId == "" {
			return nil, nil, errors.New(`gcp.service requires a non-empty "projectId" argument`)
		}
	}

	credentials, err := conn.Credentials(serviceusage.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	c, err := serviceusage.NewClient(ctx, option.WithCredentials(credentials), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}

	// name is constructed `projects/123/services/serviceusage.googleapis.com`
	item, err := c.GetService(context.Background(), &serviceusagepb.GetServiceRequest{
		Name: `projects/` + projectId + "/services/" + name,
	})
	if err != nil {
		return nil, nil, err
	}

	args["projectId"] = llx.StringData(projectId)
	args["name"] = llx.StringData(serviceName(item.Name))
	args["parentName"] = llx.StringData(item.Parent)
	args["state"] = llx.StringData(item.State.String())

	title := ""
	if item.Config != nil {
		title = item.Config.Title
	}
	args["title"] = llx.StringData(title)

	return args, nil, nil
}

func (g *mqlGcpService) enabled() (bool, error) {
	if g.State.Error != nil {
		return false, g.State.Error
	}
	state := g.State.Data
	return state == "ENABLED", nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"github.com/rs/zerolog/log"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

type mqlGcpOrganizationInternal struct {
	iamPolicyOnce  sync.Once
	iamPolicyCache *cloudresourcemanager.Policy
	iamPolicyErr   error
}

func (g *mqlGcpOrganization) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func initGcpOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

	// determine org from project in transport
	orgId, err := conn.OrganizationID()
	if err != nil {
		log.Error().Err(err).Msg("could not determine organization id")
		return nil, nil, err
	}

	name := "organizations/" + orgId
	org, err := svc.Organizations.Get(name).Do()
	if err != nil {
		// Return the error unchanged. Replacing it with a plain string here
		// used to destroy the *googleapi.Error, which is the only thing
		// callers can classify: discovery had to fall back to substring
		// matching on the message to recognize a denial it could skip.
		log.Error().Err(err).Str("organization", orgId).Msg("cannot fetch organization info")
		return nil, nil, err
	}

	args["id"] = llx.StringData(org.Name)
	args["customerId"] = llx.StringData(org.DirectoryCustomerId)
	args["name"] = llx.StringData(org.DisplayName)
	args["state"] = llx.StringData(org.State)
	args["created"] = llx.TimeDataPtr(parseTime(org.CreateTime))
	args["updated"] = llx.TimeDataPtr(parseTime(org.UpdateTime))
	args["deleteTime"] = llx.TimeDataPtr(parseTime(org.DeleteTime))

	return args, nil, nil
}

func (g *mqlGcpOrganization) name() (string, error) {
	// placeholder to convince MQL that this is an optional field
	// should never be called since the data is initialized in init
	return "", errors.New("not implemented")
}

func (g *mqlGcpOrganization) state() (string, error) {
	// placeholder to convince MQL that this is an optional field
	// should never be called since the data is initialized in init
	return "", errors.New("not implemented")
}

func (g *mqlGcpOrganization) fetchIamPolicy() (string, *cloudresourcemanager.Policy, error) {
	g.iamPolicyOnce.Do(func() {
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

		orgId, err := conn.OrganizationID()
		if err != nil {
			g.iamPolicyErr = err
			return
		}

		name := "organizations/" + orgId
		g.iamPolicyCache, g.iamPolicyErr = svc.Organizations.GetIamPolicy(name, &cloudresourcemanager.GetIamPolicyRequest{Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3}}).Do()
	})
	if g.iamPolicyErr != nil {
		return "", nil, g.iamPolicyErr
	}
	orgId, err := g.MqlRuntime.Connection.(*connection.GcpConnection).OrganizationID()
	if err != nil {
		return "", nil, err
	}
	return "organizations/" + orgId, g.iamPolicyCache, nil
}

func (g *mqlGcpOrganization) iamPolicy() ([]any, error) {
	name, policy, err := g.fetchIamPolicy()
	if err != nil {
		return nil, err
	}
	return policyBindings(g.MqlRuntime, name, policy)
}

// auditConfigID returns the cache ID for an audit config resource.
func auditConfigID(parentId, service string) string {
	return fmt.Sprintf("%s-auditConfig-%s", parentId, service)
}

// auditLogConfigID returns the cache ID for an audit log config resource.
func auditLogConfigID(parentId, service, logType string) string {
	return fmt.Sprintf("%s-auditConfig-%s-%s", parentId, service, logType)
}

// extractAuditConfigs converts cloudresourcemanager AuditConfig entries to MQL resources.
// parentId is used for constructing unique IDs (e.g., "organizations/123" or "projects/my-project").
func extractAuditConfigs(runtime *plugin.Runtime, parentId string, auditConfigs []*cloudresourcemanager.AuditConfig) ([]any, error) {
	var res []any
	for _, ac := range auditConfigs {
		logConfigs := make([]any, 0, len(ac.AuditLogConfigs))
		for _, lc := range ac.AuditLogConfigs {
			mqlLogConfig, err := CreateResource(runtime, "gcp.resourcemanager.auditConfig.logConfig", map[string]*llx.RawData{
				"id":              llx.StringData(auditLogConfigID(parentId, ac.Service, lc.LogType)),
				"logType":         llx.StringData(lc.LogType),
				"exemptedMembers": llx.ArrayData(convert.SliceAnyToInterface(lc.ExemptedMembers), types.String),
			})
			if err != nil {
				return nil, err
			}
			logConfigs = append(logConfigs, mqlLogConfig)
		}

		mqlAuditConfig, err := CreateResource(runtime, "gcp.resourcemanager.auditConfig", map[string]*llx.RawData{
			"id":              llx.StringData(auditConfigID(parentId, ac.Service)),
			"service":         llx.StringData(ac.Service),
			"auditLogConfigs": llx.ArrayData(logConfigs, types.Resource("gcp.resourcemanager.auditConfig.logConfig")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAuditConfig)
	}
	return res, nil
}

func (g *mqlGcpOrganization) auditConfig() ([]any, error) {
	name, policy, err := g.fetchIamPolicy()
	if err != nil {
		return nil, err
	}

	return extractAuditConfigs(g.MqlRuntime, name, policy.AuditConfigs)
}

func (g *mqlGcpOrganization) folders() (*mqlGcpFolders, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	orgId := g.Id.Data
	res, err := CreateResource(g.MqlRuntime, "gcp.folders", map[string]*llx.RawData{
		"parentId": llx.StringData(orgId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpFolders), nil
}

func (g *mqlGcpOrganization) projects() (*mqlGcpProjects, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	orgId := g.Id.Data
	res, err := CreateResource(g.MqlRuntime, "gcp.projects", map[string]*llx.RawData{
		"parentId": llx.StringData(orgId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjects), nil
}

func (g *mqlGcpResourcemanagerBinding) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpResourcemanagerAuditConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpResourcemanagerAuditConfigLogConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

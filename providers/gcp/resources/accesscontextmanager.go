// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	accesscontextmanager "cloud.google.com/go/accesscontextmanager/apiv1"
	acmpb "cloud.google.com/go/accesscontextmanager/apiv1/accesscontextmanagerpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpAccesscontextmanagerAccessPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpAccesscontextmanagerAccessLevel) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpAccesscontextmanagerServicePerimeter) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpAccesscontextmanagerGcpUserAccessBinding) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpOrganization) gcpUserAccessBindings() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	orgId, err := conn.OrganizationID()
	if err != nil {
		return nil, err
	}

	client, err := newACMClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListGcpUserAccessBindings(context.Background(), &acmpb.ListGcpUserAccessBindingsRequest{
		Parent: "organizations/" + orgId,
	})

	var res []any
	for {
		binding, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.accesscontextmanager.gcpUserAccessBinding", map[string]*llx.RawData{
			"name":         llx.StringData(binding.Name),
			"groupKey":     llx.StringData(binding.GroupKey),
			"accessLevels": llx.ArrayData(convert.SliceAnyToInterface(binding.AccessLevels), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}

	return res, nil
}

func newACMClient(conn *connection.GcpConnection) (*accesscontextmanager.Client, error) {
	creds, err := conn.Credentials(accesscontextmanager.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	return accesscontextmanager.NewClient(context.Background(), option.WithCredentials(creds), connection.GRPCClientTraceOption())
}

func (g *mqlGcpOrganization) accessPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	orgId, err := conn.OrganizationID()
	if err != nil {
		return nil, err
	}

	client, err := newACMClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListAccessPolicies(context.Background(), &acmpb.ListAccessPoliciesRequest{
		Parent: "organizations/" + orgId,
	})

	var res []any
	for {
		policy, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.accesscontextmanager.accessPolicy", map[string]*llx.RawData{
			"name":    llx.StringData(policy.Name),
			"title":   llx.StringData(policy.Title),
			"parent":  llx.StringData(policy.Parent),
			"etag":    llx.StringData(policy.Etag),
			"created": llx.TimeDataPtr(timestampAsTimePtr(policy.GetCreateTime())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}

	return res, nil
}

func (g *mqlGcpAccesscontextmanagerAccessPolicy) accessLevels() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	policyName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := newACMClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListAccessLevels(context.Background(), &acmpb.ListAccessLevelsRequest{
		Parent: policyName,
	})

	var res []any
	for {
		level, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		basic, err := protoToDict(level.GetBasic())
		if err != nil {
			return nil, err
		}
		custom, err := protoToDict(level.GetCustom())
		if err != nil {
			return nil, err
		}

		mqlLevel, err := CreateResource(g.MqlRuntime, "gcp.accesscontextmanager.accessLevel", map[string]*llx.RawData{
			"name":        llx.StringData(level.Name),
			"title":       llx.StringData(level.Title),
			"description": llx.StringData(level.Description),
			"basic":       llx.DictData(basic),
			"custom":      llx.DictData(custom),
			"createTime":  llx.TimeDataPtr(timestampAsTimePtr(level.CreateTime)),
			"updateTime":  llx.TimeDataPtr(timestampAsTimePtr(level.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlLevel)
	}

	return res, nil
}

func (g *mqlGcpAccesscontextmanagerAccessPolicy) servicePerimeters() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	policyName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := newACMClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListServicePerimeters(context.Background(), &acmpb.ListServicePerimetersRequest{
		Parent: policyName,
	})

	var res []any
	for {
		perimeter, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		mqlPerimeter, err := CreateResource(g.MqlRuntime, "gcp.accesscontextmanager.servicePerimeter", map[string]*llx.RawData{
			"name":                  llx.StringData(perimeter.Name),
			"title":                 llx.StringData(perimeter.Title),
			"description":           llx.StringData(perimeter.Description),
			"perimeterType":         llx.StringData(perimeter.PerimeterType.String()),
			"useExplicitDryRunSpec": llx.BoolData(perimeter.UseExplicitDryRunSpec),
			"createTime":            llx.TimeDataPtr(timestampAsTimePtr(perimeter.CreateTime)),
			"updateTime":            llx.TimeDataPtr(timestampAsTimePtr(perimeter.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlP := mqlPerimeter.(*mqlGcpAccesscontextmanagerServicePerimeter)
		mqlP.cacheStatus = perimeter.Status
		mqlP.cacheSpec = perimeter.Spec

		res = append(res, mqlPerimeter)
	}

	return res, nil
}

// mqlGcpAccesscontextmanagerServicePerimeterInternal caches the proto configs
// so that statusConfig() and specConfig() can extract typed fields.
type mqlGcpAccesscontextmanagerServicePerimeterInternal struct {
	cacheStatus *acmpb.ServicePerimeterConfig
	cacheSpec   *acmpb.ServicePerimeterConfig
}

func (g *mqlGcpAccesscontextmanagerServicePerimeterConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

// servicePerimeterConfigFromProto creates a gcp.accesscontextmanager.servicePerimeter.config
// resource from a ServicePerimeterConfig proto. Returns nil (with StateIsNull) when cfg is nil.
func servicePerimeterConfigFromProto(runtime *plugin.Runtime, id string, cfg *acmpb.ServicePerimeterConfig) (*mqlGcpAccesscontextmanagerServicePerimeterConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	vpcAccessibleServices, err := protoToDict(cfg.VpcAccessibleServices)
	if err != nil {
		return nil, err
	}

	ingressPolicies := make([]any, 0, len(cfg.IngressPolicies))
	for _, ip := range cfg.IngressPolicies {
		d, err := protoToDict(ip)
		if err != nil {
			return nil, err
		}
		ingressPolicies = append(ingressPolicies, d)
	}

	egressPolicies := make([]any, 0, len(cfg.EgressPolicies))
	for _, ep := range cfg.EgressPolicies {
		d, err := protoToDict(ep)
		if err != nil {
			return nil, err
		}
		egressPolicies = append(egressPolicies, d)
	}

	res, err := CreateResource(runtime, "gcp.accesscontextmanager.servicePerimeter.config", map[string]*llx.RawData{
		"id":                    llx.StringData(id),
		"resources":             llx.ArrayData(convert.SliceAnyToInterface(cfg.Resources), types.String),
		"restrictedServices":    llx.ArrayData(convert.SliceAnyToInterface(cfg.RestrictedServices), types.String),
		"accessLevels":          llx.ArrayData(convert.SliceAnyToInterface(cfg.AccessLevels), types.String),
		"vpcAccessibleServices": llx.DictData(vpcAccessibleServices),
		"ingressPolicies":       llx.ArrayData(ingressPolicies, types.Dict),
		"egressPolicies":        llx.ArrayData(egressPolicies, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpAccesscontextmanagerServicePerimeterConfig), nil
}

func (g *mqlGcpAccesscontextmanagerServicePerimeter) statusConfig() (*mqlGcpAccesscontextmanagerServicePerimeterConfig, error) {
	if g.cacheStatus == nil {
		g.StatusConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return servicePerimeterConfigFromProto(g.MqlRuntime, fmt.Sprintf("%s/statusConfig", g.Name.Data), g.cacheStatus)
}

func (g *mqlGcpAccesscontextmanagerServicePerimeter) specConfig() (*mqlGcpAccesscontextmanagerServicePerimeterConfig, error) {
	if g.cacheSpec == nil {
		g.SpecConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return servicePerimeterConfigFromProto(g.MqlRuntime, fmt.Sprintf("%s/specConfig", g.Name.Data), g.cacheSpec)
}

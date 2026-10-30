// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	sccpb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpSccSecurityHealthAnalyticsCustomModule) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpSccEventThreatDetectionCustomModule) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// sccShaCustomModulesParent and sccEtdCustomModulesParent return the parent
// the effective custom modules of a scope ("organizations/{id}",
// "folders/{id}", or "projects/{id}") are listed under.
func sccShaCustomModulesParent(scope string) string {
	return scope + "/securityHealthAnalyticsSettings"
}

func sccEtdCustomModulesParent(scope string) string {
	return scope + "/eventThreatDetectionSettings"
}

// listSccShaCustomModules lists the Security Health Analytics custom modules
// in effect at a scope, including the ones it inherits from an ancestor.
func listSccShaCustomModules(runtime *plugin.Runtime, scope string) ([]any, error) {
	conn := runtime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(securitycenter.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	client, err := securitycenter.NewClient(context.Background(), option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	res := []any{}
	it := client.ListEffectiveSecurityHealthAnalyticsCustomModules(context.Background(),
		&sccpb.ListEffectiveSecurityHealthAnalyticsCustomModulesRequest{Parent: sccShaCustomModulesParent(scope)})
	for {
		m, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return listRefusal(err, "could not list Security Health Analytics custom modules",
				"securitycenter.effectivesecurityhealthanalyticscustommodules.list")
		}
		customConfig, err := protoToDict(m.GetCustomConfig())
		if err != nil {
			return nil, err
		}
		mqlModule, err := CreateResource(runtime, "gcp.scc.securityHealthAnalyticsCustomModule", map[string]*llx.RawData{
			"name":            llx.StringData(m.GetName()),
			"displayName":     llx.StringData(m.GetDisplayName()),
			"enablementState": llx.StringData(m.GetEnablementState().String()),
			"severity":        llx.StringData(m.GetCustomConfig().GetSeverity().String()),
			"customConfig":    llx.DictData(customConfig),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlModule)
	}
	return res, nil
}

// listSccEtdCustomModules lists the Event Threat Detection custom modules in
// effect at a scope, including the ones it inherits from an ancestor.
func listSccEtdCustomModules(runtime *plugin.Runtime, scope string) ([]any, error) {
	conn := runtime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(securitycenter.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	client, err := securitycenter.NewClient(context.Background(), option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	res := []any{}
	it := client.ListEffectiveEventThreatDetectionCustomModules(context.Background(),
		&sccpb.ListEffectiveEventThreatDetectionCustomModulesRequest{Parent: sccEtdCustomModulesParent(scope)})
	for {
		m, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return listRefusal(err, "could not list Event Threat Detection custom modules",
				"securitycentermanagement.effectiveEventThreatDetectionCustomModules.list")
		}
		var config map[string]any
		if m.GetConfig() != nil {
			config = m.GetConfig().AsMap()
		}
		mqlModule, err := CreateResource(runtime, "gcp.scc.eventThreatDetectionCustomModule", map[string]*llx.RawData{
			"name":            llx.StringData(m.GetName()),
			"displayName":     llx.StringData(m.GetDisplayName()),
			"description":     llx.StringData(m.GetDescription()),
			"type":            llx.StringData(m.GetType()),
			"enablementState": llx.StringData(m.GetEnablementState().String()),
			"config":          llx.DictData(config),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlModule)
	}
	return res, nil
}

func (g *mqlGcpOrganization) sccSecurityHealthAnalyticsCustomModules() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	return listSccShaCustomModules(g.MqlRuntime, organizationResourceName(g.Id.Data))
}

func (g *mqlGcpOrganization) sccEventThreatDetectionCustomModules() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	return listSccEtdCustomModules(g.MqlRuntime, organizationResourceName(g.Id.Data))
}

func (g *mqlGcpFolder) sccSecurityHealthAnalyticsCustomModules() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	return listSccShaCustomModules(g.MqlRuntime, folderResourceName(g.Id.Data))
}

func (g *mqlGcpFolder) sccEventThreatDetectionCustomModules() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	return listSccEtdCustomModules(g.MqlRuntime, folderResourceName(g.Id.Data))
}

// sccProjectScope returns the project scope for the custom module listings,
// or "" when Security Command Center is not enabled on the project.
func (g *mqlGcpProject) sccProjectScope() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	serviceEnabled, err := g.isServiceEnabled(service_securitycenter)
	if err != nil {
		return "", err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_securitycenter).Msg("gcp service is not enabled, skipping")
		return "", nil
	}
	return "projects/" + g.Id.Data, nil
}

func (g *mqlGcpProject) sccSecurityHealthAnalyticsCustomModules() ([]any, error) {
	scope, err := g.sccProjectScope()
	if err != nil || scope == "" {
		return nil, err
	}
	return listSccShaCustomModules(g.MqlRuntime, scope)
}

func (g *mqlGcpProject) sccEventThreatDetectionCustomModules() ([]any, error) {
	scope, err := g.sccProjectScope()
	if err != nil || scope == "" {
		return nil, err
	}
	return listSccEtdCustomModules(g.MqlRuntime, scope)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The Plugins API accepts an Admin API key carrying one of these scopes.
var pluginReadScopes = []string{"read:plugins", "read:org_audit"}

// claude.organization.plugin

type mqlClaudeOrganizationPluginInternal struct {
	cacheMarketplaceID string
	cacheOwnerUserID   string
	cacheCreatorUserID string
	cacheCreatorKeyID  string
	// cacheComponents is nil when the API did not enumerate the served
	// version's components, which is a different answer from a version with
	// none.
	cacheComponents []anthropic.BetaPluginComponent
}

func (r *mqlClaudeOrganization) plugins() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	// The SDK sends the plugins beta header on its own.
	plugins, err := collectCursorPages(client.Beta.Organization.Plugins.List(
		context.Background(), anthropic.BetaOrganizationPluginListParams{Limit: anthropic.Int(100)}))
	if err != nil {
		return nil, classifyAdminError(fmt.Errorf("listing plugins: %w", err), endpointUnavailable, pluginReadScopes...)
	}

	res := make([]interface{}, 0, len(plugins))
	for _, p := range plugins {
		mqlPlugin, err := CreateResource(r.MqlRuntime, "claude.organization.plugin", pluginArgs(p))
		if err != nil {
			return nil, err
		}
		ref := mqlPlugin.(*mqlClaudeOrganizationPlugin)
		ref.cacheMarketplaceID = p.MarketplaceID
		ref.cacheOwnerUserID = p.Owner.UserID
		ref.cacheCreatorUserID = p.CreatedBy.UserID
		ref.cacheCreatorKeyID = p.CreatedBy.APIKeyID
		ref.cacheComponents = pluginComponents(p)
		res = append(res, mqlPlugin)
	}
	return res, nil
}

// pluginArgs maps a plugin onto resource arguments. A member-owned plugin has
// no organization-wide installation setting, and a version that has not been
// scanned has no scan result, so those read as null rather than as an empty
// string or false.
func pluginArgs(p anthropic.BetaPlugin) map[string]*llx.RawData {
	inherited := llx.NilData
	if p.JSON.OrganizationInstallationPreferenceInherited.Valid() {
		inherited = llx.BoolData(p.OrganizationInstallationPreferenceInherited)
	}

	return map[string]*llx.RawData{
		"__id":                            llx.StringData(p.ID),
		"id":                              llx.StringData(p.ID),
		"name":                            llx.StringData(p.Name),
		"displayName":                     llx.StringData(p.DisplayName),
		"description":                     llx.StringData(p.Description),
		"manifestVersion":                 llx.StringDataPtr(nullableString(p.ManifestVersion)),
		"ownerType":                       llx.StringDataPtr(nullableString(p.Owner.Type)),
		"reach":                           llx.StringDataPtr(nullableString(string(p.Reach))),
		"installationPreference":          llx.StringDataPtr(nullableString(string(p.OrganizationInstallationPreference))),
		"installationPreferenceInherited": inherited,
		"servedVersionId":                 llx.StringDataPtr(nullableString(p.ServedVersionID)),
		"servedVersionPinned":             llx.BoolData(p.ServedVersionPinned),
		"latestVersionId":                 llx.StringDataPtr(nullableString(p.LatestVersionID)),
		"contentScanStatus":               llx.StringDataPtr(nullableString(string(p.ContentScan.Status))),
		"contentScanAssessment":           llx.StringDataPtr(nullableString(string(p.ContentScan.Assessment))),
		"contentScanReason":               llx.StringDataPtr(nullableString(p.ContentScan.Reason)),
		"createdByType":                   llx.StringDataPtr(nullableString(p.CreatedBy.Type)),
		"createdAt":                       llx.TimeDataPtr(nullableTime(p.CreatedAt)),
		"updatedAt":                       llx.TimeDataPtr(nullableTime(p.UpdatedAt)),
	}
}

// pluginComponents returns the served version's components, or nil when the
// API sent components as null.
func pluginComponents(p anthropic.BetaPlugin) []anthropic.BetaPluginComponent {
	if !p.JSON.Components.Valid() {
		return nil
	}
	if p.Components == nil {
		return []anthropic.BetaPluginComponent{}
	}
	return p.Components
}

func (r *mqlClaudeOrganizationPlugin) components() ([]interface{}, error) {
	if r.cacheComponents == nil {
		r.Components.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res := make([]interface{}, 0, len(r.cacheComponents))
	for _, c := range r.cacheComponents {
		mqlComponent, err := CreateResource(r.MqlRuntime, "claude.organization.plugin.component", pluginComponentArgs(r.Id.Data, c))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlComponent)
	}
	return res, nil
}

// pluginComponentArgs maps a plugin component onto resource arguments. Two
// components of different kinds may share a name, such as a skill and a
// command, so the kind is part of the key.
func pluginComponentArgs(pluginID string, c anthropic.BetaPluginComponent) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData(pluginID + "/" + string(c.Type) + "/" + c.Name),
		"name":        llx.StringData(c.Name),
		"type":        llx.StringData(string(c.Type)),
		"description": llx.StringData(c.Description),
	}
}

func (r *mqlClaudeOrganizationPlugin) marketplace() (*mqlClaudeOrganizationPluginMarketplace, error) {
	mp, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationPluginMarketplace](
		r.MqlRuntime, r.cacheMarketplaceID, (*mqlClaudeOrganization).GetPluginMarketplaces)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Marketplace.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return mp, nil
}

func (r *mqlClaudeOrganizationPlugin) owner() (*mqlClaudeOrganizationMember, error) {
	member, ok, err := lookupMember(r.MqlRuntime, r.cacheOwnerUserID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Owner.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return member, nil
}

func (r *mqlClaudeOrganizationPlugin) createdBy() (*mqlClaudeOrganizationMember, error) {
	member, ok, err := lookupMember(r.MqlRuntime, r.cacheCreatorUserID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.CreatedBy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return member, nil
}

func (r *mqlClaudeOrganizationPlugin) createdByApiKey() (*mqlClaudeOrganizationApiKey, error) {
	key, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationApiKey](
		r.MqlRuntime, r.cacheCreatorKeyID, (*mqlClaudeOrganization).GetApiKeys)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.CreatedByApiKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return key, nil
}

// claude.organization.pluginMarketplace

type mqlClaudeOrganizationPluginMarketplaceInternal struct {
	cacheOwnerUserID string
}

func (r *mqlClaudeOrganization) pluginMarketplaces() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	marketplaces, err := collectCursorPages(client.Beta.Organization.PluginMarketplaces.List(
		context.Background(), anthropic.BetaOrganizationPluginMarketplaceListParams{Limit: anthropic.Int(1000)}))
	if err != nil {
		return nil, classifyAdminError(fmt.Errorf("listing plugin marketplaces: %w", err), endpointUnavailable, pluginReadScopes...)
	}

	res := make([]interface{}, 0, len(marketplaces))
	for _, mp := range marketplaces {
		mqlMp, err := CreateResource(r.MqlRuntime, "claude.organization.pluginMarketplace", pluginMarketplaceArgs(mp))
		if err != nil {
			return nil, err
		}
		mqlMp.(*mqlClaudeOrganizationPluginMarketplace).cacheOwnerUserID = mp.Owner.UserID
		res = append(res, mqlMp)
	}
	return res, nil
}

// pluginMarketplaceArgs maps a plugin marketplace onto resource arguments. A
// manual marketplace has never synchronized, so its sync fields read as null:
// a zero time would date its last synchronization to year 1.
func pluginMarketplaceArgs(mp anthropic.BetaPluginMarketplace) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                          llx.StringData(mp.ID),
		"id":                            llx.StringData(mp.ID),
		"name":                          llx.StringData(mp.Name),
		"source":                        llx.StringData(string(mp.Source)),
		"ownerType":                     llx.StringDataPtr(nullableString(mp.Owner.Type)),
		"defaultInstallationPreference": llx.StringDataPtr(nullableString(string(mp.DefaultInstallationPreference))),
		"syncStatus":                    llx.StringDataPtr(nullableString(string(mp.SyncStatus))),
		"lastSyncEndedAt":               llx.TimeDataPtr(nullableTime(mp.LastSyncEndedAt)),
		"lastSyncReadSha":               llx.StringDataPtr(nullableString(mp.LastSyncReadSha)),
		"createdAt":                     llx.TimeDataPtr(nullableTime(mp.CreatedAt)),
	}
}

func (r *mqlClaudeOrganizationPluginMarketplace) owner() (*mqlClaudeOrganizationMember, error) {
	member, ok, err := lookupMember(r.MqlRuntime, r.cacheOwnerUserID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Owner.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return member, nil
}

// plugins lists the marketplace's plugins from the organization's plugin list,
// fetched once for every marketplace.
func (r *mqlClaudeOrganizationPluginMarketplace) plugins() ([]interface{}, error) {
	all, err := organizationList(r.MqlRuntime, func(o *mqlClaudeOrganization) *plugin.TValue[[]interface{}] {
		return o.GetPlugins()
	})
	if err != nil {
		return nil, err
	}
	return pluginsInMarketplace(all, r.Id.Data), nil
}

func pluginsInMarketplace(all []interface{}, marketplaceID string) []interface{} {
	res := []interface{}{}
	for _, item := range all {
		p, ok := item.(*mqlClaudeOrganizationPlugin)
		if ok && p.cacheMarketplaceID == marketplaceID {
			res = append(res, p)
		}
	}
	return res
}

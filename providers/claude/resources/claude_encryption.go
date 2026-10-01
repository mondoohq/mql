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

// claude.organization.externalKey

func (r *mqlClaudeOrganization) externalKeys() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	keys, err := collectCursorPages(client.Organization.ExternalKeys.List(
		context.Background(), anthropic.OrganizationExternalKeyListParams{Limit: anthropic.Int(100)}))
	if err != nil {
		return nil, classifyAdminError(fmt.Errorf("listing external keys: %w", err), endpointUnavailable)
	}

	res := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		mqlKey, err := CreateResource(r.MqlRuntime, "claude.organization.externalKey", externalKeyArgs(k))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

// externalKeyArgs maps an external key configuration onto resource arguments.
// Each key service fills a different part of the provider configuration, so a
// location value the service does not use reads as null.
func externalKeyArgs(k anthropic.ExternalKey) map[string]*llx.RawData {
	cfg := k.ProviderConfig

	attached := llx.NilData
	switch k.Attachment.Type {
	case "attached":
		attached = llx.BoolData(true)
	case "unattached":
		attached = llx.BoolData(false)
	}

	return map[string]*llx.RawData{
		"__id":        llx.StringData(k.ID),
		"id":          llx.StringData(k.ID),
		"displayName": llx.StringDataPtr(nullableString(k.DisplayName)),
		"geo":         llx.StringData(k.Geo),
		"provider":    llx.StringDataPtr(nullableString(cfg.Type)),
		"kmsArn":      llx.StringDataPtr(nullableString(cfg.KMSARN)),
		"region":      llx.StringDataPtr(nullableString(cfg.Region)),
		"keyName":     llx.StringDataPtr(nullableString(cfg.KeyName)),
		"vaultUri":    llx.StringDataPtr(nullableString(cfg.VaultURI)),
		"tenantId":    llx.StringDataPtr(nullableString(cfg.TenantID)),
		"clientId":    llx.StringDataPtr(nullableString(cfg.ClientID)),
		"attached":    attached,
		"createdAt":   llx.TimeDataPtr(nullableTime(k.CreatedAt)),
		"updatedAt":   llx.TimeDataPtr(nullableTime(k.UpdatedAt)),
	}
}

// workspaces lists the workspaces bound to this key, read from the
// organization's workspace list, which includes archived workspaces.
func (r *mqlClaudeOrganizationExternalKey) workspaces() ([]interface{}, error) {
	all, err := organizationList(r.MqlRuntime, func(o *mqlClaudeOrganization) *plugin.TValue[[]interface{}] {
		return o.GetWorkspaces()
	})
	if err != nil {
		return nil, err
	}
	return workspacesUsingKey(all, r.Id.Data), nil
}

func workspacesUsingKey(all []interface{}, keyID string) []interface{} {
	res := []interface{}{}
	if keyID == "" {
		return res
	}
	for _, item := range all {
		ws, ok := item.(*mqlClaudeOrganizationWorkspace)
		if ok && ws.ExternalKeyId.Data == keyID {
			res = append(res, ws)
		}
	}
	return res
}

func (r *mqlClaudeOrganizationWorkspace) externalKey() (*mqlClaudeOrganizationExternalKey, error) {
	key, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationExternalKey](
		r.MqlRuntime, r.ExternalKeyId.Data, (*mqlClaudeOrganization).GetExternalKeys)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.ExternalKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return key, nil
}

// complianceApiState reads the organization's Compliance Settings, which hold
// a single state.
func (r *mqlClaudeOrganization) complianceApiState() (string, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return "", err
	}

	settings, err := client.Organization.ComplianceSettings.Get(context.Background())
	if err != nil {
		return "", classifyAdminError(fmt.Errorf("reading compliance settings: %w", err), endpointUnavailable)
	}
	if settings == nil || settings.State.Type == "" {
		r.ComplianceApiState.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return settings.State.Type, nil
}

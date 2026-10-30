// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

const (
	// armScope is the token audience for Azure Resource Manager. Tenant
	// diagnostic settings are ARM resources rather than Microsoft Graph ones,
	// so a Graph token does not open them.
	armScope = "https://management.azure.com/.default"

	// Both endpoints are tenant-scoped: neither carries a subscription in its
	// path, and each is pinned to the only api-version its resource provider
	// publishes. Casing follows what the resource providers register.
	entraDiagnosticSettingsUrl  = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"
	intuneDiagnosticSettingsUrl = "https://management.azure.com/providers/Microsoft.Intune/diagnosticSettings?api-version=2017-04-01-preview"

	// armHTTPTimeout bounds a single request. These requests do not run through
	// an SDK pipeline that would impose a deadline of its own, so without it a
	// stalled connection blocks the field forever.
	armHTTPTimeout = 60 * time.Second
)

// armHTTPClient is shared by the ARM requests so they all get the timeout.
// http.Client is safe for concurrent use.
var armHTTPClient = &http.Client{Timeout: armHTTPTimeout}

// armDiagnosticSettingsList is the ARM collection envelope. Both resource
// providers return a plain value array with no continuation link: a tenant is
// capped at five diagnostic settings per resource, so there is no page to
// follow.
type armDiagnosticSettingsList struct {
	Value []armDiagnosticSetting `json:"value"`
}

type armDiagnosticSetting struct {
	Id         string                         `json:"id"`
	Name       string                         `json:"name"`
	Type       string                         `json:"type"`
	Properties armDiagnosticSettingProperties `json:"properties"`
}

type armDiagnosticSettingProperties struct {
	Logs                        []armDiagnosticLogSetting `json:"logs"`
	WorkspaceId                 string                    `json:"workspaceId"`
	StorageAccountId            string                    `json:"storageAccountId"`
	EventHubName                string                    `json:"eventHubName"`
	EventHubAuthorizationRuleId string                    `json:"eventHubAuthorizationRuleId"`
}

type armDiagnosticLogSetting struct {
	Category string `json:"category"`
	// Enabled decides whether the category is exported. A setting lists every
	// category it knows about, switched on or off, so reading the flag is the
	// only way to tell an exported stream from a listed one.
	Enabled         bool `json:"enabled"`
	RetentionPolicy any  `json:"retentionPolicy,omitempty"`
}

// enabledLogCategories returns the categories the setting actually exports, in
// the order the service reports them. A category with an empty name is dropped:
// it names no log stream, and reporting it would put "" into a list that checks
// test with contains.
func (p armDiagnosticSettingProperties) enabledLogCategories() []string {
	out := []string{}
	for _, l := range p.Logs {
		if !l.Enabled || l.Category == "" {
			continue
		}
		out = append(out, l.Category)
	}
	return out
}

// armGet issues an authenticated GET against ARM and decodes the collection.
//
// Any non-200 response is reported as an error rather than as an empty
// collection. The distinction matters more here than usual: a tenant that has
// configured no diagnostic settings answers 200 with an empty array, so an
// empty list is a real finding, and letting a 403 arrive the same way would
// turn "we were not allowed to look" into "nothing is configured".
func armGet(ctx context.Context, token string, url string) (*armDiagnosticSettingsList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := armHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure resource manager returned %s for %s: %s", resp.Status, url, string(body))
	}

	list := &armDiagnosticSettingsList{}
	if err := json.Unmarshal(body, list); err != nil {
		return nil, err
	}
	return list, nil
}

// diagnosticSettings fetches one tenant-scoped diagnostic settings collection
// and maps it to MQL resources.
func diagnosticSettings(runtime *plugin.Runtime, url string) ([]any, error) {
	conn, ok := runtime.Connection.(*connection.Ms365Connection)
	if !ok {
		return nil, fmt.Errorf("wrong connection type for microsoft.diagnosticSetting")
	}
	ctx := context.Background()

	armToken, err := conn.Token().GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{armScope},
	})
	if err != nil {
		return nil, err
	}

	list, err := armGet(ctx, armToken.Token, url)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range list.Value {
		setting := list.Value[i]

		logs, err := convert.JsonToDictSlice(setting.Properties.Logs)
		if err != nil {
			return nil, err
		}

		mqlSetting, err := CreateResource(runtime, "microsoft.diagnosticSetting", map[string]*llx.RawData{
			"__id":                        llx.StringData(setting.Id),
			"id":                          llx.StringData(setting.Id),
			"name":                        llx.StringData(setting.Name),
			"type":                        llx.StringData(setting.Type),
			"enabledLogCategories":        llx.ArrayData(convert.SliceAnyToInterface(setting.Properties.enabledLogCategories()), types.String),
			"logs":                        llx.ArrayData(logs, types.Dict),
			"workspaceId":                 llx.StringData(setting.Properties.WorkspaceId),
			"storageAccountId":            llx.StringData(setting.Properties.StorageAccountId),
			"eventHubName":                llx.StringData(setting.Properties.EventHubName),
			"eventHubAuthorizationRuleId": llx.StringData(setting.Properties.EventHubAuthorizationRuleId),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSetting)
	}
	return res, nil
}

func (a *mqlMicrosoft) entraDiagnosticSettings() ([]any, error) {
	return diagnosticSettings(a.MqlRuntime, entraDiagnosticSettingsUrl)
}

func (a *mqlMicrosoft) intuneDiagnosticSettings() ([]any, error) {
	return diagnosticSettings(a.MqlRuntime, intuneDiagnosticSettingsUrl)
}

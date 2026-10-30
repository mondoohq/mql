// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azure/connection"
)

func (a *mqlAzureSubscriptionFunctionsServiceFunctionAppAppSetting) id() (string, error) {
	return a.Id.Data, nil
}

// secretLikeNamePattern matches setting names that almost always carry secret
// content. The match is case-insensitive and substring-based so suffix-style
// names ("DB_PASSWORD") and word-style names ("StorageAccountKey") both hit.
//
// The connection-string sub-pattern only matches `conn(ection)?_?str*` rather
// than bare `connection` so settings like `connectionRetryCount` or
// `connectionTimeout` aren't flagged as secret-like.
var secretLikeNamePattern = regexp.MustCompile(`(?i)key|password|secret|token|conn(?:ection)?_?str`)

// isLikelySecretName classifies a setting name as "looks like it carries a
// secret" using the regex above. Surfaced as the `isLikelySecret` field so
// audit queries can ask "any setting that looks secret AND is not a Key Vault
// reference" without re-implementing the regex in every policy.
func isLikelySecretName(name string) bool {
	return secretLikeNamePattern.MatchString(name)
}

// hasKeyVaultRefValue reports whether a Function App app-setting value resolves
// through Azure Key Vault. Setting values that begin with `@Microsoft.KeyVault(`
// are evaluated by App Service to a Key Vault secret at runtime.
func hasKeyVaultRefValue(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "@Microsoft.KeyVault(")
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) appSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	site, err := parsed.Component("sites")
	if err != nil {
		return nil, err
	}
	rg := parsed.ResourceGroup

	client, err := web.NewWebAppsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	settings, err := client.ListApplicationSettings(ctx, rg, site, nil)
	if err != nil {
		if isFunctionAppForbiddenError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	stickyAppSettings, _ := stickySlotNames(ctx, client, rg, site)

	res := []any{}
	keys := sortedSettingKeys(settings.Properties)
	for _, name := range keys {
		var value string
		if v := settings.Properties[name]; v != nil {
			value = *v
		}
		hasValue := value != ""
		hasKV := hasKeyVaultRefValue(value)
		mqlSetting, err := CreateResource(a.MqlRuntime, "azure.subscription.functionsService.functionApp.appSetting",
			map[string]*llx.RawData{
				"id":                   llx.StringData(a.Id.Data + "/config/appsettings/" + name),
				"name":                 llx.StringData(name),
				"hasKeyVaultReference": llx.BoolData(hasKV),
				"isLikelySecret":       llx.BoolData(isLikelySecretName(name)),
				"slotSetting":          llx.BoolData(stickyAppSettings[name]),
				"hasValue":             llx.BoolData(hasValue),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSetting)
	}
	return res, nil
}

// stickySlotNames fetches the slot-config-names resource once and returns the
// (appSettings, connectionStrings) sets of names pinned to the slot they were
// configured on (i.e., they survive a slot swap). Empty sets on permission
// errors so the `slotSetting` field stays false rather than failing the
// broader query.
//
// Returning both maps from a single call avoids a redundant ARM round-trip
// when a query accesses both `appSettings` and `connectionStrings` on the
// same function app.
func stickySlotNames(ctx context.Context, client *web.WebAppsClient, rg, site string) (appSettings, connectionStrings map[string]bool) {
	appSettings = map[string]bool{}
	connectionStrings = map[string]bool{}
	resp, err := client.ListSlotConfigurationNames(ctx, rg, site, nil)
	if err != nil || resp.Properties == nil {
		return
	}
	for _, n := range resp.Properties.AppSettingNames {
		if n != nil {
			appSettings[*n] = true
		}
	}
	for _, n := range resp.Properties.ConnectionStringNames {
		if n != nil {
			connectionStrings[*n] = true
		}
	}
	return
}

func sortedSettingKeys(m map[string]*string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedConnectionStringKeys(m map[string]*web.ConnStringValueTypePair) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (a *mqlAzureSubscriptionFunctionsServiceFunctionApp) connectionStrings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	site, err := parsed.Component("sites")
	if err != nil {
		return nil, err
	}
	rg := parsed.ResourceGroup

	client, err := web.NewWebAppsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	cs, err := client.ListConnectionStrings(ctx, rg, site, nil)
	if err != nil {
		if isFunctionAppForbiddenError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	_, stickyCS := stickySlotNames(ctx, client, rg, site)

	res := []any{}
	keys := sortedConnectionStringKeys(cs.Properties)
	for _, name := range keys {
		entry := cs.Properties[name]
		var connType, value string
		if entry != nil {
			if entry.Type != nil {
				connType = string(*entry.Type)
			}
			if entry.Value != nil {
				value = *entry.Value
			}
		}
		row := map[string]any{
			"name":                 name,
			"type":                 connType,
			"hasKeyVaultReference": hasKeyVaultRefValue(value),
			"slotSetting":          stickyCS[name],
		}
		res = append(res, row)
	}
	return res, nil
}

// isFunctionAppForbiddenError reports whether the err is the 403 we should
// treat as "no settings visible" rather than fatal — the Function App's
// app-settings/connection-strings endpoints require explicit permissions
// (Microsoft.Web/sites/config/list/action) that the audit role may lack.
func isFunctionAppForbiddenError(err error) bool {
	if rerr, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return rerr.StatusCode == http.StatusForbidden
	}
	return false
}

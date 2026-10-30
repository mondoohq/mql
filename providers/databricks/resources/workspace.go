// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"

	databricks "github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/service/settings"
	"github.com/databricks/databricks-sdk-go/service/workspace"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/databricks/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlDatabricks) ipAccessLists() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	lists, err := ws.IpAccessLists.ListAll(context.Background())
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range lists {
		l := lists[i]
		res, err := CreateResource(r.MqlRuntime, "databricks.ipAccessList", map[string]*llx.RawData{
			"__id":         llx.StringData("databricks.ipAccessList/" + l.ListId),
			"id":           llx.StringData(l.ListId),
			"label":        llx.StringData(l.Label),
			"listType":     llx.StringData(string(l.ListType)),
			"ipAddresses":  llx.ArrayData(strSlice(l.IpAddresses), types.String),
			"addressCount": llx.IntData(l.AddressCount),
			"enabled":      llx.BoolData(l.Enabled),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// tokenFields maps one token record to its MQL fields. The mapping is kept
// apart from the API call so the absent cases can be asserted directly: a
// token that has never been used and a token that never expires both have to
// arrive as null rather than as the zero time, which would read as a real date
// in the year 1.
func tokenFields(t settings.TokenInfo) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":              llx.StringData("databricks.token/" + t.TokenId),
		"id":                llx.StringData(t.TokenId),
		"comment":           llx.StringData(t.Comment),
		"ownerId":           llx.IntData(t.OwnerId),
		"createdByUsername": llx.StringData(t.CreatedByUsername),
		"creationTime":      llx.TimeDataPtr(epochMsTime(t.CreationTime)),
		"expiryTime":        llx.TimeDataPtr(epochMsTime(t.ExpiryTime)),
		"lastUsedDay":       llx.TimeDataPtr(epochMsTime(t.LastUsedDay)),
		"scopes":            llx.ArrayData(strSlice(t.Scopes), types.String),
	}
}

func (r *mqlDatabricks) tokens() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	tokens, err := ws.TokenManagement.ListAll(context.Background(), settings.ListTokenManagementRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range tokens {
		res, err := CreateResource(r.MqlRuntime, "databricks.token", tokenFields(tokens[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricks) secretScopes() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	scopes, err := ws.Secrets.ListScopesAll(context.Background())
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range scopes {
		s := scopes[i]
		res, err := CreateResource(r.MqlRuntime, "databricks.secretScope", map[string]*llx.RawData{
			"__id":        llx.StringData("databricks.secretScope/" + s.Name),
			"name":        llx.StringData(s.Name),
			"backendType": llx.StringData(string(s.BackendType)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricksSecretScope) acls() (map[string]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	resp, err := ws.Secrets.ListAclsByScope(context.Background(), r.Name.Data)
	if err != nil {
		return nil, err
	}

	acls := map[string]any{}
	for i := range resp.Items {
		acls[resp.Items[i].Principal] = string(resp.Items[i].Permission)
	}
	return acls, nil
}

// secretFields maps one secret metadata record to its MQL fields. The listing
// endpoint returns keys and metadata only, never a value, so nothing here can
// carry secret material. Kept apart from the API call so the absent case can
// be asserted directly: a secret the API reports no write time for has to
// arrive as null rather than as the zero time, which would read as a real date
// in the year 1 and make every staleness check pass.
func secretFields(scope string, s workspace.SecretMetadata) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		// A secret repeats along both the scope it lives in and its key, so
		// the cache key carries both. Keying on the key alone would collapse
		// the same key in two scopes onto one resource.
		"__id":        llx.StringData("databricks.secretScope/" + scope + "/secret/" + s.Key),
		"scopeName":   llx.StringData(scope),
		"key":         llx.StringData(s.Key),
		"lastUpdated": llx.TimeDataPtr(epochMsTime(s.LastUpdatedTimestamp)),
	}
}

// secrets lists the secrets held in the scope. The endpoint is metadata only:
// it returns each secret's key and the time its value was last written, and
// there is no path from here to a value.
//
// Reading a scope's contents needs READ on that scope, which a workspace admin
// enumerating scopes does not automatically hold. A caller that lacks it gets
// null rather than an empty list, so "I could not look inside this scope" stays
// distinct from "this scope is empty".
func (r *mqlDatabricksSecretScope) secrets() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	secrets, err := ws.Secrets.ListSecretsAll(context.Background(), workspace.ListSecretsRequest{
		Scope: r.Name.Data,
	})
	if err != nil {
		if isDatabricksUnreadable(err) {
			r.Secrets = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	out := []any{}
	for i := range secrets {
		res, err := CreateResource(r.MqlRuntime, "databricks.secretScope.secret", secretFields(r.Name.Data, secrets[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricks) workspaceSettings() (*mqlDatabricksWorkspaceConf, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	conn := r.MqlRuntime.Connection.(*connection.DatabricksConnection)
	ctx := context.Background()

	id := conn.WorkspaceID()
	if id == "" {
		id = conn.Host()
	}

	// The workspace-conf GET endpoint accepts a comma-separated key list and
	// returns every requested key in one response, so all of these settings are
	// read with a single call rather than one request per key.
	conf := confStatus(ctx, ws,
		"enableTokens",
		"maxTokenLifetimeDays",
		"enableIpAccessLists",
		"enableDeprecatedGlobalInitScripts",
		"enableDeprecatedClusterNamedInitScripts",
		"storeInteractiveNotebookResultsInCustomerAccount",
	)

	res, err := CreateResource(r.MqlRuntime, "databricks.workspaceConf", map[string]*llx.RawData{
		"__id":                               llx.StringData("databricks.workspaceConf/" + id),
		"tokensEnabled":                      llx.BoolDataPtr(confBoolFrom(conf, "enableTokens")),
		"maxTokenLifetimeDays":               llx.IntDataPtr(confIntFrom(conf, "maxTokenLifetimeDays")),
		"ipAccessListsEnabled":               llx.BoolDataPtr(confBoolFrom(conf, "enableIpAccessLists")),
		"deprecatedGlobalInitScriptsEnabled": llx.BoolDataPtr(confBoolFrom(conf, "enableDeprecatedGlobalInitScripts")),
		"deprecatedClusterNamedInitScriptsEnabled":         llx.BoolDataPtr(confBoolFrom(conf, "enableDeprecatedClusterNamedInitScripts")),
		"storeInteractiveNotebookResultsInCustomerAccount": llx.BoolDataPtr(confBoolFrom(conf, "storeInteractiveNotebookResultsInCustomerAccount")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksWorkspaceConf), nil
}

// confStatus reads the given workspace conf keys in a single request. The
// workspace-conf GET endpoint accepts a comma-separated key list and returns
// each requested key that is set, so one call covers every key. An empty map is
// returned when the settings cannot be read (for example without workspace admin
// rights), which leaves each derived field null.
func confStatus(ctx context.Context, ws *databricks.WorkspaceClient, keys ...string) map[string]string {
	resp, err := ws.WorkspaceConf.GetStatus(ctx, settings.GetStatusRequest{Keys: strings.Join(keys, ",")})
	if err != nil || resp == nil {
		return map[string]string{}
	}
	return *resp
}

// confBoolFrom interprets a workspace conf value as a boolean, returning nil
// when the key is absent from the fetched status.
func confBoolFrom(conf map[string]string, key string) *bool {
	v, ok := conf[key]
	if !ok {
		return nil
	}
	b := v == "true" || v == "1"
	return &b
}

// confIntFrom interprets a workspace conf value as an integer, returning nil
// when the key is absent or cannot be parsed.
func confIntFrom(conf map[string]string, key string) *int64 {
	v, ok := conf[key]
	if !ok {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

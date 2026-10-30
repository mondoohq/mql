// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"

	databricks "github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/service/catalog"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// The bindings endpoint interpolates the securable type straight into the
// request path (/api/2.1/unity-catalog/bindings/{type}/{name}), so these are
// lowercase path segments rather than the uppercase catalog.SecurableType
// values used for grants. Passing the grant-style constant returns no bindings
// instead of an error.
const (
	bindingsSecurableCatalog           = "catalog"
	bindingsSecurableStorageCredential = "storage_credential"
	bindingsSecurableExternalLocation  = "external_location"
	bindingsSecurableCredential        = "credential"
	bindingsSecurableConnection        = "connection"
)

// secretOptionKeys are substrings that mark a connection option as credential
// material. Connection options are free-form and differ per connection type,
// so matching on substrings covers keys such as password, personalAccessToken,
// client_secret, sasToken, and pem_private_key without enumerating all 27
// connection types.
var secretOptionKeys = []string{
	"password",
	"passphrase",
	"secret",
	"token",
	"credential",
	"privatekey",
	"private_key",
	"pem",
	"apikey",
	"api_key",
	"accesskey",
	"access_key",
	"signature",
}

// scrubConnectionOptions drops connection options whose key names credential
// material, keeping the parameters that locate the external system (host,
// port, database, account). The API already redacts secret values, but the
// keys still reveal the authentication shape and the redacted placeholders add
// no audit value.
func scrubConnectionOptions(options map[string]string) map[string]any {
	out := make(map[string]any, len(options))
	for k, v := range options {
		lower := strings.ToLower(k)
		secret := false
		for _, marker := range secretOptionKeys {
			if strings.Contains(lower, marker) {
				secret = true
				break
			}
		}
		if secret {
			continue
		}
		out[k] = v
	}
	return out
}

// mqlDatabricksWorkspaceBindings fetches the workspaces a Unity Catalog
// securable is bound to, keyed by workspace id. An empty map means the
// securable carries no explicit bindings, which only restricts access when its
// isolation mode is ISOLATED.
func mqlDatabricksWorkspaceBindings(ws *databricks.WorkspaceClient, securableType string, securableName string) (map[string]any, error) {
	bindings, err := ws.WorkspaceBindings.GetBindingsAll(context.Background(), catalog.GetBindingsRequest{
		SecurableType: securableType,
		SecurableName: securableName,
	})
	if err != nil {
		return nil, err
	}

	out := make(map[string]any, len(bindings))
	for i := range bindings {
		out[strconv.FormatInt(bindings[i].WorkspaceId, 10)] = string(bindings[i].BindingType)
	}
	return out, nil
}

func (r *mqlDatabricksCatalog) workspaceBindings() (map[string]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksWorkspaceBindings(ws, bindingsSecurableCatalog, r.Name.Data)
}

func (r *mqlDatabricksStorageCredential) workspaceBindings() (map[string]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksWorkspaceBindings(ws, bindingsSecurableStorageCredential, r.Name.Data)
}

func (r *mqlDatabricksExternalLocation) workspaceBindings() (map[string]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksWorkspaceBindings(ws, bindingsSecurableExternalLocation, r.Name.Data)
}

func (r *mqlDatabricksCredential) workspaceBindings() (map[string]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksWorkspaceBindings(ws, bindingsSecurableCredential, r.Name.Data)
}

func (r *mqlDatabricksConnection) workspaceBindings() (map[string]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksWorkspaceBindings(ws, bindingsSecurableConnection, r.Name.Data)
}

// newMqlDatabricksCredential maps a Unity Catalog credential to its resource.
func newMqlDatabricksCredential(runtime *plugin.Runtime, c catalog.CredentialInfo) (*mqlDatabricksCredential, error) {
	var awsRoleArn, awsExternalId, awsUcIamArn, azureConnectorId, azureManagedIdentityId, azureAppId, gcpEmail string
	if c.AwsIamRole != nil {
		awsRoleArn = c.AwsIamRole.RoleArn
		awsExternalId = c.AwsIamRole.ExternalId
		awsUcIamArn = c.AwsIamRole.UnityCatalogIamArn
	}
	if c.AzureManagedIdentity != nil {
		azureConnectorId = c.AzureManagedIdentity.AccessConnectorId
		azureManagedIdentityId = c.AzureManagedIdentity.ManagedIdentityId
	}
	if c.AzureServicePrincipal != nil {
		// ClientSecret is deliberately not mapped.
		azureAppId = c.AzureServicePrincipal.ApplicationId
	}
	if c.DatabricksGcpServiceAccount != nil {
		gcpEmail = c.DatabricksGcpServiceAccount.Email
	}

	res, err := CreateResource(runtime, "databricks.credential", map[string]*llx.RawData{
		"__id":                               llx.StringData("databricks.credential/" + c.Name),
		"id":                                 llx.StringData(c.Id),
		"name":                               llx.StringData(c.Name),
		"fullName":                           llx.StringData(c.FullName),
		"owner":                              llx.StringData(c.Owner),
		"comment":                            llx.StringData(c.Comment),
		"metastoreId":                        llx.StringData(c.MetastoreId),
		"purpose":                            llx.StringData(string(c.Purpose)),
		"isolationMode":                      llx.StringData(string(c.IsolationMode)),
		"readOnly":                           llx.BoolData(c.ReadOnly),
		"usedForManagedStorage":              llx.BoolData(c.UsedForManagedStorage),
		"awsIamRoleArn":                      llx.StringData(awsRoleArn),
		"awsIamRoleExternalId":               llx.StringData(awsExternalId),
		"awsIamRoleUnityCatalogIamArn":       llx.StringData(awsUcIamArn),
		"azureAccessConnectorId":             llx.StringData(azureConnectorId),
		"azureManagedIdentityId":             llx.StringData(azureManagedIdentityId),
		"azureServicePrincipalApplicationId": llx.StringData(azureAppId),
		"gcpServiceAccountEmail":             llx.StringData(gcpEmail),
		"createdAt":                          llx.TimeDataPtr(epochMsTime(c.CreatedAt)),
		"createdBy":                          llx.StringData(c.CreatedBy),
		"updatedAt":                          llx.TimeDataPtr(epochMsTime(c.UpdatedAt)),
		"updatedBy":                          llx.StringData(c.UpdatedBy),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksCredential), nil
}

func (r *mqlDatabricks) credentials() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	// An empty Purpose returns both STORAGE and SERVICE credentials.
	creds, err := ws.Credentials.ListCredentialsAll(context.Background(), catalog.ListCredentialsRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range creds {
		res, err := newMqlDatabricksCredential(r.MqlRuntime, creds[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricksCredential) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableTypeCredential, r.Name.Data)
}

func (r *mqlDatabricks) connections() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	connections, err := ws.Connections.ListAll(context.Background(), catalog.ListConnectionsRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range connections {
		c := connections[i]
		provisioningState := ""
		if c.ProvisioningInfo != nil {
			provisioningState = string(c.ProvisioningInfo.State)
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.connection", map[string]*llx.RawData{
			"__id":              llx.StringData("databricks.connection/" + c.Name),
			"id":                llx.StringData(c.ConnectionId),
			"name":              llx.StringData(c.Name),
			"fullName":          llx.StringData(c.FullName),
			"connectionType":    llx.StringData(string(c.ConnectionType)),
			"credentialType":    llx.StringData(string(c.CredentialType)),
			"url":               llx.StringData(c.Url),
			"options":           llx.MapData(scrubConnectionOptions(c.Options), types.String),
			"properties":        llx.MapData(strMap(c.Properties), types.String),
			"owner":             llx.StringData(c.Owner),
			"comment":           llx.StringData(c.Comment),
			"metastoreId":       llx.StringData(c.MetastoreId),
			"readOnly":          llx.BoolData(c.ReadOnly),
			"provisioningState": llx.StringData(provisioningState),
			"createdAt":         llx.TimeDataPtr(epochMsTime(c.CreatedAt)),
			"createdBy":         llx.StringData(c.CreatedBy),
			"updatedAt":         llx.TimeDataPtr(epochMsTime(c.UpdatedAt)),
			"updatedBy":         llx.StringData(c.UpdatedBy),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricksConnection) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableTypeConnection, r.Name.Data)
}

func (r *mqlDatabricks) systemSchemas() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	// The system schema listing is keyed on the metastore, which the workspace
	// connection does not carry; the current assignment supplies it.
	assignment, err := ws.Metastores.Current(context.Background())
	if err != nil {
		return nil, err
	}

	schemas, err := ws.SystemSchemas.ListAll(context.Background(), catalog.ListSystemSchemasRequest{
		MetastoreId: assignment.MetastoreId,
	})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range schemas {
		res, err := CreateResource(r.MqlRuntime, "databricks.systemSchema", map[string]*llx.RawData{
			"__id":   llx.StringData("databricks.systemSchema/" + assignment.MetastoreId + "/" + schemas[i].Schema),
			"schema": llx.StringData(schemas[i].Schema),
			"state":  llx.StringData(schemas[i].State),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/databricks/databricks-sdk-go/service/catalog"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlDatabricksExternalLocationInternal struct {
	cacheCredentialName string
}

// sseEncryption extracts the server-side encryption algorithm and KMS key ARN
// from a Unity Catalog securable's encryption details. Both are empty when no
// server-side encryption is recorded.
func sseEncryption(ed *catalog.EncryptionDetails) (algorithm string, kmsKeyArn string) {
	if ed == nil || ed.SseEncryptionDetails == nil {
		return "", ""
	}
	return string(ed.SseEncryptionDetails.Algorithm), ed.SseEncryptionDetails.AwsKmsKeyArn
}

// newMqlDatabricksStorageCredential maps a Unity Catalog storage credential to
// its resource. Shared by the list path and the init lookup so a credential
// hydrated by name carries the same fields as a listed one.
func newMqlDatabricksStorageCredential(runtime *plugin.Runtime, c catalog.StorageCredentialInfo) (*mqlDatabricksStorageCredential, error) {
	var awsRoleArn, awsExternalId, azureConnectorId, azureAppId, gcpEmail string
	if c.AwsIamRole != nil {
		awsRoleArn = c.AwsIamRole.RoleArn
		awsExternalId = c.AwsIamRole.ExternalId
	}
	if c.AzureManagedIdentity != nil {
		azureConnectorId = c.AzureManagedIdentity.AccessConnectorId
	}
	if c.AzureServicePrincipal != nil {
		azureAppId = c.AzureServicePrincipal.ApplicationId
	}
	if c.DatabricksGcpServiceAccount != nil {
		gcpEmail = c.DatabricksGcpServiceAccount.Email
	}

	res, err := CreateResource(runtime, "databricks.storageCredential", map[string]*llx.RawData{
		"__id":                               llx.StringData("databricks.storageCredential/" + c.Name),
		"id":                                 llx.StringData(c.Id),
		"name":                               llx.StringData(c.Name),
		"fullName":                           llx.StringData(c.FullName),
		"owner":                              llx.StringData(c.Owner),
		"comment":                            llx.StringData(c.Comment),
		"metastoreId":                        llx.StringData(c.MetastoreId),
		"isolationMode":                      llx.StringData(string(c.IsolationMode)),
		"readOnly":                           llx.BoolData(c.ReadOnly),
		"usedForManagedStorage":              llx.BoolData(c.UsedForManagedStorage),
		"awsIamRoleArn":                      llx.StringData(awsRoleArn),
		"awsIamRoleExternalId":               llx.StringData(awsExternalId),
		"azureAccessConnectorId":             llx.StringData(azureConnectorId),
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
	return res.(*mqlDatabricksStorageCredential), nil
}

// initDatabricksStorageCredential resolves a single storage credential by name
// so typed references (such as databricks.externalLocation.credential) can
// hydrate a full credential from just its name.
func initDatabricksStorageCredential(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("databricks.storageCredential requires a non-empty name")
	}

	ws, err := workspaceClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	cred, err := ws.StorageCredentials.GetByName(context.Background(), name)
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlDatabricksStorageCredential(runtime, *cred)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlDatabricks) storageCredentials() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	creds, err := ws.StorageCredentials.ListAll(context.Background(), catalog.ListStorageCredentialsRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range creds {
		res, err := newMqlDatabricksStorageCredential(r.MqlRuntime, creds[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricksStorageCredential) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableTypeStorageCredential, r.Name.Data)
}

func (r *mqlDatabricks) externalLocations() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	locations, err := ws.ExternalLocations.ListAll(context.Background(), catalog.ListExternalLocationsRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range locations {
		l := locations[i]
		sseAlgorithm, sseKmsKeyArn := sseEncryption(l.EncryptionDetails)

		res, err := CreateResource(r.MqlRuntime, "databricks.externalLocation", map[string]*llx.RawData{
			"__id":                   llx.StringData("databricks.externalLocation/" + l.Name),
			"name":                   llx.StringData(l.Name),
			"url":                    llx.StringData(l.Url),
			"owner":                  llx.StringData(l.Owner),
			"comment":                llx.StringData(l.Comment),
			"metastoreId":            llx.StringData(l.MetastoreId),
			"isolationMode":          llx.StringData(string(l.IsolationMode)),
			"readOnly":               llx.BoolData(l.ReadOnly),
			"fallback":               llx.BoolData(l.Fallback),
			"browseOnly":             llx.BoolData(l.BrowseOnly),
			"sseEncryptionAlgorithm": llx.StringData(sseAlgorithm),
			"sseKmsKeyArn":           llx.StringData(sseKmsKeyArn),
			"createdAt":              llx.TimeDataPtr(epochMsTime(l.CreatedAt)),
			"createdBy":              llx.StringData(l.CreatedBy),
			"updatedAt":              llx.TimeDataPtr(epochMsTime(l.UpdatedAt)),
			"updatedBy":              llx.StringData(l.UpdatedBy),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlDatabricksExternalLocation).cacheCredentialName = l.CredentialName
		out = append(out, res)
	}
	return out, nil
}

// credential resolves the storage credential this external location uses to
// reach its storage path, hydrated by name through the storage credential's
// init.
func (r *mqlDatabricksExternalLocation) credential() (*mqlDatabricksStorageCredential, error) {
	if r.cacheCredentialName == "" {
		r.Credential.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	cred, err := NewResource(r.MqlRuntime, "databricks.storageCredential", map[string]*llx.RawData{
		"name": llx.StringData(r.cacheCredentialName),
	})
	if err != nil {
		return nil, err
	}
	return cred.(*mqlDatabricksStorageCredential), nil
}

func (r *mqlDatabricksExternalLocation) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableTypeExternalLocation, r.Name.Data)
}

func (r *mqlDatabricksSchema) volumes() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	volumes, err := ws.Volumes.ListAll(context.Background(), catalog.ListVolumesRequest{
		CatalogName: r.CatalogName.Data,
		SchemaName:  r.Name.Data,
	})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range volumes {
		v := volumes[i]
		sseAlgorithm, sseKmsKeyArn := sseEncryption(v.EncryptionDetails)

		res, err := CreateResource(r.MqlRuntime, "databricks.volume", map[string]*llx.RawData{
			"__id":                   llx.StringData("databricks.volume/" + v.FullName),
			"id":                     llx.StringData(v.VolumeId),
			"name":                   llx.StringData(v.Name),
			"fullName":               llx.StringData(v.FullName),
			"catalogName":            llx.StringData(v.CatalogName),
			"schemaName":             llx.StringData(v.SchemaName),
			"owner":                  llx.StringData(v.Owner),
			"comment":                llx.StringData(v.Comment),
			"metastoreId":            llx.StringData(v.MetastoreId),
			"volumeType":             llx.StringData(string(v.VolumeType)),
			"storageLocation":        llx.StringData(v.StorageLocation),
			"sseEncryptionAlgorithm": llx.StringData(sseAlgorithm),
			"sseKmsKeyArn":           llx.StringData(sseKmsKeyArn),
			"createdAt":              llx.TimeDataPtr(epochMsTime(v.CreatedAt)),
			"createdBy":              llx.StringData(v.CreatedBy),
			"updatedAt":              llx.TimeDataPtr(epochMsTime(v.UpdatedAt)),
			"updatedBy":              llx.StringData(v.UpdatedBy),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricksVolume) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableTypeVolume, r.FullName.Data)
}

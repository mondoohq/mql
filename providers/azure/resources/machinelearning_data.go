// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	ml "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning/v4"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// mlWorkspaceScope pulls the subscription, resource group, and workspace name
// out of a workspace resource ID. Every workspace-scoped collection needs them.
func mlWorkspaceScope(resourceId string) (subscriptionId, resourceGroup, workspaceName string, err error) {
	parsed, err := ParseResourceID(resourceId)
	if err != nil {
		return "", "", "", err
	}
	return parsed.SubscriptionID, parsed.ResourceGroup, parsed.Path["workspaces"], nil
}

// --- Datastores ---

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) datastores() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subscriptionId, resourceGroup, workspaceName, err := mlWorkspaceScope(a.Id.Data)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := ml.NewDatastoresClient(subscriptionId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceGroup, workspaceName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureForbidden(err) {
				log.Warn().Err(err).Msg("could not list machine learning datastores due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ds := range page.Value {
			if ds == nil {
				continue
			}
			mqlDs, err := mlDatastoreToMql(a.MqlRuntime, ds)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDs)
		}
	}
	return res, nil
}

func mlDatastoreToMql(runtime *plugin.Runtime, ds *ml.Datastore) (*mqlAzureSubscriptionMachineLearningServiceWorkspaceDatastore, error) {
	var datastoreType, description, credentialsType, authIdentity string
	var accountName, containerName, filesystem, fileShareName string
	var endpoint, protocol, resourceGroup, subscriptionId string
	var isDefault bool
	tags := map[string]*string{}

	// DatastoreProperties is an interface: the concrete type carries the
	// backend-specific location fields, so each variant is read on its own.
	switch p := ds.Properties.(type) {
	case *ml.AzureBlobDatastore:
		datastoreType, description, isDefault, credentialsType, authIdentity = mlDatastoreCommon(p.DatastoreType, p.Description, p.IsDefault, p.Credentials, p.ServiceDataAccessAuthIdentity)
		accountName = convert.ToValue(p.AccountName)
		containerName = convert.ToValue(p.ContainerName)
		endpoint = convert.ToValue(p.Endpoint)
		protocol = convert.ToValue(p.Protocol)
		resourceGroup = convert.ToValue(p.ResourceGroup)
		subscriptionId = convert.ToValue(p.SubscriptionID)
		tags = p.Tags
	case *ml.AzureDataLakeGen2Datastore:
		datastoreType, description, isDefault, credentialsType, authIdentity = mlDatastoreCommon(p.DatastoreType, p.Description, p.IsDefault, p.Credentials, p.ServiceDataAccessAuthIdentity)
		accountName = convert.ToValue(p.AccountName)
		filesystem = convert.ToValue(p.Filesystem)
		endpoint = convert.ToValue(p.Endpoint)
		protocol = convert.ToValue(p.Protocol)
		resourceGroup = convert.ToValue(p.ResourceGroup)
		subscriptionId = convert.ToValue(p.SubscriptionID)
		tags = p.Tags
	case *ml.AzureFileDatastore:
		datastoreType, description, isDefault, credentialsType, authIdentity = mlDatastoreCommon(p.DatastoreType, p.Description, p.IsDefault, p.Credentials, p.ServiceDataAccessAuthIdentity)
		accountName = convert.ToValue(p.AccountName)
		fileShareName = convert.ToValue(p.FileShareName)
		endpoint = convert.ToValue(p.Endpoint)
		protocol = convert.ToValue(p.Protocol)
		resourceGroup = convert.ToValue(p.ResourceGroup)
		subscriptionId = convert.ToValue(p.SubscriptionID)
		tags = p.Tags
	case *ml.AzureDataLakeGen1Datastore:
		datastoreType, description, isDefault, credentialsType, authIdentity = mlDatastoreCommon(p.DatastoreType, p.Description, p.IsDefault, p.Credentials, p.ServiceDataAccessAuthIdentity)
		tags = p.Tags
	case nil:
		// ds.Properties is an interface, and the SDK's polymorphic unmarshaller
		// returns a nil one for a null or absent `properties` body. Without this
		// case the nil interface falls to `default` and calling a method on it
		// panics -- which kills the whole scan, not just this query.
	default:
		// OneLake and any backend added later still report the common fields
		// through the base interface.
		if base := ds.Properties.GetDatastoreProperties(); base != nil {
			datastoreType, description, isDefault, credentialsType, authIdentity = mlDatastoreCommon(base.DatastoreType, base.Description, base.IsDefault, base.Credentials, nil)
			tags = base.Tags
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.machineLearningService.workspace.datastore", map[string]*llx.RawData{
		"id":                            llx.StringDataPtr(ds.ID),
		"name":                          llx.StringDataPtr(ds.Name),
		"datastoreType":                 llx.StringData(datastoreType),
		"description":                   llx.StringData(description),
		"isDefault":                     llx.BoolData(isDefault),
		"credentialsType":               llx.StringData(credentialsType),
		"serviceDataAccessAuthIdentity": llx.StringData(authIdentity),
		"accountName":                   llx.StringData(accountName),
		"containerName":                 llx.StringData(containerName),
		"filesystem":                    llx.StringData(filesystem),
		"fileShareName":                 llx.StringData(fileShareName),
		"endpoint":                      llx.StringData(endpoint),
		"protocol":                      llx.StringData(protocol),
		"resourceGroup":                 llx.StringData(resourceGroup),
		"subscriptionId":                llx.StringData(subscriptionId),
		"tags":                          llx.MapData(convert.PtrMapStrToInterface(tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlDs := res.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceDatastore)
	sysData, err := convert.JsonToDict(ds.SystemData)
	if err != nil {
		return nil, err
	}
	mqlDs.cacheSystemData = sysData
	return mqlDs, nil
}

// mlDatastoreCommon flattens the fields every datastore variant shares.
func mlDatastoreCommon(
	dsType *ml.DatastoreType,
	description *string,
	isDefault *bool,
	credentials ml.DatastoreCredentialsClassification,
	authIdentity *ml.ServiceDataAccessAuthIdentity,
) (datastoreType, desc string, def bool, credentialsType, identity string) {
	if dsType != nil {
		datastoreType = string(*dsType)
	}
	desc = convert.ToValue(description)
	if isDefault != nil {
		def = *isDefault
	}
	if credentials != nil {
		if base := credentials.GetDatastoreCredentials(); base != nil && base.CredentialsType != nil {
			credentialsType = string(*base.CredentialsType)
		}
	}
	if authIdentity != nil {
		identity = string(*authIdentity)
	}
	return datastoreType, desc, def, credentialsType, identity
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceDatastoreInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceDatastore) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceDatastore) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// storageAccount resolves the account behind the datastore. The datastore
// records the account's subscription, resource group, and name rather than its
// resource ID, so the ID is rebuilt from those three.
//
// A datastore may omit the subscription and resource group, in which case the
// account sits alongside the workspace; both are then taken from the
// datastore's own resource ID. Because that is an inference rather than a value
// the API supplied, an account that does not resolve there reports no account
// instead of failing the query.
func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceDatastore) storageAccount() (*mqlAzureSubscriptionStorageServiceAccount, error) {
	accountName := a.AccountName.Data
	if accountName == "" {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	subscriptionId := a.SubscriptionId.Data
	resourceGroup := a.ResourceGroup.Data
	inferredScope := subscriptionId == "" || resourceGroup == ""
	if inferredScope {
		parsed, err := ParseResourceID(a.Id.Data)
		if err != nil {
			a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		if subscriptionId == "" {
			subscriptionId = parsed.SubscriptionID
		}
		if resourceGroup == "" {
			resourceGroup = parsed.ResourceGroup
		}
	}
	if subscriptionId == "" || resourceGroup == "" {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	accountId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s",
		subscriptionId, resourceGroup, accountName)
	res, err := getStorageAccount(accountId, a.MqlRuntime, conn)
	if err != nil {
		if inferredScope && isAzureNotFoundOrBadRequest(err) {
			log.Debug().Str("datastore", a.Id.Data).Str("account", accountName).
				Msg("storage account for datastore not found in the workspace scope")
			a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

// --- Workspace connections ---

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) connections() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subscriptionId, resourceGroup, workspaceName, err := mlWorkspaceScope(a.Id.Data)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := ml.NewWorkspaceConnectionsClient(subscriptionId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceGroup, workspaceName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureForbidden(err) {
				log.Warn().Err(err).Msg("could not list machine learning workspace connections due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			var category, authType, target, group string
			var isSharedToAll bool
			var expiryTime *time.Time
			var createdByWorkspaceArmId string
			metadata := map[string]*string{}
			sharedUsers := []any{}

			// The connection's stored credential (Value) is deliberately not
			// exposed: it is the secret the connection exists to hold.
			if p := c.Properties; p != nil {
				if base := p.GetWorkspaceConnectionPropertiesV2(); base != nil {
					if base.Category != nil {
						category = string(*base.Category)
					}
					if base.AuthType != nil {
						authType = string(*base.AuthType)
					}
					if base.Group != nil {
						group = string(*base.Group)
					}
					if base.IsSharedToAll != nil {
						isSharedToAll = *base.IsSharedToAll
					}
					target = convert.ToValue(base.Target)
					createdByWorkspaceArmId = convert.ToValue(base.CreatedByWorkspaceArmID)
					expiryTime = base.ExpiryTime
					if base.Metadata != nil {
						metadata = base.Metadata
					}
					sharedUsers = ptrSliceToAny(base.SharedUserList)
				}
			}

			mqlConn, err := CreateResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace.connection", map[string]*llx.RawData{
				"id":                      llx.StringDataPtr(c.ID),
				"name":                    llx.StringDataPtr(c.Name),
				"category":                llx.StringData(category),
				"authType":                llx.StringData(authType),
				"target":                  llx.StringData(target),
				"isSharedToAll":           llx.BoolData(isSharedToAll),
				"sharedUserList":          llx.ArrayData(sharedUsers, types.String),
				"expiryTime":              llx.TimeDataPtr(expiryTime),
				"group":                   llx.StringData(group),
				"createdByWorkspaceArmId": llx.StringData(createdByWorkspaceArmId),
				"metadata":                llx.MapData(convert.PtrMapStrToInterface(metadata), types.String),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(c.SystemData)
			if err != nil {
				return nil, err
			}
			mqlConn.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceConnection).cacheSystemData = sysData
			res = append(res, mqlConn)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceConnectionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// --- Batch endpoints ---

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) batchEndpoints() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subscriptionId, resourceGroup, workspaceName, err := mlWorkspaceScope(a.Id.Data)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := ml.NewBatchEndpointsClient(subscriptionId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceGroup, workspaceName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureForbidden(err) {
				log.Warn().Err(err).Msg("could not list machine learning batch endpoints due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ep := range page.Value {
			if ep == nil {
				continue
			}
			identity, err := convert.JsonToDict(ep.Identity)
			if err != nil {
				return nil, err
			}
			var authMode, description, scoringUri, swaggerUri, provisioningState, defaultDeploymentName string
			properties := map[string]*string{}

			// Keys holds the endpoint's shared auth keys and is deliberately not
			// exposed.
			if p := ep.Properties; p != nil {
				if p.AuthMode != nil {
					authMode = string(*p.AuthMode)
				}
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				description = convert.ToValue(p.Description)
				scoringUri = convert.ToValue(p.ScoringURI)
				swaggerUri = convert.ToValue(p.SwaggerURI)
				if p.Defaults != nil {
					defaultDeploymentName = convert.ToValue(p.Defaults.DeploymentName)
				}
				if p.Properties != nil {
					properties = p.Properties
				}
			}

			epArgs := map[string]*llx.RawData{
				"id":                    llx.StringDataPtr(ep.ID),
				"name":                  llx.StringDataPtr(ep.Name),
				"location":              llx.StringDataPtr(ep.Location),
				"tags":                  llx.MapData(convert.PtrMapStrToInterface(ep.Tags), types.String),
				"kind":                  llx.StringDataPtr(ep.Kind),
				"authMode":              llx.StringData(authMode),
				"description":           llx.StringData(description),
				"scoringUri":            llx.StringData(scoringUri),
				"swaggerUri":            llx.StringData(swaggerUri),
				"provisioningState":     llx.StringData(provisioningState),
				"defaultDeploymentName": llx.StringData(defaultDeploymentName),
				"identity":              llx.DictData(identity),
				"properties":            llx.MapData(convert.PtrMapStrToInterface(properties), types.String),
			}
			epIdentity := orZero(ep.Identity)
			if err := setResourceIdentity(a.MqlRuntime, epArgs, sortedUserAssignedIdentityIDs(epIdentity.UserAssignedIdentities),
				identityType(epIdentity.Type), identityPrincipalId(epIdentity.PrincipalID), identityTenantId(epIdentity.TenantID)); err != nil {
				return nil, err
			}
			mqlEp, err := CreateResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace.batchEndpoint", epArgs)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ep.SystemData)
			if err != nil {
				return nil, err
			}
			mqlBatchEp := mqlEp.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpoint)
			mqlBatchEp.cacheSystemData = sysData
			res = append(res, mqlEp)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpointInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpoint) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpoint) deployments() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceName := parsed.Path["workspaces"]
	endpointName := parsed.Path["batchEndpoints"]
	if endpointName == "" {
		endpointName = a.Name.Data
	}

	ctx := context.Background()
	client, err := ml.NewBatchDeploymentsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, workspaceName, endpointName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureForbidden(err) {
				log.Warn().Err(err).Msg("could not list machine learning batch deployments due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, dep := range page.Value {
			if dep == nil {
				continue
			}
			mqlDep, err := mlBatchDeploymentToMql(a.MqlRuntime, dep)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDep)
		}
	}
	return res, nil
}

func mlBatchDeploymentToMql(runtime *plugin.Runtime, dep *ml.BatchDeployment) (*mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpointDeployment, error) {
	identity, err := convert.JsonToDict(dep.Identity)
	if err != nil {
		return nil, err
	}

	var description, provisioningState, modelId, compute, environmentId string
	var outputAction, outputFileName, loggingLevel string
	var errorThreshold, miniBatchSize, maxConcurrency int64
	envVars := map[string]*string{}
	properties := map[string]*string{}
	var retrySettings, resources any

	if p := dep.Properties; p != nil {
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		if p.OutputAction != nil {
			outputAction = string(*p.OutputAction)
		}
		if p.LoggingLevel != nil {
			loggingLevel = string(*p.LoggingLevel)
		}
		if p.ErrorThreshold != nil {
			errorThreshold = int64(*p.ErrorThreshold)
		}
		if p.MiniBatchSize != nil {
			miniBatchSize = *p.MiniBatchSize
		}
		if p.MaxConcurrencyPerInstance != nil {
			maxConcurrency = int64(*p.MaxConcurrencyPerInstance)
		}
		description = convert.ToValue(p.Description)
		compute = convert.ToValue(p.Compute)
		environmentId = convert.ToValue(p.EnvironmentID)
		outputFileName = convert.ToValue(p.OutputFileName)
		if p.EnvironmentVariables != nil {
			envVars = p.EnvironmentVariables
		}
		if p.Properties != nil {
			properties = p.Properties
		}
		// Model is an asset-reference union; the id form is what identifies a
		// registered model version.
		if p.Model != nil {
			if idRef, ok := p.Model.(*ml.IDAssetReference); ok {
				modelId = convert.ToValue(idRef.AssetID)
			}
		}
		retrySettings, _ = convert.JsonToDict(p.RetrySettings)
		resources, _ = convert.JsonToDict(p.Resources)
	}

	depArgs := map[string]*llx.RawData{
		"id":                        llx.StringDataPtr(dep.ID),
		"name":                      llx.StringDataPtr(dep.Name),
		"location":                  llx.StringDataPtr(dep.Location),
		"tags":                      llx.MapData(convert.PtrMapStrToInterface(dep.Tags), types.String),
		"description":               llx.StringData(description),
		"provisioningState":         llx.StringData(provisioningState),
		"modelId":                   llx.StringData(modelId),
		"compute":                   llx.StringData(compute),
		"environmentId":             llx.StringData(environmentId),
		"environmentVariables":      llx.MapData(convert.PtrMapStrToInterface(envVars), types.String),
		"outputAction":              llx.StringData(outputAction),
		"outputFileName":            llx.StringData(outputFileName),
		"loggingLevel":              llx.StringData(loggingLevel),
		"errorThreshold":            llx.IntData(errorThreshold),
		"miniBatchSize":             llx.IntData(miniBatchSize),
		"maxConcurrencyPerInstance": llx.IntData(maxConcurrency),
		"retrySettings":             llx.DictData(retrySettings),
		"resources":                 llx.DictData(resources),
		"identity":                  llx.DictData(identity),
		"properties":                llx.MapData(convert.PtrMapStrToInterface(properties), types.String),
	}
	depIdentity := orZero(dep.Identity)
	if err := setResourceIdentity(runtime, depArgs, sortedUserAssignedIdentityIDs(depIdentity.UserAssignedIdentities),
		identityType(depIdentity.Type), identityPrincipalId(depIdentity.PrincipalID), identityTenantId(depIdentity.TenantID)); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "azure.subscription.machineLearningService.workspace.batchEndpoint.deployment", depArgs)
	if err != nil {
		return nil, err
	}
	mqlDep := res.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpointDeployment)
	sysData, err := convert.JsonToDict(dep.SystemData)
	if err != nil {
		return nil, err
	}
	mqlDep.cacheSystemData = sysData
	return mqlDep, nil
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpointDeploymentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpointDeployment) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceBatchEndpointDeployment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

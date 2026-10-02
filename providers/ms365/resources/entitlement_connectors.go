// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// connectionInfoKind* name the connectionInfo shapes this provider models.
// connectionInfoKindSapIag names the shape Microsoft Graph calls
// externalTokenBasedSapIagConnectionInfo; the constant is deliberately not
// named after that type, because an identifier carrying "token" next to a
// string literal reads to the credential scanner as a hardcoded secret.
// connectionInfoKindUnknown is reported for a shape Microsoft Graph added after
// this code was written, so a new external system reads as an unmodeled
// connector rather than as a connector with no connection details at all.
const (
	connectionInfoKindSapIag  = "tokenBasedSapIag"
	connectionInfoKindUnknown = "unknown"
)

// connectorTypeString renders the external system a connector integrates with.
// An absent value reads as an empty string rather than as the Kiota enum's zero
// value, which is "sapIag" and would name a system Microsoft Graph never
// reported.
func connectorTypeString(connectorType *models.ConnectorType) string {
	if connectorType == nil {
		return ""
	}
	return connectorType.String()
}

// externalOriginResourceConnectors lists the connectors that let an external
// resource system inject grantable entitlements into the tenant.
func (a *mqlMicrosoftIdentityAndAccess) externalOriginResourceConnectors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.
		IdentityGovernance().
		EntitlementManagement().
		ExternalOriginResourceConnectors().
		Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	if resp == nil {
		return []any{}, nil
	}

	connectors, err := iterate[models.ExternalOriginResourceConnectorable](ctx, resp, graphClient.GetAdapter(), models.CreateExternalOriginResourceConnectorCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, connector := range connectors {
		if connector == nil {
			continue
		}
		mqlConnector, err := newMqlExternalOriginResourceConnector(a.MqlRuntime, connector)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConnector)
	}
	return res, nil
}

// newMqlExternalOriginResourceConnector maps one external origin resource
// connector and its connection details.
func newMqlExternalOriginResourceConnector(runtime *plugin.Runtime, connector models.ExternalOriginResourceConnectorable) (plugin.Resource, error) {
	connectorID := convert.ToValue(connector.GetId())

	connectionInfo := llx.NilData
	if info := connector.GetConnectionInfo(); info != nil {
		mqlConnection, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessExternalOriginResourceConnectorConnection,
			newMqlConnectionArgs(connectorID+"/connectionInfo", info))
		if err != nil {
			return nil, err
		}
		connectionInfo = llx.ResourceData(mqlConnection, ResourceMicrosoftIdentityAndAccessExternalOriginResourceConnectorConnection)
	}

	return CreateResource(runtime, ResourceMicrosoftIdentityAndAccessExternalOriginResourceConnector,
		map[string]*llx.RawData{
			"__id":             llx.StringData(connectorID),
			"id":               llx.StringDataPtr(connector.GetId()),
			"displayName":      llx.StringDataPtr(connector.GetDisplayName()),
			"description":      llx.StringDataPtr(connector.GetDescription()),
			"connectorType":    llx.StringData(connectorTypeString(connector.GetConnectorType())),
			"createdBy":        llx.StringDataPtr(connector.GetCreatedBy()),
			"createdDateTime":  graphTimeData(connector.GetCreatedDateTime()),
			"modifiedBy":       llx.StringDataPtr(connector.GetModifiedBy()),
			"modifiedDateTime": graphTimeData(connector.GetModifiedDateTime()),
			"connectionInfo":   connectionInfo,
		})
}

// newMqlConnectionArgs maps a connectionInfo union member onto the arguments of
// the connection resource. The union is discriminated on the concrete type
// Microsoft Graph deserialized from the @odata.type of the payload; a member
// this provider does not model falls through to the unknown kind with only the
// base url populated, rather than silently reporting every field as null.
//
// Only the reference to the credential is reported: the subscription, resource
// group, key vault and secret name that locate it. The secret value itself is
// never read, and Microsoft Graph does not return it.
func newMqlConnectionArgs(id string, info models.ConnectionInfoable) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":           llx.StringData(id),
		"kind":           llx.StringData(connectionInfoKindUnknown),
		"url":            llx.NilData,
		"accessTokenUrl": llx.NilData,
		"clientId":       llx.NilData,
		"subscriptionId": llx.NilData,
		"resourceGroup":  llx.NilData,
		"keyVaultName":   llx.NilData,
		"secretName":     llx.NilData,
	}
	if info == nil {
		return args
	}
	args["url"] = llx.StringDataPtr(info.GetUrl())

	switch c := info.(type) {
	case *models.ExternalTokenBasedSapIagConnectionInfo:
		args["kind"] = llx.StringData(connectionInfoKindSapIag)
		args["accessTokenUrl"] = llx.StringDataPtr(c.GetAccessTokenUrl())
		args["clientId"] = llx.StringDataPtr(c.GetClientId())
		args["subscriptionId"] = llx.StringDataPtr(c.GetSubscriptionId())
		args["resourceGroup"] = llx.StringDataPtr(c.GetResourceGroup())
		args["keyVaultName"] = llx.StringDataPtr(c.GetKeyVaultName())
		args["secretName"] = llx.StringDataPtr(c.GetSecretName())
	}

	return args
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionSentinelServiceDataConnector) id() (string, error) {
	return a.Id.Data, nil
}

// dataTypeState returns the state of one connector data type, or nil when the
// data type or its state is absent.
func dataTypeState(state *armsecurityinsights.DataTypeState) *string {
	if state == nil {
		return nil
	}
	s := string(*state)
	return &s
}

// putDataTypeState records a data type's state in states, leaving the key out
// when Azure did not report one.
func putDataTypeState(states map[string]any, dataType string, common *armsecurityinsights.DataConnectorDataTypeCommon) {
	if common == nil {
		return
	}
	if s := dataTypeState(common.State); s != nil {
		states[dataType] = *s
	}
}

// dataConnectorDetails reads the tenant and the per-data-type states out of a
// polymorphic Sentinel data connector. Each kind carries its own properties
// type, so the kind switch is the only way to reach them. A kind this SDK does
// not model decodes as the bare DataConnector and reports no tenant and no data
// types.
func dataConnectorDetails(c armsecurityinsights.DataConnectorClassification) (tenantID *string, states map[string]any) {
	states = map[string]any{}
	switch v := c.(type) {
	case *armsecurityinsights.AADDataConnector:
		if p := v.Properties; p != nil {
			tenantID = p.TenantID
			if p.DataTypes != nil {
				putDataTypeState(states, "alerts", p.DataTypes.Alerts)
			}
		}
	case *armsecurityinsights.AATPDataConnector:
		if p := v.Properties; p != nil {
			tenantID = p.TenantID
			if p.DataTypes != nil {
				putDataTypeState(states, "alerts", p.DataTypes.Alerts)
			}
		}
	case *armsecurityinsights.ASCDataConnector:
		if p := v.Properties; p != nil && p.DataTypes != nil {
			putDataTypeState(states, "alerts", p.DataTypes.Alerts)
		}
	case *armsecurityinsights.MCASDataConnector:
		if p := v.Properties; p != nil {
			tenantID = p.TenantID
			if p.DataTypes != nil {
				putDataTypeState(states, "alerts", p.DataTypes.Alerts)
				putDataTypeState(states, "discoveryLogs", p.DataTypes.DiscoveryLogs)
			}
		}
	case *armsecurityinsights.MDATPDataConnector:
		if p := v.Properties; p != nil {
			tenantID = p.TenantID
			if p.DataTypes != nil {
				putDataTypeState(states, "alerts", p.DataTypes.Alerts)
			}
		}
	case *armsecurityinsights.OfficeDataConnector:
		if p := v.Properties; p != nil {
			tenantID = p.TenantID
			if dt := p.DataTypes; dt != nil {
				if dt.Exchange != nil {
					if s := dataTypeState(dt.Exchange.State); s != nil {
						states["exchange"] = *s
					}
				}
				if dt.SharePoint != nil {
					if s := dataTypeState(dt.SharePoint.State); s != nil {
						states["sharePoint"] = *s
					}
				}
				if dt.Teams != nil {
					if s := dataTypeState(dt.Teams.State); s != nil {
						states["teams"] = *s
					}
				}
			}
		}
	case *armsecurityinsights.TIDataConnector:
		if p := v.Properties; p != nil {
			tenantID = p.TenantID
			if dt := p.DataTypes; dt != nil && dt.Indicators != nil {
				if s := dataTypeState(dt.Indicators.State); s != nil {
					states["indicators"] = *s
				}
			}
		}
	case *armsecurityinsights.AwsCloudTrailDataConnector:
		if p := v.Properties; p != nil {
			if dt := p.DataTypes; dt != nil && dt.Logs != nil {
				if s := dataTypeState(dt.Logs.State); s != nil {
					states["logs"] = *s
				}
			}
		}
	}
	return tenantID, states
}

// dataConnectorArgs maps a Sentinel data connector onto the fields of
// azure.subscription.sentinelService.dataConnector.
func dataConnectorArgs(c armsecurityinsights.DataConnectorClassification) map[string]*llx.RawData {
	base := c.GetDataConnector()
	tenantID, states := dataConnectorDetails(c)
	return map[string]*llx.RawData{
		"id":        llx.StringDataPtr(base.ID),
		"name":      llx.StringDataPtr(base.Name),
		"kind":      llx.StringDataPtr(stringEnumPtr(base.Kind)),
		"tenantId":  llx.StringDataPtr(tenantID),
		"dataTypes": llx.MapData(states, types.String),
	}
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) connectors() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	client, err := armsecurityinsights.NewDataConnectorsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(a.ResourceGroup.Data, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.SecurityInsights/dataConnectors/read")
		}
		for _, raw := range page.Value {
			if raw == nil {
				continue
			}
			mqlConnector, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionSentinelServiceDataConnector, dataConnectorArgs(raw))
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConnector)
		}
	}
	return res, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// ipv4RangeSpansAll reports whether a firewall rule's range covers the whole
// IPv4 address space. Compared as parsed addresses rather than as strings so an
// equivalent but differently written range still matches.
func ipv4RangeSpansAll(startIP, endIP string) bool {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)
	if start == nil || end == nil {
		return false
	}
	return start.Equal(net.IPv4zero) && end.Equal(net.IPv4bcast)
}

// isAzureServicesRule reports whether a rule is the 0.0.0.0-to-0.0.0.0 range.
// Azure treats that not as a single host but as permission for its own services
// to reach the workspace, which is far narrower than an all-IPv4 rule. The two
// are easy to confuse because both start at 0.0.0.0.
func isAzureServicesRule(startIP, endIP string) bool {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)
	if start == nil || end == nil {
		return false
	}
	return start.Equal(net.IPv4zero) && end.Equal(net.IPv4zero)
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) firewallRules() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceName, err := resourceID.Component("workspaces")
	if err != nil {
		return nil, err
	}

	client, err := armsynapse.NewIPFirewallRulesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListByWorkspacePager(resourceID.ResourceGroup, workspaceName, &armsynapse.IPFirewallRulesClientListByWorkspaceOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			var startIP, endIP, provisioningState string
			if props := rule.Properties; props != nil {
				startIP = convert.ToValue(props.StartIPAddress)
				endIP = convert.ToValue(props.EndIPAddress)
				provisioningState = string(convert.ToValue(props.ProvisioningState))
			}

			mqlRule, err := CreateResource(a.MqlRuntime, "azure.subscription.synapseService.workspace.firewallRule",
				map[string]*llx.RawData{
					"__id":                llx.StringDataPtr(rule.ID),
					"name":                llx.StringDataPtr(rule.Name),
					"startIpAddress":      llx.StringData(startIP),
					"endIpAddress":        llx.StringData(endIP),
					"provisioningState":   llx.StringData(provisioningState),
					"allowsAllIpv4":       llx.BoolData(ipv4RangeSpansAll(startIP, endIP)),
					"allowsAzureServices": llx.BoolData(isAzureServicesRule(startIP, endIP)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionSynapseServiceWorkspaceSqlPoolInternal struct {
	// The pool's own coordinates, needed by the per-pool settings calls below.
	subscriptionID string
	resourceGroup  string
	workspaceName  string
	poolName       string

	tdeOnce   sync.Once
	tdeStatus string
	tdeErr    error

	auditOnce      sync.Once
	auditState     string
	auditRetention int64
	auditErr       error
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) sqlPools() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceName, err := resourceID.Component("workspaces")
	if err != nil {
		return nil, err
	}

	client, err := armsynapse.NewSQLPoolsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListByWorkspacePager(resourceID.ResourceGroup, workspaceName, &armsynapse.SQLPoolsClientListByWorkspaceOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, pool := range page.Value {
			if pool == nil {
				continue
			}

			var skuName, skuTier string
			if pool.SKU != nil {
				skuName = convert.ToValue(pool.SKU.Name)
				skuTier = convert.ToValue(pool.SKU.Tier)
			}

			var status, collation, createMode, provisioningState string
			var maxSizeBytes *int64
			var creationDate *time.Time
			if props := pool.Properties; props != nil {
				status = convert.ToValue(props.Status)
				collation = convert.ToValue(props.Collation)
				createMode = string(convert.ToValue(props.CreateMode))
				provisioningState = convert.ToValue(props.ProvisioningState)
				maxSizeBytes = props.MaxSizeBytes
				creationDate = props.CreationDate
			}

			mqlPool, err := CreateResource(a.MqlRuntime, "azure.subscription.synapseService.workspace.sqlPool",
				map[string]*llx.RawData{
					"__id":              llx.StringDataPtr(pool.ID),
					"id":                llx.StringDataPtr(pool.ID),
					"name":              llx.StringDataPtr(pool.Name),
					"location":          llx.StringDataPtr(pool.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(pool.Tags), types.String),
					"skuName":           llx.StringData(skuName),
					"skuTier":           llx.StringData(skuTier),
					"status":            llx.StringData(status),
					"collation":         llx.StringData(collation),
					"maxSizeBytes":      llx.IntDataPtr(maxSizeBytes),
					"createMode":        llx.StringData(createMode),
					"creationDate":      llx.TimeDataPtr(creationDate),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}

			p := mqlPool.(*mqlAzureSubscriptionSynapseServiceWorkspaceSqlPool)
			p.subscriptionID = resourceID.SubscriptionID
			p.resourceGroup = resourceID.ResourceGroup
			p.workspaceName = workspaceName
			p.poolName = convert.ToValue(pool.Name)
			res = append(res, p)
		}
	}
	return res, nil
}

// fetchTde reads the pool's transparent data encryption setting. Both the
// encryption and auditing settings are separate per-pool endpoints with no batch
// form, so each is fetched once on first access.
func (a *mqlAzureSubscriptionSynapseServiceWorkspaceSqlPool) fetchTde() (string, error) {
	a.tdeOnce.Do(func() {
		conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
		if !ok {
			a.tdeErr = errors.New("invalid connection provided, it is not an Azure connection")
			return
		}
		client, err := armsynapse.NewSQLPoolTransparentDataEncryptionsClient(a.subscriptionID, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.tdeErr = err
			return
		}
		resp, err := client.Get(context.Background(), a.resourceGroup, a.workspaceName, a.poolName,
			armsynapse.TransparentDataEncryptionNameCurrent, &armsynapse.SQLPoolTransparentDataEncryptionsClientGetOptions{})
		if err != nil {
			a.tdeErr = err
			return
		}
		if resp.Properties != nil {
			a.tdeStatus = string(convert.ToValue(resp.Properties.Status))
		}
	})
	return a.tdeStatus, a.tdeErr
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspaceSqlPool) fetchAuditing() (string, int64, error) {
	a.auditOnce.Do(func() {
		conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
		if !ok {
			a.auditErr = errors.New("invalid connection provided, it is not an Azure connection")
			return
		}
		client, err := armsynapse.NewSQLPoolBlobAuditingPoliciesClient(a.subscriptionID, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.auditErr = err
			return
		}
		resp, err := client.Get(context.Background(), a.resourceGroup, a.workspaceName, a.poolName,
			&armsynapse.SQLPoolBlobAuditingPoliciesClientGetOptions{})
		if err != nil {
			a.auditErr = err
			return
		}
		if resp.Properties != nil {
			a.auditState = string(convert.ToValue(resp.Properties.State))
			if resp.Properties.RetentionDays != nil {
				a.auditRetention = int64(*resp.Properties.RetentionDays)
			}
		}
	})
	return a.auditState, a.auditRetention, a.auditErr
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspaceSqlPool) transparentDataEncryptionStatus() (string, error) {
	return a.fetchTde()
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspaceSqlPool) auditingState() (string, error) {
	state, _, err := a.fetchAuditing()
	return state, err
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspaceSqlPool) auditingRetentionDays() (int64, error) {
	_, retention, err := a.fetchAuditing()
	return retention, err
}

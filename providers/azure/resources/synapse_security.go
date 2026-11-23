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
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

// synapseWorkspaceRef returns the subscription, resource group, and name of
// the workspace with the given ARM ID.
func synapseWorkspaceRef(id string) (subscriptionID, resourceGroup, workspaceName string, err error) {
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return "", "", "", err
	}
	workspaceName, err = resourceID.Component("workspaces")
	if err != nil {
		return "", "", "", err
	}
	return resourceID.SubscriptionID, resourceID.ResourceGroup, workspaceName, nil
}

func synapseClientOptions(runtime *plugin.Runtime) (*connection.AzureConnection, *arm.ClientOptions, error) {
	conn, err := azureConn(runtime)
	if err != nil {
		return nil, nil, err
	}
	return conn, &arm.ClientOptions{ClientOptions: conn.ClientOptions()}, nil
}

// fetchSQLAdmin reads the Entra administrator of the workspace's SQL
// endpoints. A workspace without one answers 404, which leaves both values
// unset.
func (a *mqlAzureSubscriptionSynapseServiceWorkspace) fetchSQLAdmin() (*armsynapse.AADAdminProperties, error) {
	a.sqlAdminOnce.Do(func() {
		sub, rg, ws, err := synapseWorkspaceRef(a.Id.Data)
		if err != nil {
			a.sqlAdminErr = err
			return
		}
		conn, opts, err := synapseClientOptions(a.MqlRuntime)
		if err != nil {
			a.sqlAdminErr = err
			return
		}
		client, err := armsynapse.NewWorkspaceAADAdminsClient(sub, conn.Token(), opts)
		if err != nil {
			a.sqlAdminErr = err
			return
		}
		resp, err := client.Get(context.Background(), rg, ws, nil)
		if err != nil {
			if !isAzureFeatureUnavailable(err) {
				a.sqlAdminErr = err
			}
			return
		}
		a.sqlAdmin = resp.Properties
	})
	return a.sqlAdmin, a.sqlAdminErr
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) sqlEntraAdminLogin() (string, error) {
	admin, err := a.fetchSQLAdmin()
	if err != nil {
		return "", err
	}
	if admin == nil || admin.Login == nil {
		a.SqlEntraAdminLogin.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *admin.Login, nil
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) sqlEntraAdminObjectId() (string, error) {
	admin, err := a.fetchSQLAdmin()
	if err != nil {
		return "", err
	}
	if admin == nil || admin.Sid == nil {
		a.SqlEntraAdminObjectId.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *admin.Sid, nil
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) sqlThreatDetectionState() (string, error) {
	sub, rg, ws, err := synapseWorkspaceRef(a.Id.Data)
	if err != nil {
		return "", err
	}
	conn, opts, err := synapseClientOptions(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	client, err := armsynapse.NewWorkspaceManagedSQLServerSecurityAlertPolicyClient(sub, conn.Token(), opts)
	if err != nil {
		return "", err
	}
	resp, err := client.Get(context.Background(), rg, ws, armsynapse.SecurityAlertPolicyNameAutoGeneratedDefault, nil)
	if err != nil {
		return "", err
	}
	if resp.Properties == nil || resp.Properties.State == nil {
		a.SqlThreatDetectionState.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(*resp.Properties.State), nil
}

// fetchSQLAuditing reads the workspace-level auditing policy that applies to
// its SQL endpoints.
func (a *mqlAzureSubscriptionSynapseServiceWorkspace) fetchSQLAuditing() (*armsynapse.ServerBlobAuditingPolicyProperties, error) {
	a.sqlAuditOnce.Do(func() {
		sub, rg, ws, err := synapseWorkspaceRef(a.Id.Data)
		if err != nil {
			a.sqlAuditErr = err
			return
		}
		conn, opts, err := synapseClientOptions(a.MqlRuntime)
		if err != nil {
			a.sqlAuditErr = err
			return
		}
		client, err := armsynapse.NewWorkspaceManagedSQLServerBlobAuditingPoliciesClient(sub, conn.Token(), opts)
		if err != nil {
			a.sqlAuditErr = err
			return
		}
		resp, err := client.Get(context.Background(), rg, ws, armsynapse.BlobAuditingPolicyNameDefault, nil)
		if err != nil {
			a.sqlAuditErr = err
			return
		}
		a.sqlAudit = resp.Properties
	})
	return a.sqlAudit, a.sqlAuditErr
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) sqlAuditingState() (string, error) {
	audit, err := a.fetchSQLAuditing()
	if err != nil {
		return "", err
	}
	if audit == nil || audit.State == nil {
		a.SqlAuditingState.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(*audit.State), nil
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) sqlAuditingRetentionDays() (int64, error) {
	audit, err := a.fetchSQLAuditing()
	if err != nil {
		return 0, err
	}
	if audit == nil || audit.RetentionDays == nil {
		a.SqlAuditingRetentionDays.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*audit.RetentionDays), nil
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) sqlMinimalTlsVersion() (string, error) {
	sub, rg, ws, err := synapseWorkspaceRef(a.Id.Data)
	if err != nil {
		return "", err
	}
	conn, opts, err := synapseClientOptions(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	client, err := armsynapse.NewWorkspaceManagedSQLServerDedicatedSQLMinimalTLSSettingsClient(sub, conn.Token(), opts)
	if err != nil {
		return "", err
	}
	resp, err := client.Get(context.Background(), rg, ws, "default", nil)
	if err != nil {
		return "", err
	}
	if resp.Properties == nil || resp.Properties.MinimalTLSVersion == nil {
		a.SqlMinimalTlsVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *resp.Properties.MinimalTLSVersion, nil
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) sqlVulnerabilityAssessmentRecurringScansEnabled() (bool, error) {
	sub, rg, ws, err := synapseWorkspaceRef(a.Id.Data)
	if err != nil {
		return false, err
	}
	conn, opts, err := synapseClientOptions(a.MqlRuntime)
	if err != nil {
		return false, err
	}
	client, err := armsynapse.NewWorkspaceManagedSQLServerVulnerabilityAssessmentsClient(sub, conn.Token(), opts)
	if err != nil {
		return false, err
	}
	resp, err := client.Get(context.Background(), rg, ws, armsynapse.VulnerabilityAssessmentNameDefault, nil)
	if err != nil {
		if isAzureFeatureUnavailable(err) {
			a.SqlVulnerabilityAssessmentRecurringScansEnabled.State = plugin.StateIsSet | plugin.StateIsNull
			return false, nil
		}
		return false, err
	}
	if resp.Properties == nil || resp.Properties.RecurringScans == nil || resp.Properties.RecurringScans.IsEnabled == nil {
		a.SqlVulnerabilityAssessmentRecurringScansEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *resp.Properties.RecurringScans.IsEnabled, nil
}

// synapseBigDataPoolArgs flattens an Apache Spark pool record into its MQL
// fields. Unset optional values stay null.
func synapseBigDataPoolArgs(pool *armsynapse.BigDataPoolResourceInfo) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                             llx.StringDataPtr(pool.ID),
		"id":                               llx.StringDataPtr(pool.ID),
		"name":                             llx.StringDataPtr(pool.Name),
		"sparkVersion":                     llx.NilData,
		"nodeSize":                         llx.NilData,
		"nodeSizeFamily":                   llx.NilData,
		"nodeCount":                        llx.NilData,
		"autoScaleEnabled":                 llx.NilData,
		"autoScaleMinNodeCount":            llx.NilData,
		"autoScaleMaxNodeCount":            llx.NilData,
		"autoPauseEnabled":                 llx.NilData,
		"autoPauseDelayInMinutes":          llx.NilData,
		"computeIsolationEnabled":          llx.NilData,
		"sessionLevelPackagesEnabled":      llx.NilData,
		"dynamicExecutorAllocationEnabled": llx.NilData,
		"provisioningState":                llx.NilData,
	}
	p := pool.Properties
	if p == nil {
		return args
	}
	args["sparkVersion"] = llx.StringDataPtr(p.SparkVersion)
	args["nodeSize"] = llx.StringDataPtr(stringEnumPtr(p.NodeSize))
	args["nodeSizeFamily"] = llx.StringDataPtr(stringEnumPtr(p.NodeSizeFamily))
	args["nodeCount"] = llx.IntDataPtr(p.NodeCount)
	args["computeIsolationEnabled"] = llx.BoolDataPtr(p.IsComputeIsolationEnabled)
	args["sessionLevelPackagesEnabled"] = llx.BoolDataPtr(p.SessionLevelPackagesEnabled)
	args["provisioningState"] = llx.StringDataPtr(p.ProvisioningState)
	if as := p.AutoScale; as != nil {
		args["autoScaleEnabled"] = llx.BoolDataPtr(as.Enabled)
		args["autoScaleMinNodeCount"] = llx.IntDataPtr(as.MinNodeCount)
		args["autoScaleMaxNodeCount"] = llx.IntDataPtr(as.MaxNodeCount)
	}
	if ap := p.AutoPause; ap != nil {
		args["autoPauseEnabled"] = llx.BoolDataPtr(ap.Enabled)
		args["autoPauseDelayInMinutes"] = llx.IntDataPtr(ap.DelayInMinutes)
	}
	if de := p.DynamicExecutorAllocation; de != nil {
		args["dynamicExecutorAllocationEnabled"] = llx.BoolDataPtr(de.Enabled)
	}
	return args
}

func (a *mqlAzureSubscriptionSynapseServiceWorkspace) bigDataPools() ([]any, error) {
	sub, rg, ws, err := synapseWorkspaceRef(a.Id.Data)
	if err != nil {
		return nil, err
	}
	conn, opts, err := synapseClientOptions(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client, err := armsynapse.NewBigDataPoolsClient(sub, conn.Token(), opts)
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListByWorkspacePager(rg, ws, nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, err
		}
		for _, pool := range page.Value {
			if pool == nil || pool.ID == nil {
				continue
			}
			r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionSynapseServiceWorkspaceBigDataPool, synapseBigDataPoolArgs(pool))
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
	}
	return res, nil
}

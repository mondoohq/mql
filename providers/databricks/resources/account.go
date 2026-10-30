// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"github.com/databricks/databricks-sdk-go/service/provisioning"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlDatabricksWorkspaceInternal struct {
	cacheNetworkId                    string
	cachePrivateAccessSettingsId      string
	cacheManagedServicesCustomerKeyId string
	cacheStorageCustomerKeyId         string
}

func (r *mqlDatabricks) workspaces() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	workspaces, err := acc.Workspaces.List(context.Background())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range workspaces {
		mqlWorkspace, err := newMqlDatabricksWorkspace(r.MqlRuntime, workspaces[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlWorkspace)
	}
	return list, nil
}

func newMqlDatabricksWorkspace(runtime *plugin.Runtime, ws provisioning.Workspace) (*mqlDatabricksWorkspace, error) {
	res, err := CreateResource(runtime, "databricks.workspace", map[string]*llx.RawData{
		"__id":           llx.StringData("databricks.workspace/" + strconv.FormatInt(ws.WorkspaceId, 10)),
		"workspaceId":    llx.IntData(ws.WorkspaceId),
		"name":           llx.StringData(ws.WorkspaceName),
		"deploymentName": llx.StringData(ws.DeploymentName),
		"status":         llx.StringData(string(ws.WorkspaceStatus)),
		"statusMessage":  llx.StringData(ws.WorkspaceStatusMessage),
		"pricingTier":    llx.StringData(string(ws.PricingTier)),
		"cloud":          llx.StringData(ws.Cloud),
		"awsRegion":      llx.StringData(ws.AwsRegion),
		"location":       llx.StringData(ws.Location),
		"customTags":     llx.MapData(strMap(ws.CustomTags), types.String),
		"creationTime":   llx.TimeDataPtr(epochMsTime(ws.CreationTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlWorkspace := res.(*mqlDatabricksWorkspace)
	mqlWorkspace.cacheNetworkId = ws.NetworkId
	mqlWorkspace.cachePrivateAccessSettingsId = ws.PrivateAccessSettingsId
	mqlWorkspace.cacheManagedServicesCustomerKeyId = ws.ManagedServicesCustomerManagedKeyId
	mqlWorkspace.cacheStorageCustomerKeyId = ws.StorageCustomerManagedKeyId
	return mqlWorkspace, nil
}

// managedServicesCustomerManagedKey resolves the customer-managed key that
// protects the workspace's control-plane managed services, hydrated by id
// through the customer-managed key's init.
func (r *mqlDatabricksWorkspace) managedServicesCustomerManagedKey() (*mqlDatabricksCustomerManagedKey, error) {
	return r.resolveCustomerManagedKey(r.cacheManagedServicesCustomerKeyId, &r.ManagedServicesCustomerManagedKey.State)
}

// storageCustomerManagedKey resolves the customer-managed key that protects the
// workspace's storage, hydrated by id through the customer-managed key's init.
func (r *mqlDatabricksWorkspace) storageCustomerManagedKey() (*mqlDatabricksCustomerManagedKey, error) {
	return r.resolveCustomerManagedKey(r.cacheStorageCustomerKeyId, &r.StorageCustomerManagedKey.State)
}

func (r *mqlDatabricksWorkspace) resolveCustomerManagedKey(keyId string, state *plugin.State) (*mqlDatabricksCustomerManagedKey, error) {
	if keyId == "" {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	key, err := NewResource(r.MqlRuntime, "databricks.customerManagedKey", map[string]*llx.RawData{
		"id": llx.StringData(keyId),
	})
	if err != nil {
		return nil, err
	}
	return key.(*mqlDatabricksCustomerManagedKey), nil
}

// cachedNetworks lists the account networks at most once per scan, caching the
// result on the root databricks resource keyed by network id so per-workspace
// network resolutions (databricks.workspaces { network }) share a single List
// rather than one Get per workspace.
func cachedNetworks(runtime *plugin.Runtime) (map[string]provisioning.Network, error) {
	rootRes, err := NewResource(runtime, "databricks", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	root := rootRes.(*mqlDatabricks)
	root.networksOnce.Do(func() {
		acc, err := accountClient(runtime)
		if err != nil {
			root.networksErr = err
			return
		}
		networks, err := acc.Networks.List(context.Background())
		if err != nil {
			root.networksErr = err
			return
		}
		byID := make(map[string]provisioning.Network, len(networks))
		for i := range networks {
			byID[networks[i].NetworkId] = networks[i]
		}
		root.networksByID = byID
	})
	return root.networksByID, root.networksErr
}

// cachedPrivateAccessSettings lists the account private access settings at most
// once per scan, caching the result on the root databricks resource keyed by id
// so per-workspace resolutions (databricks.workspaces { privateAccessSettings })
// share a single List rather than one Get per workspace.
func cachedPrivateAccessSettings(runtime *plugin.Runtime) (map[string]provisioning.PrivateAccessSettings, error) {
	rootRes, err := NewResource(runtime, "databricks", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	root := rootRes.(*mqlDatabricks)
	root.privateAccessOnce.Do(func() {
		acc, err := accountClient(runtime)
		if err != nil {
			root.privateAccessErr = err
			return
		}
		settings, err := acc.PrivateAccess.List(context.Background())
		if err != nil {
			root.privateAccessErr = err
			return
		}
		byID := make(map[string]provisioning.PrivateAccessSettings, len(settings))
		for i := range settings {
			byID[settings[i].PrivateAccessSettingsId] = settings[i]
		}
		root.privateAccessByID = byID
	})
	return root.privateAccessByID, root.privateAccessErr
}

func (r *mqlDatabricksWorkspace) network() (*mqlDatabricksNetwork, error) {
	if r.cacheNetworkId == "" {
		r.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	byID, err := cachedNetworks(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	net, ok := byID[r.cacheNetworkId]
	if !ok {
		r.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDatabricksNetwork(r.MqlRuntime, net)
}

func (r *mqlDatabricksWorkspace) privateAccessSettings() (*mqlDatabricksPrivateAccessSetting, error) {
	if r.cachePrivateAccessSettingsId == "" {
		r.PrivateAccessSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	byID, err := cachedPrivateAccessSettings(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	pas, ok := byID[r.cachePrivateAccessSettingsId]
	if !ok {
		r.PrivateAccessSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDatabricksPrivateAccessSetting(r.MqlRuntime, pas)
}

func (r *mqlDatabricks) metastores() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	metastores, err := acc.Metastores.ListAll(context.Background())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range metastores {
		m := metastores[i]
		res, err := CreateResource(r.MqlRuntime, "databricks.metastore", map[string]*llx.RawData{
			"__id":              llx.StringData("databricks.metastore/" + m.MetastoreId),
			"id":                llx.StringData(m.MetastoreId),
			"name":              llx.StringData(m.Name),
			"globalMetastoreId": llx.StringData(m.GlobalMetastoreId),
			"owner":             llx.StringData(m.Owner),
			"cloud":             llx.StringData(m.Cloud),
			"region":            llx.StringData(m.Region),
			"storageRoot":       llx.StringData(m.StorageRoot),
			"deltaSharingScope": llx.StringData(string(m.DeltaSharingScope)),
			"deltaSharingRecipientTokenLifetimeInSeconds": llx.IntData(m.DeltaSharingRecipientTokenLifetimeInSeconds),
			"externalAccessEnabled":                       llx.BoolData(m.ExternalAccessEnabled),
			"privilegeModelVersion":                       llx.StringData(m.PrivilegeModelVersion),
			"createdAt":                                   llx.TimeDataPtr(epochMsTime(m.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlDatabricks) networks() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	networks, err := acc.Networks.List(context.Background())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range networks {
		mqlNetwork, err := newMqlDatabricksNetwork(r.MqlRuntime, networks[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlNetwork)
	}
	return list, nil
}

func newMqlDatabricksNetwork(runtime *plugin.Runtime, net provisioning.Network) (*mqlDatabricksNetwork, error) {
	res, err := CreateResource(runtime, "databricks.network", map[string]*llx.RawData{
		"__id":             llx.StringData("databricks.network/" + net.NetworkId),
		"id":               llx.StringData(net.NetworkId),
		"networkName":      llx.StringData(net.NetworkName),
		"vpcId":            llx.StringData(net.VpcId),
		"subnetIds":        llx.ArrayData(strSlice(net.SubnetIds), types.String),
		"securityGroupIds": llx.ArrayData(strSlice(net.SecurityGroupIds), types.String),
		"vpcStatus":        llx.StringData(string(net.VpcStatus)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksNetwork), nil
}

func (r *mqlDatabricks) privateAccessSettings() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	settings, err := acc.PrivateAccess.List(context.Background())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range settings {
		mqlPas, err := newMqlDatabricksPrivateAccessSetting(r.MqlRuntime, settings[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlPas)
	}
	return list, nil
}

func newMqlDatabricksPrivateAccessSetting(runtime *plugin.Runtime, pas provisioning.PrivateAccessSettings) (*mqlDatabricksPrivateAccessSetting, error) {
	res, err := CreateResource(runtime, "databricks.privateAccessSetting", map[string]*llx.RawData{
		"__id":                  llx.StringData("databricks.privateAccessSetting/" + pas.PrivateAccessSettingsId),
		"id":                    llx.StringData(pas.PrivateAccessSettingsId),
		"name":                  llx.StringData(pas.PrivateAccessSettingsName),
		"region":                llx.StringData(pas.Region),
		"publicAccessEnabled":   llx.BoolData(pas.PublicAccessEnabled),
		"privateAccessLevel":    llx.StringData(string(pas.PrivateAccessLevel)),
		"allowedVpcEndpointIds": llx.ArrayData(strSlice(pas.AllowedVpcEndpointIds), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksPrivateAccessSetting), nil
}

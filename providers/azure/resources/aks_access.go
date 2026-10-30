// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	clusters "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// machineLearningWorkspaceResourceType is the lowercase ARM type segment of an
// Azure Machine Learning workspace, used to tell whether a Trusted Access
// binding's source resource is one.
const machineLearningWorkspaceResourceType = "/providers/microsoft.machinelearningservices/workspaces/"

// aksNodeAdminAccess flattens the node administrator accounts out of a cluster's
// OS profiles.
//
// Azure omits the whole Linux or Windows profile when the cluster has no node
// pool of that OS, so an absent profile means there is no such administrator
// account, which is why these report empty rather than null. The SSH keys are
// public keys; no private key material is ever returned by this API.
func aksNodeAdminAccess(props *clusters.ManagedClusterProperties) (linuxAdminUsername string, linuxSSHPublicKeys []any, windowsAdminUsername string) {
	linuxSSHPublicKeys = []any{}
	if props == nil {
		return "", linuxSSHPublicKeys, ""
	}
	if lp := props.LinuxProfile; lp != nil {
		linuxAdminUsername = convert.ToValue(lp.AdminUsername)
		if lp.SSH != nil {
			for _, key := range lp.SSH.PublicKeys {
				if key == nil || key.KeyData == nil || *key.KeyData == "" {
					continue
				}
				linuxSSHPublicKeys = append(linuxSSHPublicKeys, *key.KeyData)
			}
		}
	}
	if wp := props.WindowsProfile; wp != nil {
		windowsAdminUsername = convert.ToValue(wp.AdminUsername)
	}
	return linuxAdminUsername, linuxSSHPublicKeys, windowsAdminUsername
}

// aksNodePoolHostAccess flattens the kubelet and node network settings that
// widen what a pod or an outside caller can reach on a pool's nodes.
//
// Every one of these blocks is omitted when the pool does not configure it, so
// an absent block yields an empty collection: the pool permits nothing extra.
// The application security group IDs are returned separately so the caller can
// cache them for the typed accessor.
func aksNodePoolHostAccess(props *clusters.ManagedClusterAgentPoolProfileProperties) (unsafeSysctls, allowedHostPorts []any, nodePublicIPTags map[string]any, appSecurityGroupIDs []string) {
	unsafeSysctls = []any{}
	allowedHostPorts = []any{}
	nodePublicIPTags = map[string]any{}
	if props == nil {
		return unsafeSysctls, allowedHostPorts, nodePublicIPTags, nil
	}

	if kc := props.KubeletConfig; kc != nil {
		for _, sysctl := range kc.AllowedUnsafeSysctls {
			if sysctl == nil || *sysctl == "" {
				continue
			}
			unsafeSysctls = append(unsafeSysctls, *sysctl)
		}
	}

	np := props.NetworkProfile
	if np == nil {
		return unsafeSysctls, allowedHostPorts, nodePublicIPTags, nil
	}
	for _, portRange := range np.AllowedHostPorts {
		if portRange == nil {
			continue
		}
		entry := map[string]any{}
		if portRange.PortStart != nil {
			entry["portStart"] = int64(*portRange.PortStart)
		}
		if portRange.PortEnd != nil {
			entry["portEnd"] = int64(*portRange.PortEnd)
		}
		if portRange.Protocol != nil {
			entry["protocol"] = string(*portRange.Protocol)
		}
		allowedHostPorts = append(allowedHostPorts, entry)
	}
	for _, tag := range np.NodePublicIPTags {
		if tag == nil || tag.IPTagType == nil || *tag.IPTagType == "" {
			continue
		}
		nodePublicIPTags[*tag.IPTagType] = convert.ToValue(tag.Tag)
	}
	for _, id := range np.ApplicationSecurityGroups {
		if id == nil || *id == "" {
			continue
		}
		appSecurityGroupIDs = append(appSecurityGroupIDs, *id)
	}

	return unsafeSysctls, allowedHostPorts, nodePublicIPTags, appSecurityGroupIDs
}

func (a *mqlAzureSubscriptionAksServiceClusterNodePool) applicationSecurityGroups() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.appSecurityGroup", a.cacheAppSecurityGroupIds)
}

func (a *mqlAzureSubscriptionAksServiceCluster) diagnosticSettings() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionAksServiceCluster) diagnosticSettingsCategories() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	return getDiagnosticSettingsCategories(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionAksServiceClusterTrustedAccessRoleBinding) id() (string, error) {
	return a.Id.Data, nil
}

// createTrustedAccessRoleBindingRawData maps one Trusted Access role binding.
//
// The binding's own ARM ID already carries the cluster it belongs to and the
// binding name, so it is unique across clusters on its own.
func createTrustedAccessRoleBindingRawData(binding *clusters.TrustedAccessRoleBinding) (map[string]*llx.RawData, error) {
	if binding == nil {
		return nil, errors.New("nil trusted access role binding")
	}
	if binding.ID == nil || *binding.ID == "" {
		return nil, errors.New("trusted access role binding without a resource id")
	}

	roles := []any{}
	var provisioningState, sourceResourceID *string
	if props := binding.Properties; props != nil {
		for _, role := range props.Roles {
			if role == nil || *role == "" {
				continue
			}
			roles = append(roles, *role)
		}
		provisioningState = (*string)(props.ProvisioningState)
		sourceResourceID = props.SourceResourceID
	}

	return map[string]*llx.RawData{
		"id":                llx.StringDataPtr(binding.ID),
		"name":              llx.StringDataPtr(binding.Name),
		"roles":             llx.ArrayData(roles, types.String),
		"provisioningState": llx.StringDataPtr(provisioningState),
		"sourceResourceId":  llx.StringDataPtr(sourceResourceID),
	}, nil
}

// trustedAccessRoleBindings lists the Trusted Access grants on the cluster.
//
// A cluster that has never been granted Trusted Access returns an empty list,
// and so do the ARM answers that mean the capability is not there to read. A
// refused read is different: it returns null rather than an empty list, so
// "nothing is granted" stays distinguishable from "the grants could not be
// read".
func (a *mqlAzureSubscriptionAksServiceCluster) trustedAccessRoleBindings() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	ctx := context.Background()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := clusters.NewTrustedAccessRoleBindingsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureAccessDenied(err) {
				log.Warn().Err(err).Str("cluster", a.Id.Data).Msg("not allowed to read aks trusted access role bindings")
				a.TrustedAccessRoleBindings.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			if isAzureFeatureUnavailable(err) {
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			args, err := createTrustedAccessRoleBindingRawData(entry)
			if err != nil {
				return nil, err
			}
			binding, err := CreateResource(a.MqlRuntime, "azure.subscription.aksService.cluster.trustedAccessRoleBinding", args)
			if err != nil {
				return nil, err
			}
			res = append(res, binding)
		}
	}
	return res, nil
}

// sourceMachineLearningWorkspace resolves the binding's source resource when it
// is an Azure Machine Learning workspace, so the workspace's own exposure can
// be read from the grant. Resolution walks the subscription's workspace list,
// which is fetched once and cached, rather than resolving the workspace one
// binding at a time.
//
// A source in another subscription resolves to null: this connection is scoped
// to one subscription and cannot enumerate the workspaces of another.
func (a *mqlAzureSubscriptionAksServiceClusterTrustedAccessRoleBinding) sourceMachineLearningWorkspace() (*mqlAzureSubscriptionMachineLearningServiceWorkspace, error) {
	sourceID := a.SourceResourceId.Data
	if a.SourceResourceId.IsNull() || !strings.Contains(strings.ToLower(sourceID), machineLearningWorkspaceResourceType) {
		a.SourceMachineLearningWorkspace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	resourceID, err := ParseResourceID(sourceID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(resourceID.SubscriptionID, conn.SubId()) {
		log.Debug().Str("workspace", sourceID).Msg("trusted access source workspace lives in another subscription")
		a.SourceMachineLearningWorkspace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	svc, err := NewResource(a.MqlRuntime, "azure.subscription.machineLearningService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(resourceID.SubscriptionID),
	})
	if err != nil {
		return nil, err
	}
	workspaces := svc.(*mqlAzureSubscriptionMachineLearningService).GetWorkspaces()
	if workspaces.Error != nil {
		return nil, workspaces.Error
	}
	for _, entry := range workspaces.Data {
		workspace, ok := entry.(*mqlAzureSubscriptionMachineLearningServiceWorkspace)
		if !ok {
			continue
		}
		if strings.EqualFold(workspace.Id.Data, sourceID) {
			return workspace, nil
		}
	}

	return nil, fmt.Errorf("azure machine learning workspace %q granted trusted access to %q was not found", sourceID, a.Id.Data)
}

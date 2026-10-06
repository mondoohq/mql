// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	security "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/rs/zerolog/log"
)

const (
	vaQualysPolicyDefinitionId string = "/providers/Microsoft.Authorization/policyDefinitions/13ce0167-8ca6-4048-8e6b-f996402e3c1b"
	// There are two policy per component: one for ARC clusters and one for k8s clusters
	arcClusterDefenderExtensionDefinitionId        string = "/providers/Microsoft.Authorization/policyDefinitions/708b60a6-d253-4fe0-9114-4be4c00f012c"
	kubernetesClusterDefenderExtensionDefinitionId string = "/providers/Microsoft.Authorization/policyDefinitions/64def556-fbad-4622-930e-72d1d5589bf5"

	// 0adc5395-... is the Arc-enabled Kubernetes "Azure Policy extension" definition;
	// a8eff44f-... is the AKS "Azure Policy Add-on" definition. They were previously
	// both set to the Arc GUID, so azurePolicyForKubernetes never reflected the AKS
	// add-on assignment.
	arcClusterPolicyExtensionDefinitionId        string = "/providers/Microsoft.Authorization/policyDefinitions/0adc5395-9169-4b9b-8687-af838d69410a"
	kubernetesClusterPolicyExtensionDefinitionId string = "/providers/Microsoft.Authorization/policyDefinitions/a8eff44f-8c92-45c3-a3fb-9880802d67a7"
)

func (a *mqlAzureSubscriptionCloudDefenderService) id() (string, error) {
	return "azure.subscription.cloudDefender/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionCloudDefenderService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

// A query written for the dict fields this service used to have, such as
// azure.subscription.cloudDefender.defenderForServers.enabled, still compiles:
// the dict fields are gone, and these typed resources carry the same names, so
// the path now creates the resource by its type name with no arguments. Without
// an init that left every field unset, so each read came back null with an empty
// id and the check evaluated against nothing. These inits resolve the bare
// resource through the subscription's service, so the old path returns the same
// object forServers() and forContainers() do.

func initAzureSubscriptionCloudDefenderServiceDefenderForServers(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	svc, err := cloudDefenderServiceFor(runtime)
	if err != nil {
		return nil, nil, err
	}
	servers := svc.GetForServers()
	if servers.Error != nil {
		return nil, nil, servers.Error
	}
	return args, servers.Data, nil
}

func initAzureSubscriptionCloudDefenderServiceDefenderForContainers(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	svc, err := cloudDefenderServiceFor(runtime)
	if err != nil {
		return nil, nil, err
	}
	containers := svc.GetForContainers()
	if containers.Error != nil {
		return nil, nil, containers.Error
	}
	return args, containers.Data, nil
}

// cloudDefenderServiceFor returns the connection subscription's
// cloudDefenderService, the one the runtime already holds if it was built.
func cloudDefenderServiceFor(runtime *plugin.Runtime) (*mqlAzureSubscriptionCloudDefenderService, error) {
	res, err := NewResource(runtime, "azure.subscription.cloudDefenderService", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionCloudDefenderService), nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceSecurityContact) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionCloudDefenderServiceSecurityContactInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCloudDefenderServiceSecurityContact) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// commonPricingArgs extracts common pricing fields from an Azure PricingProperties response
// into a map suitable for CreateResource.
func commonPricingArgs(props *security.PricingProperties, mqlResourceName, subId string) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":           llx.StringData(mqlResourceName + "/" + subId),
		"subscriptionId": llx.StringData(subId),
	}

	if props == nil {
		props = &security.PricingProperties{}
	}

	enabled := false
	pricingTier := ""
	if props.PricingTier != nil {
		pricingTier = string(*props.PricingTier)
		enabled = *props.PricingTier == security.PricingTierStandard
	}
	args["enabled"] = llx.BoolData(enabled)
	args["pricingTier"] = llx.StringData(pricingTier)

	subPlan := ""
	if props.SubPlan != nil {
		subPlan = *props.SubPlan
	}
	args["subPlan"] = llx.StringData(subPlan)

	enforce := false
	if props.Enforce != nil {
		enforce = *props.Enforce == security.EnforceTrue
	}
	args["enforce"] = llx.BoolData(enforce)

	deprecated := false
	if props.Deprecated != nil {
		deprecated = *props.Deprecated
	}
	args["deprecated"] = llx.BoolData(deprecated)

	freeTrialRemainingTime := ""
	if props.FreeTrialRemainingTime != nil {
		freeTrialRemainingTime = *props.FreeTrialRemainingTime
	}
	args["freeTrialRemainingTime"] = llx.StringData(freeTrialRemainingTime)

	args["enablementTime"] = llx.TimeDataPtr(props.EnablementTime)

	inherited := false
	if props.Inherited != nil {
		inherited = *props.Inherited == security.InheritedTrue
	}
	args["inherited"] = llx.BoolData(inherited)

	inheritedFrom := ""
	if props.InheritedFrom != nil {
		inheritedFrom = *props.InheritedFrom
	}
	args["inheritedFrom"] = llx.StringData(inheritedFrom)

	replacedBy := []any{}
	for _, s := range props.ReplacedBy {
		if s != nil {
			replacedBy = append(replacedBy, *s)
		}
	}
	args["replacedBy"] = llx.ArrayData(replacedBy, types.String)

	resourcesCoverageStatus := ""
	if props.ResourcesCoverageStatus != nil {
		resourcesCoverageStatus = string(*props.ResourcesCoverageStatus)
	}
	args["resourcesCoverageStatus"] = llx.StringData(resourcesCoverageStatus)

	return args
}

// getSimpleDefenderPricing fetches pricing data for a Defender component and creates a typed resource.
func (a *mqlAzureSubscriptionCloudDefenderService) getSimpleDefenderPricing(azurePricingName, mqlResourceName string) (plugin.Resource, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pricing, err := clientFactory.NewPricingsClient().Get(ctx, fmt.Sprintf("subscriptions/%s", subId), azurePricingName, &security.PricingsClientGetOptions{})
	if err != nil {
		return nil, err
	}

	args := commonPricingArgs(pricing.Properties, mqlResourceName, subId)
	return CreateResource(a.MqlRuntime, mqlResourceName, args)
}

type mqlAzureSubscriptionCloudDefenderServiceInternal struct {
	policyAssignmentsOnce sync.Once
	policyAssignments     PolicyAssignments
	policyAssignmentsErr  error
}

// cachedPolicyAssignments fetches the subscription's policy assignments once and
// caches the result. Both the forServers and forContainers Defender plans read
// the same policy-assignments list to derive their enabled/extension state, so
// without this a scan that touches both plans issues the list call twice.
func (a *mqlAzureSubscriptionCloudDefenderService) cachedPolicyAssignments(ctx context.Context) (PolicyAssignments, error) {
	a.policyAssignmentsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
		armConn, err := getArmSecurityConnection(ctx, conn, a.SubscriptionId.Data)
		if err != nil {
			a.policyAssignmentsErr = err
			return
		}
		a.policyAssignments, a.policyAssignmentsErr = getPolicyAssignments(ctx, armConn)
	})
	return a.policyAssignments, a.policyAssignmentsErr
}

func (a *mqlAzureSubscriptionCloudDefenderService) forServers() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForServers, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	vmPricing, err := clientFactory.NewPricingsClient().Get(ctx, fmt.Sprintf("subscriptions/%s", subId), "VirtualMachines", &security.PricingsClientGetOptions{})
	if err != nil {
		return nil, err
	}

	armConn, err := getArmSecurityConnection(ctx, conn, subId)
	if err != nil {
		return nil, err
	}
	list, err := a.cachedPolicyAssignments(ctx)
	if err != nil {
		return nil, err
	}
	serverVASetings, err := getServerVulnAssessmentSettings(ctx, armConn)
	if err != nil {
		return nil, err
	}

	args := commonPricingArgs(vmPricing.Properties, ResourceAzureSubscriptionCloudDefenderServiceDefenderForServers, subId)

	// Override enabled based on policy assignments and vulnerability assessment settings
	vulnToolName := ""
	for _, it := range list.PolicyAssignments {
		// Scope the assignment to this subscription; the unfiltered list also
		// returns management-group-inherited assignments, which would otherwise
		// report enabled even when VA is not configured on this subscription
		// (mirrors the scope check in the Defender-for-Containers detection).
		if it.Properties.PolicyDefinitionID == vaQualysPolicyDefinitionId &&
			it.Properties.Scope == fmt.Sprintf("/subscriptions/%s", subId) {
			args["enabled"] = llx.BoolData(true)
			vulnToolName = "Microsoft Defender for Cloud integrated Qualys scanner"
		}
	}
	if mdvmVulnerabilityAssessmentEnabled(serverVASetings.Settings) {
		args["enabled"] = llx.BoolData(true)
		vulnToolName = "Microsoft Defender vulnerability management"
	}
	args["vulnerabilityManagementToolName"] = llx.StringData(vulnToolName)

	resource, err := CreateResource(a.MqlRuntime,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderForServers,
		args,
	)
	if err != nil {
		return nil, err
	}
	mqlServers := resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForServers)
	// The pricing response already carries the extensions, so prime the cache
	// rather than making extensions() fetch the same thing again.
	var rawExtensions []*security.Extension
	if vmPricing.Properties != nil {
		rawExtensions = vmPricing.Properties.Extensions
	}
	mqlServers.rawExtensionsOnce.Do(func() {
		mqlServers.rawExtensions = rawExtensions
	})
	return mqlServers, nil
}

type mqlAzureSubscriptionCloudDefenderServiceDefenderForServersInternal struct {
	rawExtensionsOnce sync.Once
	rawExtensions     []*security.Extension
	rawExtensionsErr  error
}

// fetchRawExtensions returns the extension list from the VirtualMachines
// pricing endpoint, resolved once. The parent forServers() primes it from the
// response it already has; reaching the resource by its own type name falls
// back to the API.
func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForServers) fetchRawExtensions() ([]*security.Extension, error) {
	a.rawExtensionsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
		subId := a.SubscriptionId.Data
		clientFactory, err := armsecurity.NewClientFactory(subId, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.rawExtensionsErr = err
			return
		}
		resp, err := clientFactory.NewPricingsClient().Get(context.Background(),
			fmt.Sprintf("subscriptions/%s", subId), "VirtualMachines",
			&security.PricingsClientGetOptions{})
		if err != nil {
			a.rawExtensionsErr = err
			return
		}
		if resp.Properties != nil {
			a.rawExtensions = resp.Properties.Extensions
		}
	})
	return a.rawExtensions, a.rawExtensionsErr
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForServers) extensions() ([]any, error) {
	exts, err := a.fetchRawExtensions()
	if err != nil {
		return nil, err
	}
	return buildExtensionResources(a.MqlRuntime, exts,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderForServersExtension,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderForServers+"/"+a.SubscriptionId.Data)
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForServersExtension) id() (string, error) {
	return a.__id, nil
}

// simpleDefenderDict serializes a typed Defender pricing resource's `enabled`
// flag into the shape that the deprecated defenderForX() dict methods used to
// return — `{"enabled": <bool>}`. Letting the dict methods delegate here keeps
// them in sync with the typed equivalent and reuses the PricingsClient.Get
// already issued by the typed resource.
func simpleDefenderDict(enabled *plugin.TValue[bool]) (any, error) {
	if enabled.Error != nil {
		return nil, enabled.Error
	}
	return map[string]any{"enabled": enabled.Data}, nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forAppServices() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForAppServices, error) {
	resource, err := a.getSimpleDefenderPricing("AppServices", ResourceAzureSubscriptionCloudDefenderServiceDefenderForAppServices)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForAppServices), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forSqlServersOnMachines() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForSqlServersOnMachines, error) {
	resource, err := a.getSimpleDefenderPricing("SqlServerVirtualMachines", ResourceAzureSubscriptionCloudDefenderServiceDefenderForSqlServersOnMachines)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForSqlServersOnMachines), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forSqlDatabases() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForSqlDatabases, error) {
	resource, err := a.getSimpleDefenderPricing("SqlServers", ResourceAzureSubscriptionCloudDefenderServiceDefenderForSqlDatabases)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForSqlDatabases), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forOpenSourceDatabases() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForOpenSourceDatabases, error) {
	resource, err := a.getSimpleDefenderPricing("OpenSourceRelationalDatabases", ResourceAzureSubscriptionCloudDefenderServiceDefenderForOpenSourceDatabases)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForOpenSourceDatabases), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forCosmosDb() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForCosmosDb, error) {
	resource, err := a.getSimpleDefenderPricing("CosmosDbs", ResourceAzureSubscriptionCloudDefenderServiceDefenderForCosmosDb)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForCosmosDb), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forStorageAccounts() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForStorageAccounts, error) {
	resource, err := a.getSimpleDefenderPricing("StorageAccounts", ResourceAzureSubscriptionCloudDefenderServiceDefenderForStorageAccounts)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForStorageAccounts), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forKeyVaults() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForKeyVaults, error) {
	resource, err := a.getSimpleDefenderPricing("KeyVaults", ResourceAzureSubscriptionCloudDefenderServiceDefenderForKeyVaults)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForKeyVaults), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forResourceManager() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForResourceManager, error) {
	resource, err := a.getSimpleDefenderPricing("Arm", ResourceAzureSubscriptionCloudDefenderServiceDefenderForResourceManager)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForResourceManager), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) defenderForApis() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForApis, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	apiPricing, err := clientFactory.NewPricingsClient().Get(ctx, fmt.Sprintf("subscriptions/%s", subId), "Api", &security.PricingsClientGetOptions{})
	if err != nil {
		return nil, err
	}

	args := commonPricingArgs(apiPricing.Properties, ResourceAzureSubscriptionCloudDefenderServiceDefenderForApis, subId)

	resource, err := CreateResource(a.MqlRuntime,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderForApis,
		args,
	)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForApis), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) defenderCSPM() (*mqlAzureSubscriptionCloudDefenderServiceDefenderCSPM, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	cloudPosturePricing, err := clientFactory.NewPricingsClient().Get(ctx, fmt.Sprintf("subscriptions/%s", subId), "CloudPosture", &security.PricingsClientGetOptions{})
	if err != nil {
		return nil, err
	}

	args := commonPricingArgs(cloudPosturePricing.Properties, ResourceAzureSubscriptionCloudDefenderServiceDefenderCSPM, subId)

	resource, err := CreateResource(a.MqlRuntime,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderCSPM,
		args,
	)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderCSPM), nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) monitoringAgentAutoProvision() (bool, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := security.NewAutoProvisioningSettingsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return false, err
	}

	setting, err := client.Get(ctx, "default", &security.AutoProvisioningSettingsClientGetOptions{})
	if err != nil {
		return false, err
	}
	if setting.Properties == nil || setting.Properties.AutoProvision == nil {
		return false, nil
	}
	return *setting.Properties.AutoProvision == security.AutoProvisionOn, nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) forContainers() (*mqlAzureSubscriptionCloudDefenderServiceDefenderForContainers, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	armConn, err := getArmSecurityConnection(ctx, conn, subId)
	if err != nil {
		return nil, err
	}

	pas, err := a.cachedPolicyAssignments(ctx)
	if err != nil {
		return nil, err
	}

	kubernetesDefender := false
	arcDefender := false
	kubernetesPolicyExt := false
	arcPolicyExt := false
	for _, it := range pas.PolicyAssignments {
		if it.Properties.PolicyDefinitionID == arcClusterDefenderExtensionDefinitionId &&
			it.Properties.Scope == fmt.Sprintf("/subscriptions/%s", subId) {
			arcDefender = true
		}
		if it.Properties.PolicyDefinitionID == kubernetesClusterDefenderExtensionDefinitionId &&
			it.Properties.Scope == fmt.Sprintf("/subscriptions/%s", subId) {
			kubernetesDefender = true
		}
		if it.Properties.PolicyDefinitionID == arcClusterPolicyExtensionDefinitionId &&
			it.Properties.Scope == fmt.Sprintf("/subscriptions/%s", subId) {
			arcPolicyExt = true
		}
		if it.Properties.PolicyDefinitionID == kubernetesClusterPolicyExtensionDefinitionId &&
			it.Properties.Scope == fmt.Sprintf("/subscriptions/%s", subId) {
			kubernetesPolicyExt = true
		}
	}

	// Check if Defender for Containers is enabled by querying the pricing tier
	clientFactory, err := armsecurity.NewClientFactory(subId, armConn.token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	containersPricing, err := clientFactory.NewPricingsClient().Get(ctx, fmt.Sprintf("subscriptions/%s", subId), "Containers", &security.PricingsClientGetOptions{})
	if err != nil {
		return nil, err
	}

	args := commonPricingArgs(containersPricing.Properties, ResourceAzureSubscriptionCloudDefenderServiceDefenderForContainers, subId)
	// Either cluster flavour counts. There are two policy definitions per
	// component -- one for Arc-enabled Kubernetes, one for AKS -- and a
	// subscription that runs only AKS, which is the common case, will never have
	// the Arc policy assigned. Both constants used to hold the Arc GUID, so this
	// was `x && x`; correcting the AKS GUID silently turned it into a real
	// conjunction and every AKS-only subscription began reporting false for a
	// component it demonstrably had.
	args["defenderDaemonSet"] = llx.BoolData(arcDefender || kubernetesDefender)
	args["azurePolicyForKubernetes"] = llx.BoolData(arcPolicyExt || kubernetesPolicyExt)

	resource, err := CreateResource(a.MqlRuntime,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderForContainers,
		args,
	)
	if err != nil {
		return nil, err
	}
	mqlContainers := resource.(*mqlAzureSubscriptionCloudDefenderServiceDefenderForContainers)
	var rawExtensions []*security.Extension
	if containersPricing.Properties != nil {
		rawExtensions = containersPricing.Properties.Extensions
	}
	mqlContainers.rawExtensionsOnce.Do(func() {
		mqlContainers.rawExtensions = rawExtensions
	})
	return mqlContainers, nil
}

type mqlAzureSubscriptionCloudDefenderServiceDefenderForContainersInternal struct {
	rawExtensionsOnce sync.Once
	rawExtensions     []*security.Extension
	rawExtensionsErr  error
}

// fetchRawExtensions returns the raw extension list from the Containers
// pricing endpoint. Cached with sync.Once so the typed extensions() accessor
// and the deprecated defenderForContainers() dict share a single fetch (the
// parent forContainers() primes the cache; standalone access falls back to
// the API).
func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForContainers) fetchRawExtensions() ([]*security.Extension, error) {
	a.rawExtensionsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
		subId := a.SubscriptionId.Data
		clientFactory, err := armsecurity.NewClientFactory(subId, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.rawExtensionsErr = err
			return
		}
		resp, err := clientFactory.NewPricingsClient().Get(context.Background(),
			fmt.Sprintf("subscriptions/%s", subId), "Containers",
			&security.PricingsClientGetOptions{})
		if err != nil {
			a.rawExtensionsErr = err
			return
		}
		if resp.Properties == nil {
			return
		}
		a.rawExtensions = resp.Properties.Extensions
	})
	return a.rawExtensions, a.rawExtensionsErr
}

func (a *mqlAzureSubscriptionCloudDefenderService) settingsMCAS() (*mqlAzureSubscriptionCloudDefenderServiceSettings, error) {
	return a.getSecuritySettingsFor(security.SettingNameMCAS)
}

func (a *mqlAzureSubscriptionCloudDefenderService) settingsWDATP() (*mqlAzureSubscriptionCloudDefenderServiceSettings, error) {
	return a.getSecuritySettingsFor(security.SettingNameWDATP)
}

func (a *mqlAzureSubscriptionCloudDefenderService) settingsSentinel() (*mqlAzureSubscriptionCloudDefenderServiceSettings, error) {
	return a.getSecuritySettingsFor(security.SettingNameSentinel)
}

func (a *mqlAzureSubscriptionCloudDefenderService) getSecuritySettingsFor(name security.SettingName) (*mqlAzureSubscriptionCloudDefenderServiceSettings, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	settingResp, err := clientFactory.NewSettingsClient().Get(ctx, name, nil)
	if err != nil {
		return nil, err
	}

	// SettingClassification is an interface, and the SDK's polymorphic
	// unmarshaller returns a nil one for a null body. The result of GetSetting
	// was checked but the receiver was not, so a 200 with a null payload panicked
	// instead of erroring.
	if settingResp.SettingClassification == nil {
		return nil, fmt.Errorf("no setting returned for '%s'", name)
	}
	baseSetting := settingResp.SettingClassification.GetSetting()
	if baseSetting == nil || baseSetting.Kind == nil {
		return nil, fmt.Errorf("retrieved setting or its kind is nil for '%s'", name)
	}

	switch *baseSetting.Kind {
	case armsecurity.SettingKindDataExportSettings:
		// Handles MCAS and Sentinel
		settings, ok := settingResp.SettingClassification.(*armsecurity.DataExportSettings)
		if !ok {
			return nil, fmt.Errorf("failed assertion to DataExportSettings for kind '%s', setting '%s'. Actual type: %T", *baseSetting.Kind, name, settingResp.SettingClassification)
		}
		properties, err := convert.JsonToDict(settings.Properties)
		if err != nil {
			return nil, err
		}
		resource, err := CreateResource(a.MqlRuntime,
			"azure.subscription.cloudDefenderService.settings",
			map[string]*llx.RawData{
				"id":         llx.StringDataPtr(settings.ID),
				"name":       llx.StringDataPtr(settings.Name),
				"kind":       llx.StringDataPtr((*string)(settings.Kind)),
				"type":       llx.StringDataPtr(settings.Type),
				"properties": llx.DictData(properties),
			},
		)
		if err != nil {
			return nil, err
		}
		return resource.(*mqlAzureSubscriptionCloudDefenderServiceSettings), nil
	case armsecurity.SettingKindAlertSyncSettings:
		// Handles WDATP
		settings, ok := settingResp.SettingClassification.(*armsecurity.AlertSyncSettings)
		if !ok {
			return nil, fmt.Errorf("failed assertion to AlertSyncSettings for kind '%s', setting '%s'. Actual type: %T", *baseSetting.Kind, name, settingResp.SettingClassification)
		}
		properties, err := convert.JsonToDict(settings.Properties)
		if err != nil {
			return nil, err
		}
		resource, err := CreateResource(a.MqlRuntime,
			"azure.subscription.cloudDefenderService.settings",
			map[string]*llx.RawData{
				"id":         llx.StringDataPtr(settings.ID),
				"name":       llx.StringDataPtr(settings.Name),
				"kind":       llx.StringDataPtr((*string)(settings.Kind)),
				"type":       llx.StringDataPtr(settings.Type),
				"properties": llx.DictData(properties),
			},
		)
		if err != nil {
			return nil, err
		}
		return resource.(*mqlAzureSubscriptionCloudDefenderServiceSettings), nil
	default:
		return nil, fmt.Errorf("unsupported settings '%s' of kind '%s'", name, *baseSetting.Kind)
	}
}

func (s *mqlAzureSubscriptionCloudDefenderServiceSettings) id() (string, error) {
	return s.Id.Data, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceSecurityAutomation) id() (string, error) {
	return a.__id, nil
}

// securityAutomations lists the subscription's continuous export rules.
//
// The scopes, sources and actions are carried as dicts rather than as typed
// sub-resources. Sources nest rule sets inside rules, and actions are a union
// whose fields differ per actionType, so a typed shape would either flatten
// away the nesting or invent a sub-resource per action kind; the dict keeps
// what Azure returns and the schema documents the keys for each discriminator.
//
// The Event Hub connection string is deliberately absent: it is a credential,
// and Azure does not return it in any response.
func (a *mqlAzureSubscriptionCloudDefenderService) securityAutomations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := clientFactory.NewAutomationsClient().NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, automation := range page.Value {
			if automation == nil {
				continue
			}
			mqlAutomation, err := securityAutomationToMql(a.MqlRuntime, automation)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAutomation)
		}
	}
	return res, nil
}

// securityAutomationToMql maps one automation onto its MQL resource.
//
// Every nested block goes through convert.JsonToDict rather than being walked
// field by field, so a source or action kind Azure adds later still arrives
// intact instead of being silently dropped by a type switch that has not heard
// of it.
func securityAutomationToMql(runtime *plugin.Runtime, automation *armsecurity.Automation) (plugin.Resource, error) {
	scopes := []any{}
	sources := []any{}
	actions := []any{}
	description := ""
	isEnabled := false

	if props := automation.Properties; props != nil {
		if props.Description != nil {
			description = *props.Description
		}
		if props.IsEnabled != nil {
			isEnabled = *props.IsEnabled
		}
		if len(props.Scopes) > 0 {
			dicts, err := convert.JsonToDictSlice(props.Scopes)
			if err != nil {
				return nil, err
			}
			scopes = dicts
		}
		if len(props.Sources) > 0 {
			dicts, err := convert.JsonToDictSlice(props.Sources)
			if err != nil {
				return nil, err
			}
			sources = dicts
		}
		if len(props.Actions) > 0 {
			dicts, err := convert.JsonToDictSlice(props.Actions)
			if err != nil {
				return nil, err
			}
			actions = dicts
		}
	}

	return CreateResource(runtime,
		ResourceAzureSubscriptionCloudDefenderServiceSecurityAutomation,
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(automation.ID),
			"id":          llx.StringDataPtr(automation.ID),
			"name":        llx.StringDataPtr(automation.Name),
			"type":        llx.StringDataPtr(automation.Type),
			"location":    llx.StringDataPtr(automation.Location),
			"tags":        llx.MapData(convert.PtrMapStrToInterface(automation.Tags), types.String),
			"description": llx.StringData(description),
			"isEnabled":   llx.BoolData(isEnabled),
			"scopes":      llx.ArrayData(scopes, types.Dict),
			"sources":     llx.ArrayData(sources, types.Dict),
			"actions":     llx.ArrayData(actions, types.Dict),
		})
}

func (a *mqlAzureSubscriptionCloudDefenderService) securityContacts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := clientFactory.NewContactsClient().NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, contact := range page.ContactList.Value {
			if contact == nil {
				continue
			}
			args := argsFromContactProperties(contact.Properties)
			args["id"] = llx.StringDataPtr(contact.ID)
			args["name"] = llx.StringDataPtr(contact.Name)

			mqlSecurityContact, err := CreateResource(
				a.MqlRuntime,
				"azure.subscription.cloudDefenderService.securityContact",
				args,
			)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(contact.SystemData)
			if err != nil {
				return nil, err
			}
			mqlSecurityContact.(*mqlAzureSubscriptionCloudDefenderServiceSecurityContact).cacheSystemData = sysData
			res = append(res, mqlSecurityContact)
		}
	}
	return res, nil
}

func argsFromContactProperties(props *armsecurity.ContactProperties) map[string]*llx.RawData {
	args := map[string]*llx.RawData{}
	if props == nil {
		return args
	}

	sources := map[string]any{}
	for _, source := range props.NotificationsSources {
		// the slice holds interface values, and a null array element unmarshals
		// to a nil one -- the result of GetNotificationsSource was checked but
		// the receiver was not
		if source == nil {
			continue
		}
		notificationSource := source.GetNotificationsSource()
		if notificationSource == nil || notificationSource.SourceType == nil {
			continue
		}

		sourceDict, err := convert.JsonToDict(source)
		if err != nil {
			log.Debug().Err(err).Msg("unable to convert armsecurity.props.NotificationsSources to dict")
			continue
		}

		if notificationSource.SourceType == nil {
			continue
		}
		sourceType := *notificationSource.SourceType
		sources[string(sourceType)] = sourceDict
	}
	args["notificationSources"] = llx.DictData(sources)

	notificationsByRole, err := convert.JsonToDict(props.NotificationsByRole)
	if err != nil {
		log.Debug().Err(err).Msg("unable to convert armsecurity.Contact.Properties.NotificationsByRole to dict")
	}
	args["notificationsByRole"] = llx.DictData(notificationsByRole)

	args["emails"] = llx.ArrayData(splitSecurityContactEmails(props.Emails), types.String)

	args["isEnabled"] = llx.BoolDataPtr(props.IsEnabled)
	args["phone"] = llx.StringDataPtr(props.Phone)

	return args
}

// splitSecurityContactEmails turns Defender's semicolon-separated contact list
// into the addresses it actually holds.
//
// strings.Split("", ";") returns []string{""}, so a contact configured with a
// phone number and no email used to report emails: [""] -- one element, not
// zero. A check phrased `securityContacts.any(emails.length > 0)` passed on a
// subscription with no email contact at all, which is the opposite of the
// finding it was written to raise. Empty entries are dropped and each address
// is trimmed, since the portal permits spaces around the separator.
func splitSecurityContactEmails(emails *string) []any {
	out := []any{}
	if emails == nil {
		return out
	}
	for _, e := range strings.Split(*emails, ";") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// buildExtensionResources creates typed extension sub-resources from a list of Azure SDK extensions.
func buildExtensionResources(runtime *plugin.Runtime, extensions []*security.Extension, mqlResourceName, parentIdPrefix string) ([]any, error) {
	res := []any{}
	for _, ext := range extensions {
		if ext == nil {
			continue
		}

		name := ""
		if ext.Name != nil {
			name = *ext.Name
		}

		isEnabled := false
		if ext.IsEnabled != nil {
			isEnabled = *ext.IsEnabled == security.IsEnabledTrue
		}

		additionalProps, err := convert.JsonToDict(ext.AdditionalExtensionProperties)
		if err != nil {
			log.Debug().Err(err).Str("extension", name).Msg("unable to convert extension additional properties to dict")
			additionalProps = nil
		}

		opCode := ""
		opMessage := ""
		if ext.OperationStatus != nil {
			if ext.OperationStatus.Code != nil {
				opCode = string(*ext.OperationStatus.Code)
			}
			if ext.OperationStatus.Message != nil {
				opMessage = *ext.OperationStatus.Message
			}
		}

		extResource, err := CreateResource(runtime, mqlResourceName, map[string]*llx.RawData{
			"__id":                   llx.StringData(parentIdPrefix + "/extension/" + name),
			"name":                   llx.StringData(name),
			"isEnabled":              llx.BoolData(isEnabled),
			"additionalProperties":   llx.DictData(additionalProps),
			"operationStatusCode":    llx.StringData(opCode),
			"operationStatusMessage": llx.StringData(opMessage),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, extResource)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForApis) id() (string, error) {
	return a.__id, nil
}

// extensions lazily fetches extension data for Defender CSPM. This re-fetches the CloudPosture
// pricing data (already retrieved by defenderCSPM) so that extensions are only loaded when accessed.
func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderCSPM) extensions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	cloudPosturePricing, err := clientFactory.NewPricingsClient().Get(ctx, fmt.Sprintf("subscriptions/%s", subId), "CloudPosture", &security.PricingsClientGetOptions{})
	if err != nil {
		return nil, err
	}

	if cloudPosturePricing.Properties == nil {
		return []any{}, nil
	}

	return buildExtensionResources(a.MqlRuntime, cloudPosturePricing.Properties.Extensions,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderCSPMExtension,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderCSPM+"/"+subId)
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderCSPM) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderCSPMExtension) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForServers) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForAppServices) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForSqlServersOnMachines) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForSqlDatabases) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForOpenSourceDatabases) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForCosmosDb) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForStorageAccounts) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForKeyVaults) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForResourceManager) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForContainers) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForContainers) extensions() ([]any, error) {
	exts, err := a.fetchRawExtensions()
	if err != nil {
		return nil, err
	}
	return buildExtensionResources(a.MqlRuntime, exts,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderForContainersExtension,
		ResourceAzureSubscriptionCloudDefenderServiceDefenderForContainers+"/"+a.SubscriptionId.Data)
}

func (a *mqlAzureSubscriptionCloudDefenderServiceDefenderForContainersExtension) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceSecureScore) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceSecureScoreControl) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceRegulatoryComplianceStandard) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceRegulatoryComplianceControl) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) secureScores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := clientFactory.NewSecureScoresClient().NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list secure scores due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			var displayName string
			var currentScore float64
			var maxScore int64
			var percentage float64
			var weight int64

			if item.Properties != nil {
				if item.Properties.DisplayName != nil {
					displayName = *item.Properties.DisplayName
				}
				if item.Properties.Score != nil {
					if item.Properties.Score.Current != nil {
						currentScore = *item.Properties.Score.Current
					}
					if item.Properties.Score.Max != nil {
						maxScore = int64(*item.Properties.Score.Max)
					}
					if item.Properties.Score.Percentage != nil {
						percentage = *item.Properties.Score.Percentage
					}
				}
				if item.Properties.Weight != nil {
					weight = *item.Properties.Weight
				}
			}

			mqlResource, err := CreateResource(a.MqlRuntime,
				ResourceAzureSubscriptionCloudDefenderServiceSecureScore,
				map[string]*llx.RawData{
					"__id":         llx.StringDataPtr(item.ID),
					"id":           llx.StringDataPtr(item.ID),
					"name":         llx.StringDataPtr(item.Name),
					"displayName":  llx.StringData(displayName),
					"currentScore": llx.FloatData(currentScore),
					"maxScore":     llx.IntData(maxScore),
					"percentage":   llx.FloatData(percentage),
					"weight":       llx.IntData(weight),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) secureScoreControls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := clientFactory.NewSecureScoreControlsClient().NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list secure score controls due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			var displayName string
			var description string
			var currentScore float64
			var maxScore int64
			var percentage float64
			var weight int64
			var healthyResourceCount int64
			var unhealthyResourceCount int64
			var notApplicableResourceCount int64

			if item.Properties != nil {
				if item.Properties.DisplayName != nil {
					displayName = *item.Properties.DisplayName
				}
				if item.Properties.Score != nil {
					if item.Properties.Score.Current != nil {
						currentScore = *item.Properties.Score.Current
					}
					if item.Properties.Score.Max != nil {
						maxScore = int64(*item.Properties.Score.Max)
					}
					if item.Properties.Score.Percentage != nil {
						percentage = *item.Properties.Score.Percentage
					}
				}
				if item.Properties.Weight != nil {
					weight = int64(*item.Properties.Weight)
				}
				if item.Properties.HealthyResourceCount != nil {
					healthyResourceCount = int64(*item.Properties.HealthyResourceCount)
				}
				if item.Properties.UnhealthyResourceCount != nil {
					unhealthyResourceCount = int64(*item.Properties.UnhealthyResourceCount)
				}
				if item.Properties.NotApplicableResourceCount != nil {
					notApplicableResourceCount = int64(*item.Properties.NotApplicableResourceCount)
				}
				if item.Properties.Definition != nil && item.Properties.Definition.Properties != nil && item.Properties.Definition.Properties.Description != nil {
					description = *item.Properties.Definition.Properties.Description
				}
			}

			mqlResource, err := CreateResource(a.MqlRuntime,
				ResourceAzureSubscriptionCloudDefenderServiceSecureScoreControl,
				map[string]*llx.RawData{
					"__id":                       llx.StringDataPtr(item.ID),
					"id":                         llx.StringDataPtr(item.ID),
					"name":                       llx.StringDataPtr(item.Name),
					"displayName":                llx.StringData(displayName),
					"description":                llx.StringData(description),
					"currentScore":               llx.FloatData(currentScore),
					"maxScore":                   llx.IntData(maxScore),
					"percentage":                 llx.FloatData(percentage),
					"weight":                     llx.IntData(weight),
					"healthyResourceCount":       llx.IntData(healthyResourceCount),
					"unhealthyResourceCount":     llx.IntData(unhealthyResourceCount),
					"notApplicableResourceCount": llx.IntData(notApplicableResourceCount),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) regulatoryComplianceStandards() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := clientFactory.NewRegulatoryComplianceStandardsClient().NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// A subscription with no standard pricing bundle has no regulatory
			// compliance surface at all, and says so with a 400 rather than an
			// empty list. That, a 403, and a 404 are all "nothing to report
			// here", not a reason to fail the whole Defender query.
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list regulatory compliance standards")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			var state string
			var passedControls int64
			var failedControls int64
			var skippedControls int64

			if item.Properties != nil {
				if item.Properties.State != nil {
					state = string(*item.Properties.State)
				}
				if item.Properties.PassedControls != nil {
					passedControls = int64(*item.Properties.PassedControls)
				}
				if item.Properties.FailedControls != nil {
					failedControls = int64(*item.Properties.FailedControls)
				}
				if item.Properties.SkippedControls != nil {
					skippedControls = int64(*item.Properties.SkippedControls)
				}
			}

			mqlResource, err := CreateResource(a.MqlRuntime,
				ResourceAzureSubscriptionCloudDefenderServiceRegulatoryComplianceStandard,
				map[string]*llx.RawData{
					"__id":            llx.StringDataPtr(item.ID),
					"id":              llx.StringDataPtr(item.ID),
					"name":            llx.StringDataPtr(item.Name),
					"state":           llx.StringData(state),
					"passedControls":  llx.IntData(passedControls),
					"failedControls":  llx.IntData(failedControls),
					"skippedControls": llx.IntData(skippedControls),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceRegulatoryComplianceStandard) controls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	// Extract subscription ID from the standard's ID path
	// Format: /subscriptions/{subId}/providers/Microsoft.Security/regulatoryComplianceStandards/{standardName}
	standardId := a.Id.Data
	parts := strings.Split(standardId, "/")
	var subId string
	for i, p := range parts {
		if strings.EqualFold(p, "subscriptions") && i+1 < len(parts) {
			subId = parts[i+1]
			break
		}
	}
	if subId == "" {
		subId = conn.SubId()
	}

	standardName := a.Name.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := clientFactory.NewRegulatoryComplianceControlsClient().NewListPager(standardName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list regulatory compliance controls")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			var state string
			var description string
			var passedAssessments int64
			var failedAssessments int64
			var skippedAssessments int64

			if item.Properties != nil {
				if item.Properties.State != nil {
					state = string(*item.Properties.State)
				}
				if item.Properties.Description != nil {
					description = *item.Properties.Description
				}
				if item.Properties.PassedAssessments != nil {
					passedAssessments = int64(*item.Properties.PassedAssessments)
				}
				if item.Properties.FailedAssessments != nil {
					failedAssessments = int64(*item.Properties.FailedAssessments)
				}
				if item.Properties.SkippedAssessments != nil {
					skippedAssessments = int64(*item.Properties.SkippedAssessments)
				}
			}

			mqlResource, err := CreateResource(a.MqlRuntime,
				ResourceAzureSubscriptionCloudDefenderServiceRegulatoryComplianceControl,
				map[string]*llx.RawData{
					"__id":               llx.StringDataPtr(item.ID),
					"id":                 llx.StringDataPtr(item.ID),
					"name":               llx.StringDataPtr(item.Name),
					"description":        llx.StringData(description),
					"state":              llx.StringData(state),
					"passedAssessments":  llx.IntData(passedAssessments),
					"failedAssessments":  llx.IntData(failedAssessments),
					"skippedAssessments": llx.IntData(skippedAssessments),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceAssessment) id() (string, error) {
	return a.__id, nil
}

type mqlAzureSubscriptionCloudDefenderServiceAssessmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCloudDefenderServiceAssessment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCloudDefenderServiceAlert) id() (string, error) {
	return a.__id, nil
}

type mqlAzureSubscriptionCloudDefenderServiceAlertInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCloudDefenderServiceAlert) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// assessmentMetadata holds the catalog metadata for a single assessment
// definition, joined into the per-assessment list results by name.
type assessmentMetadata struct {
	severity               string
	assessmentType         string
	implementationEffort   string
	userImpact             string
	remediationDescription string
	description            string
	preview                bool
	categories             []any
	threats                []any
	tactics                []any
	techniques             []any
}

// enumSliceToInterface converts a slice of pointers to string-backed enum
// values into a slice of plain strings for llx.ArrayData.
func enumSliceToInterface[T ~string](in []*T) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		if v != nil {
			out = append(out, string(*v))
		}
	}
	return out
}

// assessmentAttackPaths converts the Defender risk attack-path graph into a
// slice of {id, nodes, edges} dicts. Each node is {id, labels} and each edge
// is {id, sourceId, targetId}.
func assessmentAttackPaths(paths []*armsecurity.AssessmentPropertiesBaseRiskPathsItem) []any {
	out := make([]any, 0, len(paths))
	for _, p := range paths {
		if p == nil {
			continue
		}
		nodes := make([]any, 0, len(p.Nodes))
		for _, n := range p.Nodes {
			if n == nil {
				continue
			}
			nodes = append(nodes, map[string]any{
				"id":     convert.ToValue(n.ID),
				"labels": enumSliceToInterface(n.NodePropertiesLabel),
			})
		}
		edges := make([]any, 0, len(p.Edges))
		for _, e := range p.Edges {
			if e == nil {
				continue
			}
			edges = append(edges, map[string]any{
				"id":       convert.ToValue(e.ID),
				"sourceId": convert.ToValue(e.SourceID),
				"targetId": convert.ToValue(e.TargetID),
			})
		}
		out = append(out, map[string]any{
			"id":    convert.ToValue(p.ID),
			"nodes": nodes,
			"edges": edges,
		})
	}
	return out
}

// assessmentMetadataByName returns a map of assessment name to its catalog
// metadata. Assessment list responses don't carry this metadata, so it is
// joined in from the metadata catalog: built-in definitions come from the
// global list, custom ones from the subscription-scoped list.
func assessmentMetadataByName(ctx context.Context, clientFactory *armsecurity.ClientFactory) map[string]assessmentMetadata {
	metadata := map[string]assessmentMetadata{}
	metadataClient := clientFactory.NewAssessmentsMetadataClient()

	collect := func(items []*armsecurity.AssessmentMetadataResponse) {
		for _, item := range items {
			if item.Name == nil || item.Properties == nil {
				continue
			}
			p := item.Properties
			metadata[*item.Name] = assessmentMetadata{
				severity:               string(convert.ToValue(p.Severity)),
				assessmentType:         string(convert.ToValue(p.AssessmentType)),
				implementationEffort:   string(convert.ToValue(p.ImplementationEffort)),
				userImpact:             string(convert.ToValue(p.UserImpact)),
				remediationDescription: convert.ToValue(p.RemediationDescription),
				description:            convert.ToValue(p.Description),
				preview:                convert.ToValue(p.Preview),
				categories:             enumSliceToInterface(p.Categories),
				threats:                enumSliceToInterface(p.Threats),
				tactics:                enumSliceToInterface(p.Tactics),
				techniques:             enumSliceToInterface(p.Techniques),
			}
		}
	}

	builtinPager := metadataClient.NewListPager(nil)
	for builtinPager.More() {
		page, err := builtinPager.NextPage(ctx)
		if err != nil {
			log.Debug().Err(err).Msg("could not list built-in assessment metadata")
			break
		}
		collect(page.Value)
	}

	subPager := metadataClient.NewListBySubscriptionPager(nil)
	for subPager.More() {
		page, err := subPager.NextPage(ctx)
		if err != nil {
			log.Debug().Err(err).Msg("could not list subscription assessment metadata")
			break
		}
		collect(page.Value)
	}

	return metadata
}

func (a *mqlAzureSubscriptionCloudDefenderService) assessments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	metaByName := assessmentMetadataByName(ctx, clientFactory)

	pager := clientFactory.NewAssessmentsClient().NewListPager("/subscriptions/"+subId, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list security assessments due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			var displayName, status, statusCause, statusDescription string
			var firstEvaluationDate, statusChangeDate *time.Time
			additionalData := map[string]any{}

			var riskLevel string
			var riskIsContextual bool
			riskFactors := []any{}
			riskAttackPathRefs := []any{}
			riskAttackPaths := []any{}

			if props := item.Properties; props != nil {
				if props.DisplayName != nil {
					displayName = *props.DisplayName
				}
				if props.Status != nil {
					if props.Status.Code != nil {
						status = string(*props.Status.Code)
					}
					if props.Status.Cause != nil {
						statusCause = *props.Status.Cause
					}
					if props.Status.Description != nil {
						statusDescription = *props.Status.Description
					}
					firstEvaluationDate = props.Status.FirstEvaluationDate
					statusChangeDate = props.Status.StatusChangeDate
				}
				for k, v := range props.AdditionalData {
					if v != nil {
						additionalData[k] = *v
					}
				}
				if risk := props.Risk; risk != nil {
					riskLevel = string(convert.ToValue(risk.Level))
					riskIsContextual = convert.ToValue(risk.IsContextualRisk)
					riskFactors = enumSliceToInterface(risk.RiskFactors)
					riskAttackPathRefs = enumSliceToInterface(risk.AttackPathsReferences)
					riskAttackPaths = assessmentAttackPaths(risk.Paths)
				}
			}

			// The assessed resource is the segment of the assessment ID before the
			// Microsoft.Security/assessments path; for subscription-wide assessments
			// that is the subscription itself.
			id := ""
			if item.ID != nil {
				id = *item.ID
			}
			resourceId := strings.SplitN(id, "/providers/Microsoft.Security/assessments/", 2)[0]

			// The catalogue lookup can miss because metadata was never fetched
			// (the list call was denied or throttled) as well as because the
			// assessment genuinely has none. Report the catalogue-derived
			// fields as null in that case rather than as "" / [] / false:
			// severity is a @defaults field, and a blank severity on every
			// finding silently breaks `where(severity == "High")`.
			meta, metaKnown := assessmentMetadata{}, false
			if item.Name != nil {
				meta, metaKnown = metaByName[*item.Name]
			}
			strOrNull := func(v string) *llx.RawData {
				if !metaKnown {
					return llx.NilData
				}
				return llx.StringData(v)
			}
			arrOrNull := func(v []any) *llx.RawData {
				if !metaKnown {
					return llx.NilData
				}
				return llx.ArrayData(v, types.String)
			}

			mqlResource, err := CreateResource(a.MqlRuntime,
				"azure.subscription.cloudDefenderService.assessment",
				map[string]*llx.RawData{
					"__id":                     llx.StringDataPtr(item.ID),
					"id":                       llx.StringDataPtr(item.ID),
					"name":                     llx.StringDataPtr(item.Name),
					"displayName":              llx.StringData(displayName),
					"status":                   llx.StringData(status),
					"statusCause":              llx.StringData(statusCause),
					"statusDescription":        llx.StringData(statusDescription),
					"firstEvaluationDate":      llx.TimeDataPtr(firstEvaluationDate),
					"statusChangeDate":         llx.TimeDataPtr(statusChangeDate),
					"severity":                 strOrNull(meta.severity),
					"resourceId":               llx.StringData(resourceId),
					"additionalData":           llx.DictData(additionalData),
					"riskLevel":                llx.StringData(riskLevel),
					"riskFactors":              llx.ArrayData(riskFactors, types.String),
					"riskAttackPathReferences": llx.ArrayData(riskAttackPathRefs, types.String),
					"riskAttackPaths":          llx.ArrayData(riskAttackPaths, types.Dict),
					"riskIsContextual":         llx.BoolData(riskIsContextual),
					"assessmentType":           strOrNull(meta.assessmentType),
					"categories":               arrOrNull(meta.categories),
					"threats":                  arrOrNull(meta.threats),
					"tactics":                  arrOrNull(meta.tactics),
					"techniques":               arrOrNull(meta.techniques),
					"implementationEffort":     strOrNull(meta.implementationEffort),
					"userImpact":               strOrNull(meta.userImpact),
					"remediationDescription":   strOrNull(meta.remediationDescription),
					"preview":                  llx.BoolData(meta.preview),
					"description":              strOrNull(meta.description),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(item.SystemData)
			if err != nil {
				return nil, err
			}
			mqlResource.(*mqlAzureSubscriptionCloudDefenderServiceAssessment).cacheSystemData = sysData
			res = append(res, mqlResource)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) alerts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := clientFactory.NewAlertsClient().NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list security alerts due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			var displayName, severity, status, description, alertType string
			var intent, vendorName, compromisedEntity string
			var startTime, endTime, timeGenerated *time.Time
			remediationSteps := []any{}
			resourceIdentifiers := []any{}

			if props := item.Properties; props != nil {
				if props.AlertDisplayName != nil {
					displayName = *props.AlertDisplayName
				}
				if props.Severity != nil {
					severity = string(*props.Severity)
				}
				if props.Status != nil {
					status = string(*props.Status)
				}
				if props.Description != nil {
					description = *props.Description
				}
				if props.AlertType != nil {
					alertType = *props.AlertType
				}
				if props.Intent != nil {
					intent = string(*props.Intent)
				}
				if props.VendorName != nil {
					vendorName = *props.VendorName
				}
				if props.CompromisedEntity != nil {
					compromisedEntity = *props.CompromisedEntity
				}
				for _, step := range props.RemediationSteps {
					if step != nil {
						remediationSteps = append(remediationSteps, *step)
					}
				}
				for _, ri := range props.ResourceIdentifiers {
					riDict, err := convert.JsonToDict(ri)
					if err != nil {
						log.Debug().Err(err).Msg("unable to convert alert resource identifier to dict")
						continue
					}
					resourceIdentifiers = append(resourceIdentifiers, riDict)
				}
				startTime = props.StartTimeUTC
				endTime = props.EndTimeUTC
				timeGenerated = props.TimeGeneratedUTC
			}

			mqlResource, err := CreateResource(a.MqlRuntime,
				"azure.subscription.cloudDefenderService.alert",
				map[string]*llx.RawData{
					"__id":                llx.StringDataPtr(item.ID),
					"id":                  llx.StringDataPtr(item.ID),
					"name":                llx.StringDataPtr(item.Name),
					"displayName":         llx.StringData(displayName),
					"severity":            llx.StringData(severity),
					"status":              llx.StringData(status),
					"description":         llx.StringData(description),
					"alertType":           llx.StringData(alertType),
					"intent":              llx.StringData(intent),
					"vendorName":          llx.StringData(vendorName),
					"compromisedEntity":   llx.StringData(compromisedEntity),
					"startTime":           llx.TimeDataPtr(startTime),
					"endTime":             llx.TimeDataPtr(endTime),
					"timeGenerated":       llx.TimeDataPtr(timeGenerated),
					"remediationSteps":    llx.ArrayData(remediationSteps, types.String),
					"resourceIdentifiers": llx.ArrayData(resourceIdentifiers, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(item.SystemData)
			if err != nil {
				return nil, err
			}
			mqlResource.(*mqlAzureSubscriptionCloudDefenderServiceAlert).cacheSystemData = sysData
			res = append(res, mqlResource)
		}
	}
	return res, nil
}

// subAssessments resolves the detailed findings underlying a security
// assessment (per-CVE, per-misconfiguration). Sub-assessments are keyed by the
// assessed resource scope plus the assessment name, both of which the parent
// assessment already carries.
func (a *mqlAzureSubscriptionCloudDefenderServiceAssessment) subAssessments() ([]any, error) {
	scope := a.ResourceId.Data
	assessmentName := a.Name.Data
	if scope == "" || assessmentName == "" {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	clientFactory, err := armsecurity.NewClientFactory(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	client := clientFactory.NewSubAssessmentsClient()
	pager := client.NewListPager(scope, assessmentName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sub := range page.Value {
			if sub == nil {
				continue
			}
			var displayName, vulnerabilityId, status, severity, statusCause, statusDescription string
			var category, description, impact, remediation string
			var timeGenerated *time.Time
			resourceDetails := map[string]any{}
			additionalData := map[string]any{}
			if p := sub.Properties; p != nil {
				displayName = convert.ToValue(p.DisplayName)
				vulnerabilityId = convert.ToValue(p.ID)
				category = convert.ToValue(p.Category)
				description = convert.ToValue(p.Description)
				impact = convert.ToValue(p.Impact)
				remediation = convert.ToValue(p.Remediation)
				timeGenerated = p.TimeGenerated
				if s := p.Status; s != nil {
					if s.Code != nil {
						status = string(*s.Code)
					}
					if s.Severity != nil {
						severity = string(*s.Severity)
					}
					statusCause = convert.ToValue(s.Cause)
					statusDescription = convert.ToValue(s.Description)
				}
				if rd, err := convert.JsonToDict(p.ResourceDetails); err == nil {
					resourceDetails = rd
				}
				if ad, err := convert.JsonToDict(p.AdditionalData); err == nil {
					additionalData = ad
				}
			}
			mqlSub, err := CreateResource(a.MqlRuntime, "azure.subscription.cloudDefenderService.assessment.subAssessment",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(sub.ID),
					"name":              llx.StringDataPtr(sub.Name),
					"displayName":       llx.StringData(displayName),
					"vulnerabilityId":   llx.StringData(vulnerabilityId),
					"status":            llx.StringData(status),
					"severity":          llx.StringData(severity),
					"statusCause":       llx.StringData(statusCause),
					"statusDescription": llx.StringData(statusDescription),
					"category":          llx.StringData(category),
					"description":       llx.StringData(description),
					"impact":            llx.StringData(impact),
					"remediation":       llx.StringData(remediation),
					"timeGenerated":     llx.TimeDataPtr(timeGenerated),
					"resourceDetails":   llx.DictData(resourceDetails),
					"additionalData":    llx.DictData(additionalData),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSub)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceAssessmentSubAssessment) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicyInternal struct {
	cacheVirtualMachines []*armsecurity.JitNetworkAccessPolicyVirtualMachine
	cacheSystemData      any
}

func (a *mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicy) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// jitNetworkAccessPolicies lists the subscription's just-in-time VM access
// policies — the on-demand, time-bound alternative to leaving management ports
// open.
func (a *mqlAzureSubscriptionCloudDefenderService) jitNetworkAccessPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	clientFactory, err := armsecurity.NewClientFactory(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	client := clientFactory.NewJitNetworkAccessPoliciesClient()
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list JIT network access policies due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, pol := range page.Value {
			if pol == nil {
				continue
			}
			var provisioningState string
			if p := pol.Properties; p != nil {
				provisioningState = convert.ToValue(p.ProvisioningState)
			}
			mqlPol, err := CreateResource(a.MqlRuntime, "azure.subscription.cloudDefenderService.jitNetworkAccessPolicy",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(pol.ID),
					"name":              llx.StringDataPtr(pol.Name),
					"location":          llx.StringDataPtr(pol.Location),
					"kind":              llx.StringDataPtr(pol.Kind),
					"type":              llx.StringDataPtr(pol.Type),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			if p := pol.Properties; p != nil {
				mqlPol.(*mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicy).cacheVirtualMachines = p.VirtualMachines
			}
			sysData, err := convert.JsonToDict(pol.SystemData)
			if err != nil {
				return nil, err
			}
			mqlPol.(*mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicy).cacheSystemData = sysData
			res = append(res, mqlPol)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicy) virtualMachines() ([]any, error) {
	res := []any{}
	for _, vm := range a.cacheVirtualMachines {
		if vm == nil {
			continue
		}
		vmId := convert.ToValue(vm.ID)
		ports, err := convert.JsonToDictSlice(vm.Ports)
		if err != nil {
			return nil, err
		}
		// synthetic cache key: a VM can appear in only one policy, but key by
		// policy+VM so it stays unique across policies.
		vmKey := a.Id.Data + "/" + vmId
		portRules := []any{}
		for i, port := range vm.Ports {
			if port == nil {
				continue
			}
			prefixes := []any{}
			for _, p := range port.AllowedSourceAddressPrefixes {
				if p != nil {
					prefixes = append(prefixes, *p)
				}
			}
			// A port rule carries no identifier, so the port number keys it
			// within the VM; the position covers a rule that omits one.
			key := strconv.Itoa(i)
			if port.Number != nil {
				key = strconv.Itoa(int(*port.Number))
			}
			mqlRule, err := CreateResource(a.MqlRuntime, "azure.subscription.cloudDefenderService.jitNetworkAccessPolicy.virtualMachine.portRule",
				map[string]*llx.RawData{
					"__id":                         llx.StringData(subResourceCacheID(nil, vmKey, "portRules", key)),
					"number":                       llx.IntDataPtr(port.Number),
					"protocol":                     llx.StringDataPtr(stringEnumPtr(port.Protocol)),
					"maxRequestAccessDuration":     llx.StringDataPtr(port.MaxRequestAccessDuration),
					"allowedSourceAddressPrefix":   llx.StringDataPtr(port.AllowedSourceAddressPrefix),
					"allowedSourceAddressPrefixes": llx.ArrayData(prefixes, types.String),
				})
			if err != nil {
				return nil, err
			}
			portRules = append(portRules, mqlRule)
		}

		mqlVM, err := CreateResource(a.MqlRuntime, "azure.subscription.cloudDefenderService.jitNetworkAccessPolicy.virtualMachine",
			map[string]*llx.RawData{
				"__id":            llx.StringData(vmKey),
				"publicIpAddress": llx.StringData(convert.ToValue(vm.PublicIPAddress)),
				"ports":           llx.ArrayData(ports, types.Dict),
				"portRules":       llx.ArrayData(portRules, types.Resource("azure.subscription.cloudDefenderService.jitNetworkAccessPolicy.virtualMachine.portRule")),
			})
		if err != nil {
			return nil, err
		}
		mqlVM.(*mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicyVirtualMachine).cacheVmId = vmId
		res = append(res, mqlVM)
	}
	return res, nil
}

type mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicyVirtualMachineInternal struct {
	cacheVmId string
}

func (a *mqlAzureSubscriptionCloudDefenderServiceJitNetworkAccessPolicyVirtualMachine) vm() (*mqlAzureSubscriptionComputeServiceVm, error) {
	if a.cacheVmId == "" {
		a.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.computeService.vm", map[string]*llx.RawData{
		"id": llx.StringData(a.cacheVmId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionComputeServiceVm), nil
}

// alertSuppressionRules lists the subscription's alert suppression rules — the
// rules that auto-dismiss matching security alerts. A broad or non-expiring
// rule is a detection blind spot worth auditing.
func (a *mqlAzureSubscriptionCloudDefenderService) alertSuppressionRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := security.NewAlertsSuppressionRulesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list alert suppression rules due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			var alertType, state, reason, comment string
			var expirationDate, lastModified *time.Time
			suppressionScope := []any{}
			if p := rule.Properties; p != nil {
				alertType = convert.ToValue(p.AlertType)
				reason = convert.ToValue(p.Reason)
				comment = convert.ToValue(p.Comment)
				if p.State != nil {
					state = string(*p.State)
				}
				expirationDate = p.ExpirationDateUTC
				lastModified = p.LastModifiedUTC
				if p.SuppressionAlertsScope != nil {
					scope, err := convert.JsonToDictSlice(p.SuppressionAlertsScope.AllOf)
					if err != nil {
						return nil, err
					}
					suppressionScope = scope
				}
			}
			mqlRule, err := CreateResource(a.MqlRuntime, "azure.subscription.cloudDefenderService.alertSuppressionRule",
				map[string]*llx.RawData{
					"id":               llx.StringDataPtr(rule.ID),
					"name":             llx.StringDataPtr(rule.Name),
					"alertType":        llx.StringData(alertType),
					"state":            llx.StringData(state),
					"reason":           llx.StringData(reason),
					"comment":          llx.StringData(comment),
					"expirationDate":   llx.TimeDataPtr(expirationDate),
					"lastModified":     llx.TimeDataPtr(lastModified),
					"suppressionScope": llx.ArrayData(suppressionScope, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceAlertSuppressionRule) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionCloudDefenderServiceWorkspaceSettingInternal struct {
	cacheWorkspaceId string
}

// workspaceSettings lists the subscription's Defender workspace settings — the
// Log Analytics workspace each scope's security data is routed to.
func (a *mqlAzureSubscriptionCloudDefenderService) workspaceSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := security.NewWorkspaceSettingsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list workspace settings due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ws := range page.Value {
			if ws == nil {
				continue
			}
			var scope, workspaceId string
			if p := ws.Properties; p != nil {
				scope = convert.ToValue(p.Scope)
				workspaceId = convert.ToValue(p.WorkspaceID)
			}
			mqlWs, err := CreateResource(a.MqlRuntime, "azure.subscription.cloudDefenderService.workspaceSetting",
				map[string]*llx.RawData{
					"id":    llx.StringDataPtr(ws.ID),
					"name":  llx.StringDataPtr(ws.Name),
					"scope": llx.StringData(scope),
				})
			if err != nil {
				return nil, err
			}
			mqlWs.(*mqlAzureSubscriptionCloudDefenderServiceWorkspaceSetting).cacheWorkspaceId = workspaceId
			res = append(res, mqlWs)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceWorkspaceSetting) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceWorkspaceSetting) workspace() (*mqlAzureSubscriptionMonitorServiceWorkspace, error) {
	if a.cacheWorkspaceId == "" {
		a.Workspace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.monitorService.workspace", map[string]*llx.RawData{
		"id": llx.StringData(a.cacheWorkspaceId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionMonitorServiceWorkspace), nil
}

type mqlAzureSubscriptionCloudDefenderServiceApiCollectionInternal struct {
	cacheSystemData any
	subscriptionId  string
	discoveredViaId string
}

func (a *mqlAzureSubscriptionCloudDefenderServiceApiCollection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceApiCollection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCloudDefenderService) apiCollections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := armsecurity.NewAPICollectionsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// Defender for APIs may not be enabled on the subscription, which
			// surfaces as a 4xx; treat that as no collections rather than failing.
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode >= 400 && respErr.StatusCode < 500 {
				log.Warn().Err(err).Msg("could not list Defender for APIs collections")
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			var displayName, baseUrl, sensitivityLabel, discoveredViaId string
			var numEndpoints, numUnauth, numExternal, numSensitive, numInactive int64
			if p := c.Properties; p != nil {
				displayName = convert.ToValue(p.DisplayName)
				baseUrl = convert.ToValue(p.BaseURL)
				sensitivityLabel = convert.ToValue(p.SensitivityLabel)
				discoveredViaId = convert.ToValue(p.DiscoveredVia)
				numEndpoints = convert.ToValue(p.NumberOfAPIEndpoints)
				numUnauth = convert.ToValue(p.NumberOfUnauthenticatedAPIEndpoints)
				numExternal = convert.ToValue(p.NumberOfExternalAPIEndpoints)
				numSensitive = convert.ToValue(p.NumberOfAPIEndpointsWithSensitiveDataExposed)
				numInactive = convert.ToValue(p.NumberOfInactiveAPIEndpoints)
			}
			mqlColl, err := CreateResource(a.MqlRuntime, "azure.subscription.cloudDefenderService.apiCollection", map[string]*llx.RawData{
				"id":                                  llx.StringDataPtr(c.ID),
				"name":                                llx.StringDataPtr(c.Name),
				"displayName":                         llx.StringData(displayName),
				"baseUrl":                             llx.StringData(baseUrl),
				"sensitivityLabel":                    llx.StringData(sensitivityLabel),
				"numberOfApiEndpoints":                llx.IntData(numEndpoints),
				"numberOfUnauthenticatedApiEndpoints": llx.IntData(numUnauth),
				"numberOfExternalApiEndpoints":        llx.IntData(numExternal),
				"numberOfApiEndpointsWithSensitiveDataExposed": llx.IntData(numSensitive),
				"numberOfInactiveApiEndpoints":                 llx.IntData(numInactive),
			})
			if err != nil {
				return nil, err
			}
			coll := mqlColl.(*mqlAzureSubscriptionCloudDefenderServiceApiCollection)
			coll.subscriptionId = a.SubscriptionId.Data
			coll.discoveredViaId = discoveredViaId
			sysData, err := convert.JsonToDict(c.SystemData)
			if err != nil {
				return nil, err
			}
			coll.cacheSystemData = sysData
			res = append(res, mqlColl)
		}
	}
	return res, nil
}

// apiManagement resolves the APIM service the collection was discovered through
// by filtering the subscription's API Management services. Returns null when the
// collection was not discovered via a listable APIM service.
func (a *mqlAzureSubscriptionCloudDefenderServiceApiCollection) apiManagement() (*mqlAzureSubscriptionApiManagementServiceService, error) {
	if a.discoveredViaId == "" {
		a.ApiManagement.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ns, err := CreateResource(a.MqlRuntime, "azure.subscription.apiManagementService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.subscriptionId),
	})
	if err != nil {
		return nil, err
	}
	list := ns.(*mqlAzureSubscriptionApiManagementService).GetServices()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, x := range list.Data {
		svc, ok := x.(*mqlAzureSubscriptionApiManagementServiceService)
		if ok && strings.EqualFold(svc.Id.Data, a.discoveredViaId) {
			return svc, nil
		}
	}
	a.ApiManagement.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

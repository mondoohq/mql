// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"

	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
)

var majorVersionRegex = regexp.MustCompile(`^(\d+)`)

func isPlatformEol(platform string, version string) bool {
	if version == "" {
		return false
	}
	if platform != "node" {
		return false
	}
	m := majorVersionRegex.FindString(version)
	val, err := strconv.Atoi(m)
	if err != nil {
		log.Error().
			Err(err).
			Str("platform", platform).
			Str("version", version).
			Msg("could not parse the azure webapp version")
		return false
	}

	if val < 10 || val == 11 {
		return true
	}
	return false
}

type AzureWebAppStackRuntime struct {
	Name          string    `json:"name,omitempty"`
	ID            string    `json:"id,omitempty"`
	Os            string    `json:"os,omitempty"`
	MajorVersion  string    `json:"majorVersion,omitempty"`
	MinorVersion  string    `json:"minorVersion,omitempty"`
	IsDeprecated  bool      `json:"isDeprecated,omitempty"`
	IsHidden      bool      `json:"isHidden,omitempty"`
	AutoUpdate    bool      `json:"autoUpdate,omitempty"`
	EndOfLifeDate time.Time `json:"endOfLifeDate,omitempty"`
}

func createWebAppResourceFromSite(runtime *plugin.Runtime, resourceType string, site *web.Site) (any, error) {
	if site == nil {
		return nil, errors.New("site cannot be nil")
	}

	properties := map[string]any{}
	if site.Properties != nil {
		var err error
		properties, err = convert.JsonToDict(site.Properties)
		if err != nil {
			return nil, err
		}
	}

	identity := map[string]any{}
	if site.Identity != nil {
		var err error
		identity, err = convert.JsonToDict(site.Identity)
		if err != nil {
			return nil, err
		}
	}

	var userAssignedIdentityIds []string

	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(site.ID),
		"name":       llx.StringDataPtr(site.Name),
		"location":   llx.StringDataPtr(site.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(site.Tags), types.String),
		"type":       llx.StringDataPtr(site.Type),
		"kind":       llx.StringDataPtr(site.Kind),
		"properties": llx.DictData(properties),
	}

	siteIdentity := orZero(site.Identity)

	// Both resources keep the raw identity dict, deprecated in favour of the
	// flattened members. appsite has no tenantId field of its own: it resolves
	// the tenant through systemAssignedIdentity, off cacheIdentityTenantId.
	if resourceType == ResourceAzureSubscriptionWebServiceAppslot {
		args["identity"] = llx.DictData(identity)
		if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(siteIdentity.UserAssignedIdentities),
			identityType(siteIdentity.Type), identityPrincipalId(siteIdentity.PrincipalID), identityTenantId(siteIdentity.TenantID)); err != nil {
			return nil, err
		}
	}

	// Only set these fields for appsite, not appslot (which doesn't have them)
	if resourceType == ResourceAzureSubscriptionWebServiceAppsite && site.Properties != nil {
		args["httpsOnly"] = llx.BoolDataPtr(site.Properties.HTTPSOnly)
		args["clientCertEnabled"] = llx.BoolDataPtr(site.Properties.ClientCertEnabled)
		if site.Properties.ClientCertMode != nil {
			args["clientCertMode"] = llx.StringData(string(*site.Properties.ClientCertMode))
		}
		args["enabled"] = llx.BoolDataPtr(site.Properties.Enabled)
		args["state"] = llx.StringDataPtr(site.Properties.State)
		args["defaultHostName"] = llx.StringDataPtr(site.Properties.DefaultHostName)
		args["enabledHostNames"] = llx.ArrayData(strPtrsToAny(site.Properties.EnabledHostNames), types.String)
		args["endToEndEncryptionEnabled"] = llx.BoolDataPtr(site.Properties.EndToEndEncryptionEnabled)
		args["sshEnabled"] = llx.BoolDataPtr(site.Properties.SSHEnabled)
		args["keyVaultReferenceIdentity"] = llx.StringDataPtr(site.Properties.KeyVaultReferenceIdentity)
		args["publicNetworkAccess"] = llx.StringDataPtr(site.Properties.PublicNetworkAccess)
		args["virtualNetworkSubnetId"] = llx.StringDataPtr(site.Properties.VirtualNetworkSubnetID)
		if site.Properties.IPMode != nil {
			args["ipMode"] = llx.StringData(string(*site.Properties.IPMode))
		}
		if site.Properties.RedundancyMode != nil {
			args["redundancyMode"] = llx.StringData(string(*site.Properties.RedundancyMode))
		}
		var outboundVnetRoutingData *llx.RawData = llx.NilData
		if site.Properties.OutboundVnetRouting != nil && site.ID != nil {
			ovr := site.Properties.OutboundVnetRouting
			ovrRes, ovrErr := CreateResource(runtime, "azure.subscription.webService.appsite.outboundVnetRouting",
				map[string]*llx.RawData{
					"id":                          llx.StringData(*site.ID + "/outboundVnetRouting"),
					"allTrafficEnabled":           llx.BoolDataPtr(ovr.AllTraffic),
					"applicationTrafficEnabled":   llx.BoolDataPtr(ovr.ApplicationTraffic),
					"backupRestoreTrafficEnabled": llx.BoolDataPtr(ovr.BackupRestoreTraffic),
					"contentShareTrafficEnabled":  llx.BoolDataPtr(ovr.ContentShareTraffic),
					"imagePullTrafficEnabled":     llx.BoolDataPtr(ovr.ImagePullTraffic),
				})
			if ovrErr != nil {
				return nil, ovrErr
			}
			outboundVnetRoutingData = llx.ResourceData(ovrRes, "azure.subscription.webService.appsite.outboundVnetRouting")
		}
		args["outboundVnetRouting"] = outboundVnetRoutingData
		args["identityType"] = llx.StringDataPtr(stringEnumPtr(siteIdentity.Type))
		args["principalId"] = llx.StringDataPtr(siteIdentity.PrincipalID)
		userAssignedIdentityIds = sortedUserAssignedIdentityIDs(siteIdentity.UserAssignedIdentities)
	}

	res, err := CreateResource(runtime, resourceType, args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(site.SystemData)
	if err != nil {
		return nil, err
	}
	switch resourceType {
	case ResourceAzureSubscriptionWebServiceAppsite:
		mqlAppsite := res.(*mqlAzureSubscriptionWebServiceAppsite)
		mqlAppsite.cacheSystemData = sysData
		mqlAppsite.cacheUserAssignedIdentityIds = userAssignedIdentityIds
		if site.Identity != nil && site.Identity.TenantID != nil {
			mqlAppsite.cacheIdentityTenantId = *site.Identity.TenantID
		}
	case ResourceAzureSubscriptionWebServiceAppslot:
		mqlAppslot := res.(*mqlAzureSubscriptionWebServiceAppslot)
		mqlAppslot.cacheSystemData = sysData
	}
	return res, nil
}

type mqlAzureSubscriptionWebServiceAppsiteInternal struct {
	cacheSystemData              any
	cacheUserAssignedIdentityIds []string
	cacheIdentityTenantId        string
}

type mqlAzureSubscriptionWebServiceAppslotInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceAppslot) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionWebServiceFunctionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceFunction) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionWebServiceAppsiteconfigInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceAppsiteconfig) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionWebServiceHostingEnvironmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceHostingEnvironment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionWebServiceAppServicePlanInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceAppServicePlan) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionWebServiceCertificateInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceCertificate) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionWebServiceAppsiteHostNameBindingInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceAppsiteHostNameBinding) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionWebServiceAppsiteVirtualNetworkConnectionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionWebServiceAppsiteVirtualNetworkConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type runtimeStackDescriptor struct {
	Name         string
	MinorVersion string
	ID           string
	AutoUpdate   bool
	IsDeprecated bool
}

func runtimeStackDescriptorFromEntry(entry any) (*runtimeStackDescriptor, bool) {
	switch v := entry.(type) {
	case map[string]any:
		return runtimeStackDescriptorFromMap(v), true
	case *mqlAzureSubscriptionWebServiceAppRuntimeStack:
		return runtimeStackDescriptorFromResource(v), true
	default:
		return nil, false
	}
}

func runtimeStackDescriptorFromMap(values map[string]any) *runtimeStackDescriptor {
	descriptor := &runtimeStackDescriptor{}
	if values == nil {
		return descriptor
	}
	if name, ok := values["name"].(string); ok {
		descriptor.Name = strings.ToLower(name)
	}
	if minor, ok := values["minorVersion"].(string); ok {
		descriptor.MinorVersion = strings.ToLower(minor)
	}
	if id, ok := values["id"].(string); ok {
		descriptor.ID = id
	}
	if autoUpdate, ok := values["autoUpdate"].(bool); ok {
		descriptor.AutoUpdate = autoUpdate
	}
	if isDeprecated, ok := values["isDeprecated"].(bool); ok {
		descriptor.IsDeprecated = isDeprecated
	}
	return descriptor
}

func runtimeStackDescriptorFromResource(runtime *mqlAzureSubscriptionWebServiceAppRuntimeStack) *runtimeStackDescriptor {
	descriptor := &runtimeStackDescriptor{}
	if runtime == nil {
		return descriptor
	}
	if name, ok := stringFromTValue(&runtime.Name); ok {
		descriptor.Name = strings.ToLower(name)
	}
	if minor, ok := stringFromTValue(&runtime.MinorVersion); ok {
		descriptor.MinorVersion = strings.ToLower(minor)
	}
	// The ID is compared against the app's own runtime identifier, which is
	// either its LinuxFxVersion or "<STACK>|<version>" -- so it has to be the
	// stack's runtimeVersion ("NODE|18-lts"), not the resource's cache key. A
	// subscription-qualified key can never equal either shape, which left the
	// comparison dead and the whole match resting on name plus minor version.
	if id, ok := stringFromTValue(&runtime.RuntimeVersion); ok {
		descriptor.ID = id
	}
	if autoUpdate, ok := boolFromTValue(&runtime.AutoUpdate); ok {
		descriptor.AutoUpdate = autoUpdate
	}
	if isDeprecated, ok := boolFromTValue(&runtime.Deprecated); ok {
		descriptor.IsDeprecated = isDeprecated
	}
	return descriptor
}

func stringFromTValue(tv *plugin.TValue[string]) (string, bool) {
	if tv == nil || !tv.IsSet() || tv.IsNull() {
		return "", false
	}
	return tv.Data, true
}

func boolFromTValue(tv *plugin.TValue[bool]) (bool, bool) {
	if tv == nil || !tv.IsSet() || tv.IsNull() {
		return false, false
	}
	return tv.Data, true
}

func computeWebAppStack(runtime *plugin.Runtime, config *mqlAzureSubscriptionWebServiceAppsiteconfig, metadata any) (any, error) {
	if config == nil {
		return nil, errors.New("web app configuration is nil")
	}

	configProperties := config.Properties.Data

	data, err := json.Marshal(configProperties)
	if err != nil {
		return nil, err
	}

	var properties web.SiteConfig
	err = json.Unmarshal(data, &properties)
	if err != nil {
		return nil, err
	}

	runtimeInfo := AzureWebAppStackRuntime{
		Os: "windows",
	}

	if properties.LinuxFxVersion == nil && properties.WindowsFxVersion == nil {
		return nil, errors.New("could not determine stack version")
	}

	if properties.LinuxFxVersion != nil && len(*properties.LinuxFxVersion) > 0 {
		runtimeInfo.Os = "linux"
		runtimeInfo.ID = *properties.LinuxFxVersion

		fxversion := strings.Split(*properties.LinuxFxVersion, "|")
		runtimeInfo.Name = strings.ToLower(fxversion[0])
		// Some LinuxFxVersion values (e.g. a bare "DOCKER" or a custom image
		// string) have no "|version" suffix; only read it when present.
		if len(fxversion) > 1 {
			runtimeInfo.MinorVersion = strings.ToLower(fxversion[1])
		}
	} else {
		metadataMap, ok := metadata.(map[string]any)
		if !ok {
			return nil, nil
		}

		stack, ok := metadataMap["CURRENT_STACK"].(string)
		if !ok {
			return nil, nil
		}
		version := ""
		switch stack {
		case "dotnet":
			stack = "aspnet"
			version = convert.ToValue(properties.NetFrameworkVersion)
		case "dotnetcore":
			version = "3.1"
		case "php":
			version = convert.ToValue(properties.PhpVersion)
		case "python":
			version = convert.ToValue(properties.PythonVersion)
		case "node":
			version = convert.ToValue(properties.NodeVersion)
		case "powershell":
			version = convert.ToValue(properties.PowerShellVersion)
		case "java":
			version = convert.ToValue(properties.JavaVersion)
		case "javaContainer":
			version = convert.ToValue(properties.JavaContainerVersion)
		}

		runtimeInfo.Name = strings.ToLower(stack)
		runtimeInfo.ID = strings.ToUpper(stack) + "|" + version
		runtimeInfo.MinorVersion = version
	}

	obj, err := CreateResource(runtime, ResourceAzureSubscriptionWebService, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	azureWeb := obj.(*mqlAzureSubscriptionWebService)
	runtimesPlugin := azureWeb.GetAvailableRuntimes()
	if runtimesPlugin.Error != nil {
		return nil, runtimesPlugin.Error
	}

	runtimes := runtimesPlugin.Data
	var match *runtimeStackDescriptor

	for _, rt := range runtimes {
		descriptor, ok := runtimeStackDescriptorFromEntry(rt)
		if !ok || descriptor == nil {
			continue
		}
		sameStack := descriptor.Name != "" && strings.EqualFold(descriptor.Name, runtimeInfo.Name) &&
			strings.EqualFold(descriptor.MinorVersion, runtimeInfo.MinorVersion)
		sameID := descriptor.ID != "" && strings.EqualFold(descriptor.ID, runtimeInfo.ID)
		if sameStack || sameID {
			match = descriptor
		}
	}

	if match != nil {
		runtimeInfo.AutoUpdate = match.AutoUpdate
		runtimeInfo.IsDeprecated = match.IsDeprecated
	} else {
		if len(runtimeInfo.MinorVersion) > 0 {
			runtimeInfo.IsDeprecated = true
		}
	}

	return convert.JsonToDict(runtimeInfo)
}

func (a *mqlAzureSubscriptionWebService) id() (string, error) {
	return "azure.subscription.web/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionWebService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func initAzureSubscriptionWebServiceAppsite(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure app service app")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.webService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	webSvc := res.(*mqlAzureSubscriptionWebService)
	appList := webSvc.GetApps()
	if appList.Error != nil {
		return nil, nil, appList.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range appList.Data {
		app := entry.(*mqlAzureSubscriptionWebServiceAppsite)
		if app.Id.Data == id {
			return args, app, nil
		}
	}

	return nil, nil, errors.New("azure app service app does not exist")
}

func (a *mqlAzureSubscriptionWebServiceAppsite) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsiteauthsettings) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsiteauthsettingsv2) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsiteconfig) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsiteOutboundVnetRouting) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) diagnosticSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionWebServiceAppsite) diagnosticSettingsCategories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettingsCategories(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionWebServiceAppsite) slots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListSlotsPager(resourceID.ResourceGroup, site, &web.WebAppsClientListSlotsOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			slotResource, err := createWebAppResourceFromSite(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppslot, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, slotResource)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebService) apps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	client, err := web.NewWebAppsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(&web.WebAppsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			// Delegate to the shared builder so listed appsites carry the same
			// fields (defaultHostName, enabledHostNames, identityType, …) and
			// cached systemData as appsites reached via a slot's parent.
			mqlAzure, err := createWebAppResourceFromSite(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsite, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

// runtimeSettingsForPreferredOs picks the runtime settings matching a stack's
// preferred OS, and names that OS.
//
// The wire values are capitalized -- StackPreferredOsLinux is "Linux", not
// "linux" -- so comparing against lowercase literals matched neither arm, left
// the settings nil, and skipped every minor version of every stack. Comparing
// against the SDK constants is what keeps that from silently recurring.
func runtimeSettingsForPreferredOs(preferred *web.StackPreferredOs, settings *web.WebAppRuntimes) (*web.WebAppRuntimeSettings, string) {
	if preferred == nil || settings == nil {
		return nil, ""
	}
	switch *preferred {
	case web.StackPreferredOsLinux:
		return settings.LinuxRuntimeSettings, "linux"
	case web.StackPreferredOsWindows:
		return settings.WindowsRuntimeSettings, "windows"
	}
	return nil, ""
}

func (a *mqlAzureSubscriptionWebService) availableRuntimes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	client, err := web.NewProviderClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	mapIDs := map[string]struct{}{}
	pager := client.NewGetWebAppStacksPager(&web.ProviderClientGetWebAppStacksOptions{
		StackOsType: convert.ToPtr(web.ProviderStackOsTypeAll),
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			majorVersions := entry.Properties.MajorVersions
			stackName := convert.ToValue(entry.Name)
			for _, major := range majorVersions {
				majorText := convert.ToValue(major.DisplayText)
				for _, minor := range major.MinorVersions {
					minorText := convert.ToValue(minor.DisplayText)
					if minor.StackSettings == nil {
						log.Debug().
							Str("stack_name", stackName).
							Str("major_version", majorText).
							Str("minor_version", minorText).
							Msg("no stack settings, skipping")
						continue
					}

					settings, os := runtimeSettingsForPreferredOs(entry.Properties.PreferredOs, minor.StackSettings)

					if settings == nil {
						log.Debug().
							Str("stack_name", stackName).
							Str("major_version", majorText).
							Str("preferred_os", string(convert.ToValue(entry.Properties.PreferredOs))).
							Interface("stack_settings", minor.StackSettings).
							Msg("unknown runtime settings, skipping")
						continue
					}

					runtimeVersion := convert.ToValue(settings.RuntimeVersion)
					if runtimeVersion == "" {
						// some app runtimes like java doesn't return a runtime version, so we try
						// to build it like "stackName|minorVersion"
						runtimeVersion = strings.ToUpper(stackName + "|" + convert.ToValue(minor.Value))
					} else if stackName == "dotnet" {
						// dotnet doesn't format the runtime the same way like the rest of the runtimes
						// so we try to format it to match what the Azure portal shows
						dotNet := ".NET"
						if strings.Contains(convert.ToValue(major.Value), "asp") {
							dotNet = "ASP.NET"
						}
						runtimeVersion = strings.ToUpper(dotNet + "|" + convert.ToValue(minor.Value))
					}

					deprecated := convert.ToValue(settings.IsDeprecated) ||
						isPlatformEol(convert.ToValue(entry.Name), convert.ToValue(major.Value))

					id := strings.Join([]string{
						ResourceAzureSubscription, subId,
						"webService.appRuntimeStack", os, runtimeVersion,
					}, "/")

					if _, exist := mapIDs[id]; exist {
						continue
					}
					mapIDs[id] = struct{}{}

					resource, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppRuntimeStack,
						map[string]*llx.RawData{
							"__id":           llx.StringData(id),
							"name":           llx.StringData(stackName),
							"preferredOs":    llx.StringData(os),
							"runtimeVersion": llx.StringData(runtimeVersion),
							"deprecated":     llx.BoolData(deprecated),
							"autoUpdate":     llx.BoolDataPtr(settings.IsAutoUpdate),
							"hidden":         llx.BoolDataPtr(settings.IsHidden),
							"endOfLifeDate":  llx.TimeDataPtr(settings.EndOfLifeDate),
							"majorVersion":   llx.StringDataPtr(major.Value),
							"minorVersion":   llx.StringDataPtr(minor.Value),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, resource)
				}
			}
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionWebServiceAppsite) systemAssignedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return newSystemAssignedManagedIdentity(a.MqlRuntime, a.Id.Data, a.PrincipalId.Data, a.cacheIdentityTenantId, &a.SystemAssignedIdentity)
}

// keyVaultReferenceIdentityRef resolves the user-assigned managed identity used
// to fetch Key Vault references in app settings. When the app uses its
// system-assigned identity the raw value is "SystemAssigned" (not a resource
// ID), so the reference is null.
func (a *mqlAzureSubscriptionWebServiceAppsite) keyVaultReferenceIdentityRef() (*mqlAzureSubscriptionManagedIdentity, error) {
	id := a.KeyVaultReferenceIdentity.Data
	if id == "" || strings.EqualFold(id, "SystemAssigned") {
		a.KeyVaultReferenceIdentityRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) virtualNetworkSubnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.VirtualNetworkSubnetId.Data == "" {
		a.VirtualNetworkSubnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringData(a.VirtualNetworkSubnetId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) configuration() (*mqlAzureSubscriptionWebServiceAppsiteconfig, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return webAppSiteConfigToMql(a.MqlRuntime, conn, a.Id.Data)
}

// webAppSiteConfigToMql fetches the site configuration for an App Service site
// (regular web app or function app) and maps it to an appsiteconfig resource.
// siteConfigCorsAllowedOrigins returns the CORS allowed origins configured on
// an App Service site configuration. It is always non-nil so the typed
// corsAllowedOrigins field is set on every code path that builds an
// appsiteconfig resource (the value stays an empty list when CORS is not
// configured).
func siteConfigCorsAllowedOrigins(props *web.SiteConfig) []any {
	origins := []any{}
	if props != nil && props.Cors != nil {
		origins = strPtrsToAny(props.Cors.AllowedOrigins)
	}
	return origins
}

// addSiteConfigArgs sets the typed appsiteconfig fields read from the site
// configuration. Every field is set on every path, to null when Azure omits it
// (an app that never configured a cipher suite has no minTlsCipherSuite) or
// when the response has no properties at all. A field left out of the args is
// never set on the resource, and reading it then returns neither data nor
// error.
func addSiteConfigArgs(args map[string]*llx.RawData, props *web.SiteConfig) {
	if props == nil {
		props = &web.SiteConfig{}
	}
	args["minTlsVersion"] = llx.StringDataPtr(stringEnumPtr(props.MinTLSVersion))
	args["ftpsState"] = llx.StringDataPtr(stringEnumPtr(props.FtpsState))
	args["remoteDebuggingEnabled"] = llx.BoolDataPtr(props.RemoteDebuggingEnabled)
	args["http20Enabled"] = llx.BoolDataPtr(props.Http20Enabled)
	args["alwaysOn"] = llx.BoolDataPtr(props.AlwaysOn)
	args["webSocketsEnabled"] = llx.BoolDataPtr(props.WebSocketsEnabled)
	args["httpLoggingEnabled"] = llx.BoolDataPtr(props.HTTPLoggingEnabled)
	args["detailedErrorLoggingEnabled"] = llx.BoolDataPtr(props.DetailedErrorLoggingEnabled)
	args["autoHealEnabled"] = llx.BoolDataPtr(props.AutoHealEnabled)
	args["minTlsCipherSuite"] = llx.StringDataPtr(stringEnumPtr(props.MinTLSCipherSuite))
	args["scmMinTlsVersion"] = llx.StringDataPtr(stringEnumPtr(props.ScmMinTLSVersion))
}

func webAppSiteConfigToMql(runtime *plugin.Runtime, conn *connection.AzureConnection, id string) (*mqlAzureSubscriptionWebServiceAppsiteconfig, error) {
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	configuration, err := client.GetConfiguration(ctx, resourceID.ResourceGroup, site, &web.WebAppsClientGetConfigurationOptions{})
	if err != nil {
		return nil, err
	}

	entry := configuration
	properties, err := convert.JsonToDict(entry.Properties)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                 llx.StringDataPtr(entry.ID),
		"name":               llx.StringDataPtr(entry.Name),
		"kind":               llx.StringDataPtr(entry.Kind),
		"type":               llx.StringDataPtr(entry.Type),
		"properties":         llx.DictData(properties),
		"corsAllowedOrigins": llx.ArrayData(siteConfigCorsAllowedOrigins(entry.Properties), types.String),
	}

	addSiteConfigArgs(args, entry.Properties)

	res, err := CreateResource(runtime, ResourceAzureSubscriptionWebServiceAppsiteconfig, args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(entry.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionWebServiceAppsiteconfig).cacheSystemData = sysData

	return res.(*mqlAzureSubscriptionWebServiceAppsiteconfig), nil
}

func ipSecurityRestrictionsToMql(runtime *plugin.Runtime, configId string, restrictions []any) ([]any, error) {
	res := []any{}
	for i, r := range restrictions {
		ruleMap, ok := r.(map[string]any)
		if !ok {
			continue
		}

		id := fmt.Sprintf("%s/ipSecurityRestrictions/%d", configId, i)
		name, _ := ruleMap["name"].(string)
		description, _ := ruleMap["description"].(string)
		action, _ := ruleMap["action"].(string)
		ipAddress, _ := ruleMap["ipAddress"].(string)
		tag, _ := ruleMap["tag"].(string)
		vnetSubnetResourceId, _ := ruleMap["vnetSubnetResourceId"].(string)
		subnetMask, _ := ruleMap["subnetMask"].(string)

		var priority int64
		switch p := ruleMap["priority"].(type) {
		case float64:
			priority = int64(p)
		case int64:
			priority = p
		}

		headers, _ := convert.JsonToDict(ruleMap["headers"])

		mqlRule, err := CreateResource(runtime, "azure.subscription.webService.appsiteconfig.ipSecurityRestriction",
			map[string]*llx.RawData{
				"id":                   llx.StringData(id),
				"name":                 llx.StringData(name),
				"description":          llx.StringData(description),
				"action":               llx.StringData(action),
				"ipAddress":            llx.StringData(ipAddress),
				"priority":             llx.IntData(priority),
				"tag":                  llx.StringData(tag),
				"vnetSubnetResourceId": llx.StringData(vnetSubnetResourceId),
				"subnetMask":           llx.StringData(subnetMask),
				"headers":              llx.DictData(headers),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func extractIPRestrictions(propsData any, field string) []any {
	if propsData == nil {
		return nil
	}
	propsDict, ok := propsData.(map[string]any)
	if !ok {
		return nil
	}
	restrictions, ok := propsDict[field]
	if !ok || restrictions == nil {
		return nil
	}
	arr, ok := restrictions.([]any)
	if !ok {
		return nil
	}
	return arr
}

func (a *mqlAzureSubscriptionWebServiceAppsiteconfig) ipSecurityRestrictions() ([]any, error) {
	restrictions := extractIPRestrictions(a.Properties.Data, "ipSecurityRestrictions")
	if restrictions == nil {
		return []any{}, nil
	}
	return ipSecurityRestrictionsToMql(a.MqlRuntime, a.Id.Data, restrictions)
}

func (a *mqlAzureSubscriptionWebServiceAppsiteconfig) scmIpSecurityRestrictions() ([]any, error) {
	restrictions := extractIPRestrictions(a.Properties.Data, "scmIpSecurityRestrictions")
	if restrictions == nil {
		return []any{}, nil
	}
	return ipSecurityRestrictionsToMql(a.MqlRuntime, a.Id.Data+"/scm", restrictions)
}

func (a *mqlAzureSubscriptionWebServiceAppsiteconfig) ipSecurityRestrictionsDefaultAction() (string, error) {
	props := a.Properties.Data
	if props == nil {
		return "", nil
	}
	propsDict, ok := props.(map[string]any)
	if !ok {
		return "", nil
	}
	val, ok := propsDict["ipSecurityRestrictionsDefaultAction"]
	if !ok || val == nil {
		return "", nil
	}
	s, ok := val.(string)
	if !ok {
		return "", nil
	}
	return s, nil
}

// redactedAuthSettings copies legacy (V1) Easy Auth settings with the six
// identity-provider client secrets removed.
//
// GetAuthSettings is the `/config/authsettings/list` action, which is Azure's
// convention for the form that returns secret values -- the V2 sibling has a
// separate GetAuthSettingsV2WithoutSecrets precisely because the /list form
// does not redact. Everything else about the configuration is kept, so
// enabled, unauthenticatedClientAction, the allowed audiences and the provider
// client IDs still read as before.
//
// The V2 path is already clean: SiteAuthSettingsV2Properties carries only
// clientSecretSettingName and a certificate thumbprint, never a value.
//
// The copy is by field rather than by JSON key so a secret field renamed in a
// future SDK breaks the build instead of silently leaking again.
func redactedAuthSettings(props *web.SiteAuthSettingsProperties) *web.SiteAuthSettingsProperties {
	if props == nil {
		return nil
	}
	safe := *props
	safe.ClientSecret = nil
	safe.FacebookAppSecret = nil
	safe.GitHubClientSecret = nil
	safe.GoogleClientSecret = nil
	safe.MicrosoftAccountClientSecret = nil
	safe.TwitterConsumerSecret = nil
	return &safe
}

func (a *mqlAzureSubscriptionWebServiceAppsite) authenticationSettings() (*mqlAzureSubscriptionWebServiceAppsiteauthsettings, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	configuration, err := client.GetAuthSettings(ctx, resourceID.ResourceGroup, site, &web.WebAppsClientGetAuthSettingsOptions{})
	if err != nil {
		return nil, err
	}
	properties, err := convert.JsonToDict(redactedAuthSettings(configuration.Properties))
	if err != nil {
		return nil, err
	}

	var enabled *bool
	var unauthenticatedClientAction *string
	if configuration.Properties != nil {
		enabled = configuration.Properties.Enabled
		unauthenticatedClientAction = (*string)(configuration.Properties.UnauthenticatedClientAction)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteauthsettings,
		map[string]*llx.RawData{
			"id":                          llx.StringDataPtr(configuration.ID),
			"name":                        llx.StringDataPtr(configuration.Name),
			"kind":                        llx.StringDataPtr(configuration.Kind),
			"type":                        llx.StringDataPtr(configuration.Type),
			"properties":                  llx.DictData(properties),
			"enabled":                     llx.BoolDataPtr(enabled),
			"unauthenticatedClientAction": llx.StringDataPtr(unauthenticatedClientAction),
		})
	if err != nil {
		return nil, err
	}

	return res.(*mqlAzureSubscriptionWebServiceAppsiteauthsettings), nil
}

// authSettingsV2Args maps a V2 auth settings response onto the MQL resource
// arguments, flattening the nested configuration groups that carry the
// security-relevant answers.
//
// Every level of the V2 shape is a nullable pointer, and an absent group is
// indistinguishable at the wire from one whose values are off, so each read is
// guarded and an absent group leaves its fields at the safe reading: not
// required, not enabled, nothing allowed.
//
// The booleans are deliberately reported as false rather than null when the
// group carrying them is absent. Null is not a neutral answer in MQL: `null &&
// null` evaluates to true, so a policy asserting `requireAuthentication &&
// requireHttps` would PASS on an app whose auth configuration was never
// written. False is also the safe direction on its own terms -- it can
// overstate a weakness, never a protection.
func authSettingsV2Args(settings web.SiteAuthSettingsV2, properties any) map[string]*llx.RawData {
	var (
		enabled                     *bool
		runtimeVersion              *string
		requireAuthentication       *bool
		unauthenticatedClientAction *string
		redirectToProvider          *string
		requireHTTPS                *bool
		tokenStoreEnabled           *bool
		aadEnabled                  *bool
		excludedPaths               []any
		allowedApplications         []any
		allowedAudiences            []any
	)

	if props := settings.Properties; props != nil {
		if platform := props.Platform; platform != nil {
			enabled = platform.Enabled
			runtimeVersion = platform.RuntimeVersion
		}
		if gv := props.GlobalValidation; gv != nil {
			requireAuthentication = gv.RequireAuthentication
			unauthenticatedClientAction = (*string)(gv.UnauthenticatedClientAction)
			redirectToProvider = gv.RedirectToProvider
			excludedPaths = strPtrSliceToAny(gv.ExcludedPaths)
		}
		if http := props.HTTPSettings; http != nil {
			requireHTTPS = http.RequireHTTPS
		}
		if login := props.Login; login != nil && login.TokenStore != nil {
			tokenStoreEnabled = login.TokenStore.Enabled
		}
		if idp := props.IdentityProviders; idp != nil && idp.AzureActiveDirectory != nil {
			aad := idp.AzureActiveDirectory
			aadEnabled = aad.Enabled
			if v := aad.Validation; v != nil {
				allowedAudiences = strPtrSliceToAny(v.AllowedAudiences)
				if p := v.DefaultAuthorizationPolicy; p != nil {
					allowedApplications = strPtrSliceToAny(p.AllowedApplications)
				}
			}
		}
	}

	return map[string]*llx.RawData{
		"__id":                        llx.StringDataPtr(settings.ID),
		"id":                          llx.StringDataPtr(settings.ID),
		"name":                        llx.StringDataPtr(settings.Name),
		"kind":                        llx.StringDataPtr(settings.Kind),
		"type":                        llx.StringDataPtr(settings.Type),
		"properties":                  llx.DictData(properties),
		"enabled":                     llx.BoolData(convert.ToValue(enabled)),
		"runtimeVersion":              llx.StringData(convert.ToValue(runtimeVersion)),
		"requireAuthentication":       llx.BoolData(convert.ToValue(requireAuthentication)),
		"unauthenticatedClientAction": llx.StringData(convert.ToValue(unauthenticatedClientAction)),
		"excludedPaths":               llx.ArrayData(excludedPaths, types.String),
		"redirectToProvider":          llx.StringData(convert.ToValue(redirectToProvider)),
		"requireHttps":                llx.BoolData(convert.ToValue(requireHTTPS)),
		"tokenStoreEnabled":           llx.BoolData(convert.ToValue(tokenStoreEnabled)),
		"azureActiveDirectoryEnabled": llx.BoolData(convert.ToValue(aadEnabled)),
		"allowedApplications":         llx.ArrayData(allowedApplications, types.String),
		"allowedAudiences":            llx.ArrayData(allowedAudiences, types.String),
	}
}

// authSettingsV2 reads App Service Authentication in its V2 form.
//
// authenticationSettings reads the V1 endpoint, and the two configurations are
// stored separately: an app set up with Easy Auth V2 -- which is what the Azure
// portal writes today -- reports V1 enabled false. So an authenticated app was
// reported as unauthenticated, and was indistinguishable from an app with no
// authentication configured at all.
//
// A credential that cannot read the configuration (403) or an app with no V2
// configuration (404) yields null rather than failing the query.
func (a *mqlAzureSubscriptionWebServiceAppsite) authSettingsV2() (*mqlAzureSubscriptionWebServiceAppsiteauthsettingsv2, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	settings, err := client.GetAuthSettingsV2(ctx, resourceID.ResourceGroup, site, &web.WebAppsClientGetAuthSettingsV2Options{})
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusForbidden || respErr.StatusCode == http.StatusNotFound) {
			log.Warn().Err(err).Str("site", a.Id.Data).Msg("could not read app service auth settings v2")
			a.AuthSettingsV2.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	properties, err := convert.JsonToDict(settings.Properties)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(a.MqlRuntime, "azure.subscription.webService.appsiteauthsettingsv2",
		authSettingsV2Args(settings.SiteAuthSettingsV2, properties))
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionWebServiceAppsiteauthsettingsv2), nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) metadata() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	metadata, err := client.ListMetadata(ctx, resourceID.ResourceGroup, site, &web.WebAppsClientListMetadataOptions{})
	if err != nil {
		return nil, err
	}

	res := make(map[string]any)

	for k := range metadata.Properties {
		res[k] = convert.ToValue(metadata.Properties[k])
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) ftp() (*mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	response, err := client.GetFtpAllowed(ctx, resourceID.ResourceGroup, site, nil)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":   llx.StringDataPtr(response.ID),
		"name": llx.StringDataPtr(response.Name),
		"type": llx.StringDataPtr(response.Type),
	}
	if response.Properties != nil {
		args["allow"] = llx.BoolDataPtr(response.Properties.Allow)
	}
	mqlResource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies, args)
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies), nil
}

func (a *mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies) id() (string, error) {
	return fmt.Sprintf("%s/%s", a.Id.Data, a.Name.Data), nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) scm() (*mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	response, err := client.GetScmAllowed(ctx, resourceID.ResourceGroup, site, nil)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":   llx.StringDataPtr(response.ID),
		"name": llx.StringDataPtr(response.Name),
		"type": llx.StringDataPtr(response.Type),
	}
	if response.Properties != nil {
		args["allow"] = llx.BoolDataPtr(response.Properties.Allow)
	}
	mqlResource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies, args)
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies), nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) functions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	pager := client.NewListFunctionsPager(resourceID.ResourceGroup, site, &web.WebAppsClientListFunctionsOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			props, err := convert.JsonToDict(entry.Properties)
			if err != nil {
				return nil, err
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceFunction,
				map[string]*llx.RawData{
					"id":         llx.StringDataPtr(entry.ID),
					"name":       llx.StringDataPtr(entry.Name),
					"type":       llx.StringDataPtr(entry.Type),
					"kind":       llx.StringDataPtr(entry.Kind),
					"properties": llx.AnyData(props),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(entry.SystemData)
			if err != nil {
				return nil, err
			}
			mqlAzure.(*mqlAzureSubscriptionWebServiceFunction).cacheSystemData = sysData
			res = append(res, mqlAzure)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) webAppsClient() (*connection.AzureConnection, context.Context, *ResourceID, *web.WebAppsClient, string, string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, nil, nil, nil, "", "", err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, nil, nil, nil, "", "", err
	}

	slot, err := resourceID.Component("slots")
	if err != nil {
		return nil, nil, nil, nil, "", "", err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, nil, nil, "", "", err
	}

	return conn, ctx, resourceID, client, site, slot, nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) diagnosticSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionWebServiceAppslot) diagnosticSettingsCategories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettingsCategories(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionWebServiceAppslot) parent() (*mqlAzureSubscriptionWebServiceAppsite, error) {
	_, ctx, resourceID, client, site, _, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	response, err := client.Get(ctx, resourceID.ResourceGroup, site, &web.WebAppsClientGetOptions{})
	if err != nil {
		return nil, err
	}

	parentResource, err := createWebAppResourceFromSite(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsite, &response.Site)
	if err != nil {
		return nil, err
	}

	return parentResource.(*mqlAzureSubscriptionWebServiceAppsite), nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) configuration() (*mqlAzureSubscriptionWebServiceAppsiteconfig, error) {
	_, ctx, resourceID, client, site, slot, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	configuration, err := client.GetConfigurationSlot(ctx, resourceID.ResourceGroup, site, slot, &web.WebAppsClientGetConfigurationSlotOptions{})
	if err != nil {
		return nil, err
	}

	properties := map[string]any{}
	if configuration.Properties != nil {
		props, err := convert.JsonToDict(configuration.Properties)
		if err != nil {
			return nil, err
		}
		properties = props
	}

	args := map[string]*llx.RawData{
		"id":                 llx.StringDataPtr(configuration.ID),
		"name":               llx.StringDataPtr(configuration.Name),
		"kind":               llx.StringDataPtr(configuration.Kind),
		"type":               llx.StringDataPtr(configuration.Type),
		"properties":         llx.DictData(properties),
		"corsAllowedOrigins": llx.ArrayData(siteConfigCorsAllowedOrigins(configuration.Properties), types.String),
	}

	addSiteConfigArgs(args, configuration.Properties)

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteconfig, args)
	if err != nil {
		return nil, err
	}

	return res.(*mqlAzureSubscriptionWebServiceAppsiteconfig), nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) authenticationSettings() (*mqlAzureSubscriptionWebServiceAppsiteauthsettings, error) {
	_, ctx, resourceID, client, site, slot, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	configuration, err := client.GetAuthSettingsSlot(ctx, resourceID.ResourceGroup, site, slot, &web.WebAppsClientGetAuthSettingsSlotOptions{})
	if err != nil {
		return nil, err
	}

	properties := map[string]any{}
	var enabled *bool
	var unauthenticatedClientAction *string
	if configuration.Properties != nil {
		props, err := convert.JsonToDict(configuration.Properties)
		if err != nil {
			return nil, err
		}
		properties = props
		enabled = configuration.Properties.Enabled
		unauthenticatedClientAction = (*string)(configuration.Properties.UnauthenticatedClientAction)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteauthsettings,
		map[string]*llx.RawData{
			"id":                          llx.StringDataPtr(configuration.ID),
			"name":                        llx.StringDataPtr(configuration.Name),
			"kind":                        llx.StringDataPtr(configuration.Kind),
			"type":                        llx.StringDataPtr(configuration.Type),
			"properties":                  llx.DictData(properties),
			"enabled":                     llx.BoolDataPtr(enabled),
			"unauthenticatedClientAction": llx.StringDataPtr(unauthenticatedClientAction),
		})
	if err != nil {
		return nil, err
	}

	return res.(*mqlAzureSubscriptionWebServiceAppsiteauthsettings), nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) metadata() (any, error) {
	_, ctx, resourceID, client, site, slot, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	metadata, err := client.ListMetadataSlot(ctx, resourceID.ResourceGroup, site, slot, &web.WebAppsClientListMetadataSlotOptions{})
	if err != nil {
		return nil, err
	}

	res := make(map[string]any)

	for k := range metadata.Properties {
		res[k] = convert.ToValue(metadata.Properties[k])
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) applicationSettings() (any, error) {
	_, ctx, resourceID, client, site, slot, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	settings, err := client.ListApplicationSettingsSlot(ctx, resourceID.ResourceGroup, site, slot, &web.WebAppsClientListApplicationSettingsSlotOptions{})
	if err != nil {
		return nil, err
	}

	res := make(map[string]any)

	for k := range settings.Properties {
		res[k] = convert.ToValue(settings.Properties[k])
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) connectionSettings() (any, error) {
	_, ctx, resourceID, client, site, slot, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	settings, err := client.ListConnectionStringsSlot(ctx, resourceID.ResourceGroup, site, slot, &web.WebAppsClientListConnectionStringsSlotOptions{})
	if err != nil {
		return nil, err
	}

	res := make(map[string]any)

	for k := range settings.Properties {
		value, err := convert.JsonToDict(settings.Properties[k])
		if err != nil {
			return nil, err
		}

		res[k] = value
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) stack() (any, error) {
	configPlugin := a.GetConfiguration()
	if configPlugin.Error != nil {
		return nil, configPlugin.Error
	}
	config := configPlugin.Data

	metadataPlugin := a.GetMetadata()
	if metadataPlugin.Error != nil {
		return nil, metadataPlugin.Error
	}
	metadata := metadataPlugin.Data

	return computeWebAppStack(a.MqlRuntime, config, metadata)
}

func (a *mqlAzureSubscriptionWebServiceAppslot) functions() ([]any, error) {
	_, ctx, resourceID, client, site, slot, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	pager := client.NewListInstanceFunctionsSlotPager(resourceID.ResourceGroup, site, slot, &web.WebAppsClientListInstanceFunctionsSlotOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			props, err := convert.JsonToDict(entry.Properties)
			if err != nil {
				return nil, err
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceFunction,
				map[string]*llx.RawData{
					"id":         llx.StringDataPtr(entry.ID),
					"name":       llx.StringDataPtr(entry.Name),
					"type":       llx.StringDataPtr(entry.Type),
					"kind":       llx.StringDataPtr(entry.Kind),
					"properties": llx.AnyData(props),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(entry.SystemData)
			if err != nil {
				return nil, err
			}
			mqlAzure.(*mqlAzureSubscriptionWebServiceFunction).cacheSystemData = sysData
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) ftp() (*mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies, error) {
	_, ctx, resourceID, client, site, slot, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	response, err := client.GetFtpAllowedSlot(ctx, resourceID.ResourceGroup, site, slot, &web.WebAppsClientGetFtpAllowedSlotOptions{})
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":   llx.StringDataPtr(response.ID),
		"name": llx.StringDataPtr(response.Name),
		"type": llx.StringDataPtr(response.Type),
	}
	if response.Properties != nil {
		args["allow"] = llx.BoolDataPtr(response.Properties.Allow)
	}

	mqlResource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies, args)
	if err != nil {
		return nil, err
	}

	return mqlResource.(*mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies), nil
}

func (a *mqlAzureSubscriptionWebServiceAppslot) scm() (*mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies, error) {
	_, ctx, resourceID, client, site, slot, err := a.webAppsClient()
	if err != nil {
		return nil, err
	}

	response, err := client.GetScmAllowedSlot(ctx, resourceID.ResourceGroup, site, slot, &web.WebAppsClientGetScmAllowedSlotOptions{})
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":   llx.StringDataPtr(response.ID),
		"name": llx.StringDataPtr(response.Name),
		"type": llx.StringDataPtr(response.Type),
	}
	if response.Properties != nil {
		args["allow"] = llx.BoolDataPtr(response.Properties.Allow)
	}

	mqlResource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies, args)
	if err != nil {
		return nil, err
	}

	return mqlResource.(*mqlAzureSubscriptionWebServiceAppsiteBasicPublishingCredentialsPolicies), nil
}

func (a *mqlAzureSubscriptionWebServiceFunction) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) connectionSettings() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	settings, err := client.ListConnectionStrings(ctx, resourceID.ResourceGroup, site, &web.WebAppsClientListConnectionStringsOptions{})
	if err != nil {
		return nil, err
	}

	res := make(map[string]any)

	for k := range settings.Properties {
		value, err := convert.JsonToDict(settings.Properties[k])
		if err != nil {
			return nil, err
		}

		res[k] = value
	}

	return res, nil
}

// TODO: check here if we can use cached stuff (and how)
func (a *mqlAzureSubscriptionWebServiceAppsite) stack() (any, error) {
	configPlugin := a.GetConfiguration()
	if configPlugin.Error != nil {
		return nil, configPlugin.Error
	}
	config := configPlugin.Data

	metadataPlugin := a.GetMetadata()
	if metadataPlugin.Error != nil {
		return nil, metadataPlugin.Error
	}
	metadata := metadataPlugin.Data

	return computeWebAppStack(a.MqlRuntime, config, metadata)
}

func (a *mqlAzureSubscriptionWebServiceAppsite) applicationSettings() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	settings, err := client.ListApplicationSettings(ctx, resourceID.ResourceGroup, site, &web.WebAppsClientListApplicationSettingsOptions{})
	if err != nil {
		return nil, err
	}

	res := make(map[string]any)

	for k := range settings.Properties {
		res[k] = convert.ToValue(settings.Properties[k])
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) privateEndpointConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewGetPrivateEndpointConnectionListPager(resourceID.ResourceGroup, site, &web.WebAppsClientGetPrivateEndpointConnectionListOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}

			// A connection with no ARM ID has no stable cache key; skip it
			// rather than letting ID-less entries collide on an empty __id.
			if entry.ID == nil || *entry.ID == "" {
				continue
			}
			var pecPrivateEndpointID string
			privateEndpoint := map[string]*llx.RawData{
				"__id":        llx.StringDataPtr(entry.ID),
				"id":          llx.StringDataPtr(entry.ID),
				"name":        llx.StringDataPtr(entry.Name),
				"type":        llx.StringDataPtr(entry.Type),
				"ipAddresses": llx.ArrayData([]any{}, types.String),
			}

			if entry.Properties != nil {
				props := entry.Properties
				propsMap, err := convert.JsonToDict(props)
				if err != nil {
					return nil, err
				}

				privateEndpoint["properties"] = llx.DictData(propsMap)

				privateEndpoint["ipAddresses"] = llx.ArrayData(strPtrsToAny(props.IPAddresses), types.String)
				if props.PrivateEndpoint != nil {
					pecPrivateEndpointID = convert.ToValue(props.PrivateEndpoint.ID)
				}
				if props.PrivateLinkServiceConnectionState != nil {
					stateRes, err := newPrivateLinkServiceConnectionState(a.MqlRuntime, convert.ToValue(entry.ID),
						props.PrivateLinkServiceConnectionState.ActionsRequired,
						props.PrivateLinkServiceConnectionState.Description,
						props.PrivateLinkServiceConnectionState.Status)
					if err != nil {
						return nil, err
					}
					privateEndpoint["privateLinkServiceConnectionState"] = llx.ResourceData(stateRes, ResourceAzureSubscriptionPrivateEndpointConnectionConnectionState)
				}
				if props.ProvisioningState != nil {
					privateEndpoint["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
				}
			}

			mqlRes, err := newAzurePrivateEndpointConnection(a.MqlRuntime, privateEndpoint, pecPrivateEndpointID)
			if err != nil {
				return nil, err
			}

			res = append(res, mqlRes)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppServicePlan) id() (string, error) {
	return a.Id.Data, nil
}

// appServicePlanSkuToMql maps an ARM SKUDescription onto the plan's SKU
// resource, including the capability flags and the scale range Azure reports
// alongside the billable members.
//
// ARM omits SKUCapacity for SKUs that are not scale-eligible, so capacityLimits
// reads null there rather than reporting a plan that cannot scale as one whose
// limits are zero.
func appServicePlanSkuToMql(runtime *plugin.Runtime, planID string, sku *web.SKUDescription) (*llx.RawData, error) {
	if sku == nil {
		return llx.NilData, nil
	}
	const resourceName = "azure.subscription.webService.appServicePlan.skuDescription"

	capabilities := []any{}
	for _, capability := range sku.Capabilities {
		if capability == nil {
			continue
		}
		mqlCapability, err := CreateResource(runtime, "azure.subscription.webService.appServicePlan.skuCapability",
			map[string]*llx.RawData{
				"__id":   llx.StringData(subResourceCacheID(nil, planID, "skuCapabilities", convert.ToValue(capability.Name))),
				"name":   llx.StringDataPtr(capability.Name),
				"value":  llx.StringDataPtr(capability.Value),
				"reason": llx.StringDataPtr(capability.Reason),
			})
		if err != nil {
			return nil, err
		}
		capabilities = append(capabilities, mqlCapability)
	}

	capacityLimits := llx.NilData
	if sku.SKUCapacity != nil {
		mqlLimits, err := CreateResource(runtime, "azure.subscription.webService.appServicePlan.skuCapacityLimits",
			map[string]*llx.RawData{
				"__id":                   llx.StringData(planID + "/skuCapacityLimits"),
				"defaultCapacity":        llx.IntDataPtr(sku.SKUCapacity.Default),
				"minimumCapacity":        llx.IntDataPtr(sku.SKUCapacity.Minimum),
				"maximumCapacity":        llx.IntDataPtr(sku.SKUCapacity.Maximum),
				"elasticMaximumCapacity": llx.IntDataPtr(sku.SKUCapacity.ElasticMaximum),
				"scaleType":              llx.StringDataPtr(sku.SKUCapacity.ScaleType),
			})
		if err != nil {
			return nil, err
		}
		capacityLimits = llx.ResourceData(mqlLimits, "azure.subscription.webService.appServicePlan.skuCapacityLimits")
	}

	res, err := CreateResource(runtime, resourceName, map[string]*llx.RawData{
		"__id":           llx.StringData(planID + "/sku"),
		"name":           llx.StringDataPtr(sku.Name),
		"tier":           llx.StringDataPtr(sku.Tier),
		"size":           llx.StringDataPtr(sku.Size),
		"family":         llx.StringDataPtr(sku.Family),
		"capacity":       llx.IntDataPtr(sku.Capacity),
		"locations":      llx.ArrayData(strPtrsToAny(sku.Locations), types.String),
		"capabilities":   llx.ArrayData(capabilities, types.Resource("azure.subscription.webService.appServicePlan.skuCapability")),
		"capacityLimits": capacityLimits,
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, resourceName), nil
}

func (a *mqlAzureSubscriptionWebServiceHostingEnvironment) id() (string, error) {
	return a.Id.Data, nil
}

// id keys the restriction on the synthesized <configId>/ipSecurityRestrictions/<index>
// value built in ipSecurityRestrictionsToMql. Without it every restriction in
// the scan shares an empty cache key and reports the first rule's action.
func (a *mqlAzureSubscriptionWebServiceAppsiteconfigIpSecurityRestriction) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceHostingEnvironmentVirtualNetwork) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceCertificate) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsiteHostNameBinding) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsiteVirtualNetworkConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebService) appServicePlans() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := web.NewPlansClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&web.PlansClientListOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, plan := range page.Value {
			if plan == nil {
				continue
			}

			properties, err := convert.JsonToDict(plan.Properties)
			if err != nil {
				return nil, err
			}

			skuDict, err := convert.JsonToDict(plan.SKU)
			if err != nil {
				return nil, err
			}

			args := map[string]*llx.RawData{
				"id":         llx.StringDataPtr(plan.ID),
				"name":       llx.StringDataPtr(plan.Name),
				"location":   llx.StringDataPtr(plan.Location),
				"kind":       llx.StringDataPtr(plan.Kind),
				"tags":       llx.MapData(convert.PtrMapStrToInterface(plan.Tags), types.String),
				"properties": llx.DictData(properties),
				"sku":        llx.DictData(skuDict),
			}

			skuData, err := appServicePlanSkuToMql(a.MqlRuntime, convert.ToValue(plan.ID), plan.SKU)
			if err != nil {
				return nil, err
			}
			args["skuData"] = skuData

			if plan.Properties != nil {
				args["zoneRedundant"] = llx.BoolDataPtr(plan.Properties.ZoneRedundant)
				args["numberOfSites"] = llx.IntDataPtr(plan.Properties.NumberOfSites)
				args["maximumNumberOfWorkers"] = llx.IntDataPtr(plan.Properties.MaximumNumberOfWorkers)
				args["geoRegion"] = llx.StringDataPtr(plan.Properties.GeoRegion)
				args["reserved"] = llx.BoolDataPtr(plan.Properties.Reserved)
				args["perSiteScaling"] = llx.BoolDataPtr(plan.Properties.PerSiteScaling)
				args["elasticScaleEnabled"] = llx.BoolDataPtr(plan.Properties.ElasticScaleEnabled)
				var status *string
				if plan.Properties.Status != nil {
					val := string(*plan.Properties.Status)
					status = &val
				}
				args["status"] = llx.StringDataPtr(status)
			} else {
				args["zoneRedundant"] = llx.NilData
				args["numberOfSites"] = llx.NilData
				args["maximumNumberOfWorkers"] = llx.NilData
				args["geoRegion"] = llx.NilData
				args["reserved"] = llx.NilData
				args["perSiteScaling"] = llx.NilData
				args["elasticScaleEnabled"] = llx.NilData
				args["status"] = llx.NilData
			}

			mqlResource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppServicePlan, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(plan.SystemData)
			if err != nil {
				return nil, err
			}
			mqlPlan := mqlResource.(*mqlAzureSubscriptionWebServiceAppServicePlan)
			mqlPlan.cacheSystemData = sysData
			res = append(res, mqlResource)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebService) certificates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := web.NewCertificatesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&web.CertificatesClientListOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cert := range page.Value {
			if cert == nil {
				continue
			}

			properties, err := convert.JsonToDict(cert.Properties)
			if err != nil {
				return nil, err
			}

			args := map[string]*llx.RawData{
				"id":         llx.StringDataPtr(cert.ID),
				"name":       llx.StringDataPtr(cert.Name),
				"location":   llx.StringDataPtr(cert.Location),
				"tags":       llx.MapData(convert.PtrMapStrToInterface(cert.Tags), types.String),
				"properties": llx.DictData(properties),
			}

			if cert.Properties != nil {
				args["thumbprint"] = llx.StringDataPtr(cert.Properties.Thumbprint)
				args["subjectName"] = llx.StringDataPtr(cert.Properties.SubjectName)
				args["issuer"] = llx.StringDataPtr(cert.Properties.Issuer)
				args["issueDate"] = llx.TimeDataPtr(cert.Properties.IssueDate)
				args["expirationDate"] = llx.TimeDataPtr(cert.Properties.ExpirationDate)
				args["hostNames"] = llx.ArrayData(strPtrsToAny(cert.Properties.HostNames), types.String)
				args["valid"] = llx.BoolDataPtr(cert.Properties.Valid)
			} else {
				args["thumbprint"] = llx.NilData
				args["subjectName"] = llx.NilData
				args["issuer"] = llx.NilData
				args["issueDate"] = llx.NilData
				args["expirationDate"] = llx.NilData
				args["hostNames"] = llx.ArrayData([]any{}, types.String)
				args["valid"] = llx.NilData
			}

			mqlResource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceCertificate, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(cert.SystemData)
			if err != nil {
				return nil, err
			}
			mqlResource.(*mqlAzureSubscriptionWebServiceCertificate).cacheSystemData = sysData
			res = append(res, mqlResource)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) hostNameBindings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListHostNameBindingsPager(resourceID.ResourceGroup, site, &web.WebAppsClientListHostNameBindingsOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, binding := range page.Value {
			if binding == nil {
				continue
			}

			var hostNameType *string
			if binding.Properties != nil && binding.Properties.HostNameType != nil {
				val := string(*binding.Properties.HostNameType)
				hostNameType = &val
			}
			var sslState *string
			if binding.Properties != nil && binding.Properties.SSLState != nil {
				val := string(*binding.Properties.SSLState)
				sslState = &val
			}
			var thumbprint, virtualIP *string
			if binding.Properties != nil {
				thumbprint = binding.Properties.Thumbprint
				virtualIP = binding.Properties.VirtualIP
			}
			args := map[string]*llx.RawData{
				"id":           llx.StringDataPtr(binding.ID),
				"name":         llx.StringDataPtr(binding.Name),
				"hostNameType": llx.StringDataPtr(hostNameType),
				"sslState":     llx.StringDataPtr(sslState),
				"thumbprint":   llx.StringDataPtr(thumbprint),
				"virtualIP":    llx.StringDataPtr(virtualIP),
			}

			mqlResource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteHostNameBinding, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(binding.SystemData)
			if err != nil {
				return nil, err
			}
			mqlResource.(*mqlAzureSubscriptionWebServiceAppsiteHostNameBinding).cacheSystemData = sysData
			res = append(res, mqlResource)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) virtualNetworkConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	site, err := resourceID.Component("sites")
	if err != nil {
		return nil, err
	}

	client, err := web.NewWebAppsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	resp, err := client.ListVnetConnections(ctx, resourceID.ResourceGroup, site, &web.WebAppsClientListVnetConnectionsOptions{})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, vnet := range resp.VnetInfoResourceArray {
		if vnet == nil {
			continue
		}

		args := map[string]*llx.RawData{
			"id":   llx.StringDataPtr(vnet.ID),
			"name": llx.StringDataPtr(vnet.Name),
		}

		if vnet.Properties != nil {
			args["vnetResourceId"] = llx.StringDataPtr(vnet.Properties.VnetResourceID)
			args["isSwift"] = llx.BoolDataPtr(vnet.Properties.IsSwift)
			args["resyncRequired"] = llx.BoolDataPtr(vnet.Properties.ResyncRequired)
		} else {
			args["vnetResourceId"] = llx.NilData
			args["isSwift"] = llx.NilData
			args["resyncRequired"] = llx.NilData
		}

		mqlResource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceAppsiteVirtualNetworkConnection, args)
		if err != nil {
			return nil, err
		}
		sysData, err := convert.JsonToDict(vnet.SystemData)
		if err != nil {
			return nil, err
		}
		mqlResource.(*mqlAzureSubscriptionWebServiceAppsiteVirtualNetworkConnection).cacheSystemData = sysData
		res = append(res, mqlResource)
	}

	return res, nil
}

func (a *mqlAzureSubscriptionWebService) hostingEnvironments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.GetSubscriptionId().Data

	client, err := web.NewEnvironmentsClient(id, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&web.EnvironmentsClientListOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}

			args := map[string]*llx.RawData{
				"id":       llx.StringDataPtr(entry.ID),
				"name":     llx.StringDataPtr(entry.Name),
				"type":     llx.StringDataPtr(entry.Type),
				"kind":     llx.StringDataPtr(entry.Kind),
				"location": llx.StringDataPtr(entry.Location),
				"tags":     llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
			}

			if entry.Properties != nil {
				props := entry.Properties

				// Convert properties to dict
				propsDict, err := convert.JsonToDict(props)
				if err != nil {
					return nil, err
				}
				args["properties"] = llx.DictData(propsDict)

				args["dnsSuffix"] = llx.StringDataPtr(props.DNSSuffix)
				args["multiSize"] = llx.StringDataPtr(props.MultiSize)
				args["suspended"] = llx.BoolDataPtr(props.Suspended)
				args["hasLinuxWorkers"] = llx.BoolDataPtr(props.HasLinuxWorkers)
				args["zoneRedundant"] = llx.BoolDataPtr(props.ZoneRedundant)
				args["userWhitelistedIpRanges"] = llx.ArrayData(strPtrsToAny(props.UserWhitelistedIPRanges), types.String)

				// Handle enum fields (need to convert to string)
				if props.Status != nil {
					args["status"] = llx.StringData(string(*props.Status))
				}
				if props.InternalLoadBalancingMode != nil {
					args["internalLoadBalancingMode"] = llx.StringData(string(*props.InternalLoadBalancingMode))
				}
				if props.ProvisioningState != nil {
					args["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
				}
				args["maximumNumberOfMachines"] = llx.IntDataPtr(props.MaximumNumberOfMachines)
				args["multiRoleCount"] = llx.IntDataPtr(props.MultiRoleCount)

				args["frontEndScaleFactor"] = llx.IntDataPtr(props.FrontEndScaleFactor)
				args["ipsslAddressCount"] = llx.IntDataPtr(props.IpsslAddressCount)
				args["dedicatedHostCount"] = llx.IntDataPtr(props.DedicatedHostCount)

				if props.VirtualNetwork != nil {
					vnArgs := map[string]*llx.RawData{
						"id":     llx.StringDataPtr(props.VirtualNetwork.ID),
						"name":   llx.StringDataPtr(props.VirtualNetwork.Name),
						"type":   llx.StringDataPtr(props.VirtualNetwork.Type),
						"subnet": llx.StringDataPtr(props.VirtualNetwork.Subnet),
					}
					vnRes, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceHostingEnvironmentVirtualNetwork, vnArgs)
					if err != nil {
						return nil, err
					}
					args["virtualNetwork"] = llx.ResourceData(vnRes, vnRes.MqlName())
				}

				items := []any{}
				for _, setting := range props.ClusterSettings {
					if setting == nil {
						continue
					}
					dict, err := convert.JsonToDict(setting)
					if err != nil {
						return nil, err
					}
					items = append(items, dict)
				}
				args["clusterSettings"] = llx.ArrayData(items, types.Dict)
			}

			mqlRes, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionWebServiceHostingEnvironment, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(entry.SystemData)
			if err != nil {
				return nil, err
			}
			mqlRes.(*mqlAzureSubscriptionWebServiceHostingEnvironment).cacheSystemData = sysData

			res = append(res, mqlRes)
		}
	}

	return res, nil
}

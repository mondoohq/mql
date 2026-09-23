// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v8"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/sshutil"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
	"golang.org/x/sync/errgroup"
)

// stringEnumPtr converts a pointer to an SDK string-enum value into a *string
// so callers can pass it to llx.StringDataPtr without losing type information
// when the enum is nil. Without this, conditional `args["x"] = llx.StringData(...)`
// patterns leave the field absent from the args map, which causes accessors
// to fail with "cannot convert primitive with NO type information".
func stringEnumPtr[T ~string](e *T) *string {
	if e == nil {
		return nil
	}
	s := string(*e)
	return &s
}

func (a *mqlAzureSubscriptionComputeService) id() (string, error) {
	return "azure.subscription.compute/" + a.SubscriptionId.Data, nil
}

// vmOsType returns the OS type of a virtual machine's OS disk ("Linux" or
// "Windows"), or nil when the properties, storage profile, or OS disk are
// absent — guarding the three-level nil chain so a partially-populated VM
// doesn't panic.
func vmOsType(props *compute.VirtualMachineProperties) *string {
	if props == nil || props.StorageProfile == nil || props.StorageProfile.OSDisk == nil {
		return nil
	}
	return stringEnumPtr(props.StorageProfile.OSDisk.OSType)
}

// powerStatePrefix marks the instance-view status codes that carry the VM's
// power state. The same status list also carries ProvisioningState/* codes,
// which must not be mistaken for it.
const powerStatePrefix = "PowerState/"

// getState returns the VM's power state as reported by its instance view, or
// "unknown" when no PowerState status is present.
//
// Azure emits six power states: starting, running, stopping, stopped,
// deallocating, and deallocated. "stopped" and "deallocated" are distinct — a
// stopped VM still holds its compute reservation and public IP and is still
// billed — so they are reported verbatim rather than collapsed together.
func getState(vm compute.VirtualMachineInstanceView) string {
	state := "unknown"
	for _, s := range vm.Statuses {
		if s == nil || s.Code == nil {
			continue
		}
		if rest, ok := strings.CutPrefix(*s.Code, powerStatePrefix); ok && rest != "" {
			state = rest
		}
	}
	return state
}

func initAzureSubscriptionComputeService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionComputeService) vms() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)

	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	// list compute instances
	vmClient, err := compute.NewVirtualMachinesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := vmClient.NewListAllPager(&compute.VirtualMachinesClientListAllOptions{})
	res := []any{}
	for pager.More() {
		vms, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vm := range vms.Value {
			if vm == nil {
				continue
			}
			mqlAzureVm, err := vmToMql(a.MqlRuntime, *vm)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzureVm)
		}
	}

	return res, nil
}

func vmToMql(runtime *plugin.Runtime, vm compute.VirtualMachine) (*mqlAzureSubscriptionComputeServiceVm, error) {
	properties, err := convert.JsonToDict(vm.Properties)
	if err != nil {
		return nil, err
	}

	var encryptionAtHost, secureBootEnabled, vtpmEnabled, proxyAgentEnabled, proxyAgentAddExtension *bool
	var securityType, proxyAgentMode *string
	if vm.Properties != nil && vm.Properties.SecurityProfile != nil {
		sp := vm.Properties.SecurityProfile
		encryptionAtHost = sp.EncryptionAtHost
		securityType = (*string)(sp.SecurityType)
		if sp.UefiSettings != nil {
			secureBootEnabled = sp.UefiSettings.SecureBootEnabled
			vtpmEnabled = sp.UefiSettings.VTpmEnabled
		}
		if sp.ProxyAgentSettings != nil {
			proxyAgentEnabled = sp.ProxyAgentSettings.Enabled
			proxyAgentAddExtension = sp.ProxyAgentSettings.AddProxyAgentExtension
			proxyAgentMode = (*string)(sp.ProxyAgentSettings.Mode)
		}
	}

	var fipsEncryptionEnabled *bool
	var resiliencyProfileDict, scheduledEventsPolicyDict map[string]any
	if vm.Properties != nil {
		if vm.Properties.AdditionalCapabilities != nil {
			fipsEncryptionEnabled = vm.Properties.AdditionalCapabilities.EnableFips1403Encryption
		}
		resiliencyProfileDict, err = convert.JsonToDict(vm.Properties.ResiliencyProfile)
		if err != nil {
			return nil, err
		}
		scheduledEventsPolicyDict, err = convert.JsonToDict(vm.Properties.ScheduledEventsPolicy)
		if err != nil {
			return nil, err
		}
	}
	systemDataDict, err := convert.JsonToDict(vm.SystemData)
	if err != nil {
		return nil, err
	}

	var computerName, adminUsername, licenseType *string
	var vmId, provisioningState *string
	var timeCreated *time.Time
	var disablePasswordAuth, provisionVMAgent, enableAutomaticUpdates *bool
	var patchMode string
	var sshPublicKeys []any
	if vm.Properties != nil {
		licenseType = vm.Properties.LicenseType
		vmId = vm.Properties.VMID
		provisioningState = vm.Properties.ProvisioningState
		timeCreated = vm.Properties.TimeCreated
		if osp := vm.Properties.OSProfile; osp != nil {
			computerName = osp.ComputerName
			adminUsername = osp.AdminUsername
			if lc := osp.LinuxConfiguration; lc != nil {
				disablePasswordAuth = lc.DisablePasswordAuthentication
				provisionVMAgent = lc.ProvisionVMAgent
				if lc.SSH != nil {
					for _, k := range lc.SSH.PublicKeys {
						if k == nil {
							continue
						}
						entry := map[string]any{}
						if k.Path != nil {
							entry["path"] = *k.Path
						}
						if k.KeyData != nil {
							entry["keyData"] = *k.KeyData
							algorithm, bits := sshutil.ParsePublicKey(*k.KeyData)
							entry["algorithm"] = algorithm
							entry["bits"] = bits
						}
						sshPublicKeys = append(sshPublicKeys, entry)
					}
				}
				if lc.PatchSettings != nil && lc.PatchSettings.PatchMode != nil {
					patchMode = string(*lc.PatchSettings.PatchMode)
				}
			}
			if wc := osp.WindowsConfiguration; wc != nil {
				provisionVMAgent = wc.ProvisionVMAgent
				enableAutomaticUpdates = wc.EnableAutomaticUpdates
				if wc.PatchSettings != nil && wc.PatchSettings.PatchMode != nil {
					patchMode = string(*wc.PatchSettings.PatchMode)
				}
			}
		}
	}

	var id *string
	if vm.ID != nil {
		normalized := strings.ToLower(*vm.ID)
		id = &normalized
	}

	var bootDiagnosticsEnabled bool
	var bootDiagnosticsStorageUri string
	osType := vmOsType(vm.Properties)
	if vm.Properties != nil {
		if dp := vm.Properties.DiagnosticsProfile; dp != nil && dp.BootDiagnostics != nil {
			if dp.BootDiagnostics.Enabled != nil {
				bootDiagnosticsEnabled = *dp.BootDiagnostics.Enabled
			}
			if dp.BootDiagnostics.StorageURI != nil {
				bootDiagnosticsStorageUri = *dp.BootDiagnostics.StorageURI
			}
		}
	}

	guestAccess := vmGuestAccessSettings(vm.Properties)

	identityDict, err := convert.JsonToDict(vm.Identity)
	if err != nil {
		return nil, err
	}
	vmIdentity := orZero(vm.Identity)

	vmIDStr := ""
	if vm.ID != nil {
		vmIDStr = *vm.ID
	}
	// vmImageReferenceToMql is nil-safe on vm.Properties — always returns a
	// resource (fields default to empty strings when the VM has no storage
	// profile / image reference).
	mqlImageRef, err := vmImageReferenceToMql(runtime, vmIDStr, vm.Properties)
	if err != nil {
		return nil, err
	}

	vmArgs := map[string]*llx.RawData{
		"id":                            llx.StringDataPtr(id),
		"name":                          llx.StringDataPtr(vm.Name),
		"location":                      llx.StringDataPtr(vm.Location),
		"zones":                         llx.ArrayData(strPtrsToAny(vm.Zones), types.String),
		"tags":                          llx.MapData(convert.PtrMapStrToInterface(vm.Tags), types.String),
		"type":                          llx.StringDataPtr(vm.Type),
		"properties":                    llx.DictData(properties),
		"encryptionAtHost":              llx.BoolDataPtr(encryptionAtHost),
		"securityType":                  llx.StringDataPtr(securityType),
		"secureBootEnabled":             llx.BoolDataPtr(secureBootEnabled),
		"vtpmEnabled":                   llx.BoolDataPtr(vtpmEnabled),
		"proxyAgentEnabled":             llx.BoolDataPtr(proxyAgentEnabled),
		"proxyAgentMode":                llx.StringDataPtr(proxyAgentMode),
		"proxyAgentAddExtension":        llx.BoolDataPtr(proxyAgentAddExtension),
		"fipsEncryptionEnabled":         llx.BoolDataPtr(fipsEncryptionEnabled),
		"resiliencyProfile":             llx.DictData(resiliencyProfileDict),
		"scheduledEventsPolicy":         llx.DictData(scheduledEventsPolicyDict),
		"computerName":                  llx.StringDataPtr(computerName),
		"adminUsername":                 llx.StringDataPtr(adminUsername),
		"licenseType":                   llx.StringDataPtr(licenseType),
		"managedBy":                     llx.StringDataPtr(vm.ManagedBy),
		"vmId":                          llx.StringDataPtr(vmId),
		"provisioningState":             llx.StringDataPtr(provisioningState),
		"timeCreated":                   llx.TimeDataPtr(timeCreated),
		"sshPublicKeys":                 llx.ArrayData(sshPublicKeys, types.Dict),
		"disablePasswordAuthentication": llx.BoolDataPtr(disablePasswordAuth),
		"osType":                        llx.StringDataPtr(osType),
		"provisionVMAgent":              llx.BoolDataPtr(provisionVMAgent),
		"enableAutomaticUpdates":        llx.BoolDataPtr(enableAutomaticUpdates),
		"patchMode":                     llx.StringData(patchMode),
		"imageReference":                llx.ResourceData(mqlImageRef, mqlImageRef.MqlName()),
		"bootDiagnosticsEnabled":        llx.BoolData(bootDiagnosticsEnabled),
		"bootDiagnosticsStorageUri":     llx.StringData(bootDiagnosticsStorageUri),
		"identity":                      llx.DictData(identityDict),
		"allowExtensionOperations":      llx.BoolDataPtr(guestAccess.allowExtensionOperations),
		"requireGuestProvisionSignal":   llx.BoolDataPtr(guestAccess.requireGuestProvisionSignal),
		"winRmHttpListenerEnabled":      llx.BoolDataPtr(guestAccess.winRmHTTPListenerEnabled),
		"winRmHttpsListenerEnabled":     llx.BoolDataPtr(guestAccess.winRmHTTPSListenerEnabled),
	}
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(vmIdentity.UserAssignedIdentities)
	if err := setResourceIdentity(runtime, vmArgs, userAssignedIdentityIds,
		identityType(vmIdentity.Type), identityPrincipalId(vmIdentity.PrincipalID), identityTenantId(vmIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.vm", vmArgs)
	if err != nil {
		return nil, err
	}
	mqlVm := res.(*mqlAzureSubscriptionComputeServiceVm)
	mqlVm.cacheSystemData = systemDataDict
	mqlVm.cacheUserAssignedIdentityIds = userAssignedIdentityIds
	mqlVm.cacheCertificateSourceVaultIds = guestAccess.certificateSourceVaultIDs
	mqlVm.cacheEncryptionIdentityId = guestAccess.encryptionIdentityID
	return mqlVm, nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionComputeServiceVm) systemAssignedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return newSystemAssignedManagedIdentity(a.MqlRuntime, a.Id.Data, a.PrincipalId.Data, tenantIDFromIdentityDict(a.Identity), &a.SystemAssignedIdentity)
}

func (a *mqlAzureSubscriptionComputeServiceVm) state() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	// id is a Azure resource ID
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return "", err
	}

	vm, err := resourceID.Component("virtualMachines")
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	token := conn.Token()

	client, err := compute.NewVirtualMachinesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return "", err
	}

	view, err := client.InstanceView(ctx, resourceID.ResourceGroup, vm, &compute.VirtualMachinesClientInstanceViewOptions{})
	if err != nil {
		return "", err
	}
	return getState(view.VirtualMachineInstanceView), nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) isRunning() (bool, error) {
	state := a.GetState()
	if state.Error != nil {
		return false, state.Error
	}
	return state.Data == "running", nil
}

type mqlAzureSubscriptionComputeServiceVmInternal struct {
	extensionsOnce               sync.Once
	extensionsList               []*compute.VirtualMachineExtension
	extensionsError              error
	cacheUserAssignedIdentityIds []string
	cacheSystemData              any

	cacheCertificateSourceVaultIds []string
	cacheEncryptionIdentityId      string
}

func (a *mqlAzureSubscriptionComputeServiceVm) fetchExtensions() ([]*compute.VirtualMachineExtension, error) {
	a.extensionsOnce.Do(func() {
		conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
		if !ok {
			a.extensionsError = errors.New("invalid connection provided, it is not an Azure connection")
			return
		}
		resourceID, err := ParseResourceID(a.Id.Data)
		if err != nil {
			a.extensionsError = err
			return
		}
		vm, err := resourceID.Component("virtualMachines")
		if err != nil {
			a.extensionsError = err
			return
		}
		client, err := compute.NewVirtualMachineExtensionsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.extensionsError = err
			return
		}
		resp, err := client.List(context.Background(), resourceID.ResourceGroup, vm, &compute.VirtualMachineExtensionsClientListOptions{})
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Str("vm", a.Id.Data).Err(err).Msg("could not list VM extensions due to access denied")
				return
			}
			a.extensionsError = err
			return
		}
		a.extensionsList = resp.Value
	})
	return a.extensionsList, a.extensionsError
}

func (a *mqlAzureSubscriptionComputeServiceVm) extensions() ([]any, error) {
	list, err := a.fetchExtensions()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(list))
	for _, entry := range list {
		if entry == nil {
			continue
		}
		dict, err := convert.JsonToDict(entry.Properties)
		if err != nil {
			return nil, err
		}
		res = append(res, dict)
	}
	return res, nil
}

// extensionInstalled reports whether the VM has an extension whose
// (publisher, extension type) matches one of the entries in `match`.
// Comparisons are case-insensitive.
func (a *mqlAzureSubscriptionComputeServiceVm) extensionInstalled(match map[string][]string) (bool, error) {
	list, err := a.fetchExtensions()
	if err != nil {
		return false, err
	}
	for _, entry := range list {
		if entry == nil || entry.Properties == nil {
			continue
		}
		pub, typ := entry.Properties.Publisher, entry.Properties.Type
		if pub == nil || typ == nil {
			continue
		}
		types, ok := match[strings.ToLower(*pub)]
		if !ok {
			continue
		}
		for _, t := range types {
			if strings.EqualFold(t, *typ) {
				return true, nil
			}
		}
	}
	return false, nil
}

var (
	mdeExtensionMatches = map[string][]string{
		"microsoft.azure.azuredefenderforservers": {"MDE.Linux", "MDE.Windows"},
	}
	amaExtensionMatches = map[string][]string{
		"microsoft.azure.monitor": {"AzureMonitorLinuxAgent", "AzureMonitorWindowsAgent"},
	}
	omsExtensionMatches = map[string][]string{
		"microsoft.enterprisecloud.monitoring": {"MicrosoftMonitoringAgent", "OmsAgentForLinux"},
	}
	dependencyAgentExtensionMatches = map[string][]string{
		"microsoft.azure.monitoring.dependencyagent": {"DependencyAgentLinux", "DependencyAgentWindows"},
	}
	adeExtensionMatches = map[string][]string{
		"microsoft.azure.security": {"AzureDiskEncryption", "AzureDiskEncryptionForLinux"},
	}
)

func (a *mqlAzureSubscriptionComputeServiceVm) mdeInstalled() (bool, error) {
	return a.extensionInstalled(mdeExtensionMatches)
}

func (a *mqlAzureSubscriptionComputeServiceVm) amaInstalled() (bool, error) {
	return a.extensionInstalled(amaExtensionMatches)
}

func (a *mqlAzureSubscriptionComputeServiceVm) omsInstalled() (bool, error) {
	return a.extensionInstalled(omsExtensionMatches)
}

func (a *mqlAzureSubscriptionComputeServiceVm) dependencyAgentInstalled() (bool, error) {
	return a.extensionInstalled(dependencyAgentExtensionMatches)
}

func (a *mqlAzureSubscriptionComputeServiceVm) adeInstalled() (bool, error) {
	return a.extensionInstalled(adeExtensionMatches)
}

func (a *mqlAzureSubscriptionComputeService) disks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)

	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewDisksClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&compute.DisksClientListOptions{})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for pager.More() {
		disks, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, disk := range disks.Value {
			if disk == nil {
				continue
			}
			mqlAzureDisk, err := diskToMql(a.MqlRuntime, *disk)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzureDisk)
		}
	}

	return res, nil
}

func diskToMql(runtime *plugin.Runtime, disk compute.Disk) (*mqlAzureSubscriptionComputeServiceDisk, error) {
	properties, err := convert.JsonToDict(disk.Properties)
	if err != nil {
		return nil, err
	}

	sku, err := convert.JsonToDict(disk.SKU)
	if err != nil {
		return nil, err
	}

	managedByExtended := []any{}
	for _, mbe := range disk.ManagedByExtended {
		if mbe != nil {
			managedByExtended = append(managedByExtended, *mbe)
		}
	}
	zones := []any{}
	for _, z := range disk.Zones {
		if z != nil {
			zones = append(zones, *z)
		}
	}

	systemData, err := convert.JsonToDict(disk.SystemData)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                llx.StringDataPtr(disk.ID),
		"name":              llx.StringDataPtr(disk.Name),
		"location":          llx.StringDataPtr(disk.Location),
		"tags":              llx.MapData(convert.PtrMapStrToInterface(disk.Tags), types.String),
		"type":              llx.StringDataPtr(disk.Type),
		"managedBy":         llx.StringDataPtr(disk.ManagedBy),
		"managedByExtended": llx.ArrayData(managedByExtended, types.String),
		"zones":             llx.ArrayData(zones, types.String),
		"sku":               llx.DictData(sku),
		"properties":        llx.DictData(properties),
	}
	diskSku := orZero(disk.SKU)
	if err := setSkuData(runtime, args, skuName(diskSku.Name), skuTier(diskSku.Tier)); err != nil {
		return nil, err
	}

	// Cached for secureVmDiskEncryptionSet(); the confidential-VM guest state
	// key is a separate encryption set from the disk's own, so it cannot be
	// derived from diskEncryptionSetId.
	var secureVMDesID *string

	// Read outside the Properties guard below and set unconditionally, so a
	// disk that arrives without Properties reports these as null rather than
	// leaving them unset. An unset field crosses the plugin boundary with no
	// type information and surfaces client-side as an unattributed null; a
	// deliberate null says "not reported" and is what a security check should
	// see for securityType on a disk whose shape could not be read.
	var encryptionSettingsVersion *string
	var securityType *compute.DiskSecurityTypes
	var confidentialVMVersion *compute.ConfidentialVMVersion
	var osType *compute.OperatingSystemTypes
	var diskSizeGB *int32
	var optimizedForFrequentAttach *bool
	if p := disk.Properties; p != nil {
		if esc := p.EncryptionSettingsCollection; esc != nil {
			encryptionSettingsVersion = esc.EncryptionSettingsVersion
		}
		if sp := p.SecurityProfile; sp != nil {
			securityType = sp.SecurityType
			confidentialVMVersion = sp.ConfidentialVMVersion
			secureVMDesID = sp.SecureVMDiskEncryptionSetID
		}
		osType = p.OSType
		diskSizeGB = p.DiskSizeGB
		optimizedForFrequentAttach = p.OptimizedForFrequentAttach
	}
	args["encryptionSettingsVersion"] = llx.StringDataPtr(encryptionSettingsVersion)
	args["securityType"] = llx.StringDataPtr(stringEnumPtr(securityType))
	args["confidentialVmVersion"] = llx.StringDataPtr(stringEnumPtr(confidentialVMVersion))
	args["osType"] = llx.StringDataPtr(stringEnumPtr(osType))
	args["diskSizeGB"] = llx.IntDataPtr(diskSizeGB)
	args["optimizedForFrequentAttach"] = llx.BoolDataPtr(optimizedForFrequentAttach)

	if disk.Properties != nil {
		args["networkAccessPolicy"] = llx.StringDataPtr(stringEnumPtr(disk.Properties.NetworkAccessPolicy))
		args["publicNetworkAccess"] = llx.StringDataPtr(stringEnumPtr(disk.Properties.PublicNetworkAccess))
		var encryptionType *compute.EncryptionType
		var desID *string
		if disk.Properties.Encryption != nil {
			encryptionType = disk.Properties.Encryption.Type
			desID = disk.Properties.Encryption.DiskEncryptionSetID
		}
		args["encryptionType"] = llx.StringDataPtr(stringEnumPtr(encryptionType))
		args["diskEncryptionSetId"] = llx.StringDataPtr(desID)
		var encryptionSettingsEnabled *bool
		if esc := disk.Properties.EncryptionSettingsCollection; esc != nil {
			encryptionSettingsEnabled = esc.Enabled
		}
		args["encryptionSettingsEnabled"] = llx.BoolDataPtr(encryptionSettingsEnabled)
		args["dataAccessAuthMode"] = llx.StringDataPtr(stringEnumPtr(disk.Properties.DataAccessAuthMode))
		args["diskState"] = llx.StringDataPtr(stringEnumPtr(disk.Properties.DiskState))
		args["provisioningState"] = llx.StringDataPtr(disk.Properties.ProvisioningState)
		args["timeCreated"] = llx.TimeDataPtr(disk.Properties.TimeCreated)
		args["uniqueId"] = llx.StringDataPtr(disk.Properties.UniqueID)
		args["burstingEnabled"] = llx.BoolDataPtr(disk.Properties.BurstingEnabled)
		args["diskSizeBytes"] = llx.IntDataPtr(disk.Properties.DiskSizeBytes)
		args["diskIopsReadWrite"] = llx.IntDataPtr(disk.Properties.DiskIOPSReadWrite)
		args["diskMbpsReadWrite"] = llx.IntDataPtr(disk.Properties.DiskMBpsReadWrite)
		args["diskIopsReadOnly"] = llx.IntDataPtr(disk.Properties.DiskIOPSReadOnly)
		args["diskMbpsReadOnly"] = llx.IntDataPtr(disk.Properties.DiskMBpsReadOnly)
		args["maxShares"] = llx.IntDataPtr(disk.Properties.MaxShares)
		args["hyperVGeneration"] = llx.StringDataPtr(stringEnumPtr(disk.Properties.HyperVGeneration))
		args["tier"] = llx.StringDataPtr(disk.Properties.Tier)
		args["supportsHibernation"] = llx.BoolDataPtr(disk.Properties.SupportsHibernation)
		args["diskAccessId"] = llx.StringDataPtr(disk.Properties.DiskAccessID)
		availabilityPolicy, err := convert.JsonToDict(disk.Properties.AvailabilityPolicy)
		if err != nil {
			return nil, err
		}
		args["availabilityPolicy"] = llx.DictData(availabilityPolicy)
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.disk", args)
	if err != nil {
		return nil, err
	}
	mqlDisk := res.(*mqlAzureSubscriptionComputeServiceDisk)
	mqlDisk.cacheSecureVMDiskEncryptionSetID = secureVMDesID
	mqlDisk.cacheSystemData = systemData
	return mqlDisk, nil
}

type mqlAzureSubscriptionComputeServiceDiskInternal struct {
	cacheSecureVMDiskEncryptionSetID *string
	cacheSystemData                  any
}

// secureVmDiskEncryptionSet resolves the encryption set protecting a
// confidential VM's guest state. Only ConfidentialVM_DiskEncryptedWithCustomerKey
// disks carry one; every other disk reports null.
func (a *mqlAzureSubscriptionComputeServiceDisk) secureVmDiskEncryptionSet() (*mqlAzureSubscriptionComputeServiceDiskEncryptionSet, error) {
	return resolveSecureVMDiskEncryptionSet(a.MqlRuntime, a.cacheSecureVMDiskEncryptionSetID, &a.SecureVmDiskEncryptionSet)
}

// resolveSecureVMDiskEncryptionSet is shared by disks and snapshots, which model
// the same securityProfile block.
func resolveSecureVMDiskEncryptionSet(runtime *plugin.Runtime, id *string, field *plugin.TValue[*mqlAzureSubscriptionComputeServiceDiskEncryptionSet]) (*mqlAzureSubscriptionComputeServiceDiskEncryptionSet, error) {
	if id == nil || *id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "azure.subscription.computeService.diskEncryptionSet", map[string]*llx.RawData{
		"id": llx.StringData(strings.ToLower(*id)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceDiskEncryptionSet), nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) osDisk() (*mqlAzureSubscriptionComputeServiceDisk, error) {
	propertiesDict := a.Properties.Data
	data, err := json.Marshal(propertiesDict)
	if err != nil {
		return nil, err
	}

	var properties compute.VirtualMachineProperties
	err = json.Unmarshal(data, &properties)
	if err != nil {
		return nil, err
	}

	// A VM on unmanaged (page-blob VHD) storage has an OS disk but no managed
	// disk resource to point at, so there is nothing to resolve. Report null
	// rather than failing the field.
	if properties.StorageProfile == nil || properties.StorageProfile.OSDisk == nil || properties.StorageProfile.OSDisk.ManagedDisk == nil || properties.StorageProfile.OSDisk.ManagedDisk.ID == nil {
		a.OsDisk.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionComputeServiceDisk,
		map[string]*llx.RawData{"id": llx.StringData(*properties.StorageProfile.OSDisk.ManagedDisk.ID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceDisk), nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) dataDisks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	propertiesDict := a.Properties.Data
	data, err := json.Marshal(propertiesDict)
	if err != nil {
		return nil, err
	}

	token := conn.Token()

	var properties compute.VirtualMachineProperties
	err = json.Unmarshal(data, &properties)
	if err != nil {
		return nil, err
	}

	// A VM with no data disks omits the array entirely; that is an empty list,
	// not a failure.
	if properties.StorageProfile == nil || properties.StorageProfile.DataDisks == nil {
		return []any{}, nil
	}

	dataDisks := properties.StorageProfile.DataDisks

	// Pre-validate all disks (parse IDs, build clients) before spawning any
	// goroutines so that an early error can't leak in-flight workers.
	type diskFetch struct {
		client *compute.DisksClient
		rg     string
		name   string
		index  int
	}
	clientsBySub := map[string]*compute.DisksClient{}
	disks := make([]compute.Disk, len(dataDisks))
	fetches := make([]diskFetch, 0, len(dataDisks))
	for i, dd := range dataDisks {
		if dd.ManagedDisk == nil || dd.ManagedDisk.ID == nil {
			continue
		}
		resourceID, err := ParseResourceID(*dd.ManagedDisk.ID)
		if err != nil {
			return nil, err
		}
		diskName, err := resourceID.Component("disks")
		if err != nil {
			return nil, err
		}
		client, ok := clientsBySub[resourceID.SubscriptionID]
		if !ok {
			client, err = compute.NewDisksClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
				ClientOptions: conn.ClientOptions(),
			})
			if err != nil {
				return nil, err
			}
			clientsBySub[resourceID.SubscriptionID] = client
		}
		fetches = append(fetches, diskFetch{client: client, rg: resourceID.ResourceGroup, name: diskName, index: i})
	}

	// Azure has no batch get-by-id endpoint for disks, so concurrent per-disk
	// Gets in a bounded errgroup is the cheapest fix.
	ctx := context.Background()
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)
	for _, f := range fetches {
		g.Go(func() error {
			resp, err := f.client.Get(gctx, f.rg, f.name, &compute.DisksClientGetOptions{})
			if err != nil {
				return err
			}
			disks[f.index] = resp.Disk
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	res := []any{}
	for _, disk := range disks {
		if disk.ID == nil {
			continue
		}
		mqlDisk, err := diskToMql(a.MqlRuntime, disk)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDisk)
	}

	return res, nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeServiceDisk) id() (string, error) {
	return a.Id.Data, nil
}

// networkInterfaces returns the typed NIC resources attached to the VM via
// its networkProfile. Resolves each NIC's full state by fetching it from the
// network API in a bounded errgroup (Azure has no batch get-by-id endpoint).
func (a *mqlAzureSubscriptionComputeServiceVm) networkInterfaces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	token := conn.Token()
	resourceId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	subId := resourceId.SubscriptionID

	propertiesDict := a.Properties.Data
	data, err := json.Marshal(propertiesDict)
	if err != nil {
		return nil, err
	}
	var properties compute.VirtualMachineProperties
	if err := json.Unmarshal(data, &properties); err != nil {
		return nil, err
	}
	if properties.NetworkProfile == nil {
		return []any{}, nil
	}

	ctx := context.Background()
	nicClient, err := network.NewInterfacesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	type nicFetch struct {
		rg   string
		name string
		slot int
	}
	fetches := make([]nicFetch, 0, len(properties.NetworkProfile.NetworkInterfaces))
	for _, iface := range properties.NetworkProfile.NetworkInterfaces {
		if iface == nil || iface.ID == nil {
			continue
		}
		parsed, err := ParseResourceID(*iface.ID)
		if err != nil {
			return nil, err
		}
		name, err := parsed.Component("networkInterfaces")
		if err != nil {
			return nil, err
		}
		fetches = append(fetches, nicFetch{rg: parsed.ResourceGroup, name: name, slot: len(fetches)})
	}

	nics := make([]*network.Interface, len(fetches))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)
	for _, f := range fetches {
		g.Go(func() error {
			resp, err := nicClient.Get(gctx, f.rg, f.name, &network.InterfacesClientGetOptions{})
			if err != nil {
				// Skip NICs we can't read (403/404) instead of failing the
				// whole call — matches the per-list pattern used elsewhere
				// in this provider for partial-permission scenarios.
				var respErr *azcore.ResponseError
				if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusForbidden || respErr.StatusCode == http.StatusNotFound) {
					log.Warn().Err(err).Str("nic", f.name).Msg("could not read network interface, skipping")
					return nil
				}
				return err
			}
			nics[f.slot] = &resp.Interface
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(nics))
	for _, nic := range nics {
		if nic == nil || nic.ID == nil {
			continue
		}
		mqlNic, err := azureInterfaceToMql(a.MqlRuntime, *nic)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNic)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) publicIpAddresses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	token := conn.Token()
	resourceId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	subId := resourceId.SubscriptionID
	props := a.GetProperties()
	if props.Error != nil {
		return nil, props.Error
	}

	propsDict, ok := props.Data.(map[string]any)
	if !ok {
		return []any{}, nil
	}
	networkInterface, ok := propsDict["networkProfile"]
	if !ok {
		return nil, errors.New("cannot find network profile on vm, not retrieving ip addresses")
	}
	var networkInterfaces compute.NetworkProfile

	data, err := json.Marshal(networkInterface)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(data), &networkInterfaces)
	if err != nil {
		return nil, err
	}
	res := []any{}

	ctx := context.Background()
	nicClient, err := network.NewInterfacesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ipClient, err := network.NewPublicIPAddressesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	// Phase 1: pre-validate NIC IDs, then fetch all NICs concurrently. Per-NIC
	// Get is the only API option here (no batch endpoint), so a bounded
	// errgroup is the cheapest fix that preserves semantics.
	type nicFetch struct {
		rg   string
		name string
	}
	nicFetches := make([]nicFetch, 0, len(networkInterfaces.NetworkInterfaces))
	for _, iface := range networkInterfaces.NetworkInterfaces {
		if iface.ID == nil {
			continue
		}
		resource, err := ParseResourceID(*iface.ID)
		if err != nil {
			return nil, err
		}
		name, err := resource.Component("networkInterfaces")
		if err != nil {
			return nil, err
		}
		nicFetches = append(nicFetches, nicFetch{rg: resource.ResourceGroup, name: name})
	}

	nics := make([]network.Interface, len(nicFetches))
	g1, gctx1 := errgroup.WithContext(ctx)
	g1.SetLimit(10)
	for i, f := range nicFetches {
		g1.Go(func() error {
			resp, err := nicClient.Get(gctx1, f.rg, f.name, &network.InterfacesClientGetOptions{})
			if err != nil {
				return err
			}
			nics[i] = resp.Interface
			return nil
		})
	}
	if err := g1.Wait(); err != nil {
		return nil, err
	}

	// Phase 2: collect all public IP IDs across NICs, then fetch concurrently.
	type ipFetch struct {
		rg   string
		name string
	}
	var fetches []ipFetch
	for _, ni := range nics {
		if ni.Properties == nil {
			continue
		}
		for _, config := range ni.Properties.IPConfigurations {
			if config.Properties == nil || config.Properties.PublicIPAddress == nil || config.Properties.PublicIPAddress.ID == nil {
				continue
			}
			publicIPID := *config.Properties.PublicIPAddress.ID
			publicIpResource, err := ParseResourceID(publicIPID)
			if err != nil {
				return nil, errors.New("invalid network information for resource " + publicIPID)
			}
			ipAddrName, err := publicIpResource.Component("publicIPAddresses")
			if err != nil {
				return nil, errors.New("invalid network information for resource " + publicIPID)
			}
			fetches = append(fetches, ipFetch{rg: publicIpResource.ResourceGroup, name: ipAddrName})
		}
	}

	ipResults := make([]network.PublicIPAddress, len(fetches))
	g2, gctx2 := errgroup.WithContext(ctx)
	g2.SetLimit(10)
	for i, f := range fetches {
		g2.Go(func() error {
			resp, err := ipClient.Get(gctx2, f.rg, f.name, &network.PublicIPAddressesClientGetOptions{})
			if err != nil {
				return err
			}
			ipResults[i] = resp.PublicIPAddress
			return nil
		})
	}
	if err := g2.Wait(); err != nil {
		return nil, err
	}

	for _, ipAddress := range ipResults {
		mqlIpAddress, err := azureIpToMql(a.MqlRuntime, ipAddress)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIpAddress)
	}

	return res, nil
}

func initAzureSubscriptionComputeServiceVm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionComputeService,
		func(s *mqlAzureSubscriptionComputeService) *plugin.TValue[[]any] { return s.GetVms() },
		ResourceAzureSubscriptionComputeServiceVm)
}

// userData returns the VM's base64-encoded user data.
//
// ARM only returns userData when the read asks for it with $expand=userData,
// and the list API cannot return it at all -- ExpandTypesForListVMs offers only
// instanceView. Reading vm.Properties.UserData off a plain Get or List therefore
// always produced "", so a hunt for credentials embedded in bootstrap data
// (vms.where(userData != "")) came back empty on every subscription. Asking for
// the expansion costs one read per VM, which is why this is a computed field
// rather than part of the listing.
func (a *mqlAzureSubscriptionComputeServiceVm) userData() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return "", err
	}
	vmName, err := resourceID.Component("virtualMachines")
	if err != nil {
		return "", err
	}

	client, err := compute.NewVirtualMachinesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return "", err
	}

	expand := compute.InstanceViewTypesUserData
	resp, err := client.Get(context.Background(), resourceID.ResourceGroup, vmName, &compute.VirtualMachinesClientGetOptions{
		Expand: &expand,
	})
	if err != nil {
		if isAzureNotConfigured(err) {
			log.Warn().Err(err).Str("vm", a.Id.Data).Msg("could not read vm user data")
			return "", nil
		}
		return "", err
	}
	if resp.Properties == nil {
		return "", nil
	}
	return convert.ToValue(resp.Properties.UserData), nil
}

func (a *mqlAzureSubscriptionComputeServiceDiskEncryptionSet) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeServiceDiskAccess) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeService) diskEncryptionSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewDiskEncryptionSetsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list disk encryption sets due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, des := range page.Value {
			if des == nil {
				continue
			}
			mqlDes, err := diskEncryptionSetToMql(a.MqlRuntime, *des)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDes)
		}
	}

	return res, nil
}

func diskEncryptionSetToMql(runtime *plugin.Runtime, des compute.DiskEncryptionSet) (*mqlAzureSubscriptionComputeServiceDiskEncryptionSet, error) {
	identity, err := convert.JsonToDict(des.Identity)
	if err != nil {
		return nil, err
	}

	var encryptionType, provisioningState string
	var activeKeyUrl, activeKeySourceVaultId string
	var rotationToLatestKeyVersionEnabled *bool
	var lastKeyRotationTimestamp *time.Time

	if des.Properties != nil {
		props := des.Properties
		if props.EncryptionType != nil {
			encryptionType = string(*props.EncryptionType)
		}
		if props.ActiveKey != nil {
			if props.ActiveKey.KeyURL != nil {
				activeKeyUrl = *props.ActiveKey.KeyURL
			}
			if props.ActiveKey.SourceVault != nil && props.ActiveKey.SourceVault.ID != nil {
				activeKeySourceVaultId = *props.ActiveKey.SourceVault.ID
			}
		}
		rotationToLatestKeyVersionEnabled = props.RotationToLatestKeyVersionEnabled
		lastKeyRotationTimestamp = props.LastKeyRotationTimestamp
		if props.ProvisioningState != nil {
			provisioningState = *props.ProvisioningState
		}
	}

	desArgs := map[string]*llx.RawData{
		"id":                                llx.StringDataPtr(des.ID),
		"name":                              llx.StringDataPtr(des.Name),
		"location":                          llx.StringDataPtr(des.Location),
		"tags":                              llx.MapData(convert.PtrMapStrToInterface(des.Tags), types.String),
		"type":                              llx.StringDataPtr(des.Type),
		"identity":                          llx.DictData(identity),
		"encryptionType":                    llx.StringData(encryptionType),
		"activeKeyUrl":                      llx.StringData(activeKeyUrl),
		"activeKeySourceVaultId":            llx.StringData(activeKeySourceVaultId),
		"rotationToLatestKeyVersionEnabled": llx.BoolDataPtr(rotationToLatestKeyVersionEnabled),
		"lastKeyRotationTimestamp":          llx.TimeDataPtr(lastKeyRotationTimestamp),
		"provisioningState":                 llx.StringData(provisioningState),
	}
	desIdentity := orZero(des.Identity)
	if err := setResourceIdentity(runtime, desArgs, sortedUserAssignedIdentityIDs(desIdentity.UserAssignedIdentities),
		identityType(desIdentity.Type), identityPrincipalId(desIdentity.PrincipalID), identityTenantId(desIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionComputeServiceDiskEncryptionSet, desArgs)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(des.SystemData)
	if err != nil {
		return nil, err
	}
	mqlDes := res.(*mqlAzureSubscriptionComputeServiceDiskEncryptionSet)
	mqlDes.cacheSystemData = sysData
	return mqlDes, nil
}

type mqlAzureSubscriptionComputeServiceDiskEncryptionSetInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceDiskEncryptionSet) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionComputeServiceDiskAccessInternal struct {
	cachePrivateEndpointConnections []*compute.PrivateEndpointConnection
	cacheSystemData                 any
}

func (a *mqlAzureSubscriptionComputeServiceDiskAccess) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeService) diskAccesses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewDiskAccessesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list disk accesses due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, da := range page.Value {
			if da == nil {
				continue
			}

			var provisioningState string
			var timeCreated *time.Time
			var privateEndpointConns []*compute.PrivateEndpointConnection

			if da.Properties != nil {
				if da.Properties.ProvisioningState != nil {
					provisioningState = *da.Properties.ProvisioningState
				}
				timeCreated = da.Properties.TimeCreated
				privateEndpointConns = da.Properties.PrivateEndpointConnections
			}

			mqlDa, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionComputeServiceDiskAccess,
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(da.ID),
					"name":              llx.StringDataPtr(da.Name),
					"location":          llx.StringDataPtr(da.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(da.Tags), types.String),
					"type":              llx.StringDataPtr(da.Type),
					"provisioningState": llx.StringData(provisioningState),
					"timeCreated":       llx.TimeDataPtr(timeCreated),
				})
			if err != nil {
				return nil, err
			}

			// Cache private endpoint connections for lazy loading
			mqlDaTyped := mqlDa.(*mqlAzureSubscriptionComputeServiceDiskAccess)
			mqlDaTyped.cachePrivateEndpointConnections = privateEndpointConns

			sysData, err := convert.JsonToDict(da.SystemData)
			if err != nil {
				return nil, err
			}
			mqlDaTyped.cacheSystemData = sysData

			res = append(res, mqlDa)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionComputeServiceDiskAccess) privateEndpointConnections() ([]any, error) {
	var res []any
	if a.cachePrivateEndpointConnections == nil {
		return res, nil
	}

	for _, entry := range a.cachePrivateEndpointConnections {
		if entry == nil {
			continue
		}

		// Extract name and type from ID
		var name, resType string
		if entry.ID != nil {
			connResourceID, err := ParseResourceID(*entry.ID)
			if err == nil {
				if nameComp, err := connResourceID.Component("privateEndpointConnections"); err == nil {
					name = nameComp
				}
				if connResourceID.Provider != "" {
					resType = connResourceID.Provider + "/diskAccesses/privateEndpointConnections"
				}
			}
			if name == "" {
				parts := strings.Split(*entry.ID, "/")
				if len(parts) > 0 {
					name = parts[len(parts)-1]
				}
			}
		}
		if resType == "" {
			resType = "Microsoft.Compute/diskAccesses/privateEndpointConnections"
		}

		var pecPrivateEndpointID string
		privateEndpoint := map[string]*llx.RawData{
			"__id": llx.StringDataPtr(entry.ID),
			"id":   llx.StringDataPtr(entry.ID),
		}
		if name != "" {
			privateEndpoint["name"] = llx.StringData(name)
		}
		privateEndpoint["type"] = llx.StringData(resType)

		if entry.Properties != nil {
			props := entry.Properties
			propsMap, err := convert.JsonToDict(props)
			if err != nil {
				return nil, err
			}

			privateEndpoint["properties"] = llx.DictData(propsMap)

			if props.PrivateEndpoint != nil {
				pecPrivateEndpointID = convert.ToValue(props.PrivateEndpoint.ID)
			}
			if props.PrivateLinkServiceConnectionState != nil {
				stateRes, err := newPrivateLinkServiceConnectionState(a.MqlRuntime, convert.ToValue(entry.ID),
					stringEnumPtr(props.PrivateLinkServiceConnectionState.ActionsRequired),
					props.PrivateLinkServiceConnectionState.Description,
					stringEnumPtr(props.PrivateLinkServiceConnectionState.Status))
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

	return res, nil
}

func initAzureSubscriptionComputeServiceDisk(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure compute disk")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	diskName, err := resourceID.Component("disks")
	if err != nil {
		return nil, nil, err
	}

	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionComputeServiceDisk, id); cached != nil {
		return args, cached, nil
	}

	client, err := compute.NewDisksClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	diskResp, err := client.Get(context.Background(), resourceID.ResourceGroup, diskName, &compute.DisksClientGetOptions{})
	if err != nil {
		return nil, nil, err
	}

	res, err := diskToMql(runtime, diskResp.Disk)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func initAzureSubscriptionComputeServiceDiskEncryptionSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure compute disk encryption set")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	desName, err := resourceID.Component("diskEncryptionSets")
	if err != nil {
		return nil, nil, err
	}

	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionComputeServiceDiskEncryptionSet, id); cached != nil {
		return args, cached, nil
	}

	client, err := compute.NewDiskEncryptionSetsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), resourceID.ResourceGroup, desName, &compute.DiskEncryptionSetsClientGetOptions{})
	if err != nil {
		return nil, nil, err
	}

	mqlDes, err := diskEncryptionSetToMql(runtime, resp.DiskEncryptionSet)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlDes, nil
}

type mqlAzureSubscriptionComputeServiceSnapshotInternal struct {
	cacheSourceDiskId  *string
	cacheDESId         *string
	cacheSecureVMDESId *string
	cacheSystemData    any
}

func (a *mqlAzureSubscriptionComputeServiceSnapshot) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeService) snapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewSnapshotsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list snapshots due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, snap := range page.Value {
			if snap == nil {
				continue
			}
			mqlSnap, err := snapshotToMql(a.MqlRuntime, *snap)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSnap)
		}
	}

	return res, nil
}

func snapshotToMql(runtime *plugin.Runtime, snap compute.Snapshot) (*mqlAzureSubscriptionComputeServiceSnapshot, error) {
	properties, err := convert.JsonToDict(snap.Properties)
	if err != nil {
		return nil, err
	}
	sku, err := convert.JsonToDict(snap.SKU)
	if err != nil {
		return nil, err
	}

	systemData, err := convert.JsonToDict(snap.SystemData)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(snap.ID),
		"name":       llx.StringDataPtr(snap.Name),
		"location":   llx.StringDataPtr(snap.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(snap.Tags), types.String),
		"type":       llx.StringDataPtr(snap.Type),
		"sku":        llx.DictData(sku),
		"properties": llx.DictData(properties),
	}
	snapSku := orZero(snap.SKU)
	if err := setSkuData(runtime, args, skuName(snapSku.Name), skuTier(snapSku.Tier)); err != nil {
		return nil, err
	}

	var cacheSourceDiskId, cacheDESId, cacheSecureVMDESId *string
	if snap.Properties != nil {
		props := snap.Properties
		creationData, err := convert.JsonToDict(props.CreationData)
		if err != nil {
			return nil, err
		}
		args["creationData"] = llx.DictData(creationData)
		args["provisioningState"] = llx.StringDataPtr(props.ProvisioningState)
		args["timeCreated"] = llx.TimeDataPtr(props.TimeCreated)
		args["uniqueId"] = llx.StringDataPtr(props.UniqueID)
		args["diskSizeBytes"] = llx.IntDataPtr(props.DiskSizeBytes)
		args["hyperVGeneration"] = llx.StringDataPtr(stringEnumPtr(props.HyperVGeneration))
		args["osType"] = llx.StringDataPtr(stringEnumPtr(props.OSType))
		args["diskState"] = llx.StringDataPtr(stringEnumPtr(props.DiskState))
		args["incremental"] = llx.BoolDataPtr(props.Incremental)
		args["incrementalSnapshotFamilyId"] = llx.StringDataPtr(props.IncrementalSnapshotFamilyID)
		args["supportsHibernation"] = llx.BoolDataPtr(props.SupportsHibernation)
		args["networkAccessPolicy"] = llx.StringDataPtr(stringEnumPtr(props.NetworkAccessPolicy))
		args["publicNetworkAccess"] = llx.StringDataPtr(stringEnumPtr(props.PublicNetworkAccess))
		var encryptionType *compute.EncryptionType
		if props.Encryption != nil {
			encryptionType = props.Encryption.Type
			cacheDESId = props.Encryption.DiskEncryptionSetID
		}
		args["encryptionType"] = llx.StringDataPtr(stringEnumPtr(encryptionType))
		var encryptionSettingsEnabled *bool
		var encryptionSettingsVersion *string
		if esc := props.EncryptionSettingsCollection; esc != nil {
			encryptionSettingsEnabled = esc.Enabled
			encryptionSettingsVersion = esc.EncryptionSettingsVersion
		}
		args["encryptionSettingsEnabled"] = llx.BoolDataPtr(encryptionSettingsEnabled)
		args["encryptionSettingsVersion"] = llx.StringDataPtr(encryptionSettingsVersion)
		var securityType *compute.DiskSecurityTypes
		var confidentialVMVersion *compute.ConfidentialVMVersion
		if sp := props.SecurityProfile; sp != nil {
			securityType = sp.SecurityType
			confidentialVMVersion = sp.ConfidentialVMVersion
			cacheSecureVMDESId = sp.SecureVMDiskEncryptionSetID
		}
		args["securityType"] = llx.StringDataPtr(stringEnumPtr(securityType))
		args["confidentialVmVersion"] = llx.StringDataPtr(stringEnumPtr(confidentialVMVersion))
		args["diskSizeGB"] = llx.IntDataPtr(props.DiskSizeGB)
		args["completionPercent"] = llx.FloatDataPtr(props.CompletionPercent)
		args["dataAccessAuthMode"] = llx.StringDataPtr(stringEnumPtr(props.DataAccessAuthMode))
		args["diskAccessId"] = llx.StringDataPtr(props.DiskAccessID)
		args["snapshotAccessState"] = llx.StringDataPtr(stringEnumPtr(props.SnapshotAccessState))

		if props.CreationData != nil {
			cacheSourceDiskId = props.CreationData.SourceResourceID
			args["instantAccessDurationMinutes"] = llx.IntDataPtr(props.CreationData.InstantAccessDurationMinutes)
		}

		// Always set the immutability policy fields so they resolve to null
		// (not their Go zero value) when no policy is applied. Leaving them
		// absent from args would make immutabilityPolicyExpired default to
		// false, wrongly passing audits like `!immutabilityPolicyExpired`
		// for snapshots that have no immutability protection at all.
		var ipType *compute.ImmutabilityPolicyType
		var ipDurationDays *int32
		var ipExpired *bool
		var ipStartTime, ipExpirationTime *time.Time
		if ip := props.ImmutabilityPolicy; ip != nil {
			ipType = ip.Type
			ipDurationDays = ip.ImmutabilityDurationDays
			ipExpired = ip.IsPolicyExpired
			ipStartTime = ip.PolicyStartTime
			ipExpirationTime = ip.PolicyExpirationTime
		}
		args["immutabilityPolicyType"] = llx.StringDataPtr(stringEnumPtr(ipType))
		args["immutabilityPolicyDurationDays"] = llx.IntDataPtr(ipDurationDays)
		args["immutabilityPolicyExpired"] = llx.BoolDataPtr(ipExpired)
		args["immutabilityPolicyStartTime"] = llx.TimeDataPtr(ipStartTime)
		args["immutabilityPolicyExpirationTime"] = llx.TimeDataPtr(ipExpirationTime)
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.snapshot", args)
	if err != nil {
		return nil, err
	}
	mqlSnap := res.(*mqlAzureSubscriptionComputeServiceSnapshot)
	mqlSnap.cacheSourceDiskId = cacheSourceDiskId
	mqlSnap.cacheDESId = cacheDESId
	mqlSnap.cacheSecureVMDESId = cacheSecureVMDESId
	mqlSnap.cacheSystemData = systemData
	return mqlSnap, nil
}

// secureVmDiskEncryptionSet resolves the encryption set protecting a
// confidential VM's guest state, carried over from the source disk. Null on
// every snapshot other than one of a ConfidentialVM_DiskEncryptedWithCustomerKey
// disk.
func (a *mqlAzureSubscriptionComputeServiceSnapshot) secureVmDiskEncryptionSet() (*mqlAzureSubscriptionComputeServiceDiskEncryptionSet, error) {
	return resolveSecureVMDiskEncryptionSet(a.MqlRuntime, a.cacheSecureVMDESId, &a.SecureVmDiskEncryptionSet)
}

func (a *mqlAzureSubscriptionComputeServiceSnapshot) sourceDisk() (*mqlAzureSubscriptionComputeServiceDisk, error) {
	if a.cacheSourceDiskId == nil || *a.cacheSourceDiskId == "" {
		a.SourceDisk.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// CreationData.SourceResourceID can also point to another snapshot or a
	// gallery image. Filter to managed disks only.
	parsed, err := ParseResourceID(*a.cacheSourceDiskId)
	if err != nil {
		a.SourceDisk.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if _, ok := parsed.Path["disks"]; !ok {
		a.SourceDisk.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.computeService.disk", map[string]*llx.RawData{
		"id": llx.StringData(strings.ToLower(*a.cacheSourceDiskId)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceDisk), nil
}

func (a *mqlAzureSubscriptionComputeServiceSnapshot) diskEncryptionSet() (*mqlAzureSubscriptionComputeServiceDiskEncryptionSet, error) {
	if a.cacheDESId == nil || *a.cacheDESId == "" {
		a.DiskEncryptionSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.computeService.diskEncryptionSet", map[string]*llx.RawData{
		"id": llx.StringData(strings.ToLower(*a.cacheDESId)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceDiskEncryptionSet), nil
}

func (a *mqlAzureSubscriptionComputeServiceDisk) diskEncryptionSet() (*mqlAzureSubscriptionComputeServiceDiskEncryptionSet, error) {
	id := a.DiskEncryptionSetId.Data
	if id == "" {
		a.DiskEncryptionSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.computeService.diskEncryptionSet", map[string]*llx.RawData{
		"id": llx.StringData(strings.ToLower(id)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceDiskEncryptionSet), nil
}

func vmImageReferenceToMql(runtime *plugin.Runtime, vmID string, props *compute.VirtualMachineProperties) (*mqlAzureSubscriptionComputeServiceVmImageReference, error) {
	var ref *compute.ImageReference
	if props != nil && props.StorageProfile != nil {
		ref = props.StorageProfile.ImageReference
	}
	publisher := ""
	offer := ""
	sku := ""
	version := ""
	exactVersion := ""
	imageId := ""
	sharedGalleryId := ""
	communityGalleryId := ""
	if ref != nil {
		if ref.Publisher != nil {
			publisher = *ref.Publisher
		}
		if ref.Offer != nil {
			offer = *ref.Offer
		}
		if ref.SKU != nil {
			sku = *ref.SKU
		}
		if ref.Version != nil {
			version = *ref.Version
		}
		if ref.ExactVersion != nil {
			exactVersion = *ref.ExactVersion
		}
		if ref.ID != nil {
			imageId = *ref.ID
		}
		if ref.SharedGalleryImageID != nil {
			sharedGalleryId = *ref.SharedGalleryImageID
		}
		if ref.CommunityGalleryImageID != nil {
			communityGalleryId = *ref.CommunityGalleryImageID
		}
	}
	id := vmID + "/imageReference"
	res, err := CreateResource(runtime, "azure.subscription.computeService.vm.imageReference",
		map[string]*llx.RawData{
			"__id":                    llx.StringData(id),
			"publisher":               llx.StringData(publisher),
			"offer":                   llx.StringData(offer),
			"sku":                     llx.StringData(sku),
			"version":                 llx.StringData(version),
			"exactVersion":            llx.StringData(exactVersion),
			"imageId":                 llx.StringData(imageId),
			"sharedGalleryImageId":    llx.StringData(sharedGalleryId),
			"communityGalleryImageId": llx.StringData(communityGalleryId),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceVmImageReference), nil
}

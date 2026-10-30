// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	aci "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionContainerInstanceService) id() (string, error) {
	return "azure.subscription.containerInstanceService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionContainerInstanceServiceContainerGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerInstanceServiceContainerGroupContainer) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionContainerInstanceService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionContainerInstanceService) containerGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	client, err := aci.NewContainerGroupsClient(subId, conn.Token(), &arm.ClientOptions{
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
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure containerGroups, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlGroup, err := aciContainerGroupToMQL(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
	}
	return res, nil
}

// redactedImageRegistryCredentials copies the registry credentials with the
// registry passwords removed.
//
// The password authenticates to the private registry the group pulls from, and
// the audit signal it would serve is already carried by registryAuthUsesIdentity,
// which is computed from the same records. The server, username and identity
// are kept, so a check on which registry a group pulls from and whether it
// authenticates with a managed identity reads as before.
//
// The copy is by field rather than by JSON key so that a field renamed in a
// future SDK breaks the build instead of silently leaking again.
func redactedImageRegistryCredentials(creds []*aci.ImageRegistryCredential) []*aci.ImageRegistryCredential {
	if creds == nil {
		return nil
	}
	out := make([]*aci.ImageRegistryCredential, 0, len(creds))
	for _, cred := range creds {
		if cred == nil {
			out = append(out, nil)
			continue
		}
		safe := *cred
		safe.Password = nil
		out = append(out, &safe)
	}
	return out
}

// redactedVolumes copies the group's volumes with the secret-volume contents
// and the Azure File storage account key removed.
//
// A secret volume's map holds the base64 file contents mounted into the
// containers, and the Azure File key grants access to the whole file share.
// The file names are kept as the map's keys, with each value nulled, so a check
// on which files a secret volume mounts still reads while their contents do
// not. Everything else about a volume is kept, including the share name,
// storage account name and read-only flag, and hasSecretVolume is computed from
// the unredacted records.
//
// The copy is by field rather than by JSON key so that a field renamed in a
// future SDK breaks the build instead of silently leaking again.
func redactedVolumes(volumes []*aci.Volume) []*aci.Volume {
	if volumes == nil {
		return nil
	}
	out := make([]*aci.Volume, 0, len(volumes))
	for _, v := range volumes {
		if v == nil {
			out = append(out, nil)
			continue
		}
		safe := *v
		if v.Secret != nil {
			names := make(map[string]*string, len(v.Secret))
			for name := range v.Secret {
				names[name] = nil
			}
			safe.Secret = names
		}
		if v.AzureFile != nil {
			file := *v.AzureFile
			file.StorageAccountKey = nil
			safe.AzureFile = &file
		}
		out = append(out, &safe)
	}
	return out
}

// redactedEnvironmentVariables copies a container's environment with the secure
// values removed.
//
// SecureValue is the write-only half of an ACI environment variable, the one
// callers use precisely because the value is a credential. The variable's name
// is kept, so a check on which secure variables a container declares still
// reads; only the value is dropped. Plain Value entries are not secure by
// declaration and are kept as before.
//
// The copy is by field rather than by JSON key so that a field renamed in a
// future SDK breaks the build instead of silently leaking again.
func redactedEnvironmentVariables(env []*aci.EnvironmentVariable) []*aci.EnvironmentVariable {
	if env == nil {
		return nil
	}
	out := make([]*aci.EnvironmentVariable, 0, len(env))
	for _, e := range env {
		if e == nil {
			out = append(out, nil)
			continue
		}
		safe := *e
		safe.SecureValue = nil
		out = append(out, &safe)
	}
	return out
}

func aciContainerGroupToMQL(runtime *plugin.Runtime, entry *aci.ContainerGroup) (plugin.Resource, error) {
	var provisioningState, osType, restartPolicy, sku, ccePolicyHash string
	var ipAddressType, publicIp, fqdn, dnsLabelScope string
	var priority string
	confidential := false
	subnetIds := []any{}
	dnsConfig := map[string]any{}
	imageRegistry := []any{}
	registryUsesIdentity := false
	volumes := []any{}
	hasSecretVolume := false
	logAnalyticsWorkspaceId := ""
	encryption := map[string]any{}
	exposedPorts := []any{}
	zones := []any{}
	identity := map[string]any{}
	containerSpecs := []*aci.Container{}
	initContainerSpecs := []*aci.Container{}

	if entry.Identity != nil {
		d, err := convert.JsonToDict(entry.Identity)
		if err != nil {
			return nil, err
		}
		identity = d
	}
	for _, z := range entry.Zones {
		if z != nil {
			zones = append(zones, *z)
		}
	}

	props := entry.Properties
	if props != nil {
		if props.ProvisioningState != nil {
			provisioningState = *props.ProvisioningState
		}
		if props.OSType != nil {
			osType = string(*props.OSType)
		}
		if props.RestartPolicy != nil {
			restartPolicy = string(*props.RestartPolicy)
		}
		if props.SKU != nil {
			sku = string(*props.SKU)
			confidential = sku == string(aci.ContainerGroupSKUConfidential)
		}
		if props.ConfidentialComputeProperties != nil && props.ConfidentialComputeProperties.CcePolicy != nil {
			ccePolicyHash = *props.ConfidentialComputeProperties.CcePolicy
		}
		if props.Priority != nil {
			priority = string(*props.Priority)
		}
		if props.IPAddress != nil {
			ip := props.IPAddress
			if ip.Type != nil {
				ipAddressType = string(*ip.Type)
			}
			if ip.IP != nil {
				publicIp = *ip.IP
			}
			if ip.Fqdn != nil {
				fqdn = *ip.Fqdn
			}
			if ip.AutoGeneratedDomainNameLabelScope != nil {
				dnsLabelScope = string(*ip.AutoGeneratedDomainNameLabelScope)
			}
			if len(ip.Ports) > 0 {
				d, err := convert.JsonToDictSlice(ip.Ports)
				if err != nil {
					return nil, err
				}
				exposedPorts = d
			}
		}
		for _, sn := range props.SubnetIDs {
			if sn != nil && sn.ID != nil {
				subnetIds = append(subnetIds, *sn.ID)
			}
		}
		if props.DNSConfig != nil {
			d, err := convert.JsonToDict(props.DNSConfig)
			if err != nil {
				return nil, err
			}
			dnsConfig = d
		}
		if len(props.ImageRegistryCredentials) > 0 {
			d, err := convert.JsonToDictSlice(redactedImageRegistryCredentials(props.ImageRegistryCredentials))
			if err != nil {
				return nil, err
			}
			imageRegistry = d
			for _, cred := range props.ImageRegistryCredentials {
				if cred != nil && cred.Identity != nil && *cred.Identity != "" {
					registryUsesIdentity = true
				}
			}
		}
		if len(props.Volumes) > 0 {
			d, err := convert.JsonToDictSlice(redactedVolumes(props.Volumes))
			if err != nil {
				return nil, err
			}
			volumes = d
			for _, v := range props.Volumes {
				if v != nil && v.Secret != nil {
					hasSecretVolume = true
				}
			}
		}
		if props.Diagnostics != nil && props.Diagnostics.LogAnalytics != nil && props.Diagnostics.LogAnalytics.WorkspaceID != nil {
			logAnalyticsWorkspaceId = *props.Diagnostics.LogAnalytics.WorkspaceID
		}
		if props.EncryptionProperties != nil {
			d, err := convert.JsonToDict(props.EncryptionProperties)
			if err != nil {
				return nil, err
			}
			encryption = d
		}
		containerSpecs = props.Containers
		for _, ic := range props.InitContainers {
			if ic == nil || ic.Properties == nil {
				continue
			}
			c := &aci.Container{
				Name: ic.Name,
				Properties: &aci.ContainerProperties{
					Image:                ic.Properties.Image,
					Command:              ic.Properties.Command,
					EnvironmentVariables: ic.Properties.EnvironmentVariables,
					VolumeMounts:         ic.Properties.VolumeMounts,
					SecurityContext:      ic.Properties.SecurityContext,
				},
			}
			initContainerSpecs = append(initContainerSpecs, c)
		}
	}

	groupArgs := map[string]*llx.RawData{
		"id":                       llx.StringDataPtr(entry.ID),
		"name":                     llx.StringDataPtr(entry.Name),
		"location":                 llx.StringDataPtr(entry.Location),
		"tags":                     llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
		"provisioningState":        llx.StringData(provisioningState),
		"osType":                   llx.StringData(osType),
		"restartPolicy":            llx.StringData(restartPolicy),
		"sku":                      llx.StringData(sku),
		"confidential":             llx.BoolData(confidential),
		"ccePolicyHash":            llx.StringData(ccePolicyHash),
		"identity":                 llx.DictData(identity),
		"ipAddressType":            llx.StringData(ipAddressType),
		"publicIp":                 llx.StringData(publicIp),
		"fqdn":                     llx.StringData(fqdn),
		"dnsNameLabelReusePolicy":  llx.StringData(dnsLabelScope),
		"exposedPorts":             llx.ArrayData(exposedPorts, types.Dict),
		"subnetIds":                llx.ArrayData(subnetIds, types.String),
		"dnsConfig":                llx.DictData(dnsConfig),
		"imageRegistryCredentials": llx.ArrayData(imageRegistry, types.Dict),
		"registryAuthUsesIdentity": llx.BoolData(registryUsesIdentity),
		"volumes":                  llx.ArrayData(volumes, types.Dict),
		"hasSecretVolume":          llx.BoolData(hasSecretVolume),
		"logAnalyticsWorkspaceId":  llx.StringData(logAnalyticsWorkspaceId),
		"encryption":               llx.DictData(encryption),
		"priority":                 llx.StringData(priority),
		"zones":                    llx.ArrayData(zones, types.String),
	}
	groupIdentity := orZero(entry.Identity)
	if err := setResourceIdentity(runtime, groupArgs, sortedUserAssignedIdentityIDs(groupIdentity.UserAssignedIdentities),
		identityType(groupIdentity.Type), identityPrincipalId(groupIdentity.PrincipalID), identityTenantId(groupIdentity.TenantID)); err != nil {
		return nil, err
	}

	mqlGroup, err := CreateResource(runtime, "azure.subscription.containerInstanceService.containerGroup", groupArgs)
	if err != nil {
		return nil, err
	}

	groupRes := mqlGroup.(*mqlAzureSubscriptionContainerInstanceServiceContainerGroup)

	containers, err := aciContainersToMQL(runtime, groupRes.Id.Data, containerSpecs, "containers")
	if err != nil {
		return nil, err
	}
	initContainers, err := aciContainersToMQL(runtime, groupRes.Id.Data, initContainerSpecs, "initContainers")
	if err != nil {
		return nil, err
	}
	groupRes.Containers = plugin.TValue[[]any]{Data: containers, State: plugin.StateIsSet}
	groupRes.InitContainers = plugin.TValue[[]any]{Data: initContainers, State: plugin.StateIsSet}

	return groupRes, nil
}

type mqlAzureSubscriptionContainerInstanceServiceContainerGroupInternal struct {
}

func aciContainersToMQL(runtime *plugin.Runtime, parentId string, specs []*aci.Container, segment string) ([]any, error) {
	res := []any{}
	for _, c := range specs {
		if c == nil || c.Properties == nil {
			continue
		}
		var name, image, gpuSku string
		if c.Name != nil {
			name = *c.Name
		}
		if c.Properties.Image != nil {
			image = *c.Properties.Image
		}

		var cpu, memoryGB *float64
		var gpuCount *int32
		if c.Properties.Resources != nil && c.Properties.Resources.Requests != nil {
			req := c.Properties.Resources.Requests
			cpu = req.CPU
			memoryGB = req.MemoryInGB
			if req.Gpu != nil {
				gpuCount = req.Gpu.Count
				if req.Gpu.SKU != nil {
					gpuSku = string(*req.Gpu.SKU)
				}
			}
		}

		command := []any{}
		for _, s := range c.Properties.Command {
			if s != nil {
				command = append(command, *s)
			}
		}

		env := []any{}
		if len(c.Properties.EnvironmentVariables) > 0 {
			d, err := convert.JsonToDictSlice(redactedEnvironmentVariables(c.Properties.EnvironmentVariables))
			if err != nil {
				return nil, err
			}
			env = d
		}

		ports := []any{}
		if len(c.Properties.Ports) > 0 {
			d, err := convert.JsonToDictSlice(c.Properties.Ports)
			if err != nil {
				return nil, err
			}
			ports = d
		}

		mounts := []any{}
		if len(c.Properties.VolumeMounts) > 0 {
			d, err := convert.JsonToDictSlice(c.Properties.VolumeMounts)
			if err != nil {
				return nil, err
			}
			mounts = d
		}

		liveness := map[string]any{}
		if c.Properties.LivenessProbe != nil {
			d, err := convert.JsonToDict(c.Properties.LivenessProbe)
			if err != nil {
				return nil, err
			}
			liveness = d
		}
		readiness := map[string]any{}
		if c.Properties.ReadinessProbe != nil {
			d, err := convert.JsonToDict(c.Properties.ReadinessProbe)
			if err != nil {
				return nil, err
			}
			readiness = d
		}
		var privileged, allowPrivilegeEscalation *bool
		var runAsUser, runAsGroup *int64
		var seccompProfile *string
		addedCapabilities := []any{}
		droppedCapabilities := []any{}
		if sc := c.Properties.SecurityContext; sc != nil {
			privileged = sc.Privileged
			allowPrivilegeEscalation = sc.AllowPrivilegeEscalation
			seccompProfile = sc.SeccompProfile
			if sc.RunAsUser != nil {
				v := int64(*sc.RunAsUser)
				runAsUser = &v
			}
			if sc.RunAsGroup != nil {
				v := int64(*sc.RunAsGroup)
				runAsGroup = &v
			}
			if sc.Capabilities != nil {
				for _, capName := range sc.Capabilities.Add {
					if capName != nil {
						addedCapabilities = append(addedCapabilities, *capName)
					}
				}
				for _, capName := range sc.Capabilities.Drop {
					if capName != nil {
						droppedCapabilities = append(droppedCapabilities, *capName)
					}
				}
			}
		}
		currentState := map[string]any{}
		var restartCount *int32
		if c.Properties.InstanceView != nil {
			if c.Properties.InstanceView.CurrentState != nil {
				d, err := convert.JsonToDict(c.Properties.InstanceView.CurrentState)
				if err != nil {
					return nil, err
				}
				currentState = d
			}
			restartCount = c.Properties.InstanceView.RestartCount
		}

		mqlContainer, err := CreateResource(runtime, "azure.subscription.containerInstanceService.containerGroup.container",
			map[string]*llx.RawData{
				"id":                       llx.StringData(parentId + "/" + segment + "/" + name),
				"name":                     llx.StringData(name),
				"image":                    llx.StringData(image),
				"imagePinned":              llx.BoolData(imagePinnedByDigest(c.Properties.Image)),
				"command":                  llx.ArrayData(command, types.String),
				"env":                      llx.ArrayData(env, types.Dict),
				"cpuCores":                 llx.FloatData(convert.ToValue(cpu)),
				"memoryGB":                 llx.FloatData(convert.ToValue(memoryGB)),
				"gpuCount":                 llx.IntDataDefault(gpuCount, 0),
				"gpuSku":                   llx.StringData(gpuSku),
				"ports":                    llx.ArrayData(ports, types.Dict),
				"volumeMounts":             llx.ArrayData(mounts, types.Dict),
				"livenessProbe":            llx.DictData(liveness),
				"readinessProbe":           llx.DictData(readiness),
				"privileged":               llx.BoolDataPtr(privileged),
				"allowPrivilegeEscalation": llx.BoolDataPtr(allowPrivilegeEscalation),
				"runAsUser":                llx.IntDataPtr(runAsUser),
				"runAsGroup":               llx.IntDataPtr(runAsGroup),
				"seccompProfile":           llx.StringDataPtr(seccompProfile),
				"addedCapabilities":        llx.ArrayData(addedCapabilities, types.String),
				"droppedCapabilities":      llx.ArrayData(droppedCapabilities, types.String),
				"currentState":             llx.DictData(currentState),
				"restartCount":             llx.IntDataDefault(restartCount, 0),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlContainer)
	}
	return res, nil
}

// containers/initContainers are populated eagerly when the group is created.
func (a *mqlAzureSubscriptionContainerInstanceServiceContainerGroup) containers() ([]any, error) {
	return []any{}, nil
}

func (a *mqlAzureSubscriptionContainerInstanceServiceContainerGroup) initContainers() ([]any, error) {
	return []any{}, nil
}

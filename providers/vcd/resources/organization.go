// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"

	"go.mondoo.com/mql/providers/vcd/connection"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"

	"github.com/vmware/go-vcloud-director/v3/types/v56"

	"github.com/rs/zerolog/log"
	"github.com/vmware/go-vcloud-director/v3/govcd"
)

func (v *mqlVcd) organizations() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	orgs, err := client.GetOrgList()
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range orgs.Org {
		entry, err := newMqlVcdOrganization(v.MqlRuntime, orgs.Org[i])
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, nil
}

func newMqlVcdOrganization(runtime *plugin.Runtime, org *types.Org) (any, error) {
	return CreateResource(runtime, "vcd.organization", map[string]*llx.RawData{
		"id":          llx.StringData(org.ID),
		"name":        llx.StringData(org.Name),
		"fullName":    llx.StringData(org.FullName),
		"isEnabled":   llx.BoolData(org.IsEnabled),
		"description": llx.StringData(org.Description),
	})
}

func (v *mqlVcdOrganization) id() (string, error) {
	return "vcd.organization/" + v.Name.Data, v.Name.Error
}

func (v *mqlVcdOrganization) settings() (any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	name := v.Name.Data

	adminOrgClient, err := client.GetAdminOrgByName(name)
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(adminOrgClient.AdminOrg.OrgSettings)
}

// https://developer.broadcom.com/xapis/vmware-cloud-director-api/latest/doc/types/OrgLdapSettingsType.html
func (v *mqlVcdOrganization) ldapConfiguration() (*mqlVcdOrganizationLdapSettings, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	name := v.Name.Data

	adminOrgClient, err := client.GetAdminOrgByName(name)
	if err != nil {
		return nil, err
	}

	ldapConfig, err := adminOrgClient.GetLdapConfiguration()
	if err != nil {
		return nil, err
	}

	return newMqlVcdOrgLdapConfiguration(v.MqlRuntime, ldapConfig)
}

func newMqlVcdOrgLdapConfiguration(runtime *plugin.Runtime, org *types.OrgLdapSettingsType) (*mqlVcdOrganizationLdapSettings, error) {
	hostname := ""
	username := ""
	realm := ""
	if org.CustomOrgLdapSettings != nil {
		hostname = org.CustomOrgLdapSettings.HostName
		username = org.CustomOrgLdapSettings.Username
		realm = org.CustomOrgLdapSettings.Realm
	}
	r, err := CreateResource(runtime, "vcd.organization.ldapSettings", map[string]*llx.RawData{
		"id":            llx.StringData(org.HREF),
		"customUsersOu": llx.StringData(org.CustomUsersOu),
		"orgLdapMode":   llx.StringData(org.OrgLdapMode),
		"hostname":      llx.StringData(hostname),
		"username":      llx.StringData(username),
		"realm":         llx.StringData(realm),
	})
	if err != nil {
		return nil, err
	}

	return r.(*mqlVcdOrganizationLdapSettings), nil
}

func (v *mqlVcdOrganizationLdapSettings) id() (string, error) {
	return "vcd.organization.ldapSettings/" + v.Id.Data, v.Id.Error
}

// https://developer.broadcom.com/xapis/vmware-cloud-director-api/latest/doc/types/QueryResultAdminVMRecordType.html
func (v *mqlVcdOrganization) vms() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	name := v.Name.Data

	orgClient, err := client.GetOrgByName(name)
	if err != nil {
		return nil, err
	}
	vmList, err := orgClient.QueryVmList(types.VmQueryFilterAll)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range vmList {
		entry, err := newMqlVcdVm(v.MqlRuntime, vmList[i])
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, nil
}

func newMqlVcdVm(runtime *plugin.Runtime, vm *types.QueryResultVMRecordType) (any, error) {
	totalStorage := int64(0)
	if vm.TotalStorageAllocatedMb != "" {
		// this value can be ""
		num, err := strconv.Atoi(vm.TotalStorageAllocatedMb)
		if err == nil {
			totalStorage = int64(num)
		} else {
			log.Error().Err(err).Msg("value: " + vm.TotalStorageAllocatedMb)
		}
	}

	return CreateResource(runtime, "vcd.vm", map[string]*llx.RawData{
		"id":                       llx.StringData(vm.ID),
		"name":                     llx.StringData(vm.Name),
		"containerName":            llx.StringData(vm.ContainerName),
		"containerID":              llx.StringData(vm.ContainerID),
		"ownerId":                  llx.StringData(vm.Owner),
		"ownerName":                llx.StringData(vm.OwnerName),
		"isDeleted":                llx.BoolData(vm.Deleted),
		"guestOs":                  llx.StringData(vm.GuestOS),
		"numberOfCpus":             llx.IntData(int64(vm.Cpus)),
		"memoryMB":                 llx.IntData(int64(vm.MemoryMB)),
		"status":                   llx.StringData(vm.Status),
		"networkName":              llx.StringData(vm.NetworkName),
		"ipAddress":                llx.StringData(vm.IpAddress),
		"isBusy":                   llx.BoolData(vm.Busy),
		"isDeployed":               llx.BoolData(vm.Deployed),
		"isPublished":              llx.BoolData(vm.Published),
		"catalogName":              llx.StringData(vm.CatalogName),
		"hardwareVersion":          llx.IntData(int64(vm.HardwareVersion)),
		"vmToolsStatus":            llx.StringData(vm.VmToolsStatus),
		"isInMaintenanceMode":      llx.BoolData(vm.MaintenanceMode),
		"isAutoNature":             llx.BoolData(vm.AutoNature),
		"storageProfileName":       llx.StringData(vm.StorageProfileName),
		"gcStatus":                 llx.StringData(vm.GcStatus),
		"isComputePolicyCompliant": llx.BoolData(vm.IsComputePolicyCompliant),
		"encrypted":                llx.BoolData(vm.Encrypted),
		"totalStorageAllocatedMb":  llx.IntData(totalStorage),
		"isExpired":                llx.BoolData(vm.IsExpired),
		"hostName":                 llx.StringData(vm.HostName),
	})
}

func (v *mqlVcdVm) id() (string, error) {
	return "vcd.vm/" + v.Name.Data, v.Name.Error
}

// https://developer.broadcom.com/xapis/vmware-cloud-director-api/latest/doc/types/OrganizationRightsType.html
func (v *mqlVcdOrganization) rights() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	name := v.Name.Data

	adminOrgClient, err := client.GetAdminOrgByName(name)
	if err != nil {
		return nil, err
	}

	rightList, err := adminOrgClient.GetAllRights(nil)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range rightList {
		entry, err := newMqlVcdRight(v.MqlRuntime, rightList[i])
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, nil
}

func newMqlVcdRight(runtime *plugin.Runtime, right *types.Right) (any, error) {
	return CreateResource(runtime, "vcd.right", map[string]*llx.RawData{
		"id":               llx.StringData(right.ID),
		"name":             llx.StringData(right.Name),
		"description":      llx.StringData(right.Description),
		"bundleKey":        llx.StringData(right.BundleKey),
		"category":         llx.StringData(right.Category),
		"serviceNamespace": llx.StringData(right.ServiceNamespace),
		"rightType":        llx.StringData(right.RightType),
	})
}

func (v *mqlVcdRight) id() (string, error) {
	return "vcd.right/" + v.Name.Data, v.Name.Error
}

// see https://developer.broadcom.com/xapis/vmware-cloud-director-api/latest/doc/types/AdminVdcType.html
func (v *mqlVcdOrganization) vdcs() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	name := v.Name.Data

	adminOrgClient, err := client.GetAdminOrgByName(name)
	if err != nil {
		return nil, err
	}

	vdcList, err := adminOrgClient.GetAllVDCs(false)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range vdcList {
		entry, err := newMqlVcdVdc(v.MqlRuntime, vdcList[i])
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, nil
}

func newMqlVcdVdc(runtime *plugin.Runtime, dataCenter *govcd.Vdc) (*mqlVcdVdc, error) {
	res, err := CreateResource(runtime, "vcd.vdc", map[string]*llx.RawData{
		"id":               llx.StringData(dataCenter.Vdc.ID),
		"name":             llx.StringData(dataCenter.Vdc.Name),
		"description":      llx.StringData(dataCenter.Vdc.Description),
		"status":           llx.IntData(int64(dataCenter.Vdc.Status)),
		"allocationModel":  llx.StringData(dataCenter.Vdc.AllocationModel),
		"nicQuota":         llx.IntData(int64(dataCenter.Vdc.NicQuota)),
		"networkQuota":     llx.IntData(int64(dataCenter.Vdc.NetworkQuota)),
		"usedNetworkCount": llx.IntData(int64(dataCenter.Vdc.UsedNetworkCount)),
		"vmQuota":          llx.IntData(int64(dataCenter.Vdc.VMQuota)),
		"isEnabled":        llx.BoolData(dataCenter.Vdc.IsEnabled),
	})
	if err != nil {
		return nil, err
	}
	r := res.(*mqlVcdVdc)
	r.vcd = dataCenter

	return r, nil
}

type mqlVcdVdcInternal struct {
	vcd *govcd.Vdc
}

func (v *mqlVcdVdc) id() (string, error) {
	return "vcd.vdc/" + v.Name.Data, v.Name.Error
}

func (v *mqlVcdOrganization) vdcGroups() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	name := v.Name.Data

	adminOrgClient, err := client.GetAdminOrgByName(name)
	if err != nil {
		return nil, err
	}

	vdcGroupList, err := adminOrgClient.GetAllVdcGroups(nil)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range vdcGroupList {
		entry, err := newMqlVcdVdcGroup(v.MqlRuntime, vdcGroupList[i].VdcGroup)
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, nil
}

func newMqlVcdVdcGroup(runtime *plugin.Runtime, grp *types.VdcGroup) (any, error) {
	return CreateResource(runtime, "vcd.vdcGroup", map[string]*llx.RawData{
		"name":                       llx.StringData(grp.Name),
		"description":                llx.StringData(grp.Description),
		"localEgress":                llx.BoolData(grp.LocalEgress),
		"status":                     llx.StringData(grp.Status),
		"type":                       llx.StringData(grp.Type),
		"universalNetworkingEnabled": llx.BoolData(grp.UniversalNetworkingEnabled),
		"dfwEnabled":                 llx.BoolData(grp.DfwEnabled),
	})
}

func (v *mqlVcdVdcGroup) id() (string, error) {
	return "vcd.vdcGroup/" + v.Name.Data, v.Name.Error
}

// https://developer.broadcom.com/xapis/vmware-cloud-director-api/latest/doc/types/RoleType.html
func (v *mqlVcdOrganization) roles() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	name := v.Name.Data

	adminOrgClient, err := client.GetAdminOrgByName(name)
	if err != nil {
		return nil, err
	}

	rolesList, err := adminOrgClient.GetAllRoles(nil)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range rolesList {
		entry, err := newMqlVcdRole(v.MqlRuntime, rolesList[i].Role)
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, nil
}

func newMqlVcdRole(runtime *plugin.Runtime, role *types.Role) (any, error) {
	return CreateResource(runtime, "vcd.role", map[string]*llx.RawData{
		"id":          llx.StringData(role.ID),
		"name":        llx.StringData(role.Name),
		"description": llx.StringData(role.Description),
	})
}

func (v *mqlVcdRole) id() (string, error) {
	return "vcd.role/" + v.Id.Data, v.Id.Error
}

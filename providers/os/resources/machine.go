// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

type mqlMachineInternal struct {
	smbiosInfo plugin.TValue[*smbios.SmBiosInfo]
}

func getbiosinfo(runtime *plugin.Runtime) (*smbios.SmBiosInfo, error) {
	obj, err := CreateResource(runtime, "machine", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	machine := obj.(*mqlMachine)

	if machine.smbiosInfo.State&plugin.StateIsSet != 0 {
		return machine.smbiosInfo.Data, machine.smbiosInfo.Error
	}

	conn := runtime.Connection.(shared.Connection)
	pf := conn.Asset().Platform
	pm, err := smbios.ResolveManager(conn, pf)
	if pm == nil || err != nil {
		return nil, fmt.Errorf("could not detect suitable smbios manager for platform")
	}

	// retrieve smbios info
	biosInfo, err := pm.Info()
	if err != nil || biosInfo == nil {
		if err == nil {
			err = errors.New("could not retrieve smbios info")
		}
		machine.smbiosInfo = plugin.TValue[*smbios.SmBiosInfo]{Error: err, State: plugin.StateIsSet}
		return nil, errors.Wrap(err, "could not retrieve smbios info for platform")
	}

	machine.smbiosInfo = plugin.TValue[*smbios.SmBiosInfo]{Data: biosInfo, State: plugin.StateIsSet}
	return machine.smbiosInfo.Data, machine.smbiosInfo.Error
}

func initMachineBios(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	biosInfo, err := getbiosinfo(runtime)
	if err != nil {
		return nil, nil, err
	}

	return map[string]*llx.RawData{
		"vendor":      llx.StringData(biosInfo.BIOS.Vendor),
		"version":     llx.StringData(biosInfo.BIOS.Version),
		"releaseDate": llx.StringData(biosInfo.BIOS.ReleaseDate),
	}, nil, nil
}

func initMachineSystem(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	biosInfo, err := getbiosinfo(runtime)
	if err != nil {
		return nil, nil, err
	}

	return map[string]*llx.RawData{
		"manufacturer": llx.StringData(biosInfo.SysInfo.Vendor),
		"product":      llx.StringData(biosInfo.SysInfo.Model),
		"version":      llx.StringData(biosInfo.SysInfo.Version),
		"serial":       llx.StringData(biosInfo.SysInfo.SerialNumber),
		"uuid":         llx.StringData(biosInfo.SysInfo.UUID),
		"sku":          llx.StringData(biosInfo.SysInfo.SKU),
		"family":       llx.StringData(biosInfo.SysInfo.Family),
	}, nil, nil
}

func initMachineBaseboard(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	biosInfo, err := getbiosinfo(runtime)
	if err != nil {
		return nil, nil, err
	}

	return map[string]*llx.RawData{
		"manufacturer": llx.StringData(biosInfo.BaseBoardInfo.Vendor),
		"product":      llx.StringData(biosInfo.BaseBoardInfo.Model),
		"version":      llx.StringData(biosInfo.BaseBoardInfo.Version),
		"serial":       llx.StringData(biosInfo.BaseBoardInfo.SerialNumber),
		"assetTag":     llx.StringData(biosInfo.BaseBoardInfo.AssetTag),
	}, nil, nil
}

func initMachineChassis(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	biosInfo, err := getbiosinfo(runtime)
	if err != nil {
		return nil, nil, err
	}

	return map[string]*llx.RawData{
		"manufacturer": llx.StringData(biosInfo.ChassisInfo.Vendor),
		"version":      llx.StringData(biosInfo.ChassisInfo.Version),
		"serial":       llx.StringData(biosInfo.ChassisInfo.SerialNumber),
		"assetTag":     llx.StringData(biosInfo.ChassisInfo.AssetTag),
	}, nil, nil
}

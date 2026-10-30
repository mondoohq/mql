// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// stringOrNumber accepts a JSON string or number and stores it as a string.
// system_profiler reports number_processors as a string on Apple Silicon
// (e.g. "proc 16:12:4") but as a plain number on Intel Macs and virtual
// machines (e.g. 2).
type stringOrNumber string

func (s *stringOrNumber) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = ""
		return nil
	}
	if len(data) > 0 && data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*s = stringOrNumber(str)
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(data, &num); err != nil {
		return err
	}
	*s = stringOrNumber(num.String())
	return nil
}

type macosHardwareOverview struct {
	ActivationLockStatus string         `json:"activation_lock_status"`
	BootRomVersion       string         `json:"boot_rom_version"`
	ChipType             string         `json:"chip_type"`
	MachineModel         string         `json:"machine_model"`
	MachineName          string         `json:"machine_name"`
	ModelNumber          string         `json:"model_number"`
	NumberProcessors     stringOrNumber `json:"number_processors"`
	OsLoaderVersion      string         `json:"os_loader_version"`
	PhysicalMemory       string         `json:"physical_memory"`
	PlatformUUID         string         `json:"platform_UUID"`
	ProvisioningUDID     string         `json:"provisioning_UDID"`
	SerialNumber         string         `json:"serial_number"`
}

func parseMacosHardware(jsonData []byte) (*macosHardwareOverview, error) {
	var resp struct {
		SPHardwareDataType []macosHardwareOverview `json:"SPHardwareDataType"`
	}
	if err := json.Unmarshal(jsonData, &resp); err != nil {
		return nil, errors.New("could not gather hardware information")
	}
	if len(resp.SPHardwareDataType) == 0 {
		return nil, errors.New("could not gather hardware information")
	}
	return &resp.SPHardwareDataType[0], nil
}

func initMacosHardware(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if args == nil {
		args = map[string]*llx.RawData{}
	}

	// MQL equivalent in CLI
	// parse.json(content: command('system_profiler SPHardwareDataType -json').stdout).params['SPHardwareDataType'].first['chip_type']
	res, err := NewResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData("system_profiler SPHardwareDataType -json"),
	})
	if err != nil {
		return nil, nil, err
	}

	cmd, ok := res.(*mqlCommand)
	if !ok {
		return nil, nil, errors.New("could not run command")
	}

	hardware, err := parseMacosHardware([]byte(cmd.GetStdout().Data))
	if err != nil {
		return nil, nil, err
	}
	args["activationLockStatus"] = llx.StringData(hardware.ActivationLockStatus)
	args["bootRomVersion"] = llx.StringData(hardware.BootRomVersion)
	args["chipType"] = llx.StringData(hardware.ChipType)
	args["machineModel"] = llx.StringData(hardware.MachineModel)
	args["machineName"] = llx.StringData(hardware.MachineName)
	args["modelNumber"] = llx.StringData(hardware.ModelNumber)
	args["numberProcessors"] = llx.StringData(string(hardware.NumberProcessors))
	args["osLoaderVersion"] = llx.StringData(hardware.OsLoaderVersion)
	args["physicalMemory"] = llx.StringData(hardware.PhysicalMemory)
	args["platformUUID"] = llx.StringData(hardware.PlatformUUID)
	args["provisioningUDID"] = llx.StringData(hardware.ProvisioningUDID)
	args["serialNumber"] = llx.StringData(hardware.SerialNumber)

	return args, nil, nil
}

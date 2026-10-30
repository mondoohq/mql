// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMacosHardwareVirtualMachine(t *testing.T) {
	// Apple Virtual Machine: number_processors is a plain number
	data := []byte(`{
  "SPHardwareDataType" : [
    {
      "_name" : "hardware_overview",
      "activation_lock_status" : "activation_lock_disabled",
      "boot_rom_version" : "mBoot-18000.120.36",
      "chip_type" : "Apple M4 Max (Virtual)",
      "machine_model" : "VirtualMac2,1",
      "machine_name" : "Apple Virtual Machine 1",
      "model_number" : "VM0001LL/A",
      "number_processors" : 2,
      "os_loader_version" : "11881.140.96.701.1",
      "physical_memory" : "4 GB",
      "platform_UUID" : "50DCC3EF-6AD8-5EAA-AC56-451AD340113C",
      "provisioning_UDID" : "4db4fb49aa66c799985e792a6573e713ce8eb024",
      "serial_number" : "ZFQYR4XYHG"
    }
  ]
}`)

	hw, err := parseMacosHardware(data)
	require.NoError(t, err)
	assert.Equal(t, "activation_lock_disabled", hw.ActivationLockStatus)
	assert.Equal(t, "mBoot-18000.120.36", hw.BootRomVersion)
	assert.Equal(t, "Apple M4 Max (Virtual)", hw.ChipType)
	assert.Equal(t, "VirtualMac2,1", hw.MachineModel)
	assert.Equal(t, "Apple Virtual Machine 1", hw.MachineName)
	assert.Equal(t, "VM0001LL/A", hw.ModelNumber)
	assert.Equal(t, "2", string(hw.NumberProcessors))
	assert.Equal(t, "11881.140.96.701.1", hw.OsLoaderVersion)
	assert.Equal(t, "4 GB", hw.PhysicalMemory)
	assert.Equal(t, "50DCC3EF-6AD8-5EAA-AC56-451AD340113C", hw.PlatformUUID)
	assert.Equal(t, "4db4fb49aa66c799985e792a6573e713ce8eb024", hw.ProvisioningUDID)
	assert.Equal(t, "ZFQYR4XYHG", hw.SerialNumber)
}

func TestParseMacosHardwarePhysicalMac(t *testing.T) {
	// Physical Apple Silicon Mac: number_processors is a string like "proc 16:12:4"
	data := []byte(`{
  "SPHardwareDataType" : [
    {
      "_name" : "hardware_overview",
      "activation_lock_status" : "activation_lock_enabled",
      "boot_rom_version" : "11881.140.96",
      "chip_type" : "Apple M4 Max",
      "machine_model" : "Mac16,5",
      "machine_name" : "MacBook Pro",
      "model_number" : "Z1FS0002ULL/A",
      "number_processors" : "proc 16:12:4",
      "os_loader_version" : "11881.140.96",
      "physical_memory" : "48 GB",
      "platform_UUID" : "6D9530A4-90A2-5A28-B133-3D6011CC7772",
      "provisioning_UDID" : "00008400-001E20D40168401E",
      "serial_number" : "C6XW4X7JX1"
    }
  ]
}`)

	hw, err := parseMacosHardware(data)
	require.NoError(t, err)
	assert.Equal(t, "Apple M4 Max", hw.ChipType)
	assert.Equal(t, "proc 16:12:4", string(hw.NumberProcessors))
	assert.Equal(t, "6D9530A4-90A2-5A28-B133-3D6011CC7772", hw.PlatformUUID)
	assert.Equal(t, "00008400-001E20D40168401E", hw.ProvisioningUDID)
}

func TestParseMacosHardwareLowercaseKeys(t *testing.T) {
	// Go's JSON key matching is case-insensitive, so the platform_UUID and
	// provisioning_UDID tags must still match fully lowercase keys
	data := []byte(`{
  "SPHardwareDataType" : [
    {
      "platform_uuid" : "50DCC3EF-6AD8-5EAA-AC56-451AD340113C",
      "provisioning_udid" : "4db4fb49aa66c799985e792a6573e713ce8eb024",
      "serial_number" : "ZFQYR4XYHG"
    }
  ]
}`)

	hw, err := parseMacosHardware(data)
	require.NoError(t, err)
	assert.Equal(t, "50DCC3EF-6AD8-5EAA-AC56-451AD340113C", hw.PlatformUUID)
	assert.Equal(t, "4db4fb49aa66c799985e792a6573e713ce8eb024", hw.ProvisioningUDID)
}

func TestParseMacosHardwareNullNumberProcessors(t *testing.T) {
	data := []byte(`{
  "SPHardwareDataType" : [
    {
      "number_processors" : null,
      "serial_number" : "ZFQYR4XYHG"
    }
  ]
}`)

	hw, err := parseMacosHardware(data)
	require.NoError(t, err)
	assert.Equal(t, "", string(hw.NumberProcessors))
	assert.Equal(t, "ZFQYR4XYHG", hw.SerialNumber)
}

func TestParseMacosHardwareInvalid(t *testing.T) {
	_, err := parseMacosHardware([]byte("not json"))
	assert.Error(t, err)

	_, err = parseMacosHardware([]byte(`{"SPHardwareDataType": []}`))
	assert.Error(t, err)
}

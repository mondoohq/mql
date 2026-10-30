// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// fetchSimulatorVmConfig reads a VM's config back from vcsim, so the devices
// under test have made the round trip through the SOAP encoding.
func fetchSimulatorVmConfig(t *testing.T, ctx context.Context, vm *object.VirtualMachine) *types.VirtualMachineConfigInfo {
	t.Helper()
	var mvm mo.VirtualMachine
	require.NoError(t, vm.Properties(ctx, vm.Reference(), []string{"config"}, &mvm))
	require.NotNil(t, mvm.Config)
	return mvm.Config
}

// Synthetic (vcsim): devices added to a simulator VM through the vSphere API
// and read back from it.
func TestVmPortDevices_Simulator(t *testing.T) {
	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		finder := find.NewFinder(c, true)
		dc, err := finder.DefaultDatacenter(ctx)
		require.NoError(t, err)
		finder.SetDatacenter(dc)
		vms, err := finder.VirtualMachineList(ctx, "*")
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(vms), 2)
		vm, plainVm := vms[0], vms[1]

		devices, err := vm.Device(ctx)
		require.NoError(t, err)

		serial, err := devices.CreateSerialPort()
		require.NoError(t, err)
		serial = devices.ConnectSerialPort(serial, "telnet://:33233", false, "")
		serial.Connectable = &types.VirtualDeviceConnectInfo{StartConnected: true, AllowGuestControl: true}

		floppy, err := devices.CreateFloppy()
		require.NoError(t, err)
		floppy = devices.InsertImg(floppy, "[LocalDS_0] boot.flp")

		parallel := &types.VirtualParallelPort{
			VirtualDevice: types.VirtualDevice{
				Backing: &types.VirtualParallelPortFileBackingInfo{
					VirtualDeviceFileBackingInfo: types.VirtualDeviceFileBackingInfo{FileName: "[LocalDS_0] lpt.out"},
				},
			},
		}
		devices.AssignController(parallel, devices.PickController((*types.VirtualSIOController)(nil)))

		xhci := &types.VirtualUSBXHCIController{AutoConnectDevices: types.NewBool(true)}
		ehci := &types.VirtualUSBController{AutoConnectDevices: types.NewBool(false), EhciEnabled: types.NewBool(true)}

		require.NoError(t, vm.AddDevice(ctx, serial, floppy, parallel, xhci, ehci))
		cfg := fetchSimulatorVmConfig(t, ctx, vm)

		serials := vmSerialPorts(cfg.Hardware.Device)
		require.Len(t, serials, 1)
		assert.Equal(t, "uri", serials[0].backingType)
		require.NotNil(t, serials[0].connectedAtPowerOn)
		assert.True(t, *serials[0].connectedAtPowerOn)
		require.NotNil(t, serials[0].allowGuestControl)
		assert.True(t, *serials[0].allowGuestControl)
		assert.NotZero(t, serials[0].key)

		floppies := vmFloppies(cfg.Hardware.Device)
		require.Len(t, floppies, 1)
		assert.Equal(t, "image", floppies[0].backingType)

		parallels := vmParallelPorts(cfg.Hardware.Device)
		require.Len(t, parallels, 1)
		assert.Equal(t, "file", parallels[0].backingType)

		usb := vmUsbControllers(cfg.Hardware.Device)
		require.Len(t, usb, 2)
		byType := map[string]vmPortDevice{}
		for _, u := range usb {
			byType[u.controllerType] = u
		}
		require.Contains(t, byType, "usb3")
		require.Contains(t, byType, "usb2")
		require.NotNil(t, byType["usb3"].autoConnectDevices)
		assert.True(t, *byType["usb3"].autoConnectDevices)
		require.NotNil(t, byType["usb2"].autoConnectDevices)
		assert.False(t, *byType["usb2"].autoConnectDevices)

		// Device keys build the __id, so every device must carry its own.
		keys := map[int32]bool{}
		for _, d := range append(append(append(serials, floppies...), parallels...), usb...) {
			assert.NotZero(t, d.key)
			assert.False(t, keys[d.key], "duplicate device key %d", d.key)
			keys[d.key] = true
		}

		// A stock simulator VM has none of these devices.
		plainCfg := fetchSimulatorVmConfig(t, ctx, plainVm)
		assert.Empty(t, vmSerialPorts(plainCfg.Hardware.Device))
		assert.Empty(t, vmParallelPorts(plainCfg.Hardware.Device))
		assert.Empty(t, vmFloppies(plainCfg.Hardware.Device))
		assert.Empty(t, vmUsbControllers(plainCfg.Hardware.Device))
	})
}

// Synthetic: device shapes no simulator run produced.
func TestVmPortDevices_Synthetic(t *testing.T) {
	t.Run("label and connection state are read from the device", func(t *testing.T) {
		devices := []types.BaseVirtualDevice{
			&types.VirtualSerialPort{VirtualDevice: types.VirtualDevice{
				Key:         9000,
				DeviceInfo:  &types.Description{Label: "Serial port 1"},
				Backing:     &types.VirtualSerialPortPipeBackingInfo{},
				Connectable: &types.VirtualDeviceConnectInfo{Connected: true, StartConnected: false, AllowGuestControl: false},
			}},
		}
		got := vmSerialPorts(devices)
		require.Len(t, got, 1)
		assert.Equal(t, int32(9000), got[0].key)
		assert.Equal(t, "Serial port 1", got[0].label)
		assert.Equal(t, "pipe", got[0].backingType)
		require.NotNil(t, got[0].connected)
		assert.True(t, *got[0].connected)
		require.NotNil(t, got[0].connectedAtPowerOn)
		assert.False(t, *got[0].connectedAtPowerOn)
		require.NotNil(t, got[0].allowGuestControl)
		assert.False(t, *got[0].allowGuestControl)
	})

	t.Run("absent connection info is null, not false", func(t *testing.T) {
		devices := []types.BaseVirtualDevice{&types.VirtualUSBXHCIController{}}
		got := vmUsbControllers(devices)
		require.Len(t, got, 1)
		assert.Nil(t, got[0].connected)
		assert.Nil(t, got[0].connectedAtPowerOn)
		assert.Nil(t, got[0].allowGuestControl)
		assert.Nil(t, got[0].autoConnectDevices)
		assert.Equal(t, "", got[0].backingType)
	})

	t.Run("backing variants map to their names", func(t *testing.T) {
		serialCases := map[string]types.BaseVirtualDeviceBackingInfo{
			"file":      &types.VirtualSerialPortFileBackingInfo{},
			"pipe":      &types.VirtualSerialPortPipeBackingInfo{},
			"device":    &types.VirtualSerialPortDeviceBackingInfo{},
			"uri":       &types.VirtualSerialPortURIBackingInfo{},
			"thinPrint": &types.VirtualSerialPortThinPrintBackingInfo{},
			"":          nil,
		}
		for want, backing := range serialCases {
			got := vmSerialPorts([]types.BaseVirtualDevice{&types.VirtualSerialPort{VirtualDevice: types.VirtualDevice{Backing: backing}}})
			require.Len(t, got, 1)
			assert.Equal(t, want, got[0].backingType)
		}

		parallelCases := map[string]types.BaseVirtualDeviceBackingInfo{
			"file":   &types.VirtualParallelPortFileBackingInfo{},
			"device": &types.VirtualParallelPortDeviceBackingInfo{},
		}
		for want, backing := range parallelCases {
			got := vmParallelPorts([]types.BaseVirtualDevice{&types.VirtualParallelPort{VirtualDevice: types.VirtualDevice{Backing: backing}}})
			require.Len(t, got, 1)
			assert.Equal(t, want, got[0].backingType)
		}

		floppyCases := map[string]types.BaseVirtualDeviceBackingInfo{
			"image":        &types.VirtualFloppyImageBackingInfo{},
			"device":       &types.VirtualFloppyDeviceBackingInfo{},
			"remoteDevice": &types.VirtualFloppyRemoteDeviceBackingInfo{},
		}
		for want, backing := range floppyCases {
			got := vmFloppies([]types.BaseVirtualDevice{&types.VirtualFloppy{VirtualDevice: types.VirtualDevice{Backing: backing}}})
			require.Len(t, got, 1)
			assert.Equal(t, want, got[0].backingType)
		}
	})

	t.Run("each extractor keeps only its own device type", func(t *testing.T) {
		devices := []types.BaseVirtualDevice{
			&types.VirtualSerialPort{},
			&types.VirtualParallelPort{},
			&types.VirtualFloppy{},
			&types.VirtualUSBController{},
			&types.VirtualCdrom{},
			&types.VirtualSIOController{},
		}
		assert.Len(t, vmSerialPorts(devices), 1)
		assert.Len(t, vmParallelPorts(devices), 1)
		assert.Len(t, vmFloppies(devices), 1)
		assert.Len(t, vmUsbControllers(devices), 1)
	})
}

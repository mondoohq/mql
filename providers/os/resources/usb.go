// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"io"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
	"go.mondoo.com/mql/providers/os/resources/usb"
)

func (d *mqlUsb) devices() ([]any, error) {
	conn := d.MqlRuntime.Connection.(shared.Connection)
	pf := conn.Asset().Platform

	switch usbSourceFor(pf) {
	case usbSourceMacos:
		return d.listMacos()
	case usbSourceLinuxSysfs:
		return d.listLinux()
	default:
		return nil, errUsbUnsupported(pf)
	}
}

func errUsbUnsupported(pf *inventory.Platform) error {
	return errors.New("could not detect usb: " + pf.GetName())
}

type usbSource int

const (
	usbSourceUnsupported usbSource = iota
	usbSourceMacos
	usbSourceLinuxSysfs
)

// usbSourceFor picks where USB devices are read from on a platform.
func usbSourceFor(pf *inventory.Platform) usbSource {
	switch {
	case pf.IsFamily("darwin"):
		return usbSourceMacos
	case pf.IsFamily("linux"):
		return usbSourceLinuxSysfs
	default:
		return usbSourceUnsupported
	}
}

func (d *mqlUsb) listLinux() ([]any, error) {
	conn := d.MqlRuntime.Connection.(shared.Connection)

	devices, err := usb.ParseLinuxSysfs(conn.FileSystem(), usb.LinuxSysfsDevicesDir)
	if err != nil {
		return nil, err
	}
	return d.newUsbDevices(devices)
}

func (d *mqlUsb) listMacos() ([]any, error) {
	conn := d.MqlRuntime.Connection.(shared.Connection)

	cmd, err := conn.RunCommand("ioreg -p IOUSB -l -w 0 -a")
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	plistData, err := plist.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	// Extract USB devices
	var devices []usb.USBDevice
	usb.ParseMacosIORegData(plistData, &devices)

	// A device's LocationID is used as the usb.device resource's unique __id, so
	// devices without one are skipped to avoid blank/colliding cache keys.
	devices = usbDevicesWithLocation(devices)
	return d.newUsbDevices(devices)
}

func (d *mqlUsb) newUsbDevices(devices []usb.USBDevice) ([]any, error) {
	mqlUsbDevices := make([]any, 0, len(devices))
	for _, device := range devices {
		entry, err := CreateResource(d.MqlRuntime, "usb.device", map[string]*llx.RawData{
			"__id":         llx.StringData(device.LocationID),
			"vendorId":     llx.StringData(device.VendorID),
			"manufacturer": llx.StringData(device.Manufacturer),
			"productId":    llx.StringData(device.ProductID),
			"serial":       llx.StringData(device.SerialNumber),
			"name":         llx.StringData(device.Name),
			"version":      llx.StringData(device.FormattedVersion), // BCD Version is not human readable
			"speed":        llx.StringData(device.USBSpeed),
			"class":        llx.StringData(device.DeviceClass),
			"subclass":     llx.StringData(device.DeviceSubClass),
			"className":    llx.StringData(device.DeviceClassName),
			"protocol":     llx.StringData(device.DeviceProtocol),
			"isRemovable":  llx.BoolData(device.IsRemovable),
		})
		if err != nil {
			return nil, err
		}

		mqlUsbDevices = append(mqlUsbDevices, entry)
	}

	return mqlUsbDevices, nil
}

// usbDevicesWithLocation keeps only devices that report a LocationID, which is
// required as the usb.device resource's unique __id. Devices may legitimately
// report an empty DeviceClass (class is often defined per-interface on
// composite devices), so the LocationID — not the class — is the right filter.
func usbDevicesWithLocation(devices []usb.USBDevice) []usb.USBDevice {
	res := make([]usb.USBDevice, 0, len(devices))
	for _, device := range devices {
		if device.LocationID == "" {
			continue
		}
		res = append(res, device)
	}
	return res
}

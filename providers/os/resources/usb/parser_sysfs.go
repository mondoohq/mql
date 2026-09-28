// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package usb

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// LinuxSysfsDevicesDir is where the Linux kernel lists every USB device and
// interface. It is the same source lsusb reads.
const LinuxSysfsDevicesDir = "/sys/bus/usb/devices"

// ParseLinuxSysfs reads the USB devices listed under dir (normally
// LinuxSysfsDevicesDir). A system without a USB subsystem has no such
// directory; that yields an empty list, not an error.
//
// The directory holds one entry per device (root hubs are named "usbN",
// other devices "<bus>-<port>[.<port>...]") and one per interface
// ("<device>:<config>.<interface>"). Only devices are returned.
func ParseLinuxSysfs(fs afero.Fs, dir string) ([]USBDevice, error) {
	names, err := readDirNames(fs, dir)
	if err != nil {
		if exists, statErr := afero.Exists(fs, dir); statErr == nil && !exists {
			return []USBDevice{}, nil
		}
		return nil, err
	}
	sort.Strings(names)

	devices := make([]USBDevice, 0, len(names))
	for _, name := range names {
		if strings.Contains(name, ":") {
			// interface, not a device
			continue
		}
		device, ok := readLinuxSysfsDevice(fs, path.Join(dir, name), name)
		if !ok {
			continue
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func readDirNames(fs afero.Fs, dir string) ([]string, error) {
	f, err := fs.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}

func readLinuxSysfsDevice(fs afero.Fs, devPath string, name string) (USBDevice, bool) {
	attr := func(key string) string {
		data, err := afero.ReadFile(fs, path.Join(devPath, key))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}

	vendorID := attr("idVendor")
	if vendorID == "" {
		// Every USB device has a device descriptor; an entry without one is
		// not a device.
		return USBDevice{}, false
	}

	device := USBDevice{
		LocationID:    name,
		VendorID:      hexAttr(vendorID, 4),
		ProductID:     hexAttr(attr("idProduct"), 4),
		Manufacturer:  attr("manufacturer"),
		Product:       attr("product"),
		Name:          attr("product"),
		SerialNumber:  attr("serial"),
		BusNumber:     attr("busnum"),
		DeviceAddress: attr("devnum"),
		USBSpeed:      formatLinuxUSBSpeed(attr("speed")),
	}

	if class := attr("bDeviceClass"); class != "" {
		device.DeviceClass = hexAttr(class, 2)
		device.DeviceClassName = GetUSBClassDescription(device.DeviceClass)
	}
	if subclass := attr("bDeviceSubClass"); subclass != "" {
		device.DeviceSubClass = hexAttr(subclass, 2)
	}
	if protocol := attr("bDeviceProtocol"); protocol != "" {
		device.DeviceProtocol = hexAttr(protocol, 2)
	}

	if bcd := attr("bcdDevice"); bcd != "" {
		device.BcdDevice = hexAttr(bcd, 4)
		device.FormattedVersion = formatLinuxBcdVersion(bcd)
	}

	device.IsRemovable = isLinuxUSBDeviceRemovable(name, attr("removable"))
	return device, true
}

// hexAttr normalizes a sysfs hex value ("05ac") to the 0x-prefixed form the
// macOS parser produces ("0x05ac"). A value that does not parse is returned
// unchanged.
func hexAttr(value string, width int) string {
	if value == "" {
		return ""
	}
	v, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return value
	}
	return fmt.Sprintf("0x%0*x", width, v)
}

// formatLinuxBcdVersion formats a bcdDevice value ("0612") in the same
// major.minor[.subminor] shape as the macOS parser. Every digit is a BCD
// digit, so the major version is the high byte read as hex digits: "7200" is
// 72.0, the release lsusb reports as 72.00.
func formatLinuxBcdVersion(bcd string) string {
	v, err := strconv.ParseUint(bcd, 16, 16)
	if err != nil {
		return ""
	}
	major := (v >> 8) & 0xFF
	minor := (v >> 4) & 0x0F
	subminor := v & 0x0F
	if subminor > 0 {
		return fmt.Sprintf("%x.%d.%d", major, minor, subminor)
	}
	return fmt.Sprintf("%x.%d", major, minor)
}

// formatLinuxUSBSpeed formats the sysfs speed attribute, which the kernel
// reports in Mbit/s: "1.5", "12", "480", "5000", "10000" or "20000"
// (and "53.3-480" for wireless USB).
func formatLinuxUSBSpeed(speed string) string {
	switch speed {
	case "":
		return ""
	case "1.5":
		return "1.5 Mbps (Low Speed)"
	case "12":
		return "12 Mbps (Full Speed)"
	case "480":
		return "480 Mbps (High Speed)"
	case "5000":
		return "5 Gbps (Super Speed)"
	case "10000":
		return "10 Gbps (Super Speed+)"
	case "20000":
		return "20 Gbps (Super Speed+ Gen 2x2)"
	default:
		return speed + " Mbps"
	}
}

// isLinuxUSBDeviceRemovable interprets the sysfs removable attribute, which
// describes the port a device is plugged into: "removable", "fixed" or
// "unknown". Root hubs are part of the host controller and never removable.
// When the port does not say, the device is treated as removable, the same
// default the macOS parser applies.
func isLinuxUSBDeviceRemovable(name string, removable string) bool {
	if strings.HasPrefix(name, "usb") {
		return false
	}
	return removable != "fixed"
}

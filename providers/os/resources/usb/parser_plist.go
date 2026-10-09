// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package usb

import (
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/plist"
)

type USBDevice struct {
	Name             string
	VendorID         string
	ProductID        string
	Manufacturer     string
	Product          string
	SerialNumber     string
	DeviceClass      string
	DeviceClassName  string
	DeviceSubClass   string
	DeviceProtocol   string
	LocationID       string
	BusNumber        string
	DeviceAddress    string
	USBSpeed         string
	BcdDevice        string
	FormattedVersion string
	IsRemovable      bool
}

func ParseMacosIORegData(data any, devices *[]USBDevice) {
	// Process the data based on its type
	switch v := data.(type) {
	case plist.Data:
		// root object, we need to convert it to map[string]any
		obj := data.(plist.Data)
		// typecase so that we reach case map[string]any
		ParseMacosIORegData(map[string]any(obj), devices)
	case []any:
		// An array of entries
		for _, entry := range v {
			ParseMacosIORegData(entry, devices)
		}
	case map[string]any:
		// A single entry
		// Check if this is a USB device with the right properties
		if isUSBDevice(v) {
			device := extractDeviceInfo(v)
			*devices = append(*devices, device)
		}

		// Check if this entry has children
		if children, ok := v["IORegistryEntryChildren"]; ok {
			// Process children recursively
			ParseMacosIORegData(children, devices)
		}
	}
}

// isUSBDevice reports whether an IOUSB plane entry is a USB device. Every
// device carries the IDs from its device descriptor. Host controllers
// (AppleT8132USBXHCI, AppleUSBXHCITR, ...) sit in the same plane and have
// "USB" in their class name, but no descriptor, so they are not devices.
func isUSBDevice(entry map[string]any) bool {
	_, hasVendorID := entry["idVendor"]
	_, hasProductID := entry["idProduct"]
	return hasVendorID || hasProductID
}

func extractDeviceInfo(entry map[string]any) USBDevice {
	device := USBDevice{}

	// Extract name
	if name, ok := entry["IORegistryEntryName"].(string); ok {
		device.Name = name
	}

	// Extract USB identifiers
	if vendorID, ok := entry["idVendor"].(float64); ok {
		device.VendorID = fmt.Sprintf("0x%04x", int(vendorID))
	}

	if productID, ok := entry["idProduct"].(float64); ok {
		device.ProductID = fmt.Sprintf("0x%04x", int(productID))
	}

	// Extract device class info
	if deviceClass, ok := entry["bDeviceClass"].(float64); ok {
		device.DeviceClass = fmt.Sprintf("0x%02x", int(deviceClass))
		device.DeviceClassName = GetUSBClassDescription(device.DeviceClass)
	}

	if deviceSubClass, ok := entry["bDeviceSubClass"].(float64); ok {
		device.DeviceSubClass = fmt.Sprintf("0x%02x", int(deviceSubClass))
	}

	if deviceProtocol, ok := entry["bDeviceProtocol"].(float64); ok {
		device.DeviceProtocol = fmt.Sprintf("0x%02x", int(deviceProtocol))
	}

	// Extract descriptive strings
	if manufacturer, ok := entry["USB Vendor Name"].(string); ok {
		device.Manufacturer = manufacturer
	}

	if product, ok := entry["USB Product Name"].(string); ok {
		device.Product = product
	}

	if serial, ok := entry["USB Serial Number"].(string); ok {
		device.SerialNumber = serial
	}

	// Extract location info
	if locationID, ok := entry["locationID"].(float64); ok {
		device.LocationID = fmt.Sprintf("0x%08x", int(locationID))

		// Extract bus and address from location ID
		busNum := (int(locationID) >> 24) & 0xFF
		deviceAddr := int(locationID) & 0xFF

		device.BusNumber = fmt.Sprintf("%d", busNum)
		device.DeviceAddress = fmt.Sprintf("%d", deviceAddr)
	}

	// Extract speed
	if speed, ok := entry["USBSpeed"].(float64); ok {
		// Convert numeric speed to string with units
		device.USBSpeed = formatUSBSpeed(int(speed))
	}

	// Extract device version
	if bcdDevice, ok := entry["bcdDevice"].(float64); ok {
		device.BcdDevice = fmt.Sprintf("0x%04x", int(bcdDevice))
		device.FormattedVersion = formatBcdVersion(uint64(bcdDevice))
	}

	device.IsRemovable = isUSBDeviceRemovable(entry)
	return device
}

// GetUSBClassDescription returns a description for standard USB device class codes
// See https://www.usb.org/defined-class-codes
func GetUSBClassDescription(classCode string) string {
	// Remove 0x prefix if present
	classCode = strings.TrimPrefix(classCode, "0x")

	// Parse hex value
	classValue, err := strconv.ParseInt(classCode, 16, 64)
	if err != nil {
		return ""
	}

	switch classValue {
	case 0x00:
		return "Device"
	case 0x01:
		return "Audio"
	case 0x02:
		return "Communications and CDC Control"
	case 0x03:
		return "Human Interface Device (HID)"
	case 0x05:
		return "Physical"
	case 0x06:
		return "Image"
	case 0x07:
		return "Printer"
	case 0x08:
		return "Mass Storage"
	case 0x09:
		return "Hub"
	case 0x0A:
		return "CDC-Data"
	case 0x0B:
		return "Smart Card"
	case 0x0D:
		return "Content Security"
	case 0x0E:
		return "Video"
	case 0x0F:
		return "Personal Healthcare"
	case 0x10:
		return "Audio/Video Devices"
	case 0x11:
		return "Billboard Device Class"
	case 0x12:
		return "USB Type-C Bridge Class"
	case 0xDC:
		return "Diagnostic Device"
	case 0xE0:
		return "Wireless Controller"
	case 0xEF:
		return "Miscellaneous"
	case 0xFE:
		return "Application Specific"
	case 0xFF:
		return "Vendor Specific"
	default:
		return ""
	}
}

// formatUSBSpeed formats the IOKit USBSpeed property. It holds a
// tIOUSBHostConnectionSpeed value (IOUSBHostFamilyDefinitions.h), not a rate:
// 0 none, 1 full, 2 low, 3 high, 4 super, 5 super+, 6 super+ 2x2, 7 other.
func formatUSBSpeed(speed int) string {
	switch speed {
	case 1:
		return formatUSBSpeedMbps("12")
	case 2:
		return formatUSBSpeedMbps("1.5")
	case 3:
		return formatUSBSpeedMbps("480")
	case 4:
		return formatUSBSpeedMbps("5000")
	case 5:
		return formatUSBSpeedMbps("10000")
	case 6:
		return formatUSBSpeedMbps("20000")
	default:
		return ""
	}
}

// Determine if a USB device is removable based on IOKit properties
func isUSBDeviceRemovable(entry map[string]any) bool {
	// Check the official IOKit "non-removable" property
	// If this property exists and is true, the device is explicitly marked as non-removable
	if nonRemovable, ok := entry["non-removable"].(bool); ok {
		return !nonRemovable
	}

	// If we can't determine definitively, default to true
	return true
}

// formatBcdVersion formats a binary-coded decimal release number (bcdDevice)
// as major.minor[.subminor]. Every nibble is a decimal digit, so the major
// version is the high byte printed as hex digits: 0x1000 is 10.0, 0x5212 is
// 52.1.2.
func formatBcdVersion(bcdVersion uint64) string {
	major := (bcdVersion >> 8) & 0xFF
	minor := (bcdVersion >> 4) & 0x0F
	subminor := bcdVersion & 0x0F
	if subminor > 0 {
		return fmt.Sprintf("%x.%d.%d", major, minor, subminor)
	}
	return fmt.Sprintf("%x.%d", major, minor)
}

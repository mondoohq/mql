// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"go.mondoo.com/mql/providers/os/resources/wmiquery"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modkernel32                            = windows.NewLazySystemDLL("kernel32.dll")
	procLCIDToLocaleName                   = modkernel32.NewProc("LCIDToLocaleName")
	procGetFirmwareType                    = modkernel32.NewProc("GetFirmwareType")
	procGetPhysicallyInstalledSystemMemory = modkernel32.NewProc("GetPhysicallyInstalledSystemMemory")
)

// NativeComputerInfo returns the part of Get-ComputerInfo's output that can be
// read without PowerShell, under Get-ComputerInfo's key names and with the
// value shapes its JSON has (numbers as float64, enums as their numbers, dates
// as "/Date(ms)/"). A key it cannot read is left out, never filled with a
// guess; see NativeComputerInfoKeys for the keys it covers.
func NativeComputerInfo() (info map[string]any, err error) {
	// wmiquery already turns a panic in the WMI library into an error; this
	// guard covers the rest of the native reads, so the caller falls back to
	// PowerShell instead of the scan crashing
	defer func() {
		if r := recover(); r != nil {
			info, err = nil, fmt.Errorf("panic reading computer info natively: %v", r)
		}
	}()

	info = map[string]any{}

	if err := addCurrentVersion(info); err != nil {
		return nil, err
	}

	// OsProductType: 1 workstation, 2 domain controller, 3 server, as
	// Win32_OperatingSystem.ProductType and Get-ComputerInfo report it.
	if v := windows.RtlGetVersion(); v != nil && v.ProductType != 0 {
		info["OsProductType"] = float64(v.ProductType)
	}

	if err := addOperatingSystem(info); err != nil {
		return nil, err
	}
	if err := addComputerSystem(info); err != nil {
		return nil, err
	}
	if err := addProcessors(info); err != nil {
		return nil, err
	}

	var fw uint32
	if r, _, _ := procGetFirmwareType.Call(uintptr(unsafe.Pointer(&fw))); r != 0 && fw != 0 {
		// FIRMWARE_TYPE: 1 BIOS, 2 UEFI, the same numbers as Get-ComputerInfo's
		// BiosFirmwareType enum
		info["BiosFirmwareType"] = float64(fw)
	}

	var kb uint64
	if r, _, _ := procGetPhysicallyInstalledSystemMemory.Call(uintptr(unsafe.Pointer(&kb))); r != 0 && kb != 0 {
		info["CsPhyicallyInstalledMemory"] = float64(kb)
	}

	if tz, ok := timeZoneDisplayName(); ok {
		info["TimeZone"] = tz
	}

	return info, nil
}

// NativeComputerInfoKeys are the keys NativeComputerInfo sets on a host where
// every source answers. The test on Windows compares each of them with
// Get-ComputerInfo on the same host.
var NativeComputerInfoKeys = []string{
	"WindowsProductName", "WindowsEditionId", "WindowsCurrentVersion", "WindowsBuildLabEx",
	"WindowsInstallationType", "WindowsProductId", "WindowsRegisteredOwner",
	"WindowsRegisteredOrganization", "WindowsSystemRoot", "WindowsInstallDateFromRegistry",
	"OsProductType",
	"OsName", "OsVersion", "OsBuildNumber", "OsArchitecture", "OsLanguage", "OsLocale", "OsLocaleID",
	"OsCountryCode", "OsCodeSet", "OsType", "OsMuiLanguages", "OsSystemDirectory", "OsWindowsDirectory",
	"OsSystemDrive",
	"CsManufacturer", "CsModel", "CsDomainRole", "CsDomain", "CsPartOfDomain", "CsName", "CsDNSHostName",
	"CsNumberOfProcessors", "CsNumberOfLogicalProcessors", "CsTotalPhysicalMemory", "CsSystemType",
	"CsWorkgroup", "CsProcessors", "CsPhyicallyInstalledMemory",
	"BiosFirmwareType", "TimeZone",
}

func addCurrentVersion(info map[string]any) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	for key, name := range map[string]string{
		"WindowsProductName":            "ProductName",
		"WindowsEditionId":              "EditionID",
		"WindowsCurrentVersion":         "CurrentVersion",
		"WindowsBuildLabEx":             "BuildLabEx",
		"WindowsInstallationType":       "InstallationType",
		"WindowsProductId":              "ProductId",
		"WindowsRegisteredOwner":        "RegisteredOwner",
		"WindowsRegisteredOrganization": "RegisteredOrganization",
		"WindowsSystemRoot":             "SystemRoot",
	} {
		if v, _, err := k.GetStringValue(name); err == nil {
			info[key] = v
		}
	}
	// InstallDate is seconds since the Unix epoch, rendered as Get-ComputerInfo's
	// JSON has it; see installDateJSON.
	if v, _, err := k.GetIntegerValue("InstallDate"); err == nil && v != 0 {
		info["WindowsInstallDateFromRegistry"] = installDateJSON(v, time.Local)
	}
	return nil
}

func addOperatingSystem(info map[string]any) error {
	rows, err := wmiquery.Query("SELECT Caption, Version, BuildNumber, OSArchitecture, OSLanguage, Locale, CountryCode, CodeSet, OSType, MUILanguages, SystemDirectory, WindowsDirectory, SystemDrive FROM Win32_OperatingSystem",
		"Caption", "Version", "BuildNumber", "OSArchitecture", "OSLanguage", "Locale", "CountryCode", "CodeSet", "OSType", "MUILanguages", "SystemDirectory", "WindowsDirectory", "SystemDrive")
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("Win32_OperatingSystem returned no instance")
	}
	o := rows[0]
	setString(info, "OsName", o.StringPtr("Caption"))
	setString(info, "OsVersion", o.StringPtr("Version"))
	setString(info, "OsBuildNumber", o.StringPtr("BuildNumber"))
	setString(info, "OsArchitecture", o.StringPtr("OSArchitecture"))
	setString(info, "OsLocaleID", o.StringPtr("Locale"))
	setString(info, "OsCountryCode", o.StringPtr("CountryCode"))
	setString(info, "OsCodeSet", o.StringPtr("CodeSet"))
	setString(info, "OsSystemDirectory", o.StringPtr("SystemDirectory"))
	setString(info, "OsWindowsDirectory", o.StringPtr("WindowsDirectory"))
	setString(info, "OsSystemDrive", o.StringPtr("SystemDrive"))
	setNumber(info, "OsType", o, "OSType")
	if langs, ok := o.Strings("MUILanguages"); ok {
		out := make([]any, len(langs))
		for i := range langs {
			out[i] = langs[i]
		}
		info["OsMuiLanguages"] = out
	}
	// Get-ComputerInfo reports OsLanguage and OsLocale as culture names, from
	// Win32_OperatingSystem's OSLanguage (an LCID) and Locale (a hex LCID).
	if lcid, ok := o.Int64("OSLanguage"); ok && lcid >= 0 && lcid <= 0xFFFFFFFF {
		if name, ok := lcidToLocaleName(uint32(lcid)); ok {
			info["OsLanguage"] = name
		}
	}
	if locale := o.StringPtr("Locale"); locale != nil {
		if lcid, err := strconv.ParseUint(*locale, 16, 32); err == nil {
			if name, ok := lcidToLocaleName(uint32(lcid)); ok {
				info["OsLocale"] = name
			}
		}
	}
	return nil
}

func addComputerSystem(info map[string]any) error {
	rows, err := wmiquery.Query("SELECT Manufacturer, Model, DomainRole, Domain, PartOfDomain, Name, DNSHostName, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, SystemType, Workgroup FROM Win32_ComputerSystem",
		"Manufacturer", "Model", "DomainRole", "Domain", "PartOfDomain", "Name", "DNSHostName", "NumberOfProcessors", "NumberOfLogicalProcessors", "TotalPhysicalMemory", "SystemType", "Workgroup")
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("Win32_ComputerSystem returned no instance")
	}
	c := rows[0]
	setString(info, "CsManufacturer", c.StringPtr("Manufacturer"))
	setString(info, "CsModel", c.StringPtr("Model"))
	setString(info, "CsDomain", c.StringPtr("Domain"))
	setString(info, "CsName", c.StringPtr("Name"))
	setString(info, "CsDNSHostName", c.StringPtr("DNSHostName"))
	setString(info, "CsSystemType", c.StringPtr("SystemType"))
	setString(info, "CsWorkgroup", c.StringPtr("Workgroup"))
	setNumber(info, "CsDomainRole", c, "DomainRole")
	if b, ok := c.Bool("PartOfDomain"); ok {
		info["CsPartOfDomain"] = b
	}
	setNumber(info, "CsNumberOfProcessors", c, "NumberOfProcessors")
	setNumber(info, "CsNumberOfLogicalProcessors", c, "NumberOfLogicalProcessors")
	// a uint64, which WMI sends as a string; Int64 parses it
	setNumber(info, "CsTotalPhysicalMemory", c, "TotalPhysicalMemory")
	return nil
}

// addProcessors fills CsProcessors like Get-ComputerInfo: one object per
// Win32_Processor with these 17 properties, ProcessorID spelled as
// Get-ComputerInfo spells it.
func addProcessors(info map[string]any) error {
	rows, err := wmiquery.Query("SELECT Name, Manufacturer, Description, Architecture, AddressWidth, DataWidth, MaxClockSpeed, CurrentClockSpeed, NumberOfCores, NumberOfLogicalProcessors, ProcessorId, SocketDesignation, ProcessorType, Role, Status, CpuStatus, Availability FROM Win32_Processor",
		"Name", "Manufacturer", "Description", "Architecture", "AddressWidth", "DataWidth", "MaxClockSpeed", "CurrentClockSpeed", "NumberOfCores", "NumberOfLogicalProcessors", "ProcessorId", "SocketDesignation", "ProcessorType", "Role", "Status", "CpuStatus", "Availability")
	if err != nil {
		return err
	}
	out := make([]any, 0, len(rows))
	for _, p := range rows {
		out = append(out, map[string]any{
			"Name":                      strOrNil(p.StringPtr("Name")),
			"Manufacturer":              strOrNil(p.StringPtr("Manufacturer")),
			"Description":               strOrNil(p.StringPtr("Description")),
			"Architecture":              numberOrNil(p, "Architecture"),
			"AddressWidth":              numberOrNil(p, "AddressWidth"),
			"DataWidth":                 numberOrNil(p, "DataWidth"),
			"MaxClockSpeed":             numberOrNil(p, "MaxClockSpeed"),
			"CurrentClockSpeed":         numberOrNil(p, "CurrentClockSpeed"),
			"NumberOfCores":             numberOrNil(p, "NumberOfCores"),
			"NumberOfLogicalProcessors": numberOrNil(p, "NumberOfLogicalProcessors"),
			"ProcessorID":               strOrNil(p.StringPtr("ProcessorId")),
			"SocketDesignation":         strOrNil(p.StringPtr("SocketDesignation")),
			"ProcessorType":             numberOrNil(p, "ProcessorType"),
			"Role":                      strOrNil(p.StringPtr("Role")),
			"Status":                    strOrNil(p.StringPtr("Status")),
			"CpuStatus":                 numberOrNil(p, "CpuStatus"),
			"Availability":              numberOrNil(p, "Availability"),
		})
	}
	info["CsProcessors"] = out
	return nil
}

// timeZoneDisplayName returns the current time zone's display name in the
// system's language, as TimeZoneInfo.Local.DisplayName (Get-ComputerInfo's
// TimeZone) does: the zone's MUI_Display string, else its Display value.
func timeZoneDisplayName() (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	keyName, _, err := k.GetStringValue("TimeZoneKeyName")
	k.Close()
	if err != nil || keyName == "" {
		return "", false
	}
	z, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\`+strings.TrimRight(keyName, "\x00"), registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer z.Close()
	if v, err := z.GetMUIStringValue("MUI_Display"); err == nil && v != "" {
		return v, true
	}
	if v, _, err := z.GetStringValue("Display"); err == nil && v != "" {
		return v, true
	}
	return "", false
}

// lcidToLocaleName resolves an LCID to its culture name (1031 → de-DE).
func lcidToLocaleName(lcid uint32) (string, bool) {
	buf := make([]uint16, 85) // LOCALE_NAME_MAX_LENGTH
	r, _, _ := procLCIDToLocaleName.Call(uintptr(lcid), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if r == 0 {
		return "", false
	}
	name := windows.UTF16ToString(buf)
	return name, name != ""
}

func setString(info map[string]any, key string, v *string) {
	if v != nil {
		info[key] = *v
	}
}

func strOrNil(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

// numberOrNil returns an integer property as Get-ComputerInfo's JSON has it
// (a float64), or nil when WMI reports it NULL or as another type.
func numberOrNil(row wmiquery.Row, name string) any {
	n, ok := row.Int64(name)
	if !ok {
		return nil
	}
	return float64(n)
}

// setNumber sets key to an integer property as a float64, and leaves it out
// when the property is NULL.
func setNumber(info map[string]any, key string, row wmiquery.Row, name string) {
	if n, ok := row.Int64(name); ok {
		info[key] = float64(n)
	}
}

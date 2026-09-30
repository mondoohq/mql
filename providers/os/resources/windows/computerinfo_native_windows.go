// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	wmi "github.com/StackExchange/wmi"
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
	// the wmi lib can panic on unexpected COM variant types; recover so the
	// caller falls back to PowerShell instead of the scan crashing
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
	// InstallDate is seconds since the Unix epoch; Get-ComputerInfo reports it
	// as a DateTime, which ConvertTo-Json writes as /Date(milliseconds)/.
	if v, _, err := k.GetIntegerValue("InstallDate"); err == nil && v != 0 {
		info["WindowsInstallDateFromRegistry"] = "/Date(" + strconv.FormatUint(v*1000, 10) + ")/"
	}
	return nil
}

type win32OperatingSystem struct {
	Caption          *string
	Version          *string
	BuildNumber      *string
	OSArchitecture   *string
	OSLanguage       *uint32
	Locale           *string
	CountryCode      *string
	CodeSet          *string
	OSType           *uint16
	MUILanguages     []string
	SystemDirectory  *string
	WindowsDirectory *string
	SystemDrive      *string
}

func addOperatingSystem(info map[string]any) error {
	var os []win32OperatingSystem
	if err := wmi.Query("SELECT Caption, Version, BuildNumber, OSArchitecture, OSLanguage, Locale, CountryCode, CodeSet, OSType, MUILanguages, SystemDirectory, WindowsDirectory, SystemDrive FROM Win32_OperatingSystem", &os); err != nil {
		return err
	}
	if len(os) == 0 {
		return errors.New("Win32_OperatingSystem returned no instance")
	}
	o := os[0]
	setString(info, "OsName", o.Caption)
	setString(info, "OsVersion", o.Version)
	setString(info, "OsBuildNumber", o.BuildNumber)
	setString(info, "OsArchitecture", o.OSArchitecture)
	setString(info, "OsLocaleID", o.Locale)
	setString(info, "OsCountryCode", o.CountryCode)
	setString(info, "OsCodeSet", o.CodeSet)
	setString(info, "OsSystemDirectory", o.SystemDirectory)
	setString(info, "OsWindowsDirectory", o.WindowsDirectory)
	setString(info, "OsSystemDrive", o.SystemDrive)
	if o.OSType != nil {
		info["OsType"] = float64(*o.OSType)
	}
	if o.MUILanguages != nil {
		langs := make([]any, len(o.MUILanguages))
		for i := range o.MUILanguages {
			langs[i] = o.MUILanguages[i]
		}
		info["OsMuiLanguages"] = langs
	}
	// Get-ComputerInfo reports OsLanguage and OsLocale as culture names, from
	// Win32_OperatingSystem's OSLanguage (an LCID) and Locale (a hex LCID).
	if o.OSLanguage != nil {
		if name, ok := lcidToLocaleName(*o.OSLanguage); ok {
			info["OsLanguage"] = name
		}
	}
	if o.Locale != nil {
		if lcid, err := strconv.ParseUint(*o.Locale, 16, 32); err == nil {
			if name, ok := lcidToLocaleName(uint32(lcid)); ok {
				info["OsLocale"] = name
			}
		}
	}
	return nil
}

type win32ComputerSystem struct {
	Manufacturer              *string
	Model                     *string
	DomainRole                *uint16
	Domain                    *string
	PartOfDomain              *bool
	Name                      *string
	DNSHostName               *string
	NumberOfProcessors        *uint32
	NumberOfLogicalProcessors *uint32
	TotalPhysicalMemory       *uint64
	SystemType                *string
	Workgroup                 *string
}

func addComputerSystem(info map[string]any) error {
	var cs []win32ComputerSystem
	if err := wmi.Query("SELECT Manufacturer, Model, DomainRole, Domain, PartOfDomain, Name, DNSHostName, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, SystemType, Workgroup FROM Win32_ComputerSystem", &cs); err != nil {
		return err
	}
	if len(cs) == 0 {
		return errors.New("Win32_ComputerSystem returned no instance")
	}
	c := cs[0]
	setString(info, "CsManufacturer", c.Manufacturer)
	setString(info, "CsModel", c.Model)
	setString(info, "CsDomain", c.Domain)
	setString(info, "CsName", c.Name)
	setString(info, "CsDNSHostName", c.DNSHostName)
	setString(info, "CsSystemType", c.SystemType)
	setString(info, "CsWorkgroup", c.Workgroup)
	if c.DomainRole != nil {
		info["CsDomainRole"] = float64(*c.DomainRole)
	}
	if c.PartOfDomain != nil {
		info["CsPartOfDomain"] = *c.PartOfDomain
	}
	if c.NumberOfProcessors != nil {
		info["CsNumberOfProcessors"] = float64(*c.NumberOfProcessors)
	}
	if c.NumberOfLogicalProcessors != nil {
		info["CsNumberOfLogicalProcessors"] = float64(*c.NumberOfLogicalProcessors)
	}
	if c.TotalPhysicalMemory != nil {
		info["CsTotalPhysicalMemory"] = float64(*c.TotalPhysicalMemory)
	}
	return nil
}

type win32Processor struct {
	Name                      *string
	Manufacturer              *string
	Description               *string
	Architecture              *uint16
	AddressWidth              *uint16
	DataWidth                 *uint16
	MaxClockSpeed             *uint32
	CurrentClockSpeed         *uint32
	NumberOfCores             *uint32
	NumberOfLogicalProcessors *uint32
	ProcessorId               *string
	SocketDesignation         *string
	ProcessorType             *uint16
	Role                      *string
	Status                    *string
	CpuStatus                 *uint16
	Availability              *uint16
}

// addProcessors fills CsProcessors like Get-ComputerInfo: one object per
// Win32_Processor with these 17 properties, ProcessorID spelled as
// Get-ComputerInfo spells it.
func addProcessors(info map[string]any) error {
	var procs []win32Processor
	if err := wmi.Query("SELECT Name, Manufacturer, Description, Architecture, AddressWidth, DataWidth, MaxClockSpeed, CurrentClockSpeed, NumberOfCores, NumberOfLogicalProcessors, ProcessorId, SocketDesignation, ProcessorType, Role, Status, CpuStatus, Availability FROM Win32_Processor", &procs); err != nil {
		return err
	}
	out := make([]any, 0, len(procs))
	for _, p := range procs {
		out = append(out, map[string]any{
			"Name":                      strOrNil(p.Name),
			"Manufacturer":              strOrNil(p.Manufacturer),
			"Description":               strOrNil(p.Description),
			"Architecture":              u16OrNil(p.Architecture),
			"AddressWidth":              u16OrNil(p.AddressWidth),
			"DataWidth":                 u16OrNil(p.DataWidth),
			"MaxClockSpeed":             u32OrNil(p.MaxClockSpeed),
			"CurrentClockSpeed":         u32OrNil(p.CurrentClockSpeed),
			"NumberOfCores":             u32OrNil(p.NumberOfCores),
			"NumberOfLogicalProcessors": u32OrNil(p.NumberOfLogicalProcessors),
			"ProcessorID":               strOrNil(p.ProcessorId),
			"SocketDesignation":         strOrNil(p.SocketDesignation),
			"ProcessorType":             u16OrNil(p.ProcessorType),
			"Role":                      strOrNil(p.Role),
			"Status":                    strOrNil(p.Status),
			"CpuStatus":                 u16OrNil(p.CpuStatus),
			"Availability":              u16OrNil(p.Availability),
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

func u16OrNil(v *uint16) any {
	if v == nil {
		return nil
	}
	return float64(*v)
}

func u32OrNil(v *uint32) any {
	if v == nil {
		return nil
	}
	return float64(*v)
}

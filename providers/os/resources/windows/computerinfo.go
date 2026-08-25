// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"io"
	"strings"
)

// PSGetComputerInfo is a PowerShell script that retrieves computer information.
const PSGetComputerInfo = `Get-ComputerInfo | ConvertTo-Json`

// PSGetComputerInfoCustom is a PowerShell script that retrieves computer information. It
// implements a fallback to work on systems with winrm disabled. See
// https://github.com/mondoohq/mql/pull/4520 for more information.
const PSGetComputerInfoCustom = `
function Get-CustomComputerInfo {
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $timeZone = Get-CimInstance -ClassName Win32_TimeZone
    $windowsProduct = Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"
    $firmwareType = $env:firmware_type
    $hal = (Get-Item "$env:SystemRoot\System32\hal.dll" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
    $physicalMemoryKB = $null
    $capacity = (Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue | Measure-Object -Property Capacity -Sum).Sum
    if ($capacity) { $physicalMemoryKB = [int64]($capacity / 1024) }
    $uptime = $null
    if ($os.LastBootUpTime) { $uptime = (Get-Date) - $os.LastBootUpTime }
    $result = [PSCustomObject]@{
        Bios = $bios
        ComputerSystem = $computerSystem
        Os = $os
        TimeZone = $timeZone
        WindowsProduct = $windowsProduct
        FirmwareType = $firmwareType
        Hal = $hal
        PhysicalMemoryKB = $physicalMemoryKB
        Uptime = $uptime
    }
    return $result
}
Get-CustomComputerInfo | ConvertTo-Json
`

func ParseComputerInfo(r io.Reader) (map[string]any, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var properties map[string]any
	err = json.Unmarshal(data, &properties)
	if err != nil {
		return nil, err
	}

	return properties, nil
}

type CustomComputerInfo struct {
	Bios           map[string]any `json:"Bios"`
	ComputerSystem map[string]any `json:"ComputerSystem"`
	Os             map[string]any `json:"Os"`
	TimeZone       map[string]any `json:"TimeZone"`
	WindowsProduct map[string]any `json:"WindowsProduct"`
	// FirmwareType is emitted at the top level by the script, not inside
	// WindowsProduct. Reading it from WindowsProduct found nothing on any
	// host, so BiosFirmwareType was always null even though the script had
	// gone and fetched it.
	//
	// The value carried here is the firmware_type environment variable
	// ("Legacy" or "UEFI"). Win32_ComputerSystem.FirmwareType, which the
	// script used to read, is empty on every host tested, so that source
	// could not have filled the field in even with the mapping corrected.
	FirmwareType string `json:"FirmwareType"`
	// Hal is the hal.dll product version, which is what
	// OsHardwareAbstractionLayer reports. It used to be filled in with the
	// operating system version instead, which is a different and shorter
	// value: the HAL revision is the part that matters and it was never there.
	Hal any `json:"Hal"`
	// PhysicalMemoryKB is the SMBIOS-reported installed memory in KB, which is
	// what CsPhyicallyInstalledMemory reports. It used to be filled in with
	// Win32_ComputerSystem.TotalPhysicalMemory, which is a different quantity
	// (memory visible to the OS, minus what the hardware reserves) in a
	// different unit (bytes), so the value was wrong by roughly a factor of a
	// thousand.
	PhysicalMemoryKB any `json:"PhysicalMemoryKB"`
	// Uptime is how long the host has been up, which is what OsUptime reports.
	// It used to be filled in with the boot timestamp, so a field documented
	// as a duration carried a point in time.
	Uptime any `json:"Uptime"`
}

// biosFirmwareType maps the firmware_type environment variable to the
// vocabulary Get-ComputerInfo uses for BiosFirmwareType, so a host that falls
// back reports the same two words as one that does not. An unrecognized or
// absent value yields nil: "the firmware type could not be read" is not the
// same claim as "this machine boots BIOS".
func biosFirmwareType(v string) any {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "legacy":
		return "Bios"
	case "uefi":
		return "Uefi"
	default:
		return nil
	}
}

func ParseCustomComputerInfo(r io.Reader) (map[string]any, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	customComputerInfo := &CustomComputerInfo{}
	err = json.Unmarshal(data, customComputerInfo)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"BiosBIOSVersion":                    customComputerInfo.Bios["SMBIOSBIOSVersion"],
		"BiosCaption":                        customComputerInfo.Bios["Caption"],
		"BiosCharacteristics":                customComputerInfo.Bios["BiosCharacteristics"],
		"BiosCurrentLanguage":                customComputerInfo.Bios["CurrentLanguage"],
		"BiosDescription":                    customComputerInfo.Bios["Description"],
		"BiosEmbeddedControllerMajorVersion": customComputerInfo.Bios["EmbeddedControllerMajorVersion"],
		"BiosEmbeddedControllerMinorVersion": customComputerInfo.Bios["EmbeddedControllerMinorVersion"],
		"BiosFirmwareType":                   biosFirmwareType(customComputerInfo.FirmwareType),
		"BiosIdentificationCode":             customComputerInfo.Bios["IdentificationCode"],
		"BiosInstallDate":                    customComputerInfo.Bios["InstallDate"],
		"BiosInstallableLanguages":           customComputerInfo.Bios["InstallableLanguages"],
		"BiosLanguageEdition":                customComputerInfo.Bios["LanguageEdition"],
		"BiosListOfLanguages":                customComputerInfo.Bios["ListOfLanguages"],
		"BiosManufacturer":                   customComputerInfo.Bios["Manufacturer"],
		"BiosName":                           customComputerInfo.Bios["Name"],
		"BiosOtherTargetOS":                  customComputerInfo.Bios["OtherTargetOS"],
		"BiosPrimaryBIOS":                    customComputerInfo.Bios["PrimaryBIOS"],
		"BiosReleaseDate":                    customComputerInfo.Bios["ReleaseDate"],
		"BiosSMBIOSBIOSVersion":              customComputerInfo.Bios["SMBIOSBIOSVersion"],
		"BiosSMBIOSMajorVersion":             customComputerInfo.Bios["SMBIOSMajorVersion"],
		"BiosSMBIOSMinorVersion":             customComputerInfo.Bios["SMBIOSMinorVersion"],
		"BiosSMBIOSPresent":                  customComputerInfo.Bios["SMBIOSPresent"],
		"BiosSerialNumber":                   customComputerInfo.Bios["SerialNumber"],
		"BiosSoftwareElementState":           customComputerInfo.Bios["SoftwareElementState"],
		"BiosStatus":                         customComputerInfo.Bios["Status"],
		"BiosSystemBiosMajorVersion":         customComputerInfo.Bios["SystemBiosMajorVersion"],
		"BiosSystemBiosMinorVersion":         customComputerInfo.Bios["SystemBiosMinorVersion"],
		"BiosTargetOperatingSystem":          customComputerInfo.Bios["TargetOperatingSystem"],
		"BiosVersion":                        customComputerInfo.Bios["Version"],

		"CsAdminPasswordStatus":         customComputerInfo.ComputerSystem["AdminPasswordStatus"],
		"CsAutomaticManagedPagefile":    customComputerInfo.ComputerSystem["AutomaticManagedPagefile"],
		"CsAutomaticResetBootOption":    customComputerInfo.ComputerSystem["AutomaticResetBootOption"],
		"CsAutomaticResetCapability":    customComputerInfo.ComputerSystem["AutomaticResetCapability"],
		"CsBootOptionOnLimit":           customComputerInfo.ComputerSystem["BootOptionOnLimit"],
		"CsBootOptionOnWatchDog":        customComputerInfo.ComputerSystem["BootOptionOnWatchDog"],
		"CsBootROMSupported":            customComputerInfo.ComputerSystem["BootROMSupported"],
		"CsBootStatus":                  customComputerInfo.ComputerSystem["BootStatus"],
		"CsBootupState":                 customComputerInfo.ComputerSystem["BootupState"],
		"CsCaption":                     customComputerInfo.ComputerSystem["Caption"],
		"CsChassisBootupState":          customComputerInfo.ComputerSystem["ChassisBootupState"],
		"CsChassisSKUNumber":            customComputerInfo.ComputerSystem["SKUNumber"],
		"CsCurrentTimeZone":             customComputerInfo.TimeZone["StandardName"],
		"CsDNSHostName":                 customComputerInfo.ComputerSystem["DNSHostName"],
		"CsDaylightInEffect":            customComputerInfo.TimeZone["DaylightInEffect"],
		"CsDescription":                 customComputerInfo.ComputerSystem["Description"],
		"CsDomain":                      customComputerInfo.ComputerSystem["Domain"],
		"CsDomainRole":                  customComputerInfo.ComputerSystem["DomainRole"],
		"CsEnableDaylightSavingsTime":   customComputerInfo.ComputerSystem["EnableDaylightSavingsTime"],
		"CsFrontPanelResetStatus":       customComputerInfo.ComputerSystem["FrontPanelResetStatus"],
		"CsHypervisorPresent":           customComputerInfo.ComputerSystem["HypervisorPresent"],
		"CsInfraredSupported":           customComputerInfo.ComputerSystem["InfraredSupported"],
		"CsInitialLoadInfo":             customComputerInfo.ComputerSystem["InitialLoadInfo"],
		"CsInstallDate":                 customComputerInfo.ComputerSystem["InstallDate"],
		"CsKeyboardPasswordStatus":      customComputerInfo.ComputerSystem["KeyboardPasswordStatus"],
		"CsLastLoadInfo":                customComputerInfo.ComputerSystem["LastLoadInfo"],
		"CsManufacturer":                customComputerInfo.ComputerSystem["Manufacturer"],
		"CsModel":                       customComputerInfo.ComputerSystem["Model"],
		"CsName":                        customComputerInfo.ComputerSystem["Name"],
		"CsNetworkServerModeEnabled":    customComputerInfo.ComputerSystem["NetworkServerModeEnabled"],
		"CsNumberOfLogicalProcessors":   customComputerInfo.ComputerSystem["NumberOfLogicalProcessors"],
		"CsNumberOfProcessors":          customComputerInfo.ComputerSystem["NumberOfProcessors"],
		"CsOEMStringArray":              customComputerInfo.ComputerSystem["OEMStringArray"],
		"CsPCSystemType":                customComputerInfo.ComputerSystem["PCSystemType"],
		"CsPCSystemTypeEx":              customComputerInfo.ComputerSystem["PCSystemTypeEx"],
		"CsPartOfDomain":                customComputerInfo.ComputerSystem["PartOfDomain"],
		"CsPauseAfterReset":             customComputerInfo.ComputerSystem["PauseAfterReset"],
		"CsPhyicallyInstalledMemory":    customComputerInfo.PhysicalMemoryKB,
		"CsPowerManagementCapabilities": customComputerInfo.ComputerSystem["PowerManagementCapabilities"],
		"CsPowerManagementSupported":    customComputerInfo.ComputerSystem["PowerManagementSupported"],
		"CsPowerOnPasswordStatus":       customComputerInfo.ComputerSystem["PowerOnPasswordStatus"],
		"CsPowerState":                  customComputerInfo.ComputerSystem["PowerState"],
		"CsPowerSupplyState":            customComputerInfo.ComputerSystem["PowerSupplyState"],
		"CsPrimaryOwnerContact":         customComputerInfo.ComputerSystem["PrimaryOwnerContact"],
		"CsPrimaryOwnerName":            customComputerInfo.ComputerSystem["PrimaryOwnerName"],
		"CsProcessors":                  customComputerInfo.ComputerSystem["Processor"],
		"CsResetCapability":             customComputerInfo.ComputerSystem["ResetCapability"],
		"CsResetCount":                  customComputerInfo.ComputerSystem["ResetCount"],
		"CsResetLimit":                  customComputerInfo.ComputerSystem["ResetLimit"],
		"CsRoles":                       customComputerInfo.ComputerSystem["Roles"],
		"CsStatus":                      customComputerInfo.ComputerSystem["Status"],
		"CsSupportContactDescription":   customComputerInfo.ComputerSystem["SupportContactDescription"],
		"CsSystemFamily":                customComputerInfo.ComputerSystem["SystemFamily"],
		"CsSystemSKUNumber":             customComputerInfo.ComputerSystem["SystemSKUNumber"],
		"CsSystemType":                  customComputerInfo.ComputerSystem["SystemType"],
		"CsThermalState":                customComputerInfo.ComputerSystem["ThermalState"],
		"CsTotalPhysicalMemory":         customComputerInfo.ComputerSystem["TotalPhysicalMemory"],
		"CsUserName":                    customComputerInfo.ComputerSystem["UserName"],
		"CsWakeUpType":                  customComputerInfo.ComputerSystem["WakeUpType"],
		"CsWorkgroup":                   customComputerInfo.ComputerSystem["Workgroup"],

		"OsArchitecture":    customComputerInfo.Os["OSArchitecture"],
		"OsBootDevice":      customComputerInfo.Os["BootDevice"],
		"OsBuildNumber":     customComputerInfo.Os["BuildNumber"],
		"OsBuildType":       customComputerInfo.Os["BuildType"],
		"OsCSDVersion":      customComputerInfo.Os["CSDVersion"],
		"OsCodeSet":         customComputerInfo.Os["CodeSet"],
		"OsCountryCode":     customComputerInfo.Os["CountryCode"],
		"OsCurrentTimeZone": customComputerInfo.Os["CurrentTimeZone"],
		"OsDataExecutionPrevention32BitApplications": customComputerInfo.Os["DataExecutionPrevention_32BitApplications"],
		"OsDataExecutionPreventionAvailable":         customComputerInfo.Os["DataExecutionPrevention_Available"],
		"OsDataExecutionPreventionDrivers":           customComputerInfo.Os["DataExecutionPrevention_Drivers"],
		"OsDataExecutionPreventionSupportPolicy":     customComputerInfo.Os["DataExecutionPrevention_SupportPolicy"],
		"OsDebug":                                    customComputerInfo.Os["Debug"],
		"OsDistributed":                              customComputerInfo.Os["Distributed"],
		"OsEncryptionLevel":                          customComputerInfo.Os["EncryptionLevel"],
		"OsForegroundApplicationBoost":               customComputerInfo.Os["ForegroundApplicationBoost"],
		"OsFreePhysicalMemory":                       customComputerInfo.Os["FreePhysicalMemory"],
		"OsFreeSpaceInPagingFiles":                   customComputerInfo.Os["FreeSpaceInPagingFiles"],
		"OsFreeVirtualMemory":                        customComputerInfo.Os["FreeVirtualMemory"],
		"OsHardwareAbstractionLayer":                 customComputerInfo.Hal,
		"OsHotFixes":                                 customComputerInfo.Os["HotFixes"],
		"OsInUseVirtualMemory":                       customComputerInfo.Os["InUseVirtualMemory"],
		"OsInstallDate":                              customComputerInfo.Os["InstallDate"],
		"OsLanguage":                                 customComputerInfo.Os["OSLanguage"],
		"OsLastBootUpTime":                           customComputerInfo.Os["LastBootUpTime"],
		"OsLocalDateTime":                            customComputerInfo.Os["LocalDateTime"],
		"OsLocale":                                   customComputerInfo.Os["Locale"],
		"OsLocaleID":                                 customComputerInfo.Os["LocaleID"],
		"OsManufacturer":                             customComputerInfo.Os["Manufacturer"],
		"OsMaxNumberOfProcesses":                     customComputerInfo.Os["MaxNumberOfProcesses"],
		"OsMaxProcessMemorySize":                     customComputerInfo.Os["MaxProcessMemorySize"],
		"OsMuiLanguages":                             customComputerInfo.Os["MUILanguages"],
		"OsName":                                     customComputerInfo.Os["Name"],
		"OsNumberOfLicensedUsers":                    customComputerInfo.Os["NumberOfLicensedUsers"],
		"OsNumberOfProcesses":                        customComputerInfo.Os["NumberOfProcesses"],
		"OsNumberOfUsers":                            customComputerInfo.Os["NumberOfUsers"],
		"OsOperatingSystemSKU":                       customComputerInfo.Os["OperatingSystemSKU"],
		"OsOrganization":                             customComputerInfo.Os["Organization"],
		"OsOtherTypeDescription":                     customComputerInfo.Os["OtherTypeDescription"],
		"OsPAEEnabled":                               customComputerInfo.Os["PAEEnabled"],
		"OsPagingFiles":                              customComputerInfo.Os["PagingFiles"],
		"OsPortableOperatingSystem":                  customComputerInfo.Os["PortableOperatingSystem"],
		"OsPrimary":                                  customComputerInfo.Os["Primary"],
		"OsProductSuites":                            customComputerInfo.Os["ProductSuites"],
		"OsProductType":                              customComputerInfo.Os["ProductType"],
		"OsRegisteredUser":                           customComputerInfo.Os["RegisteredUser"],
		"OsSerialNumber":                             customComputerInfo.Os["SerialNumber"],
		"OsServerLevel":                              customComputerInfo.Os["ServerLevel"],
		"OsServicePackMajorVersion":                  customComputerInfo.Os["ServicePackMajorVersion"],
		"OsServicePackMinorVersion":                  customComputerInfo.Os["ServicePackMinorVersion"],
		"OsSizeStoredInPagingFiles":                  customComputerInfo.Os["SizeStoredInPagingFiles"],
		"OsStatus":                                   customComputerInfo.Os["Status"],
		"OsSuites":                                   customComputerInfo.Os["Suites"],
		"OsSystemDevice":                             customComputerInfo.Os["SystemDevice"],
		"OsSystemDirectory":                          customComputerInfo.Os["SystemDirectory"],
		"OsSystemDrive":                              customComputerInfo.Os["SystemDrive"],
		"OsTotalSwapSpaceSize":                       customComputerInfo.Os["TotalSwapSpaceSize"],
		"OsTotalVirtualMemorySize":                   customComputerInfo.Os["TotalVirtualMemorySize"],
		"OsTotalVisibleMemorySize":                   customComputerInfo.Os["TotalVisibleMemorySize"],
		"OsType":                                     customComputerInfo.Os["OSType"],
		"OsUptime":                                   customComputerInfo.Uptime,
		"OsVersion":                                  customComputerInfo.Os["Version"],
		"OsWindowsDirectory":                         customComputerInfo.Os["WindowsDirectory"],

		"TimeZone":                       customComputerInfo.TimeZone["StandardName"],
		"WindowsBuildLabEx":              customComputerInfo.WindowsProduct["BuildLabEx"],
		"WindowsCurrentVersion":          customComputerInfo.WindowsProduct["CurrentVersion"],
		"WindowsEditionId":               customComputerInfo.WindowsProduct["EditionID"],
		"WindowsInstallDateFromRegistry": customComputerInfo.WindowsProduct["InstallDate"],
		"WindowsInstallationType":        customComputerInfo.WindowsProduct["InstallationType"],
		"WindowsProductId":               customComputerInfo.WindowsProduct["ProductId"],
		"WindowsProductName":             customComputerInfo.WindowsProduct["ProductName"],
		"WindowsRegisteredOrganization":  customComputerInfo.WindowsProduct["RegisteredOrganization"],
		"WindowsRegisteredOwner":         customComputerInfo.WindowsProduct["RegisteredOwner"],
		"WindowsSystemRoot":              customComputerInfo.WindowsProduct["SystemRoot"],
	}, nil
}

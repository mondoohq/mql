// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	HotpatchPackage = "Hotpatch Enrollment Package"

	// HotpatchLabel is the platform label carrying the hotpatch detection
	// result. On Windows clients it only says the device is configured for
	// hotpatch (AllowRebootlessUpdates, VBS) on an edition and build that can
	// be enrolled. It does NOT prove enrollment: eligibility depends on the
	// tenant's licence (e.g. Microsoft 365 Business Premium keeps the device
	// on Windows 11 Pro), which Microsoft decides in its cloud and nothing on
	// the device shows. Consumers that must know whether a client actually
	// receives hotpatches should look for an installed hotpatch update instead.
	// On servers the value comes from the Hotpatch Enrollment Package check.
	HotpatchLabel = "windows.mondoo.com/hotpatch"
)

// isClientOS returns true if the platform's product-type indicates a workstation (Windows client).
func isClientOS(pf *inventory.Platform) bool {
	return pf.Labels["windows.mondoo.com/product-type"] == "1"
}

// WindowsClientHotpatch holds the values relevant for client (Win11) hotpatch detection.
type WindowsClientHotpatch struct {
	AllowRebootlessUpdates string `json:"AllowRebootlessUpdates"`
	// EnableVirtualizationBasedSecurity is the CONFIGURED state of VBS (registry
	// value HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard). VBS can be
	// running without this value being set, so it is only a fallback.
	EnableVirtualizationBasedSecurity string `json:"EnableVirtualizationBasedSecurity"`
	// VirtualizationBasedSecurityStatus is the RUNNING state of VBS as reported by
	// Win32_DeviceGuard (root\Microsoft\Windows\DeviceGuard): "0" = not enabled,
	// "1" = enabled but not running, "2" = enabled and running. Empty when the
	// WMI query returned nothing.
	// https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#validate-enabled-vbs-and-memory-integrity-features
	VirtualizationBasedSecurityStatus string `json:"VirtualizationBasedSecurityStatus"`
}

// vbsRunning reports whether VBS satisfies the hotpatch prerequisite. Microsoft
// asks to verify that VBS is running, so the WMI running state wins whenever it
// is present (a configured-but-not-running VBS does not satisfy it). Only when
// the running state is unavailable (older OS, WMI error) do we fall back to the
// configured registry value.
func (h WindowsClientHotpatch) vbsRunning() bool {
	if h.VirtualizationBasedSecurityStatus != "" {
		return h.VirtualizationBasedSecurityStatus == "2"
	}
	return h.EnableVirtualizationBasedSecurity == "1"
}

// enabled reports whether the client hotpatch prerequisites hold: the
// rebootless-updates policy is on and VBS is running. Shared by the PowerShell
// and native paths.
func (h WindowsClientHotpatch) enabled() bool {
	return h.AllowRebootlessUpdates == "1" && h.vbsRunning()
}

// ParseWinRegistryClientHotpatch checks whether AllowRebootlessUpdates is enabled and VBS is running.
func ParseWinRegistryClientHotpatch(r io.Reader) (bool, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return false, err
	}

	var hotpatch WindowsClientHotpatch
	err = json.Unmarshal(data, &hotpatch)
	if err != nil {
		return false, err
	}
	log.Debug().Interface("ClientHotpatch", hotpatch).Msg("Parsed client hotpatch information")

	return hotpatch.enabled(), nil
}

// hotpatchSupported checks whether the given platform meets the prerequisites
// for hotpatching:
//   - Windows Server 2022+ (build 20348+, product-type "2" or "3")
//   - Windows 11 24H2+ client (product-type "1") on an edition that can be
//     enrolled (see isHotpatchEligibleClientEdition):
//   - x64 (AMD64/Intel): build 26100.2033+
//   - arm64: build 26100.4929+
//
// Client hotpatch is license-gated, not edition-gated. Microsoft lists Windows
// Enterprise E3/E5, Education A3/A5, Microsoft 365 F3, Microsoft 365 Business
// Premium and Windows 365 Enterprise as eligible. Business Premium includes
// "Windows for business" (Windows 11 Pro / Pro for Workstations) and does not
// step the device up to Enterprise, so a hotpatch-enrolled client can run Pro.
// The edition therefore only rules out SKUs that can never be enrolled (Home, SE).
//
// The resulting label is a hint: a Pro device with the hotpatch policy and VBS
// but without an entitlement is still reported as hotpatch-capable here. The
// asset's build number is the stronger signal for consumers of this label.
//
// References:
//   - https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/manage/windows-autopatch-hotpatch-updates#prerequisites (eligible licenses)
//   - https://learn.microsoft.com/microsoft-365/business-premium/microsoft-365-business-faqs (Business Premium includes Windows for business)
//   - https://learn.microsoft.com/windows/deployment/windows-subscription-activation#how-it-works (only Enterprise E3/E5 steps Pro up to Enterprise)
//   - https://learn.microsoft.com/en-us/intune/device-updates/windows/manage-quality-updates#prerequisites (quality update policies support Pro, Pro Education, Enterprise, Education)
//   - https://learn.microsoft.com/en-us/windows/client-management/hotpatch (technical preconditions: build, UBR, VBS, ARM64 CHPE)
func hotpatchSupported(pf *inventory.Platform) bool {
	buildNumber, err := strconv.Atoi(pf.Version)
	if err != nil {
		log.Error().Err(err).Msg("could not parse windows build number")
		return false
	}
	log.Debug().Int("buildNumber", buildNumber).Msg("parsed windows build number")

	productType := pf.Labels["windows.mondoo.com/product-type"]
	switch productType {
	case "1": // Workstation (Windows client)
		if !isHotpatchEligibleClientEdition(pf.Title) {
			log.Debug().Str("title", pf.Title).Msg("windows client edition is not hotpatch-eligible")
			return false
		}
		if buildNumber > 26100 {
			return true
		}
		if buildNumber < 26100 {
			return false
		}
		ubr, err := strconv.Atoi(pf.Build)
		if err != nil {
			log.Error().Err(err).Msg("could not parse windows UBR")
			return false
		}
		log.Debug().Int("ubr", ubr).Str("arch", pf.Arch).Msg("parsed windows UBR for client hotpatch check")
		minUBR := 2033
		if strings.EqualFold(pf.Arch, "arm64") {
			minUBR = 4929
		}
		return ubr >= minUBR
	case "2", "3": // Domain Controller or Server
		return buildNumber >= 20348
	default:
		return false
	}
}

// isHotpatchEligibleClientEdition reports whether `title` (the human-readable
// Windows edition string from platform detection, e.g. "Windows 11 Enterprise"
// or "Windows 11 Pro") corresponds to an edition that can be enrolled in client
// hotpatch.
//
// Eligibility is license-gated, and not every eligible license activates
// Enterprise: Microsoft 365 Business Premium keeps the device on Windows 11 Pro
// (see hotpatchSupported). Accepted are the editions Intune quality-update
// policies and Windows Autopatch support: Pro, Pro for Workstations, Pro
// Education, Enterprise, Education and IoT Enterprise. Home, Home Single
// Language and SE can never be enrolled. An empty Title is refused since we
// cannot tell what is running.
//
// Autopatch prerequisites: https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/prepare/windows-autopatch-prerequisites
func isHotpatchEligibleClientEdition(title string) bool {
	t := strings.ToLower(title)
	if t == "" {
		return false
	}
	if strings.Contains(t, "enterprise") || strings.Contains(t, "education") {
		return true
	}
	// Pro family ("Pro", "Pro for Workstations", "Professional"): match on whole
	// words so unrelated titles containing "pro" as a substring do not qualify.
	for _, w := range strings.Fields(t) {
		if w == "pro" || w == "professional" {
			return true
		}
	}
	return false
}

type WindowsHotpatch struct {
	Name                              string `json:"Name"`
	HotPatchTableSize                 string `json:"HotPatchTableSize"`
	EnableVirtualizationBasedSecurity string `json:"EnableVirtualizationBasedSecurity"`
}

func ParseWinRegistryHotpatch(r io.Reader) (bool, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return false, err
	}

	var hotpatch WindowsHotpatch
	err = json.Unmarshal(data, &hotpatch)
	if err != nil {
		return false, err
	}
	log.Debug().Interface("Hotpatch", hotpatch).Msg("Parsed hotpatch information")

	return hotpatch.Name == HotpatchPackage && hotpatch.EnableVirtualizationBasedSecurity == "1" && hotpatch.HotPatchTableSize != "0", nil
}

// https://learn.microsoft.com/en-us/windows-server/get-started/hotpatch
// https://learn.microsoft.com/en-us/windows-server/get-started/enable-hotpatch-azure-edition
// https://learn.microsoft.com/en-us/windows/client-management/hotpatch

// powershellGetWindowsClientHotpatch queries the client-specific AllowRebootlessUpdates policy and VBS.
// VBS is read as its running state from Win32_DeviceGuard; the registry
// configuration value is collected as a fallback for when WMI yields nothing.
func powershellGetWindowsClientHotpatch(conn shared.Connection) (bool, error) {
	pscommand := `
$rebootless = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -Name AllowRebootlessUpdates -ErrorAction SilentlyContinue
$sysInfo = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue
$dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$result = @{}
if ($rebootless) { $result.AllowRebootlessUpdates = [string]$rebootless.AllowRebootlessUpdates }
if ($sysInfo) { $result.EnableVirtualizationBasedSecurity = [string]$sysInfo.EnableVirtualizationBasedSecurity }
if ($dg -and $null -ne $dg.VirtualizationBasedSecurityStatus) { $result.VirtualizationBasedSecurityStatus = [string]$dg.VirtualizationBasedSecurityStatus }
$result | ConvertTo-Json
`

	log.Debug().Msg("checking Windows client hotpatch runtime")
	cmd, err := conn.RunCommand(powershell.Encode(pscommand))
	if err != nil {
		log.Debug().Err(err).Msg("could not run powershell command to get client hotpatch information")
		return false, nil
	}
	return ParseWinRegistryClientHotpatch(cmd.Stdout)
}

// powershellGetWindowsServerHotpatch queries the server-specific hotpatch enrollment, VBS and HotPatchTableSize.
func powershellGetWindowsServerHotpatch(conn shared.Connection, arch string) (bool, error) {
	// FIXME: for windows 2025 this might be arm64
	pscommand := `
$info = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled\Hotpatch.` + strings.ToLower(arch) + `' -Name Name
$sysInfo = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name EnableVirtualizationBasedSecurity
$hotpatch = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name HotPatchTableSize
$sysInfo | Add-Member -MemberType NoteProperty -Name Name -Value $info.Name
$hotpatch | Add-Member -MemberType NoteProperty -Name HotPatchTableSize -Value $hotpatch.HotPatchTableSize
$sysInfo | Select-Object Name, EnableVirtualizationBasedSecurity, HotPatchTableSize | ConvertTo-Json
`

	log.Debug().Msg("checking Windows server hotpatch runtime")
	cmd, err := conn.RunCommand(powershell.Encode(pscommand))
	if err != nil {
		log.Debug().Err(err).Msg("could not run powershell command to get hotpatch information")
		return false, nil
	}
	return ParseWinRegistryHotpatch(cmd.Stdout)
}

// powershellGetWindowsHotpatch runs a powershell script to determine whether hotpatching is enabled on the system.
// Hotpatching is supported on Windows Server 2022+ and Windows 11 Enterprise 24H2+.
func powershellGetWindowsHotpatch(conn shared.Connection, pf *inventory.Platform) (bool, error) {
	if isClientOS(pf) {
		return powershellGetWindowsClientHotpatch(conn)
	}
	return powershellGetWindowsServerHotpatch(conn, pf.Arch)
}

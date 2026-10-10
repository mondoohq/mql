// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
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

// Registry locations read for hotpatch. Software paths are relative to
// HKLM\SOFTWARE, system paths to the active control set of HKLM\SYSTEM.
const (
	hotpatchPackageKeyPrefix = `Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled\Hotpatch.`
	rebootlessUpdatesKey     = `Microsoft\PolicyManager\current\device\Update`
	deviceGuardSystemKey     = `Control\DeviceGuard`
	memoryManagementKey      = `Control\Session Manager\Memory Management`
)

// isClientOS returns true if the platform's product-type indicates a workstation (Windows client).
func isClientOS(pf *inventory.Platform) bool {
	return pf.Labels["windows.mondoo.com/product-type"] == "1"
}

// IsClientOS reports whether the platform is a Windows client (product-type 1).
func IsClientOS(pf *inventory.Platform) bool {
	return isClientOS(pf)
}

// HotpatchState is the hotpatch-related state of a Windows host as read from
// the registry and, where available, WMI. Every field is nil when its value is
// absent or could not be read, so "not set" stays distinguishable from 0.
type HotpatchState struct {
	// EnrollmentPackage is the Name value under
	// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled\Hotpatch.<arch>.
	EnrollmentPackage *string
	// HotPatchTableSize is the value under
	// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management.
	HotPatchTableSize *int64
	// AllowRebootlessUpdates is the client hotpatch policy under
	// HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update.
	AllowRebootlessUpdates *int64
	// EnableVirtualizationBasedSecurity is the CONFIGURED state of VBS (registry
	// value HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard). VBS can be
	// running without this value being set.
	EnableVirtualizationBasedSecurity *int64
	// VirtualizationBasedSecurityStatus is the RUNNING state of VBS as reported by
	// Win32_DeviceGuard (root\Microsoft\Windows\DeviceGuard): 0 = not enabled,
	// 1 = enabled but not running, 2 = enabled and running. Nil when WMI could
	// not be queried, as in an offline scan of registry hives.
	// https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#validate-enabled-vbs-and-memory-integrity-features
	VirtualizationBasedSecurityStatus *int64
}

// VBSConfigured reports the configured VBS value, nil when it is absent.
func (s *HotpatchState) VBSConfigured() *bool {
	if s.EnableVirtualizationBasedSecurity == nil {
		return nil
	}
	v := *s.EnableVirtualizationBasedSecurity == 1
	return &v
}

// VBSRunning reports the WMI running state of VBS, nil when it is unknown.
func (s *HotpatchState) VBSRunning() *bool {
	if s.VirtualizationBasedSecurityStatus == nil {
		return nil
	}
	v := *s.VirtualizationBasedSecurityStatus == 2
	return &v
}

// RebootlessUpdatesPolicy reports the AllowRebootlessUpdates policy, nil when
// it is absent.
func (s *HotpatchState) RebootlessUpdatesPolicy() *bool {
	if s.AllowRebootlessUpdates == nil {
		return nil
	}
	v := *s.AllowRebootlessUpdates == 1
	return &v
}

// clientVBSRunning reports whether VBS satisfies the client hotpatch
// prerequisite. Microsoft asks to verify that VBS is running, so the WMI
// running state wins whenever it is present (a configured-but-not-running VBS
// does not satisfy it). Only when the running state is unavailable (older OS,
// WMI error, offline scan) do we fall back to the configured registry value.
func (s *HotpatchState) clientVBSRunning() bool {
	if running := s.VBSRunning(); running != nil {
		return *running
	}
	return s.EnableVirtualizationBasedSecurity != nil && *s.EnableVirtualizationBasedSecurity == 1
}

// ClientEnrolled reports whether the client hotpatch prerequisites hold: the
// rebootless-updates policy is on and VBS is running. This means the device is
// configured for hotpatch; whether it receives hotpatches is decided by
// Microsoft's cloud based on licensing.
func (s *HotpatchState) ClientEnrolled() bool {
	return s.AllowRebootlessUpdates != nil && *s.AllowRebootlessUpdates == 1 && s.clientVBSRunning()
}

// ServerEnrolled reports whether a server is enrolled in hotpatch: the
// Hotpatch Enrollment Package is installed, VBS is configured, and the
// HotPatchTableSize is non-zero.
func (s *HotpatchState) ServerEnrolled() bool {
	return s.EnrollmentPackage != nil && *s.EnrollmentPackage == HotpatchPackage &&
		s.EnableVirtualizationBasedSecurity != nil && *s.EnableVirtualizationBasedSecurity == 1 &&
		s.HotPatchTableSize != nil && *s.HotPatchTableSize != 0
}

// Enrolled applies the client or the server rule.
func (s *HotpatchState) Enrolled(client bool) bool {
	if client {
		return s.ClientEnrolled()
	}
	return s.ServerEnrolled()
}

// ParseHotpatchState parses the JSON written by the hotpatch PowerShell
// script. Values may be strings or numbers; absent, null and empty values
// stay nil.
func ParseHotpatchState(r io.Reader) (*HotpatchState, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	st := &HotpatchState{
		HotPatchTableSize:                 jsonInt(raw["HotPatchTableSize"]),
		AllowRebootlessUpdates:            jsonInt(raw["AllowRebootlessUpdates"]),
		EnableVirtualizationBasedSecurity: jsonInt(raw["EnableVirtualizationBasedSecurity"]),
		VirtualizationBasedSecurityStatus: jsonInt(raw["VirtualizationBasedSecurityStatus"]),
	}
	if v, ok := raw["Name"].(string); ok && v != "" {
		st.EnrollmentPackage = &v
	}
	log.Debug().Interface("hotpatch", st).Msg("parsed windows hotpatch state")
	return st, nil
}

func jsonInt(v any) *int64 {
	switch x := v.(type) {
	case float64:
		i := int64(x)
		return &i
	case string:
		return parseInt(x)
	}
	return nil
}

func parseInt(s string) *int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	return &i
}

// ParseWinRegistryClientHotpatch checks whether AllowRebootlessUpdates is enabled and VBS is running.
func ParseWinRegistryClientHotpatch(r io.Reader) (bool, error) {
	st, err := ParseHotpatchState(r)
	if err != nil {
		return false, err
	}
	return st.ClientEnrolled(), nil
}

// ParseWinRegistryHotpatch checks the server hotpatch enrollment rule.
func ParseWinRegistryHotpatch(r io.Reader) (bool, error) {
	st, err := ParseHotpatchState(r)
	if err != nil {
		return false, err
	}
	return st.ServerEnrolled(), nil
}

// HotpatchEligible reports whether the platform's OS, edition, build and
// architecture allow hotpatch. It says nothing about enrollment.
func HotpatchEligible(pf *inventory.Platform) bool {
	return hotpatchSupported(pf)
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
//   - https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/manage/windows-autopatch-hotpatch-updates (technical preconditions: build, UBR, VBS, ARM64 CHPE)
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

// hotpatchArch returns the architecture suffix of the enrollment package key,
// such as amd64. An unknown architecture is read as amd64.
func hotpatchArch(arch string) string {
	if arch == "" {
		return "amd64"
	}
	return strings.ToLower(arch)
}

// https://learn.microsoft.com/en-us/windows-server/get-started/hotpatch
// https://learn.microsoft.com/en-us/windows-server/get-started/enable-hotpatch-azure-edition
// https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/manage/windows-autopatch-hotpatch-updates

// hotpatchStateScript reads every hotpatch value in one PowerShell run. Each
// value is written as a string and left out when it is absent, so the parser
// can tell an absent value from 0. VBS is read as its running state from
// Win32_DeviceGuard, which is left out when WMI yields nothing.
const hotpatchStateScript = `
$result = @{}
$pkg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled\Hotpatch.%s' -Name Name -ErrorAction SilentlyContinue
if ($pkg -and $null -ne $pkg.Name) { $result.Name = [string]$pkg.Name }
$mm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name HotPatchTableSize -ErrorAction SilentlyContinue
if ($mm -and $null -ne $mm.HotPatchTableSize) { $result.HotPatchTableSize = [string]$mm.HotPatchTableSize }
$rebootless = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -Name AllowRebootlessUpdates -ErrorAction SilentlyContinue
if ($rebootless -and $null -ne $rebootless.AllowRebootlessUpdates) { $result.AllowRebootlessUpdates = [string]$rebootless.AllowRebootlessUpdates }
$sysInfo = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue
if ($sysInfo -and $null -ne $sysInfo.EnableVirtualizationBasedSecurity) { $result.EnableVirtualizationBasedSecurity = [string]$sysInfo.EnableVirtualizationBasedSecurity }
$dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
if ($dg -and $null -ne $dg.VirtualizationBasedSecurityStatus) { $result.VirtualizationBasedSecurityStatus = [string]$dg.VirtualizationBasedSecurityStatus }
$result | ConvertTo-Json
`

// HotpatchStateCommand returns the encoded PowerShell command that reads the
// hotpatch state for the given architecture.
func HotpatchStateCommand(arch string) string {
	return powershell.Encode(fmt.Sprintf(hotpatchStateScript, hotpatchArch(arch)))
}

// powershellGetHotpatchState reads the hotpatch state over PowerShell.
func powershellGetHotpatchState(conn shared.Connection, arch string) (*HotpatchState, error) {
	log.Debug().Msg("checking Windows hotpatch state")
	cmd, err := conn.RunCommand(HotpatchStateCommand(arch))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("could not read the windows hotpatch state: %s", strings.TrimSpace(string(stderr)))
	}
	return ParseHotpatchState(cmd.Stdout)
}

// hotpatchRegistry reads the values of a key under HKLM\SOFTWARE or under the
// active control set of HKLM\SYSTEM. It hides whether the live registry or a
// hive loaded from a file is read.
type hotpatchRegistry interface {
	softwareItems(path string) ([]registry.RegistryKeyItem, error)
	systemItems(path string) ([]registry.RegistryKeyItem, error)
}

// readHotpatchRegistry reads the hotpatch registry values. A key or value that
// cannot be read leaves its field nil. The VBS running state is not in the
// registry and stays nil.
func readHotpatchRegistry(r hotpatchRegistry, arch string) *HotpatchState {
	st := &HotpatchState{}
	if items, err := r.softwareItems(hotpatchPackageKeyPrefix + hotpatchArch(arch)); err == nil {
		if it, ok := findRegistryItem(items, "Name"); ok && it.Value.String != "" {
			name := it.Value.String
			st.EnrollmentPackage = &name
		}
	} else {
		log.Debug().Err(err).Msg("could not read the hotpatch enrollment package key")
	}
	st.AllowRebootlessUpdates = registryInt(r.softwareItems, rebootlessUpdatesKey, "AllowRebootlessUpdates")
	st.EnableVirtualizationBasedSecurity = registryInt(r.systemItems, deviceGuardSystemKey, "EnableVirtualizationBasedSecurity")
	st.HotPatchTableSize = registryInt(r.systemItems, memoryManagementKey, "HotPatchTableSize")
	log.Debug().Interface("hotpatch", st).Msg("read windows hotpatch registry values")
	return st
}

func registryInt(read func(string) ([]registry.RegistryKeyItem, error), path, name string) *int64 {
	items, err := read(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not read hotpatch registry key")
		return nil
	}
	it, ok := findRegistryItem(items, name)
	if !ok {
		return nil
	}
	return parseInt(it.Value.String)
}

// findRegistryItem looks up a value by name. Registry value names are
// case-insensitive.
func findRegistryItem(items []registry.RegistryKeyItem, name string) (registry.RegistryKeyItem, bool) {
	for _, it := range items {
		if strings.EqualFold(it.Key, name) {
			return it, true
		}
	}
	return registry.RegistryKeyItem{}, false
}

// HiveValueReader reads one value from a hive loaded from a file;
// *registry.RegistryHandler implements it.
type HiveValueReader interface {
	GetRegistryItemValue(registryId string, path, key string) (registry.RegistryKeyItem, error)
}

// HiveReader is the part of the registry handler offline hotpatch reads need;
// *registry.RegistryHandler implements it.
type HiveReader interface {
	HiveValueReader
	GetNativeRegistryKeyItems(registryId string, path string) ([]registry.RegistryKeyItem, error)
}

// StaticControlSet returns the SYSTEM hive's active control set key, such as
// ControlSet001. CurrentControlSet exists only in the live registry, as a link
// the kernel creates at boot; a SYSTEM hive loaded from a file has only the
// numbered control sets and names the active one in Select\Current.
func StaticControlSet(rh HiveValueReader) string {
	if v, err := rh.GetRegistryItemValue(registry.System, "Select", "Current"); err == nil && v.Value.Number > 0 && v.Value.Number < 1000 {
		return fmt.Sprintf("ControlSet%03d", v.Value.Number)
	}
	return "ControlSet001"
}

// hiveRegistry reads SOFTWARE and SYSTEM hives loaded from files.
type hiveRegistry struct {
	rh         HiveReader
	controlSet string
}

func (h hiveRegistry) softwareItems(path string) ([]registry.RegistryKeyItem, error) {
	return h.rh.GetNativeRegistryKeyItems(registry.Software, path)
}

func (h hiveRegistry) systemItems(path string) ([]registry.RegistryKeyItem, error) {
	return h.rh.GetNativeRegistryKeyItems(registry.System, h.controlSet+`\`+path)
}

// ReadStaticHotpatchState reads the hotpatch state from loaded SOFTWARE and
// SYSTEM hives. An offline scan cannot ask WMI, so the VBS running state is
// always nil.
func ReadStaticHotpatchState(rh HiveReader, arch string) *HotpatchState {
	return readHotpatchRegistry(hiveRegistry{rh: rh, controlSet: StaticControlSet(rh)}, arch)
}

// LoadStaticHotpatchState loads the SOFTWARE and SYSTEM hives of an offline
// Windows filesystem and reads the hotpatch state from them.
func LoadStaticHotpatchState(conn shared.Connection, arch string) (*HotpatchState, error) {
	rh := registry.NewRegistryHandler()
	defer func() {
		if err := rh.UnloadSubkeys(); err != nil {
			log.Debug().Err(err).Msg("could not unload registry subkeys")
		}
	}()
	loaded := false
	for _, hive := range []string{registry.Software, registry.System} {
		fi, err := conn.FileInfo(registry.KnownRegistryFiles[hive])
		if err != nil {
			log.Debug().Err(err).Str("hive", hive).Msg("could not find registry hive")
			continue
		}
		if err := rh.LoadSubkey(hive, fi.Path); err != nil {
			log.Debug().Err(err).Str("hive", hive).Msg("could not load registry hive")
			continue
		}
		loaded = true
	}
	if !loaded {
		return nil, errors.New("could not load the SOFTWARE or SYSTEM registry hive")
	}
	return ReadStaticHotpatchState(rh, arch), nil
}

// GetHotpatchState reads the hotpatch state over the given connection: the
// native registry and WMI when scanning the local Windows machine, PowerShell
// on connections that can run commands, and the offline registry hives
// otherwise.
func GetHotpatchState(conn shared.Connection, arch string) (*HotpatchState, error) {
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		return nativeGetHotpatchState(arch), nil
	}
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		return powershellGetHotpatchState(conn, arch)
	}
	if conn.Capabilities().Has(shared.Capability_FileSearch) {
		return LoadStaticHotpatchState(conn, arch)
	}
	return nil, errors.New("windows hotpatch state cannot be read on this connection")
}

// GetWindowsHotpatch reports the hotpatch label value: false when the platform
// is not eligible, otherwise the client or server enrollment rule.
func GetWindowsHotpatch(conn shared.Connection, pf *inventory.Platform) (bool, error) {
	log.Debug().Msg("checking windows hotpatch")
	if !hotpatchSupported(pf) {
		return false, nil
	}
	st, err := GetHotpatchState(conn, pf.Arch)
	if err != nil {
		return false, err
	}
	return st.Enrolled(isClientOS(pf)), nil
}

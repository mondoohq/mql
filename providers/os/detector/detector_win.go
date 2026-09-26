// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	win "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/providers/os/registry"
)

// runtimeWindowsDetector uses powershell to gather information about the windows system
func runtimeWindowsDetector(pf *inventory.Platform, conn shared.Connection) (bool, error) {
	// most systems support wmi, but windows on arm does not ship with wmic, therefore we are trying to use windows
	// builds from registry key first. If that fails, we try to use wmi
	// see https://techcommunity.microsoft.com/t5/windows-it-pro-blog/wmi-command-line-wmic-utility-deprecation-next-steps/ba-p/4039242

	if pf.Labels == nil {
		pf.Labels = map[string]string{}
	}

	//  try to get build + ubr number (win 10+, 2019+)
	current, err := win.GetWindowsOSBuild(conn)
	if err == nil && current.UBR > 0 {
		platformFromWinCurrentVersion(pf, current)

		hotpatchEnabled, err := win.GetWindowsHotpatch(conn, pf)
		if err != nil {
			// Don't return an error here, as it is expected that this key may not exist
			log.Debug().Err(err).Msg("could not get windows hotpatch status")
		}

		pf.Labels["windows.mondoo.com/hotpatch"] = strconv.FormatBool(hotpatchEnabled)

		detectIntuneDeviceID(pf, conn)
		detectESU(pf, conn)
		return true, nil
	}

	// fallback to wmi if the registry key is not available
	data, err := win.GetWmiInformation(conn)
	if err != nil {
		log.Debug().Err(err).Msg("could not gather wmi information")
		return false, nil
	}

	pf.Name = "windows"
	pf.Title = data.Caption

	// instead of using windows major.minor.build.ubr we just use build.ubr since
	// major and minor can be derived from the build version
	pf.Version = data.BuildNumber

	// FIXME: we need to ask wmic cpu get architecture
	pf.Arch = data.OSArchitecture
	pf.Labels["windows.mondoo.com/product-type"] = data.ProductType

	correctForWindows11(pf)

	detectIntuneDeviceID(pf, conn)
	detectESU(pf, conn)
	return true, nil
}

func platformFromWinCurrentVersion(pf *inventory.Platform, current *win.WindowsCurrentVersion) {
	pf.Name = "windows"
	pf.Title = current.ProductName
	pf.Version = current.CurrentBuild
	pf.Build = strconv.Itoa(current.UBR)
	pf.Arch = current.Architecture

	var productType string
	switch current.ProductType {
	case "WinNT":
		productType = "1" // Workstation
	case "ServerNT":
		productType = "3" // Server
	case "LanmanNT":
		productType = "2" // Domain Controller
	}

	if pf.Labels == nil {
		pf.Labels = map[string]string{}
	}

	pf.Labels["windows.mondoo.com/product-type"] = productType
	pf.Labels["windows.mondoo.com/display-version"] = current.DisplayVersion
	pf.Labels["windows.mondoo.com/edition-id"] = current.EditionID

	correctForWindows11(pf)
}

func staticWindowsDetector(pf *inventory.Platform, conn shared.Connection) (bool, error) {
	rh := registry.NewRegistryHandler()
	defer func() {
		err := rh.UnloadSubkeys()
		if err != nil {
			log.Debug().Err(err).Msg("could not unload registry subkeys")
		}
	}()
	fi, err := conn.FileInfo(registry.SoftwareRegPath)
	if err != nil {
		log.Debug().Err(err).Msg("could not find SOFTWARE registry key file")
		return false, nil
	}
	err = rh.LoadSubkey(registry.Software, fi.Path)
	if err != nil {
		log.Debug().Err(err).Msg("could not load SOFTWARE registry key file")
		return false, nil
	}

	// Load SYSTEM hive for ProductType, VBS, and HotPatchTableSize reads
	systemFi, err := conn.FileInfo(registry.SystemRegPath)
	if err != nil {
		log.Debug().Err(err).Msg("could not find SYSTEM registry key file")
	} else {
		err = rh.LoadSubkey(registry.System, systemFi.Path)
		if err != nil {
			log.Debug().Err(err).Msg("could not load SYSTEM registry key file")
		}
	}

	// Build a WindowsCurrentVersion from the registry hives and reuse platformFromWinCurrentVersion
	current := &win.WindowsCurrentVersion{}

	if v, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\Windows NT\\CurrentVersion", "ProductName"); err == nil {
		current.ProductName = v.Value.String
	}
	if v, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\Windows NT\\CurrentVersion", "EditionID"); err == nil {
		current.EditionID = v.Value.String
	}
	if v, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\Windows NT\\CurrentVersion", "Architecture"); err == nil {
		current.Architecture = v.Value.String
	}
	if v, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion"); err == nil {
		current.DisplayVersion = v.Value.String
	}
	if v, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\Windows NT\\CurrentVersion", "UBR"); err == nil {
		current.UBR, _ = strconv.Atoi(v.Value.String)
	}
	// we try both CurrentBuild and CurrentBuildNumber for the version number
	if v, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild"); err == nil && v.Value.String != "" {
		current.CurrentBuild = v.Value.String
	} else if v, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber"); err == nil {
		current.CurrentBuild = v.Value.String
	}
	if v, err := rh.GetRegistryItemValue(registry.System, staticControlSet(rh)+"\\Control\\ProductOptions", "ProductType"); err == nil {
		current.ProductType = v.Value.String
	}

	platformFromWinCurrentVersion(pf, current)

	var hotpatchEnabled bool
	if pf.Labels["windows.mondoo.com/product-type"] == "1" {
		hotpatchEnabled = staticClientHotpatch(rh)
	} else {
		hotpatchEnabled = staticServerHotpatch(rh, pf.Arch)
	}
	pf.Labels["windows.mondoo.com/hotpatch"] = strconv.FormatBool(hotpatchEnabled)

	if win.IdentityDetectable(pf) {
		applyIntuneInfo(pf, staticIntuneInfo(rh))
	}

	return true, nil
}

// staticControlSet returns the SYSTEM hive's active control set key, such as
// ControlSet001. CurrentControlSet exists only in the live registry, as a link
// the kernel creates at boot; a SYSTEM hive loaded from a file has only the
// numbered control sets and names the active one in Select\Current.
// hiveValueReader is the part of the registry handler staticControlSet needs.
type hiveValueReader interface {
	GetRegistryItemValue(registryId string, path, key string) (registry.RegistryKeyItem, error)
}

func staticControlSet(rh hiveValueReader) string {
	if v, err := rh.GetRegistryItemValue(registry.System, "Select", "Current"); err == nil && v.Value.Number > 0 && v.Value.Number < 1000 {
		return fmt.Sprintf("ControlSet%03d", v.Value.Number)
	}
	return "ControlSet001"
}

// staticClientHotpatch checks AllowRebootlessUpdates + VBS from offline registry hives.
func staticClientHotpatch(rh *registry.RegistryHandler) bool {
	allowRebootless, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\PolicyManager\\current\\device\\Update", "AllowRebootlessUpdates")
	if err == nil && allowRebootless.Value.String != "" {
		log.Debug().Str("allowRebootlessUpdates", allowRebootless.Value.String).Msg("found AllowRebootlessUpdates")
	}

	enableVBS, err := rh.GetRegistryItemValue(registry.System, staticControlSet(rh)+"\\Control\\DeviceGuard", "EnableVirtualizationBasedSecurity")
	if err == nil && enableVBS.Value.String != "" {
		log.Debug().Str("enableVirtualizationBasedSecurity", enableVBS.Value.String).Msg("found enableVirtualizationBasedSecurity")
	}

	return allowRebootless.Value.String == "1" && enableVBS.Value.String == "1"
}

// staticServerHotpatch checks hotpatch enrollment package + VBS + HotPatchTableSize from offline registry hives.
func staticServerHotpatch(rh *registry.RegistryHandler, arch string) bool {
	platformArch := "amd64"
	if arch != "" {
		platformArch = strings.ToLower(arch)
	}
	hotpatchPackage, err := rh.GetRegistryItemValue(registry.Software, "Microsoft\\Windows NT\\CurrentVersion\\Update\\TargetingInfo\\DynamicInstalled\\Hotpatch."+platformArch, "Name")
	if err == nil && hotpatchPackage.Value.String != "" {
		log.Debug().Str("hotpatchPackage", hotpatchPackage.Value.String).Msg("found hotpatchPackage")
	}

	enableVBS, err := rh.GetRegistryItemValue(registry.System, staticControlSet(rh)+"\\Control\\DeviceGuard", "EnableVirtualizationBasedSecurity")
	if err == nil && enableVBS.Value.String != "" {
		log.Debug().Str("enableVirtualizationBasedSecurity", enableVBS.Value.String).Msg("found enableVirtualizationBasedSecurity")
	}

	hotPatchTableSize, err := rh.GetRegistryItemValue(registry.System, staticControlSet(rh)+"\\Control\\Session Manager\\Memory Management", "HotPatchTableSize")
	if err == nil && hotPatchTableSize.Value.String != "" {
		log.Debug().Str("hotPatchTableSize", hotPatchTableSize.Value.String).Msg("found hotPatchTableSize")
	}

	return hotpatchPackage.Value.String == win.HotpatchPackage && enableVBS.Value.String == "1" && hotPatchTableSize.Value.String != "0" && hotPatchTableSize.Value.String != ""
}

// detectIntuneDeviceID detects the Intune device ID for Windows client systems.
// This includes workstations (product-type "1") and Windows 11 Enterprise Multi-Session
// systems which report as product-type "3" but are manageable via Intune.
func detectIntuneDeviceID(pf *inventory.Platform, conn shared.Connection) {
	if !win.IdentityDetectable(pf) {
		return
	}

	info, err := win.GetIntuneInfo(conn)
	if err != nil {
		log.Debug().Err(err).Msg("could not get Intune device information")
		return
	}
	applyIntuneInfo(pf, info)
}

// applyIntuneInfo sets the labels every detection path derives from the same
// Intune information, so the live, remote, and offline paths cannot disagree.
func applyIntuneInfo(pf *inventory.Platform, info *win.IntuneInfo) {
	if info == nil {
		return
	}
	if info.EntDMID != "" {
		pf.Labels["windows.mondoo.com/intune-device-id"] = info.EntDMID
	}
	// The Microsoft device identity comes from the public device certificates;
	// without access to the store the labels are absent.
	info.Identity().SetLabels(pf)
}

// hiveReader is the part of the registry handler the offline Intune reader
// needs; *registry.RegistryHandler implements it.
type hiveReader interface {
	GetNativeRegistryKeyChildren(registryId string, path string) ([]registry.RegistryKeyChild, error)
	GetNativeRegistryKeyItems(registryId string, path string) ([]registry.RegistryKeyItem, error)
}

const (
	enrollmentsKey        = `Microsoft\Enrollments`
	machineMyCertsKey     = `Microsoft\SystemCertificates\MY\Certificates`
	enrollmentDMClientKey = `DMClient\MS DM Server`
)

// staticIntuneInfo reads the Intune enrollment ID and the machine's personal
// certificates from a loaded SOFTWARE hive. It is the offline counterpart of
// GetIntuneInfo for filesystem connections, where no command can run. The
// certificate store lives in the same hive: each certificate is a subkey named
// by its thumbprint whose "Blob" value is a serialized store element.
func staticIntuneInfo(rh hiveReader) *win.IntuneInfo {
	info := &win.IntuneInfo{}

	if enrollments, err := rh.GetNativeRegistryKeyChildren(registry.Software, enrollmentsKey); err == nil {
		for _, e := range enrollments {
			items, err := rh.GetNativeRegistryKeyItems(registry.Software, enrollmentsKey+`\`+e.Name+`\`+enrollmentDMClientKey)
			if err != nil {
				continue
			}
			if id := registryString(items, "EntDMID"); id != "" {
				info.EntDMID = id
				break
			}
		}
	}

	if certs, err := rh.GetNativeRegistryKeyChildren(registry.Software, machineMyCertsKey); err == nil {
		for _, c := range certs {
			items, err := rh.GetNativeRegistryKeyItems(registry.Software, machineMyCertsKey+`\`+c.Name)
			if err != nil {
				continue
			}
			blob := registryBinary(items, "Blob")
			if len(blob) == 0 {
				continue
			}
			der, err := win.CertificateFromStoreBlob(blob)
			if err != nil {
				log.Debug().Err(err).Str("certificate", c.Name).Msg("skipping unreadable certificate store entry")
				continue
			}
			info.Certificates = append(info.Certificates, der)
		}
	}

	if info.EntDMID == "" && len(info.Certificates) == 0 {
		return nil
	}
	return info
}

// registryString and registryBinary look up a value by name. Registry value
// names are case-insensitive.
func registryString(items []registry.RegistryKeyItem, name string) string {
	for _, it := range items {
		if strings.EqualFold(it.Key, name) {
			return it.Value.String
		}
	}
	return ""
}

func registryBinary(items []registry.RegistryKeyItem, name string) []byte {
	for _, it := range items {
		if strings.EqualFold(it.Key, name) {
			return it.Value.Binary
		}
	}
	return nil
}

// detectESU checks if Windows 10 Extended Security Updates (ESU) are enabled.
// ESU is only relevant for Windows 10 version 22H2 (build 19045).
func detectESU(pf *inventory.Platform, conn shared.Connection) {
	// pf.Version holds the numeric OS build number (e.g. "19045" for Win10 22H2).
	buildNumber, err := strconv.Atoi(pf.Version)
	if err != nil {
		return
	}
	// Skip pre-Windows 10 builds (e.g. older Windows Server) and Windows 11+ (build >= 22000).
	// Only Windows 10 version 22H2 (build 19045) is supported for ESU.
	if buildNumber != 19045 {
		return
	}

	esuStatus, err := win.GetWindowsESUStatus(conn)
	if err != nil {
		log.Debug().Err(err).Msg("could not get Windows ESU status")
		return
	}

	if esuStatus.ESUEnabled() {
		if pf.Metadata == nil {
			pf.Metadata = map[string]string{}
		}
		pf.Metadata["windows.mondoo.com/support-type"] = "esu"
	}
}

// correctForWindows11 replaces the windows 10 title with windows 11 if the build number is greater than 22000
// See https://techcommunity.microsoft.com/discussions/windows-management/windows-10-21h2-and-windows-11-21h2-both-show-up-as-2009-release/2994441
func correctForWindows11(pf *inventory.Platform) {
	if strings.Contains(pf.Title, "10") {
		buildNumber, err := strconv.Atoi(pf.Version)
		if err != nil {
			return
		}
		if buildNumber >= 22000 {
			// replace 10 with 11
			pf.Title = strings.Replace(pf.Title, "10", "11", 1)
		}
	}
}

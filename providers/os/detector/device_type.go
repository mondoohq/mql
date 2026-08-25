// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"path"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

const (
	// MetadataDeviceType is the platform metadata key for the device type classification.
	MetadataDeviceType = "mondoo.com/device-type"

	// DeviceTypeServer indicates a system primarily used to run services
	// without an interactive desktop session.
	DeviceTypeServer = "server"

	// DeviceTypeWorkstation indicates a system with an interactive desktop
	// user session (physical or virtual).
	DeviceTypeWorkstation = "workstation"

	// DeviceTypeContainer indicates a container or container image.
	DeviceTypeContainer = "container"
)

// desktopVariantIDs lists VARIANT_ID values from /etc/os-release that indicate
// a desktop/workstation system (desktop environments, gaming, etc.).
var desktopVariantIDs = map[string]bool{
	"budgie":      true,
	"cinnamon":    true,
	"gnome":       true,
	"kde":         true,
	"lxde":        true,
	"lxqt":        true,
	"mate":        true,
	"pantheon":    true,
	"plasma":      true,
	"sway":        true,
	"steamdeck":   true,
	"workstation": true,
	"xfce":        true,
}

// serverVariantIDs lists VARIANT_ID values from /etc/os-release that indicate
// a server system (minimal/headless, cloud-optimized, etc.).
var serverVariantIDs = map[string]bool{
	"coreos": true,
	"server": true,
}

// containerVariantIDPrefixes lists VARIANT_ID prefixes from /etc/os-release that
// indicate a container environment (e.g. "container", "container-arm64").
var containerVariantIDPrefixes = []string{
	"container",
}

// desktopPlatformNames lists platform names (from os-release ID) that are
// inherently desktop-oriented distributions.
var desktopPlatformNames = map[string]bool{
	"elementary": true,
	"linuxmint":  true,
	"nobara":     true,
	"pop":        true,
	"steamos":    true,
	"zorin":      true,
}

// serverPlatformNames lists platform names that are inherently server-oriented
// or minimal distributions with no desktop use case.
// Note: Alpine has a desktop edition, but the vast majority of Alpine installs
// are containers or servers. Desktop Alpine users will be detected via the
// systemd target or session directory fallbacks.
var serverPlatformNames = map[string]bool{
	"alpine":           true,
	"bottlerocket":     true,
	"cos":              true,
	"flatcar":          true,
	"gardenlinux":      true,
	"opensuse-microos": true,
	"photon":           true,
	"suse-microos":     true,
}

// systemdDefaultTargetPaths lists the paths where systemd stores the default
// target symlink, in order of precedence.
var systemdDefaultTargetPaths = []string{
	"/etc/systemd/system/default.target",
	"/usr/lib/systemd/system/default.target",
}

// desktopSessionDirs lists directories whose presence indicates a system
// configured for interactive graphical sessions.
var desktopSessionDirs = []string{
	"/usr/share/xsessions",
	"/usr/share/wayland-sessions",
}

// DetectDeviceType classifies a platform as server, workstation, or container
// based on all available platform metadata and filesystem signals. It sets the
// MetadataDeviceType key in the platform's Metadata map.
func DetectDeviceType(pf *inventory.Platform, conn shared.Connection) {
	if pf == nil {
		return
	}

	if pf.Metadata == nil {
		pf.Metadata = map[string]string{}
	}

	deviceType := classifyDeviceType(pf, conn)
	pf.Metadata[MetadataDeviceType] = deviceType
	log.Debug().Str("device-type", deviceType).Msg("platform> detected device type")
}

func classifyDeviceType(pf *inventory.Platform, conn shared.Connection) string {
	// Containers and container images.
	if pf.Kind == "container" || pf.Kind == "container-image" {
		return DeviceTypeContainer
	}

	// Read VARIANT_ID once and reuse across checks.
	variantID := variantIDFromPlatform(pf)

	// Check VARIANT_ID for container indicators (e.g. "container", "container-arm64").
	if isContainerVariant(variantID) {
		return DeviceTypeContainer
	}

	// macOS is always a workstation. Currently the only darwin platform mql
	// detects is macOS; if iOS/visionOS targets are added this may need revisiting.
	if pf.IsFamily("darwin") || pf.Name == "macos" {
		return DeviceTypeWorkstation
	}

	// Windows: use the existing product-type label.
	if pf.IsFamily("windows") || pf.Name == "windows" {
		return classifyWindows(pf)
	}

	// Linux and other Unix systems.
	if pf.IsFamily("linux") || pf.IsFamily("unix") {
		return classifyLinux(pf, variantID, conn)
	}

	// Unknown platform: default to server (safe assumption for headless systems).
	return DeviceTypeServer
}

func isContainerVariant(variantID string) bool {
	for _, prefix := range containerVariantIDPrefixes {
		if strings.HasPrefix(variantID, prefix) {
			return true
		}
	}
	return false
}

func variantIDFromPlatform(pf *inventory.Platform) string {
	v := pf.Labels["variant-id"]
	if v == "" {
		v = pf.Metadata["variant-id"]
	}
	return strings.ToLower(v)
}

func classifyWindows(pf *inventory.Platform) string {
	productType := pf.Labels["windows.mondoo.com/product-type"]
	switch productType {
	case "1":
		return DeviceTypeWorkstation
	case "2", "3":
		// Domain controllers and servers, but check for Windows 11 Enterprise
		// Multi-Session which is a virtual desktop despite reporting as server.
		if strings.Contains(pf.Title, "Multi-Session") {
			return DeviceTypeWorkstation
		}
		return DeviceTypeServer
	default:
		// If product type is unknown, try title heuristics.
		if strings.Contains(strings.ToLower(pf.Title), "server") {
			return DeviceTypeServer
		}
		return DeviceTypeWorkstation
	}
}

func classifyLinux(pf *inventory.Platform, variantID string, conn shared.Connection) string {
	// 1. Check VARIANT_ID from os-release (most reliable when present, but rare).
	if variantID != "" {
		if desktopVariantIDs[variantID] {
			return DeviceTypeWorkstation
		}
		if serverVariantIDs[variantID] {
			return DeviceTypeServer
		}
	}

	// 2. Check platform name for well-known desktop or server distributions.
	nameLower := strings.ToLower(pf.Name)
	if desktopPlatformNames[nameLower] {
		return DeviceTypeWorkstation
	}
	if serverPlatformNames[nameLower] {
		return DeviceTypeServer
	}

	// 3. Check the platform title for keywords (e.g. "Ubuntu Server", "Fedora Workstation").
	titleLower := strings.ToLower(pf.Title)
	if strings.Contains(titleLower, "server") {
		return DeviceTypeServer
	}
	if strings.Contains(titleLower, "desktop") || strings.Contains(titleLower, "workstation") {
		return DeviceTypeWorkstation
	}

	// 4. Check systemd default target (covers Ubuntu, Debian, CentOS, Arch, etc.).
	if conn != nil {
		fs := conn.FileSystem()
		if dt := detectFromSystemdTarget(fs); dt != "" {
			return dt
		}

		// 5. Check for desktop session directories.
		if hasDesktopSessions(fs) {
			return DeviceTypeWorkstation
		}
	}

	// 6. Default: most Linux systems without explicit desktop indicators are servers.
	return DeviceTypeServer
}

// detectFromSystemdTarget reads the systemd default.target symlink and returns
// the device type if it points to a known target, or empty string if unknown.
func detectFromSystemdTarget(fs afero.Fs) string {
	lr, ok := fs.(afero.LinkReader)
	if !ok {
		log.Debug().Msg("device-type> filesystem does not support symlink reading")
		return ""
	}

	for _, targetPath := range systemdDefaultTargetPaths {
		linkDest, err := lr.ReadlinkIfPossible(targetPath)
		if err != nil {
			continue
		}

		target := path.Base(linkDest)
		switch target {
		case "graphical.target":
			return DeviceTypeWorkstation
		case "multi-user.target", "rescue.target", "emergency.target":
			return DeviceTypeServer
		}
		// If the symlink points to something else, keep trying other paths.
	}
	return ""
}

// hasDesktopSessions checks whether X11 or Wayland session directories exist
// and contain session files.
func hasDesktopSessions(fs afero.Fs) bool {
	for _, dir := range desktopSessionDirs {
		entries, err := afero.ReadDir(fs, dir)
		if err != nil {
			continue
		}
		// The directory must contain at least one session file to count.
		for _, e := range entries {
			if !e.IsDir() {
				return true
			}
		}
	}
	return false
}

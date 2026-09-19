// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type PkgFilesAvailable int

const (
	// PkgFilesNotAvailable means that the package manager does not provide any file information about the packages.
	// This is the default value.
	PkgFilesNotAvailable PkgFilesAvailable = 0
	// PkgFilesIncluded means that the package manager includes the files in the package metadata and can be queried
	// via the List function.
	PkgFilesIncluded PkgFilesAvailable = 1
	// PkgFilesAsync means that the package manager does not include the files in the package metadata and needs to be
	// queried asynchronously via the Files function.
	PkgFilesAsync PkgFilesAvailable = 2
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Epoch   string `json:"epoch,omitempty"`
	Arch    string `json:"arch"`
	Status  string `json:"status,omitempty"`

	// Pinned reports that the package manager is configured to hold this
	// package at its current version: a dpkg or opkg hold, a dnf or yum
	// versionlock, or a zypper lock.
	Pinned      bool   `json:"pinned,omitempty"`
	Description string `json:"description"`

	// this may be the source package or an origin
	// e.g. on alpine it is used for parent  packages
	// o 	Package Origin - https://wiki.alpinelinux.org/wiki/Apk_spec
	Origin string `json:"origin"`
	Format string `json:"format"`

	// Package Url follows https://github.com/package-url/purl-spec
	PUrl string `json:"purl,omitempty"`

	// Package CPE
	CPEs []string `json:"cpes,omitempty"`

	// Package files (optional, only for some package managers)
	FilesAvailable PkgFilesAvailable `json:"files_available,omitempty"`
	Files          []FileRecord      `json:"files,omitempty"`

	// This is used for the CPE generation and exposed via MQL
	Vendor string `json:"vendor,omitempty"`

	// SPDX license expression or upstream-reported license string.
	// Empty when the backend has no source for it (e.g. Windows
	// registry — DisplayName has no license field).
	License string `json:"license,omitempty"`

	// Time the package was installed on this asset. Zero when the
	// backend doesn't surface install time (dpkg-without-log, apk,
	// pacman, macOS).
	InstallDate time.Time `json:"install_date,omitempty"`
}

type FileRecord struct {
	Path     string      `json:"path"`
	Digest   PkgDigest   `json:"digest"`
	FileInfo PkgFileInfo `json:"permission"`
}

type PkgDigest struct {
	Value     string `json:"value"`
	Algorithm string `json:"type"`
}

type PkgFileInfo struct {
	Size  int64  `json:"size"`
	Mode  uint16 `json:"mode"`
	Flags int32  `json:"flags"`
	Owner string `json:"owner"`
	Group string `json:"group"`
}

// extends Package to store available version
type PackageUpdate struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Arch      string `json:"arch"`
	Available string `json:"available"`
	Repo      string `json:"repo"`
}

type OperatingSystemPkgManager interface {
	Name() string
	// List returns a list of Packages
	List() ([]Package, error)
	// Available returns a map of available package updates from the perspective of the package manager
	Available() (map[string]PackageUpdate, error)
	// Files returns a list of files on disk for a given package
	Files(name string, version string, arch string) ([]FileRecord, error)
}

// this will find the right package manager for the operating system
func ResolveSystemPkgManagers(conn shared.Connection) ([]OperatingSystemPkgManager, error) {
	var pms []OperatingSystemPkgManager

	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, errors.New("cannot find OS information for package detection")
	}

	switch {
	case asset.Platform.IsFamily("arch"): // arch family
		pms = append(pms, &PacmanPkgManager{conn: conn, platform: asset.Platform})
	case asset.Platform.IsFamily("debian"): // debian family
		pms = append(pms, &DebPkgManager{conn: conn, platform: asset.Platform})
		// This is supported in Debian and Ubuntu:
		// https: // snapcraft.io/docs/distro-support
		pms = append(pms, &SnapPkgManager{conn: conn, platform: asset.Platform})
	// ALT Linux is rpm based but is not in the redhat family: it ships
	// /etc/redhat-release and /etc/fedora-release carrying only "ALT Container"
	// with no distro name, so detection gives it a resolver of its own under
	// plain linux. Without a case here it matched nothing and packages reported
	// an error on a system with a populated rpm database.
	case asset.Platform.Name == "altlinux":
		fallthrough
	// opencloudos is rpm based but ships no /etc/redhat-release, so the redhat
	// family declines it and it resolves as a platform of its own. mariner is
	// CBL-Mariner 2.x, the name Azure Linux carried before the 3.0 rename; it
	// is rpm based and resolves as its own platform for the same reason.
	case asset.Platform.Name == "amazonlinux" || asset.Platform.Name == "photon" || asset.Platform.Name == "wrlinux" || asset.Platform.Name == "bottlerocket" || asset.Platform.Name == "azurelinux" || asset.Platform.Name == "mariner" || asset.Platform.Name == "opencloudos":
		fallthrough
	case asset.Platform.IsFamily("redhat") ||
		asset.Platform.IsFamily("euler") ||
		asset.Platform.Name == "mageia": // rhel/euler/mageia based systems
		pms = append(pms, &RpmPkgManager{conn: conn, platform: asset.Platform})
		if asset.Platform.Name == "fedora" {
			// https: // snapcraft.io/docs/distro-support
			pms = append(pms, &SnapPkgManager{conn: conn, platform: asset.Platform})
		}
	case asset.Platform.IsFamily("suse"): // suse handling
		pms = append(pms, &SusePkgManager{RpmPkgManager{conn: conn, platform: asset.Platform}})
	// alpine, wolfi, wizos, alpaquita, Chainguard OS, MinimOS, Echo and BellSoft
	// Hardened Containers share apk. The hardened image distros ship no apk
	// binary at all, but the database it wrote is left in place, so the package
	// inventory still reads.
	case asset.Platform.Name == "alpine" || asset.Platform.Name == "wolfi" || asset.Platform.Name == "wizos" ||
		asset.Platform.Name == "alpaquita" || asset.Platform.Name == "bellsoft-hardened-containers" ||
		asset.Platform.Name == "chainguard" || asset.Platform.Name == "minimos" ||
		asset.Platform.Name == "echo":
		pms = append(pms, &AlpinePkgManager{conn: conn, platform: asset.Platform})
	case asset.Platform.Name == "void": // Void Linux uses xbps
		pms = append(pms, &XbpsPkgManager{conn: conn, platform: asset.Platform})
	case asset.Platform.Name == "macos": // macos family
		pms = append(pms, &MacOSPkgManager{conn: conn, platform: asset.Platform})
	case asset.Platform.Name == "windows":
		pms = append(pms, &WinPkgManager{conn: conn, platform: asset.Platform})
	// Flatcar Container Linux is the continuation of CoreOS Container Linux
	// and keeps its design: /usr is immutable and the image ships no package
	// manager and no package database at all (verified on a live
	// Flatcar 4757.2.0 host: none of /var/lib/rpm, /usr/lib/sysimage/rpm,
	// /var/lib/dpkg/status, /lib/apk/db/installed, /var/db/pkg or
	// /var/lib/pacman exists). Its os-release says ID=flatcar with
	// ID_LIKE=coreos, so the name below is what detection reports and the
	// coreos case never matched it. Without this it fell through to the
	// filesystem probe, found no database, and `packages` failed with
	// "could not detect suitable package manager for platform" rather than
	// reporting the empty inventory that is the truth for the platform.
	case asset.Platform.Name == "scratch" || asset.Platform.Name == "coreos" || asset.Platform.Name == "flatcar":
		pms = append(pms, &ScratchPkgManager{conn: conn})
	case asset.Platform.Name == "openwrt":
		pms = append(pms, &OpkgPkgManager{conn: conn})
	case asset.Platform.Name == "solaris":
		pms = append(pms, &SolarisPkgManager{conn: conn})
	case asset.Platform.Name == "cos":
		pms = append(pms, &CosPkgManager{conn: conn, platform: asset.Platform})
	case asset.Platform.Name == "freebsd" || asset.Platform.Name == "dragonflybsd": // both use pkg cli
		pms = append(pms, &FreeBSDPkgManager{conn: conn})
	case asset.Platform.Name == "netbsd":
		pms = append(pms, &NetBSDPkgManager{conn: conn})
	case asset.Platform.Name == "openbsd":
		pms = append(pms, &OpenBSDPkgManager{conn: conn})
	case asset.Platform.Name == "aix":
		pms = append(pms, &AixPkgManager{conn: conn, platform: asset.Platform})
	case asset.Platform.Name == "gentoo":
		pms = append(pms, &GentooPkgManager{conn: conn, platform: asset.Platform})
	case asset.Platform.IsFamily("linux"):
		// No case above claimed this platform, so nothing above it knows which
		// package manager it uses. Every distro named above had to be named
		// because it carries neither a family nor a name any earlier case
		// matches, and a distro nobody has added yet is indistinguishable from
		// one nobody ever will: it lands here and, without a probe, reports no
		// package manager at all. CBL-Mariner 2.0 (ID=mariner) was one such
		// case, with a populated rpm database and no package inventory.
		//
		// So ask the filesystem instead of the name. A package database on
		// disk is the same evidence the named cases stand on, and it is
		// evidence the distro provides itself.
		opkgPaths := []string{"/bin/opkg", "/usr/bin/opkg"}
		for i := range opkgPaths {
			if _, err := conn.FileSystem().Stat(opkgPaths[i]); err == nil {
				pms = append(pms, &OpkgPkgManager{conn: conn})
				break
			}
		}

		// rpm keeps its database under /var/lib/rpm, or under
		// /usr/lib/sysimage/rpm on systems that moved it for /var immutability.
		rpmPaths := []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"}
		for i := range rpmPaths {
			if _, err := conn.FileSystem().Stat(rpmPaths[i]); err == nil {
				pms = append(pms, &RpmPkgManager{conn: conn, platform: asset.Platform})
				break
			}
		}

		if _, err := conn.FileSystem().Stat("/var/lib/dpkg/status"); err == nil {
			pms = append(pms, &DebPkgManager{conn: conn, platform: asset.Platform})
		}

		for _, path := range ApkDbPaths {
			if _, err := conn.FileSystem().Stat(path); err == nil {
				pms = append(pms, &AlpinePkgManager{conn: conn, platform: asset.Platform})
				break
			}
		}
	}

	// Nix can be installed on any Linux or macOS system.
	if asset.Platform.IsFamily("linux") || asset.Platform.Name == "macos" {
		if _, err := conn.FileSystem().Stat("/nix/store"); err == nil {
			pms = append(pms, &NixPkgManager{conn: conn, platform: asset.Platform})
		}
	}

	// Flatpak is cross-distro — check for its presence on any Linux platform.
	if asset.Platform.IsFamily("linux") {
		hasFlatpak := false
		if _, err := conn.FileSystem().Stat("/var/lib/flatpak"); err == nil {
			hasFlatpak = true
		}
		if !hasFlatpak && conn.Capabilities().Has(shared.Capability_RunCommand) {
			cmd, err := conn.RunCommand("which flatpak")
			if err == nil && cmd.ExitStatus == 0 {
				hasFlatpak = true
			}
		}
		if hasFlatpak {
			pms = append(pms, &FlatpakPkgManager{conn: conn, platform: asset.Platform})
		}
	}

	if len(pms) == 0 {
		return nil, errors.New("could not detect suitable package manager for platform: " + asset.Platform.Name)
	}

	return pms, nil
}

// isHeldStatus reports whether a dpkg-style status triple holds the package at
// its current version.
//
// The triple is "<want> <flag> <state>". dpkg records a hold in the want field,
// which is what `apt-mark hold` writes:
//
//	Status: hold ok installed
//
// opkg records it in the flag field, where dpkg carried it historically:
//
//	Status: install hold installed
//
// Only those two positions are considered. Matching "hold" anywhere in the
// string would also fire on a package whose name or state merely contains it.
func isHeldStatus(status string) bool {
	fields := strings.Fields(status)
	for i := 0; i < len(fields) && i < 2; i++ {
		if fields[i] == "hold" {
			return true
		}
	}
	return false
}

// epochFromVersion returns the epoch a Debian-style version string carries, or
// the empty string when it carries none.
//
// Debian writes a version as "[epoch:]upstream_version[-debian_revision]" and
// keeps the epoch inside the single Version field of the dpkg status file. rpm
// reports the two separately, so the rpm reader fills both Package.Epoch and
// the epoch-prefixed Package.Version and every consumer downstream sees an
// epoch. A deb package with an epoch reported an empty Epoch while its Version
// plainly began with one, which also left the epoch qualifier off its purl and
// an empty epoch in its CPE.
//
// Only a leading run of digits before the first colon is an epoch. An
// upstream_version may itself contain a colon, but Debian policy allows that
// only when an epoch is present, so the first colon is the epoch separator
// exactly when what precedes it is numeric and non-empty.
//
// "0" is reported as no epoch, matching normalizeRpmEpoch: an explicit zero is
// the same as an absent epoch, and purl already drops a "0" epoch qualifier.
func epochFromVersion(version string) string {
	colon := strings.IndexByte(version, ':')
	if colon < 1 {
		return ""
	}
	epoch := version[:colon]
	for i := 0; i < len(epoch); i++ {
		if epoch[i] < '0' || epoch[i] > '9' {
			return ""
		}
	}
	if strings.TrimLeft(epoch, "0") == "" {
		return ""
	}
	return epoch
}

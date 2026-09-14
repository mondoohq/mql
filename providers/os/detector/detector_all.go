// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"bytes"
	"io"
	"regexp"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

const (
	LabelDistroID = "distro-id"
)

// Operating Systems
var macOS = &PlatformResolver{
	Name:     "macos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// when we reach here, we know it is darwin
		// check xml /System/Library/CoreServices/SystemVersion.plist
		f, err := conn.FileSystem().Open("/System/Library/CoreServices/SystemVersion.plist")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil || len(c) == 0 {
			return false, nil
		}

		sv, err := ParseMacOSSystemVersion(string(c))
		if err != nil || len(c) == 0 {
			return false, nil
		}

		pf.Name = "macos"
		pf.Title = sv["ProductName"]
		pf.Version = sv["ProductVersion"]
		pf.Build = sv["ProductBuildVersion"]

		return true, nil
	},
}

// is part of the darwin platform and fallback for non-known darwin systems
var otherDarwin = &PlatformResolver{
	Name:     "darwin",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return true, nil
	},
}

var alpine = &PlatformResolver{
	Name:     "alpine",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// check if we are on edge
		osrd := NewOSReleaseDetector(conn)
		osr, err := osrd.osrelease()
		if err != nil {
			return false, nil
		}

		if osr["PRETTY_NAME"] == "Alpine Linux edge" {
			pf.Name = "alpine"
			pf.Version = "edge"
			pf.Build = osr["VERSION_ID"]
		}

		// if we are on alpine, the release was detected properly from parent check
		if pf.Name == "alpine" {
			return true, nil
		}

		f, err := conn.FileSystem().Open("/etc/alpine-release")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil || len(c) == 0 {
			return false, nil
		}

		pf.Name = "alpine"
		return true, nil
	},
}

var wolfi = &PlatformResolver{
	Name:     "wolfi",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "wolfi" {
			return true, nil
		}
		return false, nil
	},
}

// BellSoft Alpaquita is an Alpine-lineage distro (ID_LIKE=alpine) that ships
// its own ID=alpaquita in /etc/os-release and uses apk. It ships
// /etc/alpaquita-release rather than /etc/alpine-release, so alpine's fallback
// never claims it, and it is resolved before alpine regardless so that its
// exact-name match wins.
//
// VERSION_ID is the release line rather than a dotted version: "stream" on the
// rolling line, "23" and "25" on the LTS lines.
var alpaquita = &PlatformResolver{
	Name:     "alpaquita",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "alpaquita", nil
	},
}

// BellSoft Hardened Containers are built on Alpaquita and declare
// ID_LIKE=alpine, but they are a product of their own with
// ID=bellsoft-hardened-containers in /etc/os-release, their own release line
// and their own advisory feed, so they resolve as their own platform rather
// than as Alpaquita.
//
// The images carry no package manager and no release marker file: the apk
// database is left in place but the apk binary is removed. That makes
// /etc/os-release the only evidence detection has, and it is why the resolver
// matches on the name alone with no file probe to fall back on.
var bellsoftHardenedContainers = &PlatformResolver{
	Name:     "bellsoft-hardened-containers",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "bellsoft-hardened-containers", nil
	},
}

// Chainguard OS is the distribution behind Chainguard's production container
// images. It is not Wolfi: the free-tier images report ID=wolfi and resolve as
// wolfi, while the production images set ID=chainguard, declare no ID_LIKE and
// carry their own release line and advisory feed.
//
// VERSION_ID is a date stamp rather than a dotted version ("20230214"), which is
// how a rolling distribution spells a release.
//
// The images ship an apk database but no apk binary, so /etc/os-release is the
// only evidence detection has, and there is no /etc/alpine-release for alpine's
// fallback to find either. The package inventory still reads: the database apk
// wrote is left in place.
var chainguard = &PlatformResolver{
	Name:     "chainguard",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "chainguard", nil
	},
}

// MinimOS is the distribution behind the Minimus hardened container images. It
// sets ID=minimos with no ID_LIKE, and VERSION_ID is a date stamp
// ("20241031") rather than a dotted version.
//
// The images ship an apk database but no apk binary, the same shape as
// Chainguard OS and BellSoft Hardened Containers, so os-release is the only
// evidence detection has and the package inventory reads from the database apk
// left behind.
//
// Minimus announced it is ceasing operations on 2026-10-22 and handing its
// technology to Echo, and reg.mini.dev goes dark with it. Images pulled before
// then keep running, and keep needing to be scanned, which is why this stays.
var minimos = &PlatformResolver{
	Name:     "minimos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "minimos", nil
	},
}

// Echo builds hardened container images and is where Minimus technology landed
// when Minimus wound down, so its images are expected to carry the same
// Alpine-lineage shape.
//
// UNVERIFIED: the id here is Echo's published platform identifier. Every Echo
// registry host requires an account, so no image has been pulled to confirm the
// os-release contents, and there is deliberately no fixture rather than one
// written from values nobody checked. What is covered is that the name is
// registered and catalogued; the detector test arrives with the first image
// someone can pull.
var echo = &PlatformResolver{
	Name:     "echo",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "echo", nil
	},
}

// WizOS is an Alpine-lineage distro (ID_LIKE=alpine) that ships its own
// ID=wizos in /etc/os-release and uses apk. It is resolved before alpine so
// its exact-name match wins over alpine's /etc/alpine-release fallback.
var wizos = &PlatformResolver{
	Name:     "wizos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "wizos" {
			return true, nil
		}
		return false, nil
	},
}

var arch = &PlatformResolver{
	Name:     "arch",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// Arch Linux ARM ships ID=archarm. It is the same distribution built for
		// ARM, so it reports as arch rather than as a platform of its own.
		if pf.Name == "archarm" {
			pf.Name = "arch"
			return true, nil
		}
		return pf.Name == "arch", nil
	},
}

var manjaro = &PlatformResolver{
	Name:     "manjaro",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// Manjaro ARM ships ID=manjaro-arm. It is the same distribution built for
		// ARM, so it reports as manjaro rather than as a platform of its own.
		if pf.Name == "manjaro-arm" {
			pf.Name = "manjaro"
			return true, nil
		}
		return pf.Name == "manjaro", nil
	},
}

// Azure Linux, and CBL-Mariner before it. Microsoft renamed the distribution
// from CBL-Mariner to Azure Linux with the 3.0 release, so 2.x systems still
// ship ID=mariner in /etc/os-release while 3.0 and later ship ID=azurelinux.
// Both IDs resolve here and keep their own platform name: mariner stays
// mariner so existing filters on it keep working. Emits registers both names
// in the platform tree, which is what the platform catalog is derived from.
var azurelinux = &PlatformResolver{
	Name:     "azurelinux",
	IsFamily: false,
	Emits:    []string{"azurelinux", "mariner"},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "azurelinux" || pf.Name == "mariner" {
			osrd := NewOSReleaseDetector(conn)
			osr, err := osrd.osrelease()
			if err == nil {
				pf.Title = osr["NAME"]
				pf.Build = osr["VERSION"]
			}
			return true, nil
		}
		return false, nil
	},
}

// Container-Optimized OS ships only /etc/os-release, with ID=cos. It has no
// package manager, so this is detection only.
var cos = &PlatformResolver{
	Name:     "cos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "cos", nil
	},
}

// OpenCloudOS is the Tencent-backed CentOS successor. It is rpm based, but it
// ships /etc/system-release ("OpenCloudOS release 9.0") and no
// /etc/redhat-release, so the redhat family declines it before any of that
// family's children get a look. It resolves here instead, the way amazonlinux
// and azurelinux do, and packages.go names it alongside them so it still gets
// the rpm package manager.
var opencloudos = &PlatformResolver{
	Name:     "opencloudos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "opencloudos", nil
	},
}

// Talos is an API-managed Kubernetes host: it ships no shell, no /bin or
// /sbin, and no package database, so nothing here can be derived from a
// command. /etc/os-release is the whole of what detection can read.
//
// Talos writes VERSION_ID with its own "v" prefix ("v1.13.9"). The prefix is
// stripped so the field holds a bare version like every other platform reports:
// pf.Version is what version comparisons in policies run against, and a leading
// "v" makes Talos the one platform those comparisons have to special-case. The
// prefixed string is still visible in Title, which keeps PRETTY_NAME verbatim.
var talos = &PlatformResolver{
	Name:     "talos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name != "talos" {
			return false, nil
		}
		pf.Version = strings.TrimPrefix(pf.Version, "v")
		return true, nil
	},
}

var flatcar = &PlatformResolver{
	Name:     "flatcar",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "flatcar" {
			osrd := NewOSReleaseDetector(conn)
			osr, err := osrd.osrelease()
			if err == nil {
				pf.Title = osr["NAME"]
			}
			return true, nil
		}
		return false, nil
	},
}

var debian = &PlatformResolver{
	Name:     "debian",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		osrd := NewOSReleaseDetector(conn)

		f, err := conn.FileSystem().Open("/etc/debian_version")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil || len(c) == 0 {
			return false, nil
		}

		osr, err := osrd.osrelease()
		if err != nil {
			return false, nil
		}

		if osr["ID"] != "debian" {
			return false, nil
		}

		// gardenlinux identifies itself as debian, but we want to set the proper name / version
		if osr["GARDENLINUX_VERSION"] != "" {
			pf.Name = "gardenlinux"
			pf.Version = osr["GARDENLINUX_VERSION"]
		} else {
			pf.Version = strings.TrimSpace(string(c))
		}

		unamem, err := osrd.unamem()
		if err == nil {
			pf.Arch = unamem
		}

		return true, nil
	},
}

var gardenlinux = &PlatformResolver{
	Name:     "gardenlinux",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name != "gardenlinux" {
			return false, nil
		}
		osrd := NewOSReleaseDetector(conn)

		osr, err := osrd.osrelease()
		if err != nil {
			return false, nil
		}

		pf.Version = osr["GARDENLINUX_VERSION"]

		return true, nil
	},
}

var ubuntu = &PlatformResolver{
	Name:     "ubuntu",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name != "ubuntu" {
			return false, nil
		}

		afs := &afero.Afero{Fs: conn.FileSystem()}

		// Prefer non-root detection via ESM apt source list files
		esmFiles := []string{
			"/etc/apt/sources.list.d/ubuntu-esm-infra.list",
			"/etc/apt/sources.list.d/ubuntu-esm-apps.list",
			"/etc/apt/sources.list.d/ubuntu-pro-client.list",
		}
		for _, p := range esmFiles {
			if ok, err := afs.Exists(p); err == nil && ok {
				pf.Metadata["ubuntu/pro"] = "enabled"
				return true, nil
			}
		}

		pf.Metadata["ubuntu/pro"] = "disabled"
		return true, nil
	},
}

var zorin = &PlatformResolver{
	Name:     "zorin",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "zorin" {
			return true, nil
		}
		return false, nil
	},
}

var cumulus = &PlatformResolver{
	Name:     "cumulus-linux",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name != "cumulus-linux" {
			return false, nil
		}

		osrd := NewOSReleaseDetector(conn)

		image, err := osrd.imagerelease()
		if err != nil {
			return false, nil
		}

		// Notice from the docs:
		// The /etc/image-release file updates only when you run a Cumulus Linux image install.
		// Therefore, if you run a Cumulus Linux image install of Cumulus Linux 5.13, followed by a package upgrade to 5.15, the /etc/image-release file continues to display Cumulus Linux 5.13, which is the originally installed base image.
		pf.Build = image["IMAGE_BUILD_SERIAL_ID"]

		return true, nil
	},
}

var parrot = &PlatformResolver{
	Name:     "parrot",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "parrot" {
			return true, nil
		}
		return false, nil
	},
}

var raspbian = &PlatformResolver{
	Name:     "raspbian",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "raspbian" {
			return true, nil
		}
		return false, nil
	},
}

var kali = &PlatformResolver{
	Name:     "kali",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "kali" {
			return true, nil
		}
		return false, nil
	},
}

var linuxmint = &PlatformResolver{
	Name:     "linuxmint",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "linuxmint" {
			return true, nil
		}
		return false, nil
	},
}

var popos = &PlatformResolver{
	Name:     "pop",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "pop" {
			return true, nil
		}
		return false, nil
	},
}

var endeavouros = &PlatformResolver{
	Name:     "endeavouros",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "endeavouros" {
			return true, nil
		}
		return false, nil
	},
}

var elementary = &PlatformResolver{
	Name:     "elementary",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "elementary" {
			return true, nil
		}
		return false, nil
	},
}

var steamos = &PlatformResolver{
	Name:     "steamos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "steamos" {
			return true, nil
		}
		return false, nil
	},
}

var cachyos = &PlatformResolver{
	Name:     "cachyos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "cachyos" {
			return true, nil
		}
		return false, nil
	},
}

var nobara = &PlatformResolver{
	Name:     "nobara",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "nobara" {
			return true, nil
		}
		return false, nil
	},
}

var qubes = &PlatformResolver{
	Name:     "qubes",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "qubes" {
			return true, nil
		}
		return false, nil
	},
}

var tails = &PlatformResolver{
	Name:     "tails",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "tails" {
			return true, nil
		}
		return false, nil
	},
}

var kdeneon = &PlatformResolver{
	Name:     "neon",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "neon" {
			return true, nil
		}
		return false, nil
	},
}

// deepin ships dpkg/apt and /etc/debian_version, but its os-release carries
// ID=deepin and no ID_LIKE, so the debian resolver, which requires ID=debian,
// never claims it. It resolves inside the debian family for the package
// manager and the debian-specific resources to be selected.
var deepin = &PlatformResolver{
	Name:     "deepin",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "deepin", nil
	},
}

// openKylin ships dpkg/apt but no /etc/debian_version at all, so it cannot be
// reached through the debian resolver, which opens that file first. The
// debian family itself claims every linux host, so matching on the name here
// is what puts it in the family and selects dpkg.
var openkylin = &PlatformResolver{
	Name:     "openkylin",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "openkylin", nil
	},
}

// elxr is a Debian derivative (os-release carries ID=elxr, ID_LIKE=debian).
// It ships dpkg/apt, so it has to resolve inside the debian family for the
// package manager and the debian-specific resources to be selected.
var elxr = &PlatformResolver{
	Name:     "elxr",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "elxr" {
			return true, nil
		}
		return false, nil
	},
}

// rhcos is Red Hat Enterprise Linux CoreOS, the immutable rpm-ostree based RHEL
// variant that OpenShift runs its nodes on. Its os-release carries ID="rhcos"
// with ID_LIKE="rhel fedora", and /etc/redhat-release reads like stock RHEL
// ("Red Hat Enterprise Linux release 9.6 (Plow)"), so os-release ID is the only
// thing that tells the two apart. It has to be resolved before rhel: the RHCOS
// PRETTY_NAME starts with "Red Hat", which is enough for the rhel resolver to
// claim the host and report it as plain redhat.
var rhcos = &PlatformResolver{
	Name:     "rhcos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name != "rhcos" {
			return false, nil
		}

		osrd := NewOSReleaseDetector(conn)
		osr, err := osrd.osrelease()
		if err != nil {
			log.Debug().Err(err).Msg("platform> cannot parse os-release on this rhcos system")
			return true, nil
		}

		if len(osr["NAME"]) > 0 {
			// PRETTY_NAME carries the build string too, e.g.
			// "Red Hat Enterprise Linux CoreOS 9.6.20250523-0"
			pf.Title = osr["NAME"]
		}

		// VERSION_ID is the RHCOS image build, not the RHEL release the packages
		// are cut from. RHEL_VERSION is what package versions and advisories line
		// up with, so it wins where the image ships it. Without it we keep what
		// the family already read out of /etc/redhat-release, which is the same
		// RHEL release.
		if len(osr["RHEL_VERSION"]) > 0 {
			pf.Version = osr["RHEL_VERSION"]
		}

		// the image build is still worth keeping, RHCOS does not ship BUILD_ID
		if len(osr["OSTREE_VERSION"]) > 0 {
			pf.Build = osr["OSTREE_VERSION"]
		}

		if len(osr["OPENSHIFT_VERSION"]) > 0 {
			pf.Metadata["openshift/version"] = osr["OPENSHIFT_VERSION"]
		}

		return true, nil
	},
}

// rhel PlatformResolver only detects redhat and no derivatives
var rhel = &PlatformResolver{
	Name:     "redhat",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// etc redhat release was parsed by the family already,
		// we reuse that information here
		// e.g. Red Hat Linux, Red Hat Enterprise Linux Server
		if strings.Contains(pf.Title, "Red Hat") || pf.Name == "redhat" {
			pf.Name = "redhat"
			return true, nil
		}

		// fallback to /etc/redhat-release file
		f, err := conn.FileSystem().Open("/etc/redhat-release")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil || len(c) == 0 {
			return false, nil
		}

		if strings.Contains(string(c), "Red Hat") {
			pf.Name = "redhat"
			return true, nil
		}

		return false, nil
	},
}

var eurolinux = &PlatformResolver{
	Name:     "eurolinux",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "eurolinux" {
			return true, nil
		}
		return false, nil
	},
}

// CloudLinux OS is a RHEL rebuild (os-release carries ID=cloudlinux,
// ID_LIKE="rhel fedora centos"). Without a resolver here no child of the redhat
// family claims it, the family gate is abandoned, and everything keyed on
// IsFamily("redhat") goes dead: packages, updates, yum and services among them.
var cloudlinux = &PlatformResolver{
	Name:     "cloudlinux",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "cloudlinux" {
			return true, nil
		}

		// fallback for images that ship no os-release, only /etc/redhat-release
		if strings.Contains(pf.Title, "CloudLinux") {
			pf.Name = "cloudlinux"
			return true, nil
		}

		return false, nil
	},
}

// The centos platform resolver finds CentOS and CentOS-like platforms like alma and rocky
var centos = &PlatformResolver{
	Name:     "centos",
	IsFamily: false,
	Emits:    []string{"centos", "rockylinux", "almalinux"},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// works for centos 5+
		if strings.Contains(pf.Title, "CentOS") || pf.Name == "centos" {
			pf.Name = "centos"
			return true, nil
		}

		// adapt the name for rocky to align it with amazonlinux, almalinux etc.
		if pf.Name == "rocky" {
			pf.Name = "rockylinux"
		}

		// newer alma linux do not have /etc/centos-release, check for alma linux
		afs := &afero.Afero{Fs: conn.FileSystem()}
		if pf.Name == "almalinux" {
			if ok, err := afs.Exists("/etc/almalinux-release"); err == nil && ok {
				return true, nil
			}
		}

		// newer rockylinux do not have /etc/centos-release
		if pf.Name == "rockylinux" {
			if ok, err := afs.Exists("/etc/rocky-release"); err == nil && ok {
				return true, nil
			}
		}

		// NOTE: CentOS 5 does not have /etc/centos-release
		// fallback to /etc/centos-release file
		if ok, err := afs.Exists("/etc/centos-release"); err != nil || !ok {
			return false, nil
		}

		if len(pf.Name) == 0 {
			pf.Name = "centos"
		}

		return true, nil
	},
}

// Anolis OS is the Alibaba-backed CentOS successor. It ships
// /etc/redhat-release ("Anolis OS release 8.8") and an rpm database, so it
// resolves inside the redhat family and picks up the rpm package manager.
// It declares ID_LIKE="rhel fedora centos", so it is resolved before centos,
// whose last resort is the mere existence of /etc/centos-release.
var anolis = &PlatformResolver{
	Name:     "anolis",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "anolis", nil
	},
}

var fedora = &PlatformResolver{
	Name:     "fedora",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if strings.Contains(pf.Title, "Fedora") || pf.Name == "fedora" {
			pf.Name = "fedora"
			return true, nil
		}

		// fallback to /etc/fedora-release file
		f, err := conn.FileSystem().Open("/etc/fedora-release")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil || len(c) == 0 {
			return false, nil
		}

		if len(pf.Name) == 0 {
			pf.Name = "fedora"
		}

		return true, nil
	},
}

var oracle = &PlatformResolver{
	Name:     "oracle",
	IsFamily: false,
	Emits:    []string{"oraclelinux"},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// works for oracle 7+
		if pf.Name == "ol" {
			pf.Name = "oraclelinux"
			if hasOracleELSEnabled(conn) {
				pf.Metadata["oracle/support-type"] = "els"
			}
			return true, nil
		}

		// check if we have /etc/oracle-release file
		f, err := conn.FileSystem().Open("/etc/oracle-release")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil || len(c) == 0 {
			return false, nil
		}

		if len(pf.Name) == 0 {
			pf.Name = "oraclelinux"
		}

		if hasOracleELSEnabled(conn) {
			pf.Metadata["oracle/support-type"] = "els"
		}
		return true, nil
	},
}

var scientific = &PlatformResolver{
	Name:     "scientific",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// works for oracle 7+
		if pf.Name == "scientific" {
			return true, nil
		}

		// we only get here if this is a rhel distribution
		if strings.Contains(pf.Title, "Scientific Linux") {
			pf.Name = "scientific"
			return true, nil
		}

		return false, nil
	},
}

var amazonlinux = &PlatformResolver{
	Name:     "amazonlinux",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "amzn" {
			pf.Name = "amazonlinux"
			return true, nil
		}
		return false, nil
	},
}

// Bottlerocket carries /etc/bottlerocket-release on older versions, but newer
// ones dropped it, and on a raw root-partition scan (an EBS volume snapshot)
// /etc is an overlay whose upper layer lives on the data partition, so neither
// that file nor /etc/os-release is present. The canonical /usr/lib/os-release
// always is, and the linux family detection already reads it, so the release
// file is only an enrichment source here and the claim falls back to the name
// os-release yielded. Gating the claim on opening the file left those systems
// to the generic linux fallback, and a container or container image claimed by
// that fallback is reported as "scratch".
var bottlerocket = &PlatformResolver{
	Name:     "bottlerocket",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		enrichFromBottlerocketRelease(pf, conn)
		return pf.Name == "bottlerocket", nil
	},
}

// enrichFromBottlerocketRelease overlays /etc/bottlerocket-release onto pf when
// that file is present. Every field it sets is best-effort: a missing or
// unreadable file leaves pf as the os-release detection left it.
func enrichFromBottlerocketRelease(pf *inventory.Platform, conn shared.Connection) {
	f, err := conn.FileSystem().Open("/etc/bottlerocket-release")
	if err != nil {
		return
	}
	defer f.Close()

	c, err := io.ReadAll(f)
	if err != nil || len(c) == 0 {
		log.Debug().Err(err).Msg("platform> cannot read /etc/bottlerocket-release")
		return
	}

	osr, err := ParseOsRelease(strings.TrimSpace(string(c)))
	if err != nil {
		log.Debug().Err(err).Msg("platform> cannot parse /etc/bottlerocket-release")
		return
	}

	if len(osr["ID"]) > 0 {
		pf.Name = osr["ID"]
	}
	if len(osr["PRETTY_NAME"]) > 0 {
		pf.Title = osr["PRETTY_NAME"]
	}
	if len(osr["VERSION_ID"]) > 0 {
		pf.Version = osr["VERSION_ID"]
	}
	if len(osr["BUILD_ID"]) > 0 {
		pf.Build = osr["BUILD_ID"]
	}
}

var windriver = &PlatformResolver{
	Name:     "wrlinux",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "wrlinux" {
			return true, nil
		}
		return false, nil
	},
}

var opensuse = &PlatformResolver{
	Name:     "opensuse",
	IsFamily: false,
	Emits:    []string{"opensuse", "opensuse-leap", "opensuse-tumbleweed"},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "opensuse" || pf.Name == "opensuse-leap" || pf.Name == "opensuse-tumbleweed" {
			return true, nil
		}

		return false, nil
	},
}

var sles = &PlatformResolver{
	Name:     "sles",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "sles" {
			// SLES can have various modules/repos activated, identify them via filesystem
			modules := getActivatedSlesModules(conn)
			pf.Metadata["suse/modules"] = strings.Join(modules, ",")

			baseproduct := getSlesBaseProduct(conn)
			if len(baseproduct) > 0 {
				pf.Metadata["suse/baseproduct"] = baseproduct
			}
			return true, nil
		}
		return false, nil
	},
}

// suseMicroOs claims both transactional SUSE systems: SUSE Linux Enterprise
// Micro, which sets ID=suse-microos, and openSUSE MicroOS, which sets
// ID=opensuse-microos. They share a read-only root, transactional-update and
// zypper, so every consumer in the provider treats them alike, and the
// services manager already dispatches on both names.
var suseMicroOs = &PlatformResolver{
	Name:     "suse-microos",
	IsFamily: false,
	Emits:    []string{"suse-microos", "opensuse-microos"},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "suse-microos" || pf.Name == "opensuse-microos" {
			return true, nil
		}
		return false, nil
	},
}

var nixos = &PlatformResolver{
	Name:     "nixos",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// NixOS sets ID=nixos in /etc/os-release
		if pf.Name == "nixos" {
			return true, nil
		}

		// Nix container images (e.g., nixos/nix) may lack /etc/os-release entirely.
		// Detect them by the presence of /nix/store.
		nixStoreExists, err := afero.Exists(conn.FileSystem(), "/nix/store")
		if err != nil {
			return false, nil
		}
		if nixStoreExists {
			pf.Name = "nixos"
			pf.Title = "NixOS"
			return true, nil
		}

		return false, nil
	},
}

var gentoo = &PlatformResolver{
	Name:     "gentoo",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "gentoo" {
			return true, nil
		}
		return false, nil
	},
}

var busybox = &PlatformResolver{
	Name:     "busybox",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		busyboxExists, err := afero.Exists(conn.FileSystem(), "/bin/busybox")
		if !busyboxExists || err != nil {
			return false, nil
		}

		// we need to read this file because all others show up as zero size
		// This file seems to be the "original"
		// all others are hardlinks
		f, err := conn.FileSystem().Open("/bin/[")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		content, err := io.ReadAll(f)
		if err != nil {
			return false, err
		}

		// strings are \0 terminated
		rodataByteStrings := bytes.Split(content, []byte("\x00"))
		if rodataByteStrings == nil {
			return false, nil
		}

		releaseRegex := regexp.MustCompile(`^(.+)\s(v[\d\.]+)\s*\((.*)\).*$`)
		for _, rodataByteString := range rodataByteStrings {
			rodataString := string(rodataByteString)
			m := releaseRegex.FindStringSubmatch(rodataString)
			if len(m) >= 2 {
				title := m[1]
				release := m[2]

				if strings.ToLower(title) == "busybox" {
					pf.Name = "busybox"
					pf.Title = title
					pf.Version = release
					return true, nil
				}
			}
		}

		return false, nil
	},
}

var photon = &PlatformResolver{
	Name:     "photon",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "photon" {
			return true, nil
		}
		return false, nil
	},
}

// ALT Linux (BaseALT) sets ID=altlinux in os-release. It also ships
// /etc/redhat-release, /etc/fedora-release and /etc/system-release for
// compatibility, each carrying only "ALT Container" with no distro name and no
// version, so nothing in the redhat family can identify it from those. Without
// a resolver of its own the generic linux fallback claimed it, and a container
// image claimed by that fallback is reported as "scratch".
var altlinux = &PlatformResolver{
	Name:     "altlinux",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "altlinux", nil
	},
}

// Void Linux ships only /etc/os-release, carrying ID=void and no version of any
// kind because it is a rolling release. Without a resolver of its own the
// generic linux fallback claimed it, and a container image claimed by that
// fallback is reported as "scratch" — discarding the identity the image states
// outright. Note the os provider has no xbps support, so packages are not
// available on this platform; detection only.
// Clear Linux OS ships only /etc/os-release, as a symlink to the copy in
// /usr/lib, carrying ID=clear-linux-os. Without a resolver of its own the
// generic linux fallback claimed it, and a container image claimed by that
// fallback is reported as "scratch". Detection only: the os provider has no
// swupd support, so packages are not available on this platform.
var clearlinux = &PlatformResolver{
	Name:     "clear-linux-os",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "clear-linux-os", nil
	},
}

var voidlinux = &PlatformResolver{
	Name:     "void",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return pf.Name == "void", nil
	},
}

var mageia = &PlatformResolver{
	Name:     "mageia",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "mageia" {
			return true, nil
		}
		return false, nil
	},
}

var mxlinux = &PlatformResolver{
	Name:     "mxlinux",
	IsFamily: false,
	Emits:    []string{"mx"},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		osrd := NewOSReleaseDetector(conn)
		lsb, err := osrd.lsbconfig()
		// we're not on mx if we can't read lsb
		if err != nil {
			return false, nil
		}

		if len(lsb["DISTRIB_ID"]) > 0 && strings.ToLower(lsb["DISTRIB_ID"]) == "mx" {
			pf.Name = "mx"
			pf.Version = lsb["DISTRIB_RELEASE"]
			pf.Title = lsb["DISTRIB_DESCRIPTION"]
			return true, nil
		}

		return false, nil
	},
}

var lede = &PlatformResolver{
	Name:     "lede",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "lede" {
			return true, nil
		}
		return false, nil
	},
}

var openwrt = &PlatformResolver{
	Name:     "openwrt",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// modern releases of openwrt include /etc/os-release but legacy versions do not
		f, err := conn.FileSystem().Open("/etc/openwrt_release")
		if err != nil {
			return false, err
		}
		defer f.Close()

		content, err := io.ReadAll(f)
		if err != nil {
			return false, err
		}

		lsb, err := ParseLsbRelease(string(content))
		if err == nil {
			if len(lsb["DISTRIB_ID"]) > 0 {
				pf.Name = strings.ToLower(lsb["DISTRIB_ID"])
				pf.Title = lsb["DISTRIB_ID"]
			}
			if len(lsb["DISTRIB_RELEASE"]) > 0 {
				pf.Version = lsb["DISTRIB_RELEASE"]
			}

			return true, nil
		}

		return false, nil
	},
}

var (
	plcnextVersion      = regexp.MustCompile(`(?m)^Arpversion:\s+(.*)$`)
	plcnextBuildVersion = regexp.MustCompile(`(?m)^GIT Commit Hash:\s+(.*)$`)
)

var plcnext = &PlatformResolver{
	Name:     "plcnext",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// No clue why they are not using either lsb-release or os-release
		f, err := conn.FileSystem().Open("/etc/plcnext/arpversion")
		if err != nil {
			return false, err
		}
		defer f.Close()

		content, err := io.ReadAll(f)
		if err != nil {
			return false, err
		}

		m := plcnextVersion.FindStringSubmatch(string(content))
		if len(m) >= 2 {
			pf.Name = "plcnext"
			pf.Title = "PLCnext"
			pf.Version = m[1]

			bm := plcnextBuildVersion.FindStringSubmatch(string(content))
			if len(bm) >= 2 {
				pf.Build = bm[1]
			}

			return true, err
		}

		return false, nil
	},
}

var openeuler = &PlatformResolver{
	Name:     "openeuler",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "openEuler" {
			pf.Name = "openeuler"
			return true, nil
		}
		return false, nil
	},
}

var hce = &PlatformResolver{
	Name:     "hce",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "hce" {
			return true, nil
		}
		return false, nil
	},
}

var euleros = &PlatformResolver{
	Name:     "euleros",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// EulerOS includes /etc/os-release file, but version information in this file is not reliable
		// So, we need to check whether /etc/euleros-release file exists
		f, err := conn.FileSystem().Open("/etc/euleros-release")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		content, err := io.ReadAll(f)
		if err != nil {
			return false, err
		}
		prettyName := strings.Trim(string(content), "\n")
		if len(prettyName) > 0 {
			// align with title from /etc/os-release
			// EulerOS release 2.0 (SP9x86_64) => EulerOS 2.0 (SP9x86_64)
			prettyName = strings.Replace(prettyName, " release", "", 1)
			pf.Title = prettyName
		}

		if pf.Name == "euleros" {
			return true, nil
		}
		return false, nil
	},
}

// CirrOS is a minimal Buildroot-based cloud test image; it self-identifies via
// /etc/os-release (ID=cirros), populated by the generic linux family detection.
var cirros = &PlatformResolver{
	Name:     "cirros",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if pf.Name == "cirros" {
			return true, nil
		}
		return false, nil
	},
}

// fallback linux detection, since we do not know the system, the family detection may not be correct
var defaultLinux = &PlatformResolver{
	Name:     "generic-linux",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// if we reach here, we know that we detected linux already
		log.Debug().Msg("platform> we do not know the linux system, but we do our best in guessing")
		// the system carries no name we could derive from lsb or os-release, so
		// fall back to this resolver's own name. Without it the platform stays
		// unnamed and gets reported as "unknown" (see addTechnologyUrl).
		if pf.Name == "" {
			pf.Name = r.Name
		}
		return true, nil
	},
}

var netbsd = &PlatformResolver{
	Name:     "netbsd",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if !strings.Contains(strings.ToLower(pf.Name), "netbsd") {
			return false, nil
		}

		osrd := NewOSReleaseDetector(conn)
		release, err := osrd.unamer()
		if err == nil {
			pf.Version = release
		}

		return true, nil
	},
}

var freebsd = &PlatformResolver{
	Name:     "freebsd",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if !strings.Contains(strings.ToLower(pf.Name), "freebsd") {
			return false, nil
		}

		osrd := NewOSReleaseDetector(conn)
		release, err := osrd.unamer()
		if err == nil {
			pf.Version = release
		}

		return true, nil
	},
}

var openbsd = &PlatformResolver{
	Name:     "openbsd",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if !strings.Contains(strings.ToLower(pf.Name), "openbsd") {
			return false, nil
		}

		osrd := NewOSReleaseDetector(conn)
		release, err := osrd.unamer()
		if err == nil {
			pf.Version = release
		}

		return true, nil
	},
}

var dragonflybsd = &PlatformResolver{
	Name:     "dragonflybsd",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if !strings.Contains(strings.ToLower(pf.Name), "dragonfly") {
			return false, nil
		}

		pf.Name = "dragonflybsd"
		osrd := NewOSReleaseDetector(conn)
		release, err := osrd.unamer()
		if err == nil {
			pf.Version = release
		}

		return true, nil
	},
}

var windows = &PlatformResolver{
	Name:     "windows",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if conn.Capabilities().Has(shared.Capability_RunCommand) {
			return runtimeWindowsDetector(pf, conn)
		}

		if conn.Capabilities().Has(shared.Capability_FileSearch) {
			return staticWindowsDetector(pf, conn)
		}
		return false, nil
	},
}

var slugRe = regexp.MustCompile("[^a-z0-9]+")

func slugifyDarwin(s string) string {
	s = strings.ToLower(s)
	s = slugRe.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}

var (
	// characters that are dropped outright, so "FRITZ!OS" slugs to "fritzos"
	// instead of gaining a separator where the punctuation used to be
	platformNameDropRe = regexp.MustCompile(`[^a-z0-9\s._-]+`)
	// runs of whitespace and underscores that become a single "-"
	platformNameSepRe = regexp.MustCompile(`[\s_]+`)
)

// slugifyPlatformName derives a platform name from a human-readable os-release
// value (NAME or PRETTY_NAME) for systems that ship no ID field. It mirrors how
// vendors write ID themselves: "FRITZ!OS" -> "fritzos", "Generic Vendor Linux"
// -> "generic-vendor-linux".
func slugifyPlatformName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = platformNameDropRe.ReplaceAllString(s, "")
	s = platformNameSepRe.ReplaceAllString(s, "-")
	return strings.Trim(s, "-.")
}

// Families
var darwinFamily = &PlatformResolver{
	Name:     inventory.FAMILY_DARWIN,
	IsFamily: true,
	Children: []*PlatformResolver{macOS, otherDarwin},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		if !strings.Contains(strings.ToLower(pf.Name), "darwin") {
			return false, nil
		}
		// from here we know it is a darwin system

		// read information from /usr/bin/sw_vers
		osrd := NewOSReleaseDetector(conn)
		dsv, err := osrd.darwin_swversion()
		// ignore dsv config if we got an error
		if err == nil {
			if len(dsv["ProductName"]) > 0 {
				// name needs to be slugged
				pf.Name = slugifyDarwin(dsv["ProductName"])
				if pf.Name == "mac_os_x" {
					pf.Name = "macos"
				}
				pf.Title = dsv["ProductName"]
			}
			if len(dsv["ProductVersion"]) > 0 {
				pf.Version = dsv["ProductVersion"]
			}
		} else {
			// TODO: we know its darwin, but without swversion support
			log.Error().Err(err)
		}

		return true, nil
	},
}

var bsdFamily = &PlatformResolver{
	Name:     inventory.FAMILY_BSD,
	IsFamily: true,
	Children: []*PlatformResolver{darwinFamily, netbsd, freebsd, openbsd, dragonflybsd},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		osrd := NewOSReleaseDetector(conn)
		unames, err := osrd.unames()
		if err != nil {
			return false, err
		}

		unamem, err := osrd.unamem()
		if err == nil {
			pf.Arch = unamem
		}

		if len(unames) > 0 {
			pf.Name = strings.ToLower(unames)
			pf.Title = unames
			return true, nil
		}
		return false, nil
	},
}

var redhatFamily = &PlatformResolver{
	Name:     "redhat",
	IsFamily: true,
	// NOTE: oracle pretends to be redhat with /etc/redhat-release and Red Hat Linux, therefore we
	// want to check that platform before redhat. rhcos has the same problem: its
	// /etc/redhat-release is stock RHEL and its PRETTY_NAME starts with "Red Hat",
	// so it also has to be resolved before redhat.
	// NOTE: cloudlinux runs before centos, whose last resort is the mere existence of
	// /etc/centos-release, which a rebuild may ship for compatibility
	Children: []*PlatformResolver{oracle, rhcos, rhel, cloudlinux, anolis, centos, fedora, scientific, eurolinux, nobara, qubes},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		f, err := conn.FileSystem().Open("/etc/redhat-release")
		if err != nil {
			log.Debug().Err(err)
			return false, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil || len(c) == 0 {
			log.Debug().Err(err)
			return false, nil
		}

		content := strings.TrimSpace(string(c))
		title, release, err := ParseRhelVersion(content)
		if err == nil {
			log.Debug().Str("title", title).Str("release", release).Msg("detected rhelish platform")

			// only set title if not already properly detected by lsb or os-release
			if len(pf.Title) == 0 {
				pf.Title = title
			}

			// always override the version from the release file, since it is
			// more accurate
			if len(release) > 0 {
				pf.Version = release
			}

			// RHEL can have various modules activated, identify them via filesystem
			modules := getActivatedRhelModules(conn)
			pf.Metadata["redhat/modules"] = strings.Join(modules, ",")

			// RHEL has multiple support levels, identify them via repository files
			pf.Metadata["redhat/support-type"] = strings.Join(getActivatedRhelSupportLevels(conn), ",")

			return true, nil
		}

		return false, nil
	},
}

var debianFamily = &PlatformResolver{
	Name:     "debian",
	IsFamily: true,
	Children: []*PlatformResolver{mxlinux, debian, ubuntu, raspbian, kali, linuxmint, popos, elementary, zorin, parrot, cumulus, gardenlinux, tails, kdeneon, elxr, deepin, openkylin},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return true, nil
	},
}

var suseFamily = &PlatformResolver{
	Name:     "suse",
	IsFamily: true,
	Children: []*PlatformResolver{opensuse, sles, suseMicroOs},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return true, nil
	},
}

var archFamily = &PlatformResolver{
	Name:     "arch",
	IsFamily: true,
	Children: []*PlatformResolver{arch, manjaro, endeavouros, steamos, cachyos},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// if the file exists, we are on arch or one of its derivatives
		f, err := conn.FileSystem().Open("/etc/arch-release")
		if err != nil {
			return false, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil {
			return false, nil
		}

		// on arch containers, /etc/os-release may not be present
		if len(pf.Name) == 0 && strings.Contains(strings.ToLower(string(c)), "manjaro") {
			pf.Name = "manjaro"
			pf.Title = strings.TrimSpace(string(c))
			return true, nil
		}

		if len(pf.Name) == 0 {
			// fallback to arch
			pf.Name = "arch"
			pf.Title = "Arch Linux"
		}
		return true, nil
	},
}

var eulerFamily = &PlatformResolver{
	Name:     "euler",
	IsFamily: true,
	Children: []*PlatformResolver{openeuler, hce, euleros},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return true, nil
	},
}

var linuxFamily = &PlatformResolver{
	Name:     inventory.FAMILY_LINUX,
	IsFamily: true,
	// NOTE: altlinux runs before the redhat family, whose members probe
	// /etc/redhat-release and /etc/fedora-release, both of which ALT ships.
	Children: []*PlatformResolver{archFamily, altlinux, redhatFamily, debianFamily, suseFamily, eulerFamily, bottlerocket, amazonlinux, alpaquita, bellsoftHardenedContainers, chainguard, minimos, echo, wizos, alpine, wolfi, nixos, gentoo, voidlinux, clearlinux, busybox, photon, windriver, lede, openwrt, plcnext, mageia, azurelinux, cos, flatcar, talos, opencloudos, cirros, defaultLinux},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		detected := false
		osrd := NewOSReleaseDetector(conn)

		pf.Name = ""
		pf.Title = ""
		if pf.Labels == nil {
			pf.Labels = map[string]string{}
		}
		if pf.Metadata == nil {
			pf.Metadata = map[string]string{}
		}

		lsb, err := osrd.lsbconfig()
		// ignore lsb config if we got an error
		if err == nil {
			if len(lsb["DISTRIB_ID"]) > 0 {
				pf.Name = strings.ToLower(lsb["DISTRIB_ID"])
			}
			if len(lsb["DISTRIB_DESCRIPTION"]) > 0 {
				pf.Title = lsb["DISTRIB_DESCRIPTION"]
			} else if len(lsb["DISTRIB_ID"]) > 0 {
				pf.Title = lsb["DISTRIB_ID"]
			}
			if len(lsb["DISTRIB_RELEASE"]) > 0 {
				pf.Version = lsb["DISTRIB_RELEASE"]
			}

			detected = true
		} else {
			log.Debug().Err(err).Msg("platform> cannot parse lsb config on this linux system")
		}

		osr, err := osrd.osrelease()
		// ignore os release if we have an error
		if err != nil {
			log.Debug().Err(err).Msg("platform> cannot parse os-release on this linux system")
		} else {
			if len(osr["ID"]) > 0 {
				pf.Name = osr["ID"]
				// Deprecated: remove in 12.0
				pf.Labels[LabelDistroID] = osr["ID"]
				pf.Metadata[LabelDistroID] = osr["ID"]
			} else if name := slugifyPlatformName(osr["NAME"]); name != "" {
				// ID is optional per the os-release spec and vendor firmware
				// (e.g. FRITZ!OS) often ships without it. Derive the name from
				// NAME instead, otherwise the platform stays unnamed and is
				// reported as "unknown" downstream.
				//
				// PRETTY_NAME is deliberately not used as a further fallback: it
				// usually carries the version too, which would mint a new
				// platform name for every release. Without a NAME we fall
				// through to generic-linux.
				pf.Name = name
			}
			if len(osr["PRETTY_NAME"]) > 0 {
				pf.Title = osr["PRETTY_NAME"]
			}
			if len(osr["VERSION_ID"]) > 0 {
				pf.Version = osr["VERSION_ID"]
			}

			if len(osr["BUILD_ID"]) > 0 {
				pf.Build = osr["BUILD_ID"]
			}

			if len(osr["VARIANT_ID"]) > 0 {
				// Deprecated: remove in 12.0
				pf.Labels["variant-id"] = osr["VARIANT_ID"]
				pf.Metadata["variant-id"] = osr["VARIANT_ID"]
			}

			detected = true
		}

		// Centos 6 does not include /etc/os-release or /etc/lsb-release, therefore any static analysis
		// will not be able to detect the system, since the following unamem and unames mechanism is not
		// available there. Instead the system can be identified by the availability of /etc/redhat-release
		// If /etc/redhat-release is available, we know its a linux system.
		f, err := conn.FileSystem().Open("/etc/redhat-release")
		if f != nil {
			f.Close()
		}

		if err == nil {
			detected = true
		}

		// BusyBox images do not contain /etc/os-release or /etc/lsb-release, therefore any static analysis
		// will not be able to detect the system, since the following unamem and unames mechanism is not
		// available there. Instead the system can be identified by the availability of /bin/busybox
		// If /bin/busybox is available, we know its a linux system.
		f, err = conn.FileSystem().Open("/bin/busybox")
		if f != nil {
			f.Close()
		}

		if err == nil {
			detected = true
		}

		// Nix container images (e.g., nixos/nix) may lack /etc/os-release entirely.
		// If /nix/store exists, we know it's a Linux system.
		nixStoreExists, nixErr := afero.Exists(conn.FileSystem(), "/nix/store")
		if nixErr == nil && nixStoreExists {
			detected = true
		}

		// try to read the architecture, we cannot assume this works if we use the tar backend where we
		// just load the filesystem, therefore we do not fail here
		unamem, err := osrd.unamem()
		if err == nil {
			pf.Arch = unamem
		}

		// abort if os-release or lsb config was available, we don't need uname -s then
		if detected {
			return true, nil
		}

		// if we reached here, we have a strange linux distro because it does not ship with
		// lsb config and/or os release information, lets use the uname test to verify that this
		// is a linux, it will fail for container images without the ability to run a process
		unames, err := osrd.unames()
		if err != nil {
			return false, err
		}

		if !strings.Contains(strings.ToLower(unames), "linux") {
			return false, nil
		}

		return true, nil
	},
}

var unixFamily = &PlatformResolver{
	Name:     inventory.FAMILY_UNIX,
	IsFamily: true,
	Children: []*PlatformResolver{bsdFamily, linuxFamily, solaris, aix},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// in order to support linux container image detection, we cannot run
		// processes here, lets just read files to detect a system
		// We don't want to run unix detection on local windows connections
		return conn.Type() != shared.Type_Local || runtime.GOOS != "windows", nil
	},
}

var solaris = &PlatformResolver{
	Name:     "solaris",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		osrd := NewOSReleaseDetector(conn)

		unames, err := osrd.unames()
		if err != nil {
			return false, err
		}

		if !strings.Contains(strings.ToLower(unames), "sunos") {
			return false, nil
		}

		// try to read the architecture
		unamem, err := osrd.unamem()
		if err == nil {
			pf.Arch = unamem
		}

		pf.Name = "solaris"

		// NOTE: we have only one solaris system here, since we only get here is the family is sunos, we pass

		// try to read "/etc/release" for more details. uname already confirmed
		// SunOS, so a missing or unreadable release file only costs us the title
		// and version - it must not retract the platform detection itself.
		f, err := conn.FileSystem().Open("/etc/release")
		if err != nil {
			return true, nil
		}
		defer f.Close()

		c, err := io.ReadAll(f)
		if err != nil {
			return true, nil
		}

		release, err := ParseSolarisRelease(string(c))
		if err == nil {
			pf.Name = release.ID
			pf.Title = release.Title
			pf.Version = release.Release
		}

		return true, nil
	},
}

var aixUnameParser = regexp.MustCompile(`(\d+)\s+(\d+)\s+(.*)`)

var aix = &PlatformResolver{
	Name:     "aix",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		osrd := NewOSReleaseDetector(conn)

		unames, err := osrd.unames()
		if err != nil {
			return false, err
		}

		if !strings.Contains(strings.ToLower(unames), "aix") {
			return false, nil
		}

		pf.Name = "aix"
		pf.Title = "AIX"

		// try to read the architecture and version
		unamervp, err := osrd.command("uname -rvp")
		if err == nil {
			m := aixUnameParser.FindStringSubmatch(unamervp)
			if len(m) == 4 {
				pf.Version = m[2] + "." + m[1]
				pf.Arch = m[3]
			}
		}

		// collect build version
		buildversion, err := osrd.command("oslevel -s")
		if err == nil {
			pf.Build = strings.TrimSpace(buildversion)
		}

		detectAixHardware(pf, osrd)

		return true, nil
	},
}

var esxi = &PlatformResolver{
	Name:     "esxi",
	IsFamily: false,
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		log.Debug().Msg("check for esxi system")
		// at this point, we are already 99% its esxi
		cmd, err := conn.RunCommand("vmware -v")
		if err != nil {
			log.Debug().Err(err).Msg("could not run command")
			return false, nil
		}
		vmware_info, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			log.Debug().Err(err).Msg("could not run command")
			return false, err
		}

		version, err := ParseEsxiRelease(string(vmware_info))
		if err != nil {
			log.Debug().Err(err).Msg("could not run command")
			return false, err
		}

		pf.Version = version
		return true, nil
	},
}

var esxFamily = &PlatformResolver{
	Name:     "esx",
	IsFamily: true,
	Children: []*PlatformResolver{esxi},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		osrd := NewOSReleaseDetector(conn)

		// check if we got vmkernel
		unames, err := osrd.unames()
		if err != nil {
			return false, err
		}

		if !strings.Contains(strings.ToLower(unames), "vmkernel") {
			return false, nil
		}

		pf.Name = "esxi"

		// try to read the architecture
		unamem, err := osrd.unamem()
		if err == nil {
			pf.Arch = unamem
		}

		return true, nil
	},
}

var WindowsFamily = &PlatformResolver{
	Name:     inventory.FAMILY_WINDOWS,
	IsFamily: true,
	Children: []*PlatformResolver{windows},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return true, nil
	},
}

var unknownOperatingSystem = &PlatformResolver{
	Name:     "unknown-os",
	IsFamily: false,
	// names nothing: it is the terminal fallback and leaves the platform
	// unnamed, so "unknown-os" is not a platform any asset can report
	Emits: []string{},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		// if we reach here, we really do not know the system
		log.Debug().Msg("platform> we do not know the operating system, please contact support")
		return true, nil
	},
}

var OperatingSystems = &PlatformResolver{
	Name:     "os",
	IsFamily: true,
	Children: []*PlatformResolver{unixFamily, WindowsFamily, esxFamily, unknownOperatingSystem},
	Detect: func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error) {
		return true, nil
	},
}

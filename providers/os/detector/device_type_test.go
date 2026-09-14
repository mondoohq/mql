// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestDetectDeviceType_NilPlatform(t *testing.T) {
	DetectDeviceType(nil, nil)
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

func TestDetectDeviceType_Containers(t *testing.T) {
	tests := []struct {
		name string
		pf   *inventory.Platform
	}{
		{
			name: "container kind",
			pf:   &inventory.Platform{Kind: "container", Name: "ubuntu"},
		},
		{
			name: "container-image kind",
			pf:   &inventory.Platform{Kind: "container-image", Name: "alpine"},
		},
		{
			// Fedora 29 container image: VARIANT_ID=container
			name: "fedora container image via variant-id",
			pf: &inventory.Platform{
				Name:   "fedora",
				Title:  "Fedora 29 (Container Image)",
				Family: []string{"redhat", "linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "container"},
			},
		},
		{
			// Garden Linux 1877 container: VARIANT_ID=container-arm64
			// Prefix match: starts with "container"
			name: "gardenlinux container-arm64 variant-id",
			pf: &inventory.Platform{
				Name:   "gardenlinux",
				Title:  "Garden Linux 1877.9",
				Family: []string{"debian", "linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "container-arm64"},
			},
		},
		{
			// Arch Linux in a container (detected via connection type, no variant-id)
			name: "arch linux container kind",
			pf: &inventory.Platform{
				Kind:   "container",
				Name:   "arch",
				Title:  "Arch Linux",
				Family: []string{"arch", "linux", "unix", "os"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DetectDeviceType(tt.pf, nil)
			assert.Equal(t, DeviceTypeContainer, tt.pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// macOS — always workstation
// ---------------------------------------------------------------------------

func TestDetectDeviceType_MacOS(t *testing.T) {
	// Based on detect-macos.toml: macOS 10.14.5
	pf := &inventory.Platform{
		Name:   "macos",
		Title:  "Mac OS X",
		Family: []string{"darwin", "bsd", "unix", "os"},
	}
	DetectDeviceType(pf, nil)
	assert.Equal(t, DeviceTypeWorkstation, pf.Metadata[MetadataDeviceType])
}

// ---------------------------------------------------------------------------
// Windows — real data from testdata/*.toml
// ---------------------------------------------------------------------------

func TestDetectDeviceType_Windows(t *testing.T) {
	tests := []struct {
		name     string
		pf       *inventory.Platform
		expected string
	}{
		{
			// detect-windows11-24h2.toml: product-type "1" (WinNT)
			name: "windows 11 enterprise LTSC 24H2",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows 11 Enterprise LTSC",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type":    "1",
					"windows.mondoo.com/display-version": "24H2",
					"windows.mondoo.com/edition-id":      "EnterpriseS",
					"windows.mondoo.com/hotpatch":        "false",
				},
			},
			expected: DeviceTypeWorkstation,
		},
		{
			// detect-windows11-24h2-hotpatch.toml: product-type "1" with hotpatch
			name: "windows 11 enterprise hotpatch",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows 11 Enterprise",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "1",
					"windows.mondoo.com/hotpatch":     "true",
				},
			},
			expected: DeviceTypeWorkstation,
		},
		{
			// detect-windows2016.toml: WMI-detected server
			name: "windows server 2016",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Microsoft Windows Server 2016 Standard Evaluation",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "3",
				},
			},
			expected: DeviceTypeServer,
		},
		{
			// detect-windows2019.toml
			name: "windows server 2019 datacenter",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows Server 2019 Datacenter",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "3",
				},
			},
			expected: DeviceTypeServer,
		},
		{
			// detect-windows2022.toml
			name: "windows server 2022 datacenter",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows Server 2022 Datacenter",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "3",
				},
			},
			expected: DeviceTypeServer,
		},
		{
			// detect-windows2025.toml
			name: "windows server 2025 datacenter",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows Server 2025 Datacenter",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "3",
				},
			},
			expected: DeviceTypeServer,
		},
		{
			// detect-azure-windows2025.toml: Azure edition with ServerTurbine
			name: "windows server 2025 azure edition",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows Server 2025 Datacenter Azure Edition",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "3",
					"windows.mondoo.com/edition-id":   "ServerTurbine",
					"windows.mondoo.com/hotpatch":     "false",
				},
			},
			expected: DeviceTypeServer,
		},
		{
			// Domain controller (product-type "2")
			name: "windows domain controller",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows Server 2022 Datacenter",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "2",
				},
			},
			expected: DeviceTypeServer,
		},
		{
			// Windows 11 Enterprise Multi-Session reports product-type "3" but is a VDI
			name: "windows 11 multi-session VDI",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows 11 Enterprise Multi-Session",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "3",
				},
			},
			expected: DeviceTypeWorkstation,
		},
		{
			// detect-windowsnano.toml: Nano Server is a minimal server
			name: "windows nano server",
			pf: &inventory.Platform{
				Name:   "windows",
				Title:  "Windows Server 2016 Standard",
				Family: []string{"windows", "os"},
				Labels: map[string]string{
					"windows.mondoo.com/product-type": "3",
				},
			},
			expected: DeviceTypeServer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DetectDeviceType(tt.pf, nil)
			assert.Equal(t, tt.expected, tt.pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// Linux — distros with VARIANT_ID set (the ~14% that have it)
// ---------------------------------------------------------------------------

func TestDetectDeviceType_LinuxWithVariantID(t *testing.T) {
	tests := []struct {
		name     string
		pf       *inventory.Platform
		expected string
	}{
		{
			// detect-oracle8.toml: VARIANT_ID="server"
			name: "oracle linux 8 server",
			pf: &inventory.Platform{
				Name:   "oraclelinux",
				Title:  "Oracle Linux Server 8.0",
				Family: []string{"redhat", "linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "server"},
			},
			expected: DeviceTypeServer,
		},
		{
			// detect-coreos-fedora.toml: VARIANT_ID=coreos
			name: "fedora coreos",
			pf: &inventory.Platform{
				Name:   "fedora",
				Title:  "Fedora CoreOS 31.20200310.3.0",
				Family: []string{"redhat", "linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "coreos"},
			},
			expected: DeviceTypeServer,
		},
		{
			// detect-nobara.toml: VARIANT_ID=kde
			name: "nobara kde",
			pf: &inventory.Platform{
				Name:   "nobara",
				Title:  "Nobara Linux 40 (KDE Plasma)",
				Family: []string{"redhat", "linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "kde"},
			},
			expected: DeviceTypeWorkstation,
		},
		{
			// detect-steamos.toml: VARIANT_ID=steamdeck
			name: "steamos steamdeck",
			pf: &inventory.Platform{
				Name:   "steamos",
				Title:  "SteamOS",
				Family: []string{"arch", "linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "steamdeck"},
			},
			expected: DeviceTypeWorkstation,
		},
		{
			// Fedora Workstation spin: VARIANT_ID=workstation
			name: "fedora workstation variant",
			pf: &inventory.Platform{
				Name:   "fedora",
				Title:  "Fedora Linux 43 (Workstation Edition)",
				Family: []string{"redhat", "linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "workstation"},
			},
			expected: DeviceTypeWorkstation,
		},
		{
			// Fedora Cloud: VARIANT_ID=cloud (unknown variant, falls through to title)
			name: "fedora cloud",
			pf: &inventory.Platform{
				Name:   "fedora",
				Title:  "Fedora Linux 43 (Cloud Edition)",
				Family: []string{"redhat", "linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "cloud"},
			},
			expected: DeviceTypeServer,
		},
		{
			// detect-suse-sles-15-sap.toml: VARIANT_ID=sles-sap (not in any list, falls through)
			name: "sles sap variant",
			pf: &inventory.Platform{
				Name:   "sles",
				Title:  "SUSE Linux Enterprise Server 15 SP2",
				Family: []string{"suse", "linux", "unix", "os"},
				Labels: map[string]string{"distro-id": "sles", "variant-id": "sles-sap"},
			},
			expected: DeviceTypeServer,
		},
		{
			// detect-bottlerocket.toml: VARIANT_ID=aws-ecs-2-fips (not in lists, falls to name match)
			name: "bottlerocket aws-ecs-2-fips",
			pf: &inventory.Platform{
				Name:   "bottlerocket",
				Title:  "Bottlerocket OS 1.33.0 (aws-ecs-2-fips)",
				Family: []string{"linux", "unix", "os"},
				Labels: map[string]string{"variant-id": "aws-ecs-2-fips"},
			},
			expected: DeviceTypeServer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DetectDeviceType(tt.pf, nil)
			assert.Equal(t, tt.expected, tt.pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// Linux — well-known desktop distros (detected by platform name)
// ---------------------------------------------------------------------------

func TestDetectDeviceType_DesktopDistros(t *testing.T) {
	tests := []struct {
		name   string
		pfName string
		title  string
		family []string
	}{
		// detect-elementary.toml
		{"elementary os", "elementary", "elementary OS 7 Horus", []string{"debian", "linux", "unix", "os"}},
		// detect-mint20.toml
		{"linux mint", "linuxmint", "Linux Mint 20", []string{"debian", "linux", "unix", "os"}},
		// detect-nobara.toml (also has variant-id=kde, but name alone is enough)
		{"nobara", "nobara", "Nobara Linux 40 (KDE Plasma)", []string{"redhat", "linux", "unix", "os"}},
		// detect-popos.toml
		{"pop os", "pop", "Pop!_OS 20.04 LTS", []string{"debian", "linux", "unix", "os"}},
		// detect-steamos.toml
		{"steamos", "steamos", "SteamOS", []string{"arch", "linux", "unix", "os"}},
		// detect-zorin.toml
		{"zorin os", "zorin", "Zorin OS 16", []string{"debian", "linux", "unix", "os"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			DetectDeviceType(pf, nil)
			assert.Equal(t, DeviceTypeWorkstation, pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// Linux — well-known server/minimal distros (detected by platform name)
// ---------------------------------------------------------------------------

func TestDetectDeviceType_ServerDistros(t *testing.T) {
	tests := []struct {
		name   string
		pfName string
		title  string
		family []string
	}{
		// detect-alpine.toml
		{"alpine linux", "alpine", "Alpine Linux v3.7", []string{"linux", "unix", "os"}},
		// detect-bottlerocket.toml
		{"bottlerocket", "bottlerocket", "Bottlerocket OS 1.33.0 (aws-ecs-2-fips)", []string{"linux", "unix", "os"}},
		// detect-google-cos.toml
		{"google cos", "cos", "Container-Optimized OS from Google", []string{"linux", "unix", "os"}},
		// detect-flatcar.toml
		{"flatcar", "flatcar", "Flatcar Container Linux by Kinvolk", []string{"linux", "unix", "os"}},
		// detect-photon1.toml, detect-photon2.toml, detect-photon3.toml
		{"photon os", "photon", "VMware Photon OS/Linux", []string{"linux", "unix", "os"}},
		// detect-suse-micro-5.toml
		{"suse microos", "suse-microos", "SUSE Linux Enterprise Micro 5.1", []string{"suse", "linux", "unix", "os"}},
		// detect-opensuse-microos.toml. The title carries no "server" keyword
		// and the desktop spins built on it ship their own ids (aeon,
		// kalpa-desktop), so the name is what has to answer this.
		{"opensuse microos", "opensuse-microos", "openSUSE MicroOS", []string{"suse", "linux", "unix", "os"}},
		// detect-talos.toml. An API-managed Kubernetes host, never a desktop.
		{"talos", "talos", "Talos (v1.13.9)", []string{"linux", "unix", "os"}},
		// detect-gardenlinux.toml (no container variant-id on this one)
		{"gardenlinux", "gardenlinux", "Garden Linux 934.0", []string{"debian", "linux", "unix", "os"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			DetectDeviceType(pf, nil)
			assert.Equal(t, DeviceTypeServer, pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// Linux — title heuristics (for distros with "Server"/"Desktop" in title)
// ---------------------------------------------------------------------------

func TestDetectDeviceType_TitleHeuristics(t *testing.T) {
	tests := []struct {
		name     string
		pfName   string
		title    string
		family   []string
		expected string
	}{
		// SUSE titles contain "Server"
		// detect-suse-sles-15.toml
		{"sles 15", "sles", "SUSE Linux Enterprise Server 15 SP1", []string{"suse", "linux", "unix", "os"}, DeviceTypeServer},
		// detect-suse-sles-12.toml
		{"sles 12", "sles", "SUSE Linux Enterprise Server 12 SP3", []string{"suse", "linux", "unix", "os"}, DeviceTypeServer},
		// detect-oracle7.toml: title says "Server"
		{"oracle linux 7", "oraclelinux", "Oracle Linux Server 7.5", []string{"redhat", "linux", "unix", "os"}, DeviceTypeServer},
		// detect-oracle6.toml: title says "Server"
		{"oracle linux 6", "oraclelinux", "Oracle Linux Server 6.9", []string{"redhat", "linux", "unix", "os"}, DeviceTypeServer},
		// RHEL 7: title says "Server"
		{"rhel 7 server", "redhat", "Red Hat Enterprise Linux Server 7.2 (Maipo)", []string{"redhat", "linux", "unix", "os"}, DeviceTypeServer},
		// Ubuntu Desktop (hypothetical, title-based)
		{"ubuntu desktop title", "ubuntu", "Ubuntu 24.04 LTS Desktop", []string{"debian", "linux", "unix", "os"}, DeviceTypeWorkstation},
		// Fedora Workstation title (no variant-id set)
		{"fedora workstation title", "fedora", "Fedora Linux 43 (Workstation Edition)", []string{"redhat", "linux", "unix", "os"}, DeviceTypeWorkstation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			DetectDeviceType(pf, nil)
			assert.Equal(t, tt.expected, pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// Linux — distros with NO variant-id and no title hint (default to server
// without filesystem, or use filesystem signals when available)
// ---------------------------------------------------------------------------

func TestDetectDeviceType_LinuxNoSignals_DefaultServer(t *testing.T) {
	// These distros have no VARIANT_ID, no distinctive title, and no
	// well-known name mapping. Without a filesystem connection they
	// default to server.
	tests := []struct {
		name   string
		pfName string
		title  string
		family []string
	}{
		// detect-ubuntu2204.toml
		{"ubuntu 22.04", "ubuntu", "Ubuntu Jammy Jellyfish (development branch)", []string{"debian", "linux", "unix", "os"}},
		// detect-debian10.toml
		{"debian 10", "debian", "Debian GNU/Linux 10 (buster)", []string{"debian", "linux", "unix", "os"}},
		// detect-centos-7.toml
		{"centos 7", "centos", "CentOS Linux 7 (Core)", []string{"redhat", "linux", "unix", "os"}},
		// detect-centos-8.toml
		{"centos 8", "centos", "CentOS Linux 8", []string{"redhat", "linux", "unix", "os"}},
		// detect-rhel-8.toml
		{"rhel 8", "redhat", "Red Hat Enterprise Linux 8.0 (Ootpa)", []string{"redhat", "linux", "unix", "os"}},
		// detect-rhel-9.toml
		{"rhel 9", "redhat", "Red Hat Enterprise Linux 9.0 (Plow)", []string{"redhat", "linux", "unix", "os"}},
		// detect-arch-vm.toml
		{"arch linux", "arch", "Arch Linux", []string{"arch", "linux", "unix", "os"}},
		// detect-manjaro.toml
		{"manjaro", "manjaro", "Manjaro Linux", []string{"arch", "linux", "unix", "os"}},
		// detect-amazonlinux-2017.09.toml
		{"amazon linux", "amazonlinux", "Amazon Linux AMI 2017.09", []string{"linux", "unix", "os"}},
		// detect-amzn-2.toml
		{"amazon linux 2", "amazonlinux", "Amazon Linux 2", []string{"linux", "unix", "os"}},
		// detect-amzn-2022.toml
		{"amazon linux 2022", "amazonlinux", "Amazon Linux 2022", []string{"linux", "unix", "os"}},
		// detect-almalinux-8.toml
		{"almalinux 8", "almalinux", "AlmaLinux 8.3 Beta (Purple Manul)", []string{"redhat", "linux", "unix", "os"}},
		// detect-rocky-linux-8.toml
		{"rocky linux 8", "rockylinux", "Rocky Linux 8.5 (Green Obsidian)", []string{"redhat", "linux", "unix", "os"}},
		// detect-opensuse-leap-15.toml
		{"opensuse leap 15", "opensuse-leap", "openSUSE Leap 15.6", []string{"suse", "linux", "unix", "os"}},
		// detect-opensuse-tumbleweed.toml
		{"opensuse tumbleweed", "opensuse-tumbleweed", "openSUSE Tumbleweed", []string{"suse", "linux", "unix", "os"}},
		// detect-nixos.toml
		{"nixos", "nixos", "NixOS 24.11 (Vicuna)", []string{"linux", "unix", "os"}},
		// detect-gentoo.toml
		{"gentoo", "gentoo", "Gentoo Linux", []string{"linux", "unix", "os"}},
		// detect-kalirolling.toml
		{"kali linux", "kali", "Kali GNU/Linux Rolling", []string{"debian", "linux", "unix", "os"}},
		// detect-azurelinux.toml
		{"azure linux", "azurelinux", "Microsoft Azure Linux", []string{"linux", "unix", "os"}},
		// detect-wolfi.toml
		{"wolfi", "wolfi", "Wolfi", []string{"linux", "unix", "os"}},
		// detect-wizos.toml
		{"wizos", "wizos", "WizOS", []string{"linux", "unix", "os"}},
		// detect-alpaquita.toml
		{"alpaquita", "alpaquita", "BellSoft Alpaquita Linux Stream (glibc)", []string{"linux", "unix", "os"}},
		// detect-bellsoft-hardened-containers.toml
		{"bellsoft hardened containers", "bellsoft-hardened-containers", "BellSoft Hardened Containers Stream (musl)", []string{"linux", "unix", "os"}},
		// detect-buildroot.toml
		{"buildroot", "buildroot", "Buildroot 2019.02.9", []string{"linux", "unix", "os"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			// No connection provided: no filesystem checks possible.
			DetectDeviceType(pf, nil)
			assert.Equal(t, DeviceTypeServer, pf.Metadata[MetadataDeviceType],
				"%s should default to server without filesystem signals", tt.name)
		})
	}
}

// ---------------------------------------------------------------------------
// Non-Linux Unix — BSD, Solaris
// ---------------------------------------------------------------------------

func TestDetectDeviceType_Unix(t *testing.T) {
	tests := []struct {
		name   string
		pfName string
		title  string
		family []string
	}{
		// detect-freebsd12.toml
		{"freebsd", "freebsd", "FreeBSD", []string{"bsd", "unix", "os"}},
		// detect-openbsd7.toml
		{"openbsd", "openbsd", "OpenBSD", []string{"bsd", "unix", "os"}},
		// detect-netbsd8.toml
		{"netbsd", "netbsd", "NetBSD", []string{"bsd", "unix", "os"}},
		// detect-dragonflybsd5.toml
		{"dragonflybsd", "dragonflybsd", "DragonFly", []string{"bsd", "unix", "os"}},
		// detect-solaris11.toml
		{"solaris", "solaris", "Oracle Solaris", []string{"unix", "os"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			DetectDeviceType(pf, nil)
			assert.Equal(t, DeviceTypeServer, pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// Variant-ID in metadata only (labels map absent)
// ---------------------------------------------------------------------------

func TestDetectDeviceType_VariantInMetadata(t *testing.T) {
	pf := &inventory.Platform{
		Name:     "fedora",
		Family:   []string{"redhat", "linux", "unix", "os"},
		Metadata: map[string]string{"variant-id": "kde"},
	}
	DetectDeviceType(pf, nil)
	assert.Equal(t, DeviceTypeWorkstation, pf.Metadata[MetadataDeviceType])
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestDetectDeviceType_UnknownPlatform(t *testing.T) {
	pf := &inventory.Platform{
		Name: "something-unknown",
	}
	DetectDeviceType(pf, nil)
	assert.Equal(t, DeviceTypeServer, pf.Metadata[MetadataDeviceType])
}

func TestDetectDeviceType_NilMetadataInitialized(t *testing.T) {
	pf := &inventory.Platform{
		Name:   "windows",
		Family: []string{"windows", "os"},
	}
	DetectDeviceType(pf, nil)
	assert.NotNil(t, pf.Metadata)
	assert.Equal(t, DeviceTypeWorkstation, pf.Metadata[MetadataDeviceType])
}

func TestDetectDeviceType_ExistingMetadataPreserved(t *testing.T) {
	pf := &inventory.Platform{
		Name:     "alpine",
		Family:   []string{"linux", "unix", "os"},
		Metadata: map[string]string{"some-existing-key": "value"},
	}
	DetectDeviceType(pf, nil)
	assert.Equal(t, DeviceTypeServer, pf.Metadata[MetadataDeviceType])
	assert.Equal(t, "value", pf.Metadata["some-existing-key"])
}

// ---------------------------------------------------------------------------
// Filesystem-based detection: systemd default.target
// ---------------------------------------------------------------------------

func TestDetectFromSystemdTarget_Graphical(t *testing.T) {
	tmpDir := t.TempDir()
	osFs := afero.NewBasePathFs(afero.NewOsFs(), tmpDir)
	_ = osFs.MkdirAll("/etc/systemd/system", 0o755)
	_ = afero.WriteFile(osFs, "/usr/lib/systemd/system/graphical.target", []byte("[Unit]\n"), 0o644)
	err := os.Symlink("/usr/lib/systemd/system/graphical.target", tmpDir+"/etc/systemd/system/default.target")
	if err != nil {
		t.Skip("cannot create symlinks on this filesystem")
	}

	result := detectFromSystemdTarget(osFs)
	assert.Equal(t, DeviceTypeWorkstation, result)
}

func TestDetectFromSystemdTarget_MultiUser(t *testing.T) {
	tmpDir := t.TempDir()
	osFs := afero.NewBasePathFs(afero.NewOsFs(), tmpDir)
	_ = osFs.MkdirAll("/etc/systemd/system", 0o755)
	_ = afero.WriteFile(osFs, "/usr/lib/systemd/system/multi-user.target", []byte("[Unit]\n"), 0o644)
	err := os.Symlink("/usr/lib/systemd/system/multi-user.target", tmpDir+"/etc/systemd/system/default.target")
	if err != nil {
		t.Skip("cannot create symlinks on this filesystem")
	}

	result := detectFromSystemdTarget(osFs)
	assert.Equal(t, DeviceTypeServer, result)
}

func TestDetectFromSystemdTarget_Rescue(t *testing.T) {
	tmpDir := t.TempDir()
	osFs := afero.NewBasePathFs(afero.NewOsFs(), tmpDir)
	_ = osFs.MkdirAll("/etc/systemd/system", 0o755)
	_ = afero.WriteFile(osFs, "/usr/lib/systemd/system/rescue.target", []byte("[Unit]\n"), 0o644)
	err := os.Symlink("/usr/lib/systemd/system/rescue.target", tmpDir+"/etc/systemd/system/default.target")
	if err != nil {
		t.Skip("cannot create symlinks on this filesystem")
	}

	result := detectFromSystemdTarget(osFs)
	assert.Equal(t, DeviceTypeServer, result)
}

func TestDetectFromSystemdTarget_FallbackToUsrLib(t *testing.T) {
	// No /etc/systemd/system/default.target, but /usr/lib/systemd/system/default.target exists
	tmpDir := t.TempDir()
	osFs := afero.NewBasePathFs(afero.NewOsFs(), tmpDir)
	_ = osFs.MkdirAll("/usr/lib/systemd/system", 0o755)
	_ = afero.WriteFile(osFs, "/usr/lib/systemd/system/graphical.target.real", []byte("[Unit]\n"), 0o644)
	err := os.Symlink("graphical.target.real", tmpDir+"/usr/lib/systemd/system/default.target")
	if err != nil {
		t.Skip("cannot create symlinks on this filesystem")
	}

	// The readlink will return "graphical.target.real" which doesn't match any known target.
	// This tests that we handle the fallback path correctly.
	result := detectFromSystemdTarget(osFs)
	assert.Equal(t, "", result)
}

func TestDetectFromSystemdTarget_NoSystemd(t *testing.T) {
	fs := afero.NewMemMapFs()
	result := detectFromSystemdTarget(fs)
	assert.Equal(t, "", result)
}

// ---------------------------------------------------------------------------
// Filesystem-based detection: desktop session directories
// ---------------------------------------------------------------------------

func TestHasDesktopSessions_X11(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = fs.MkdirAll("/usr/share/xsessions", 0o755)
	_ = afero.WriteFile(fs, "/usr/share/xsessions/gnome.desktop", []byte("[Desktop Entry]\n"), 0o644)
	_ = afero.WriteFile(fs, "/usr/share/xsessions/plasma.desktop", []byte("[Desktop Entry]\n"), 0o644)

	assert.True(t, hasDesktopSessions(fs))
}

func TestHasDesktopSessions_Wayland(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = fs.MkdirAll("/usr/share/wayland-sessions", 0o755)
	_ = afero.WriteFile(fs, "/usr/share/wayland-sessions/sway.desktop", []byte("[Desktop Entry]\n"), 0o644)

	assert.True(t, hasDesktopSessions(fs))
}

func TestHasDesktopSessions_EmptyDir(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = fs.MkdirAll("/usr/share/xsessions", 0o755)

	assert.False(t, hasDesktopSessions(fs))
}

func TestHasDesktopSessions_NoDir(t *testing.T) {
	fs := afero.NewMemMapFs()
	assert.False(t, hasDesktopSessions(fs))
}

func TestHasDesktopSessions_OnlySubdirectories(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = fs.MkdirAll("/usr/share/xsessions/subdir", 0o755)

	assert.False(t, hasDesktopSessions(fs))
}

// ---------------------------------------------------------------------------
// Embedded/IoT Linux
// ---------------------------------------------------------------------------

func TestDetectDeviceType_EmbeddedLinux(t *testing.T) {
	tests := []struct {
		name   string
		pfName string
		title  string
		family []string
	}{
		// detect-openwrt.toml
		{"openwrt", "openwrt", "OpenWrt", []string{"linux", "unix", "os"}},
		// detect-lede.toml
		{"lede", "lede", "LEDE Reboot 17.01.6", []string{"linux", "unix", "os"}},
		// detect-busybox.toml
		{"busybox", "busybox", "BusyBox", []string{"linux", "unix", "os"}},
		// detect-plcnext.toml
		{"plcnext", "plcnext", "PLCnext", []string{"linux", "unix", "os"}},
		// detect-windriver7.toml
		{"wind river linux", "wrlinux", "Wind River Linux 7.0.0.2", []string{"linux", "unix", "os"}},
		// detect-cumulus.toml
		{"cumulus linux", "cumulus-linux", "Cumulus Linux", []string{"debian", "linux", "unix", "os"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			DetectDeviceType(pf, nil)
			assert.Equal(t, DeviceTypeServer, pf.Metadata[MetadataDeviceType],
				"%s should be classified as server (embedded/IoT)", tt.name)
		})
	}
}

// ---------------------------------------------------------------------------
// Security-focused distros
// ---------------------------------------------------------------------------

func TestDetectDeviceType_SecurityDistros(t *testing.T) {
	tests := []struct {
		name     string
		pfName   string
		title    string
		family   []string
		expected string
	}{
		// detect-kalirolling.toml - penetration testing distro (typically desktop)
		// No variant-id, no name match, no title hint -> defaults to server
		{"kali linux", "kali", "Kali GNU/Linux Rolling", []string{"debian", "linux", "unix", "os"}, DeviceTypeServer},
		// detect-parrot.toml - security distro
		{"parrot os", "parrot", "Parrot OS 5.3 (Electro Ara)", []string{"debian", "linux", "unix", "os"}, DeviceTypeServer},
		// detect-tails.toml - privacy focused, always runs as desktop
		{"tails", "tails", "Tails", []string{"debian", "linux", "unix", "os"}, DeviceTypeServer},
		// detect-qubes.toml - security focused desktop
		{"qubes os", "qubes", "Qubes OS 4.2 (R4.2)", []string{"redhat", "linux", "unix", "os"}, DeviceTypeServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			DetectDeviceType(pf, nil)
			assert.Equal(t, tt.expected, pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// Other enterprise Linux distros
// ---------------------------------------------------------------------------

func TestDetectDeviceType_EnterpriseLinux(t *testing.T) {
	tests := []struct {
		name   string
		pfName string
		title  string
		family []string
	}{
		// detect-eurolinux-9.toml
		{"eurolinux 9", "eurolinux", "EuroLinux 9.1 (Stockholm)", []string{"redhat", "linux", "unix", "os"}},
		// detect-cloudlinux-9.toml
		{"cloudlinux 9", "cloudlinux", "CloudLinux 9.6 (Vladimir Lyakhov)", []string{"redhat", "linux", "unix", "os"}},
		// detect-scientific.toml
		{"scientific linux", "scientific", "Scientific Linux CERN SLC", []string{"redhat", "linux", "unix", "os"}},
		// detect-centos-9-stream.toml
		{"centos stream 9", "centos-stream", "CentOS Stream 9", []string{"redhat", "linux", "unix", "os"}},
		// detect-hce-2.toml
		{"huawei cloud euleros", "hce", "Huawei Cloud EulerOS 2.0 (x86_64)", []string{"euler", "linux", "unix", "os"}},
		// detect-euleros-2.toml
		{"euleros", "euleros", "EulerOS 2.0 (SP9x86_64)", []string{"euler", "linux", "unix", "os"}},
		// detect-openeuler.toml
		{"openeuler", "openeuler", "openEuler 24.03 (LTS-SP2)", []string{"euler", "linux", "unix", "os"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			DetectDeviceType(pf, nil)
			assert.Equal(t, DeviceTypeServer, pf.Metadata[MetadataDeviceType])
		})
	}
}

// ---------------------------------------------------------------------------
// Desktop-oriented distros detected via KDE neon, Manjaro, etc.
// These are desktop distros NOT in the desktopPlatformNames list, so without
// filesystem signals they fall through to the default.
// ---------------------------------------------------------------------------

func TestDetectDeviceType_DesktopDistrosWithoutNameMatch(t *testing.T) {
	tests := []struct {
		name   string
		pfName string
		title  string
		family []string
	}{
		// detect-kdeneon.toml: name is "neon", not in desktopPlatformNames
		{"kde neon", "neon", "KDE neon 6.2", []string{"debian", "linux", "unix", "os"}},
		// detect-manjaro.toml: name is "manjaro", not in desktopPlatformNames
		{"manjaro", "manjaro", "Manjaro Linux", []string{"arch", "linux", "unix", "os"}},
		// detect-cachyos.toml: gaming/desktop Arch derivative
		{"cachyos", "cachyos", "CachyOS", []string{"arch", "linux", "unix", "os"}},
		// detect-endeavouros.toml: desktop Arch derivative
		{"endeavouros", "endeavouros", "EndeavourOS", []string{"arch", "linux", "unix", "os"}},
		// detect-mx.toml: MX Linux, desktop distro
		{"mx linux", "mx", "MX 23.2 Libretto", []string{"debian", "linux", "unix", "os"}},
		// detect-mageia-9.toml: desktop-oriented distro
		{"mageia", "mageia", "Mageia 9", []string{"linux", "unix", "os"}},
		// detect-raspbian.toml: Raspberry Pi desktop OS
		{"raspbian", "raspbian", "Raspbian GNU/Linux 10 (buster)", []string{"debian", "linux", "unix", "os"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := &inventory.Platform{
				Name:   tt.pfName,
				Title:  tt.title,
				Family: tt.family,
			}
			// Without filesystem: defaults to server (no signal available)
			DetectDeviceType(pf, nil)
			assert.Equal(t, DeviceTypeServer, pf.Metadata[MetadataDeviceType],
				"%s defaults to server without filesystem signals", tt.name)
		})
	}
}

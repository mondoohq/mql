// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package services_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/services"
)

func TestManagerMacos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "macos",
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./testdata/macos.toml"))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)
	serviceList, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 15, len(serviceList))
}

func TestManagerFreebsd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)
	serviceList, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 25, len(serviceList))
}

func TestManagerDragonflybsd5(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "dragonflybsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/dragonfly5.toml"))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)
	serviceList, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 11, len(serviceList))
}

func TestManagerOpenBsd6(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "openbsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/openbsd6.toml"))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)
	serviceList, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 70, len(serviceList))
}

func TestManagerWindows(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "windows",
			Family: []string{"windows", "os"},
		},
	}, mock.WithPath("./testdata/windows2019.toml"))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)
	serviceList, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 1, len(serviceList))
}

func TestManagerUbuntu2204(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "ubuntu",
			Version: "22.04",
			Family:  []string{"ubuntu", "linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/ubuntu2204.toml"))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)
	serviceList, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 263, len(serviceList))
}

func TestManagerPhoton(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "photon",
			Version: "3.0",
			Family:  []string{"linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/photon.toml"))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)
	serviceList, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 137, len(serviceList))
}

func TestManagerCumulus(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "cumulus-linux",
			Version: "5.12.1",
			Family:  []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Cumulus Linux")
}

func TestManagerRaspbian(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "raspbian",
			Version: "13",
			Family:  []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Raspbian")
}

func TestManagerArch(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "arch",
			Version: "unknown",
			Family:  []string{"arch", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Arch Linux")
}

func TestManagerParrot(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "parrot",
			Version: "5.3",
			Family:  []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Parrot Linux")
}

func TestManagerOpenSuseMicroOs(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "opensuse-microos",
			Version: "20211224",
			Family:  []string{"suse", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for OpenSUSE MicroOS")
}

func TestManagerSuseMicroOs(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "suse-microos",
			Version: "5.1",
			Family:  []string{"suse", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for SUSE MicroOS")
}

func TestManagerCos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "cos",
			Version: "97",
			Family:  []string{"linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for COS")
}

func TestManagerOpenEuler(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "openeuler",
			Version: "24.03",
			Family:  []string{"euler", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for OpenEuler")
}

func TestManagerKali(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "kali",
			Version: "2019.4",
			Family:  []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Kali Linux")
}

func TestManagerMageia(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "mageia",
			Version: "9",
			Family:  []string{"linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Mageia Linux")
}

func TestManagerCloudLinux(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "cloudlinux",
			Version: "9.0",
			Family:  []string{"redhat", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for CloudLinux")
}

func TestManagerElementary(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "elementary",
			Version: "7",
			Family:  []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Elementary Linux")
}

func TestManagerMXLinux(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "mx",
			Version: "23.2",
			Family:  []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for MX Linux")
}

func TestManagerZorin(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "zorin",
			Version: "16",
			Family:  []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Zorin Linux")
}

func TestManagerFlatcar(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "flatcar",
			Version: "4459.0.0",
			Family:  []string{"linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Flatcar Linux")
}

func TestManagerNobara(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "nobara",
			Version: "4459.0.0",
			Family:  []string{"redhat", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {},
		},
	}))
	require.NoError(t, err)

	mm, err := services.ResolveManager(mock)
	require.NoError(t, err)

	_, ok := mm.(*services.SystemDServiceManager)
	assert.True(t, ok, "SystemDServiceManager used for Nobara Linux")
}

// Probing only /sbin/init put every systemd distro that ships no init binary on
// the noop manager, which answers with an empty service list instead of saying
// it could not look. Debian, Ubuntu, Fedora, openSUSE and Amazon Linux images
// all carry systemd unit files without /sbin/init, and AlmaLinux ships
// /sbin/init as a symlink to a systemd binary that is not in the image.
func TestResolveManagerFindsSystemdWithoutSbinInit(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "debian",
			Version: "12",
			Family:  []string{"debian", "linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/systemd-units-no-sbin-init.toml"))
	require.NoError(t, err)

	osm, err := services.ResolveManager(mockConn)
	require.NoError(t, err)
	assert.NotEqual(t, "none", osm.Name(),
		"a target carrying systemd unit files has a service manager to read")
}

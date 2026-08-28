// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/providers/os/resources/updates"
)

// isRpmPlatform decides whether the answer comes from the rpm database or from
// the updates package's file readers. A platform that falls on the wrong side
// reads null instead of a timestamp, which no error surfaces.
func TestIsRpmPlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform *inventory.Platform
		want     bool
	}{
		{"rhel", &inventory.Platform{Name: "redhat", Family: []string{"redhat", "linux", "unix", "os"}}, true},
		{"fedora", &inventory.Platform{Name: "fedora", Family: []string{"redhat", "linux", "unix", "os"}}, true},
		{"centos", &inventory.Platform{Name: "centos", Family: []string{"redhat", "linux", "unix", "os"}}, true},
		{"sles", &inventory.Platform{Name: "sles", Family: []string{"suse", "linux", "unix", "os"}}, true},
		{"euler", &inventory.Platform{Name: "euleros", Family: []string{"euler", "linux", "unix", "os"}}, true},
		{"amazonlinux", &inventory.Platform{Name: "amazonlinux", Family: []string{"linux", "unix", "os"}}, true},
		{"photon", &inventory.Platform{Name: "photon", Family: []string{"linux", "unix", "os"}}, true},
		{"bottlerocket", &inventory.Platform{Name: "bottlerocket", Family: []string{"linux", "unix", "os"}}, true},
		{"azurelinux", &inventory.Platform{Name: "azurelinux", Family: []string{"linux", "unix", "os"}}, true},
		{"wrlinux", &inventory.Platform{Name: "wrlinux", Family: []string{"linux", "unix", "os"}}, true},
		{"mageia", &inventory.Platform{Name: "mageia", Family: []string{"linux", "unix", "os"}}, true},
		// rpm based but outside the redhat family: each resolves as a platform
		// of its own, so only the name can catch them.
		{"altlinux", &inventory.Platform{Name: "altlinux", Family: []string{"linux", "unix", "os"}}, true},
		{"opencloudos", &inventory.Platform{Name: "opencloudos", Family: []string{"linux", "unix", "os"}}, true},
		{"ubuntu", &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}, false},
		{"debian", &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix", "os"}}, false},
		{"alpine", &inventory.Platform{Name: "alpine", Family: []string{"linux", "unix", "os"}}, false},
		{"arch", &inventory.Platform{Name: "arch", Family: []string{"arch", "linux", "unix", "os"}}, false},
		{"macos", &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}, false},
		{"windows", &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isRpmPlatform(test.platform))
		})
	}
}

func TestLastUpdateAge(t *testing.T) {
	installed := time.Now().Add(-48 * time.Hour)

	age := lastUpdateAge(installed)
	require.NotNil(t, age)

	// The result is a duration-typed time, the same encoding uptime uses, so it
	// is read back through the epoch rather than as a wall-clock instant.
	seconds := llx.TimeToDuration(age)
	assert.InDelta(t, (48 * time.Hour).Seconds(), float64(seconds), 5)
}

// Central validation rejects materially future installs before any field sees
// them, but a few minutes of clock skew pass through inside its tolerance. A
// negative age would render as a nonsense duration, so it clamps to zero.
func TestLastUpdateAgeClampsFutureInstall(t *testing.T) {
	age := lastUpdateAge(time.Now().Add(2 * time.Minute))
	require.NotNil(t, age)
	assert.Equal(t, int64(0), llx.TimeToDuration(age))
}

// lastUpdate, lastUpdateAge and lastUpdateSource share one cache, and the
// executor resolves a resource's fields in separate goroutines, so they can
// enter it at the same time. Run under -race this is what catches a cache that
// reads its own state outside the lock; without -race it still pins that every
// caller sees the same outcome.
//
// A runtime with no connection resolves to a null record, which is the whole
// point here: the test exercises the cache, not the platform dispatch.
func TestLastUpdateCacheConcurrentGet(t *testing.T) {
	const callers = 64

	cache := &lastUpdateCache{}
	runtime := &plugin.Runtime{}

	type result struct {
		update *updates.LastInstalledUpdate
		err    error
	}
	results := make([]result, callers)

	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func(i int) {
			defer wg.Done()
			update, err := cache.get(runtime)
			results[i] = result{update: update, err: err}
		}(i)
	}
	wg.Wait()

	for i := range results {
		assert.Equal(t, results[0].update, results[i].update, "every caller must see the same record")
		assert.Equal(t, results[0].err, results[i].err, "every caller must see the same error")
	}
}

// A container is rebuilt rather than patched, so the age of the newest install
// inside it says nothing about whether anyone is maintaining the workload. A
// platform that lands on the wrong side of this reports an image build date as
// patch age, which no error surfaces.
func TestIsContainerPlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform *inventory.Platform
		want     bool
	}{
		{"container kind", &inventory.Platform{Kind: "container", Name: "ubuntu"}, true},
		{"container image kind", &inventory.Platform{Kind: "container-image", Name: "alpine"}, true},
		{
			// An image reached over a filesystem or tar connection can arrive
			// with no Kind, and the device type is what catches it.
			name: "device type metadata",
			platform: &inventory.Platform{
				Name:     "ubuntu",
				Metadata: map[string]string{detector.MetadataDeviceType: detector.DeviceTypeContainer},
			},
			want: true,
		},
		{
			name: "device type server",
			platform: &inventory.Platform{
				Name:     "ubuntu",
				Metadata: map[string]string{detector.MetadataDeviceType: detector.DeviceTypeServer},
			},
			want: false,
		},
		{"bare host", &inventory.Platform{Kind: "baremetal", Name: "ubuntu"}, false},
		{"virtual machine", &inventory.Platform{Kind: "virtualmachine", Name: "redhat"}, false},
		{"no metadata", &inventory.Platform{Name: "ubuntu"}, false},
		{"nil platform", nil, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isContainerPlatform(test.platform))
		})
	}
}

// The negative cases carry the weight here: a tar can be a virtual machine
// export and a filesystem connection is routinely a mounted host root, so
// excluding either would null the field on assets that genuinely are patched.
func TestIsContainerConnection(t *testing.T) {
	containers := []shared.ConnectionType{
		shared.Type_DockerContainer,
		shared.Type_DockerImage,
		shared.Type_DockerSnapshot,
		shared.Type_DockerRegistry,
		shared.Type_ContainerRegistry,
		shared.Type_RegistryImage,
		shared.Type_DockerFile,
	}
	for _, ct := range containers {
		t.Run(string(ct), func(t *testing.T) {
			assert.True(t, isContainerConnection(ct))
		})
	}

	notContainers := []shared.ConnectionType{
		shared.Type_Local,
		shared.Type_SSH,
		shared.Type_Winrm,
		shared.Type_Vagrant,
		shared.Type_Device,
		shared.Type_Tar,
		shared.Type_FileSystem,
	}
	for _, ct := range notContainers {
		t.Run(string(ct), func(t *testing.T) {
			assert.False(t, isContainerConnection(ct))
		})
	}
}

func rpmTestPackage(name, vendor string, installed *time.Time) *mqlPackage {
	return rpmTestPackageFormat(name, vendor, packages.RpmPkgFormat, installed)
}

func rpmTestPackageFormat(name, vendor, format string, installed *time.Time) *mqlPackage {
	return &mqlPackage{
		Name:        plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		Vendor:      plugin.TValue[string]{Data: vendor, State: plugin.StateIsSet},
		Format:      plugin.TValue[string]{Data: format, State: plugin.StateIsSet},
		InstallDate: plugin.TValue[*time.Time]{Data: installed, State: plugin.StateIsSet},
	}
}

// The vendor of the anchor packages is what the operating system vendor calls
// itself on this asset. Deriving it beats a shipped distribution table, which
// goes stale and nulls the field on a distribution nobody added to it.
func TestRpmOSVendors(t *testing.T) {
	t.Run("derives the vendor from an anchor", func(t *testing.T) {
		vendors := rpmOSVendors([]any{
			rpmTestPackage("glibc", "Red Hat, Inc.", nil),
			rpmTestPackage("docker-ce", "Docker", nil),
		})
		assert.Equal(t, map[string]struct{}{"red hat, inc.": {}}, vendors)
	})

	t.Run("unions several anchors", func(t *testing.T) {
		// Amazon Linux ships more than one vendor string across its own
		// packages; trusting a single anchor would drop the other spelling.
		vendors := rpmOSVendors([]any{
			rpmTestPackage("glibc", "Amazon Linux", nil),
			rpmTestPackage("bash", "Amazon.com", nil),
		})
		assert.Len(t, vendors, 2)
		assert.Contains(t, vendors, "amazon linux")
		assert.Contains(t, vendors, "amazon.com")
	})

	t.Run("ignores non-rpm anchors", func(t *testing.T) {
		vendors := rpmOSVendors([]any{
			rpmTestPackageFormat("bash", "Snapcrafters", "snap", nil),
		})
		assert.Empty(t, vendors)
	})

	t.Run("ignores an anchor with no vendor", func(t *testing.T) {
		assert.Empty(t, rpmOSVendors([]any{rpmTestPackage("glibc", "  ", nil)}))
	})

	t.Run("no anchor present", func(t *testing.T) {
		assert.Empty(t, rpmOSVendors([]any{rpmTestPackage("nginx", "nginx.org", nil)}))
	})
}

// The matcher is what attributes a dnf log line to the operating system
// vendor: the log carries only a package name, and the rpm database entry
// behind that name carries the vendor.
func TestRpmVendorPackageMatcher(t *testing.T) {
	t.Run("vendor names vouch, third-party names do not", func(t *testing.T) {
		// The failure this prevents: Docker CE moves far more often than a
		// distribution does, so counting its upgrades reports an unpatched
		// host as patched last week.
		isVendor := rpmVendorPackageMatcher([]any{
			rpmTestPackage("glibc", "Red Hat, Inc.", nil),
			rpmTestPackage("kernel", "Red Hat, Inc.", nil),
			rpmTestPackage("docker-ce", "Docker", nil),
			rpmTestPackage("htop", "Fedora Project", nil),
		})
		require.NotNil(t, isVendor)
		assert.True(t, isVendor("glibc"))
		assert.True(t, isVendor("kernel"))
		assert.False(t, isVendor("docker-ce"))
		assert.False(t, isVendor("htop"), "EPEL is not the distribution vendor")
		assert.False(t, isVendor("removed-package"))
	})

	t.Run("other package formats do not vouch", func(t *testing.T) {
		// A rpm host can also carry snap, nix or flatpak packages; a name
		// coming from one of those must not attribute a rpm log line.
		isVendor := rpmVendorPackageMatcher([]any{
			rpmTestPackage("glibc", "SUSE LLC", nil),
			rpmTestPackageFormat("code", "SUSE LLC", "snap", nil),
		})
		require.NotNil(t, isVendor)
		assert.True(t, isVendor("glibc"))
		assert.False(t, isVendor("code"))
	})

	t.Run("no anchor means no matcher", func(t *testing.T) {
		isVendor := rpmVendorPackageMatcher([]any{
			rpmTestPackage("nginx", "nginx.org", nil),
		})
		assert.Nil(t, isVendor, "an unattributable answer is none, not a coarser one")
	})

	t.Run("empty list", func(t *testing.T) {
		assert.Nil(t, rpmVendorPackageMatcher(nil))
	})
}

// An image-based system is updated by swapping the operating system image, so
// no package transaction ever records an update. Reporting the image's rpm
// timestamps as patch state would date the image build, not the patching.
func TestIsImageBasedRpmPlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform *inventory.Platform
		want     bool
	}{
		{"bottlerocket", &inventory.Platform{Name: "bottlerocket"}, true},
		{"rhcos", &inventory.Platform{Name: "rhcos"}, true},
		{
			name: "fedora coreos via label",
			platform: &inventory.Platform{
				Name:   "fedora",
				Labels: map[string]string{"variant-id": "coreos"},
			},
			want: true,
		},
		{
			name: "fedora coreos via metadata",
			platform: &inventory.Platform{
				Name:     "fedora",
				Metadata: map[string]string{"variant-id": "coreos"},
			},
			want: true,
		},
		{"plain fedora", &inventory.Platform{Name: "fedora"}, false},
		{"rhel", &inventory.Platform{Name: "redhat"}, false},
		{
			name: "fedora workstation variant",
			platform: &inventory.Platform{
				Name:   "fedora",
				Labels: map[string]string{"variant-id": "workstation"},
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isImageBasedRpmPlatform(test.platform))
		})
	}
}

func TestNormalizeVendor(t *testing.T) {
	assert.Equal(t, "red hat, inc.", normalizeVendor("  Red Hat, Inc. "))
	assert.Equal(t, "", normalizeVendor("   "))
}

func TestEntryCategories(t *testing.T) {
	entry := &mqlWindowsUpdateEntry{
		Categories: plugin.TValue[[]any]{
			Data:  []any{"Security Updates", "", nil, 42, "Windows 11"},
			State: plugin.StateIsSet,
		},
	}
	assert.Equal(t, []string{"Security Updates", "Windows 11"}, entryCategories(entry),
		"a category that is not a string is not a product name")
}

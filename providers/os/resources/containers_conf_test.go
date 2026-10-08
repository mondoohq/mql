// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixtures, all copied out of the distributions' packages:
//   - containers-conf/fedora-usr-share.conf: /usr/share/containers/containers.conf
//     from containers-common 0.67.2 (Fedora 44, quay.io/podman/stable)
//   - containers-conf/podman-stable-etc.conf: /etc/containers/containers.conf of
//     the quay.io/podman/stable image, which runs Podman inside a container
//   - containers-conf/debian-usr-share.conf: golang-github-containers-common
//     0.62.2 (Debian 13)
//   - containers-storage/fedora-usr-share.conf, podman-stable-etc.conf: as above
//   - containers-storage/rhel9-etc.conf: containers-common 5.8 (UBI 9)
//   - containers-storage/debian-usr-share.conf: containers-storage 1.57.2 (Debian 13)
//   - podman6-*: the vendor files of quay.io/podman/upstream (Podman 6.2,
//     containers-common 0.70), which ship settings as /usr/share drop-ins
//
// hardening.conf, more-caps.conf and fuse-overlay.conf are drop-ins as an
// administrator would write them. Podman 5.8.7 reads hardening.conf and
// more-caps.conf on top of the Fedora files to the capability list asserted in
// TestContainersConfAppend.
func readContainersConfFixture(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", dir, name))
	require.NoError(t, err)
	return string(b)
}

func mergeContainersFixtures(t *testing.T, dir string, names ...string) map[string]any {
	t.Helper()
	contents := make([]string, len(names))
	for i, n := range names {
		contents[i] = readContainersConfFixture(t, dir, n)
	}
	defaults, tables := map[string]any(nil), storageConfStructTables
	if dir == "containers-conf" {
		defaults, tables = containersConfDefaults(), containersConfStructTables
	}
	merged, err := mergeContainersFiles(defaults, tables, names, contents)
	require.NoError(t, err)
	return merged
}

// confResource builds a containers.conf resource over an already merged
// configuration, so the fields' defaults can be read without a connection.
func confResource(merged map[string]any, sharedLoader bool) *mqlContainersConf {
	c := &mqlContainersConf{}
	c.loaded = true
	c.sharedLoader = sharedLoader
	c.cfg = &containersConfig{merged: merged}
	return c
}

func TestContainersConfPaths(t *testing.T) {
	present := map[string]bool{containersConfEtc: true, containersConfUsr: true}
	exists := func(p string) (bool, error) { return present[p], nil }
	var askedDirs []string
	dropIns := func(dirs []string) ([]string, error) {
		askedDirs = dirs
		return []string{"/etc/containers/containers.conf.d/50-hardening.conf"}, nil
	}

	t.Run("before podman 6 both main files are merged", func(t *testing.T) {
		paths, err := containersConfPaths(false, exists, dropIns)
		require.NoError(t, err)
		assert.Equal(t, []string{containersConfUsr, containersConfEtc, "/etc/containers/containers.conf.d/50-hardening.conf"}, paths)
		assert.Equal(t, []string{"/etc/containers/containers.conf.d"}, askedDirs)
	})

	t.Run("podman 6 reads the first main file found", func(t *testing.T) {
		paths, err := containersConfPaths(true, exists, dropIns)
		require.NoError(t, err)
		assert.Equal(t, []string{containersConfEtc, "/etc/containers/containers.conf.d/50-hardening.conf"}, paths)
		assert.Equal(t, containersConfDropInDirs, askedDirs)
	})

	t.Run("vendor file alone", func(t *testing.T) {
		onlyUsr := func(p string) (bool, error) { return p == containersConfUsr, nil }
		none := func([]string) ([]string, error) { return nil, nil }
		paths, err := containersConfPaths(true, onlyUsr, none)
		require.NoError(t, err)
		assert.Equal(t, []string{containersConfUsr}, paths)
		paths, err = containersConfPaths(false, onlyUsr, none)
		require.NoError(t, err)
		assert.Equal(t, []string{containersConfUsr}, paths)
	})
}

func TestStorageConfPaths(t *testing.T) {
	none := func([]string) ([]string, error) { return nil, nil }

	both := func(p string) (bool, error) { return p == storageConfEtc || p == storageConfUsr, nil }
	paths, err := storageConfPaths(both, none)
	require.NoError(t, err)
	assert.Equal(t, []string{storageConfEtc}, paths, "the vendor file is only a fallback")

	// Debian's containers-storage ships only /usr/share/containers/storage.conf
	onlyUsr := func(p string) (bool, error) { return p == storageConfUsr, nil }
	paths, err = storageConfPaths(onlyUsr, func(dirs []string) ([]string, error) {
		assert.Equal(t, storageConfDropInDirs, dirs)
		return []string{"/etc/containers/storage.conf.d/50-fuse.conf"}, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{storageConfUsr, "/etc/containers/storage.conf.d/50-fuse.conf"}, paths)
}

// Before Podman 6 the vendor file is read first and /etc/containers/containers.conf
// on top of it: the vendor's sysctl stays, the image's log driver wins.
func TestContainersConfLegacyMerge(t *testing.T) {
	merged := mergeContainersFixtures(t, "containers-conf", "fedora-usr-share.conf", "podman-stable-etc.conf")
	c := confResource(merged, false)

	sysctls, err := c.defaultSysctls()
	require.NoError(t, err)
	assert.Equal(t, []any{"net.ipv4.ping_group_range=0 0"}, sysctls)

	logDriver, err := c.logDriver()
	require.NoError(t, err)
	assert.Equal(t, "k8s-file", logDriver)

	for name, get := range map[string]func() (string, error){
		"netns": c.netns, "userns": c.userns, "ipcns": c.ipcns, "utsns": c.utsns, "cgroupns": c.cgroupns,
	} {
		v, err := get()
		require.NoError(t, err)
		assert.Equal(t, "host", v, name)
	}
	cgroups, err := c.cgroups()
	require.NoError(t, err)
	assert.Equal(t, "disabled", cgroups)

	runtime, err := c.runtime()
	require.NoError(t, err)
	assert.Equal(t, "crun", runtime)
	cgroupManager, err := c.cgroupManager()
	require.NoError(t, err)
	assert.Equal(t, "cgroupfs", cgroupManager)
	eventsLogger, err := c.eventsLogger()
	require.NoError(t, err)
	assert.Equal(t, "file", eventsLogger)
}

// Podman 6 reads only the first main file, then the drop-ins, including the
// vendor's under /usr/share. In quay.io/podman/upstream (Podman 6.2) the
// vendor drop-in's journald overrides the image's k8s-file, which Podman
// confirms: a container created there logs to journald.
func TestContainersConfSharedLoader(t *testing.T) {
	merged := mergeContainersFixtures(t, "containers-conf", "podman-stable-etc.conf", "podman6-usr-share-00-vendor.conf")
	c := confResource(merged, true)
	sysctls, err := c.defaultSysctls()
	require.NoError(t, err)
	assert.Empty(t, sysctls)
	logDriver, err := c.logDriver()
	require.NoError(t, err)
	assert.Equal(t, "journald", logDriver)
	netns, err := c.netns()
	require.NoError(t, err)
	assert.Equal(t, "host", netns)
	caps, err := c.defaultCapabilities()
	require.NoError(t, err)
	assert.Len(t, caps, 11)
}

// The vendor files set almost nothing, so the fields report the engine's
// defaults.
func TestContainersConfDefaults(t *testing.T) {
	merged := mergeContainersFixtures(t, "containers-conf", "debian-usr-share.conf")

	c := confResource(merged, false)
	privileged, err := c.privileged()
	require.NoError(t, err)
	assert.False(t, privileged)
	caps, err := c.defaultCapabilities()
	require.NoError(t, err)
	assert.Len(t, caps, 11)
	assert.Contains(t, caps, "CAP_NET_BIND_SERVICE")
	assert.NotContains(t, caps, "CAP_NET_RAW")
	pids, err := c.pidsLimit()
	require.NoError(t, err)
	assert.Equal(t, int64(2048), pids)
	userns, err := c.userns()
	require.NoError(t, err)
	assert.Equal(t, "host", userns)
	ipcns, err := c.ipcns()
	require.NoError(t, err)
	assert.Equal(t, "shareable", ipcns)
	netns, err := c.netns()
	require.NoError(t, err)
	assert.Equal(t, "private", netns)
	network, err := c.defaultNetwork()
	require.NoError(t, err)
	assert.Equal(t, "podman", network)

	// host-dependent defaults are null
	_, err = c.seccompProfile()
	require.NoError(t, err)
	assert.True(t, c.SeccompProfile.IsNull())
	_, err = c.label()
	require.NoError(t, err)
	assert.True(t, c.Label.IsNull())
	_, err = c.logDriver()
	require.NoError(t, err)
	assert.True(t, c.LogDriver.IsNull())
	_, err = c.runtime()
	require.NoError(t, err)
	assert.True(t, c.Runtime.IsNull(), "Debian's vendor file sets no runtime")
	_, err = c.networkBackend()
	require.NoError(t, err)
	assert.True(t, c.NetworkBackend.IsNull())
	_, err = c.cgroupns()
	require.NoError(t, err)
	assert.True(t, c.Cgroupns.IsNull(), "before Podman 6 the default depends on the cgroup version")

	shared := confResource(merged, true)
	cgroupns, err := shared.cgroupns()
	require.NoError(t, err)
	assert.Equal(t, "private", cgroupns)
}

// A list with {append = true} adds to the earlier one, and the attribute
// sticks: a later list without it appends too. Podman 5.8.7 gives a container
// created with these drop-ins exactly this capability set.
func TestContainersConfAppend(t *testing.T) {
	merged := mergeContainersFixtures(t, "containers-conf",
		"fedora-usr-share.conf", "podman-stable-etc.conf", "hardening.conf", "more-caps.conf")
	c := confResource(merged, false)

	caps, err := c.defaultCapabilities()
	require.NoError(t, err)
	// appended to the engine's default list, which no file sets
	assert.ElementsMatch(t, []any{
		"CAP_AUDIT_WRITE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
		"CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT",
	}, caps)

	sysctls, err := c.defaultSysctls()
	require.NoError(t, err)
	assert.Empty(t, sysctls, "an empty list replaces the vendor's sysctl")

	pids, err := c.pidsLimit()
	require.NoError(t, err)
	assert.Equal(t, int64(0), pids, "0 is no limit, not unset")

	seccomp, err := c.seccompProfile()
	require.NoError(t, err)
	assert.Equal(t, "/etc/containers/seccomp-strict.json", seccomp)

	assert.Equal(t, "k8s-file", containersTable(merged, "containers")["log_driver"], "a drop-in keeps settings it does not set")
}

func TestContainersConfAppendOff(t *testing.T) {
	merged, err := mergeContainersFiles(nil, containersConfStructTables, []string{"a", "b", "c"}, []string{
		`[containers]
default_ulimits = ["nofile=1024:2048"]`,
		`[containers]
default_ulimits = ["nproc=100:200", {append = true}]`,
		`[containers]
default_ulimits = ["core=0:0", {append = false}]`,
	})
	require.NoError(t, err)
	assert.Equal(t, []any{"core=0:0"}, containersTable(merged, "containers")["default_ulimits"])
}

func TestContainersConfParseError(t *testing.T) {
	_, err := mergeContainersFiles(nil, containersConfStructTables, []string{"/etc/containers/containers.conf"}, []string{"[containers\n"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/etc/containers/containers.conf")
}

// The library decodes these tables into structs, and BurntSushi/toml matches
// field names regardless of case: with this drop-in Podman 5.8.7 reports the
// log driver "none" and the events logger "none".
func TestContainersConfKeyCase(t *testing.T) {
	merged, err := mergeContainersFiles(containersConfDefaults(), containersConfStructTables, []string{"a", "b"}, []string{
		`[containers]
log_driver = "journald"
default_capabilities = ["CAP_CHOWN"]`,
		`[Containers]
Log_Driver = "none"
SECCOMP_PROFILE = "unconfined"
Default_Capabilities = ["CAP_SYS_ADMIN", {append = true}]

[ENGINE]
Events_Logger = "none"`,
	})
	require.NoError(t, err)
	c := confResource(merged, false)

	logDriver, err := c.logDriver()
	require.NoError(t, err)
	assert.Equal(t, "none", logDriver)
	seccomp, err := c.seccompProfile()
	require.NoError(t, err)
	assert.Equal(t, "unconfined", seccomp)
	events, err := c.eventsLogger()
	require.NoError(t, err)
	assert.Equal(t, "none", events)
	caps, err := c.defaultCapabilities()
	require.NoError(t, err)
	assert.Equal(t, []any{"CAP_CHOWN", "CAP_SYS_ADMIN"}, caps)
}

func TestLowerStructKeys(t *testing.T) {
	in := map[string]any{
		"Storage": map[string]any{
			"Driver": "vfs",
			"options": map[string]any{
				"Pull_Options": map[string]any{"Enable_Partial_Images": "true"},
			},
		},
		"storage": map[string]any{"driver": "overlay"},
	}
	out := lowerStructKeys(in, "", storageConfStructTables)
	storage := out["storage"].(map[string]any)
	assert.Equal(t, "overlay", storage["driver"], "the exact spelling wins")
	assert.NotContains(t, out, "Storage")
	// a map table keeps its keys as written
	pull := storage["options"].(map[string]any)["pull_options"].(map[string]any)
	assert.Equal(t, map[string]any{"Enable_Partial_Images": "true"}, pull)
}

func TestContainersStorageKeyCase(t *testing.T) {
	merged, err := mergeContainersFiles(nil, storageConfStructTables, []string{"a"}, []string{`[Storage]
Driver = "btrfs"
[Storage.Options.Overlay]
MountOpt = "nodev"`})
	require.NoError(t, err)
	s := storageResource(merged)
	driver, err := s.driver()
	require.NoError(t, err)
	assert.Equal(t, "btrfs", driver)
	opts, err := s.overlayMountOptions()
	require.NoError(t, err)
	assert.Equal(t, []any{"nodev"}, opts)
}

func TestPodmanPackageMajorVersion(t *testing.T) {
	for version, want := range map[string]int{
		"5.8.7-1.fc44":   5,
		"5:5.4.0-1.el9":  5,
		"5.4.2+ds1-2":    5,
		"6.1.3-1.fc45":   6,
		"4.3.1+ds1-8+b1": 4,
	} {
		got, ok := podmanPackageMajorVersion(version)
		assert.True(t, ok, version)
		assert.Equal(t, want, got, version)
	}
	_, ok := podmanPackageMajorVersion("")
	assert.False(t, ok)
}

func storageResource(merged map[string]any) *mqlContainersStorage {
	s := &mqlContainersStorage{}
	s.loaded = true
	s.cfg = &containersConfig{merged: merged}
	return s
}

func TestContainersStorage(t *testing.T) {
	t.Run("rhel 9", func(t *testing.T) {
		s := storageResource(mergeContainersFixtures(t, "containers-storage", "rhel9-etc.conf"))
		driver, err := s.driver()
		require.NoError(t, err)
		assert.Equal(t, "overlay", driver)
		opts, err := s.overlayMountOptions()
		require.NoError(t, err)
		assert.Equal(t, []any{"nodev", "metacopy=on"}, opts)
		pull, err := s.pullOptions()
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"enable_partial_images": "false"}, pull)
		stores, err := s.additionalImageStores()
		require.NoError(t, err)
		assert.Empty(t, stores)
		program, err := s.overlayMountProgram()
		require.NoError(t, err)
		assert.Empty(t, program)
	})

	t.Run("podman in a container", func(t *testing.T) {
		s := storageResource(mergeContainersFixtures(t, "containers-storage", "podman-stable-etc.conf"))
		program, err := s.overlayMountProgram()
		require.NoError(t, err)
		assert.Equal(t, "/usr/bin/fuse-overlayfs", program)
		opts, err := s.overlayMountOptions()
		require.NoError(t, err)
		assert.Equal(t, []any{"nodev", "fsync=0"}, opts)
		stores, err := s.additionalImageStores()
		require.NoError(t, err)
		assert.Equal(t, []any{"/var/lib/shared", "/usr/lib/containers/storage"}, stores)
	})

	t.Run("drop-in", func(t *testing.T) {
		s := storageResource(mergeContainersFixtures(t, "containers-storage", "debian-usr-share.conf", "fuse-overlay.conf"))
		driver, err := s.driver()
		require.NoError(t, err)
		assert.Equal(t, "overlay", driver, "overlay2 is an alias")
		// the overlay table's mountopt from the vendor file wins over the
		// generic one the drop-in sets
		opts, err := s.overlayMountOptions()
		require.NoError(t, err)
		assert.Equal(t, []any{"nodev"}, opts)
		program, err := s.overlayMountProgram()
		require.NoError(t, err)
		assert.Equal(t, "/usr/bin/fuse-overlayfs", program)
		stores, err := s.additionalImageStores()
		require.NoError(t, err)
		assert.Equal(t, []any{"/mnt/images"}, stores)
		graph, err := s.graphRoot()
		require.NoError(t, err)
		assert.Equal(t, "/var/lib/containers/storage", graph)
	})

	// Podman 6.2's vendor files: the main file only sets the overlay table's
	// nodev, the rootful drop-in adds metacopy and an image store. Podman
	// reports overlay.mountopt nodev,metacopy=on on that image.
	t.Run("podman 6 vendor drop-ins", func(t *testing.T) {
		s := storageResource(mergeContainersFixtures(t, "containers-storage",
			"podman6-usr-share.conf", "podman6-usr-share-00-vendor.conf", "podman6-usr-share-rootful-00-vendor-rootful.conf"))
		driver, err := s.driver()
		require.NoError(t, err)
		assert.Equal(t, "overlay", driver)
		opts, err := s.overlayMountOptions()
		require.NoError(t, err)
		assert.Equal(t, []any{"nodev", "metacopy=on"}, opts)
		stores, err := s.additionalImageStores()
		require.NoError(t, err)
		assert.Equal(t, []any{"/usr/lib/containers/storage"}, stores)
	})

	t.Run("generic mount options apply without an overlay table", func(t *testing.T) {
		assert.Equal(t, "nodev,nosuid", storageOverlayOption(map[string]any{"mountopt": "nodev,nosuid"}, "mountopt"))
		assert.Equal(t, "nodev", storageOverlayOption(map[string]any{
			"mountopt": "nodev,nosuid",
			"overlay":  map[string]any{"mountopt": "nodev"},
		}, "mountopt"))
	})

	t.Run("nothing set", func(t *testing.T) {
		s := storageResource(map[string]any{})
		_, err := s.driver()
		require.NoError(t, err)
		assert.True(t, s.Driver.IsNull())
		graph, err := s.graphRoot()
		require.NoError(t, err)
		assert.Equal(t, storageDefaultGraphRoot, graph)
		run, err := s.runRoot()
		require.NoError(t, err)
		assert.Equal(t, storageDefaultRunRoot, run)
		transient, err := s.transientStore()
		require.NoError(t, err)
		assert.False(t, transient)
		opts, err := s.overlayMountOptions()
		require.NoError(t, err)
		assert.Empty(t, opts)
	})
}

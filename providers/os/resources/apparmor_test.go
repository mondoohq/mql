// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	processmgr "go.mondoo.com/mql/providers/os/resources/processes"
)

const testApparmorJSON = `{"version": "2", "profiles": {"/usr/bin/man": "enforce", "/usr/lib/NetworkManager/nm-dhcp-client.action": "enforce", "/usr/lib/connman/scripts/dhclient-script": "enforce", "/usr/sbin/chronyd": "enforce", "/usr/{lib/NetworkManager,libexec}/nm-dhcp-helper": "enforce", "/{,usr/}sbin/dhclient": "enforce", "docker-default": "enforce", "libvirtd": "enforce", "libvirtd//qemu_bridge_helper": "enforce", "lsb_release": "enforce", "man_filter": "enforce", "man_groff": "enforce", "nvidia_modprobe": "enforce", "nvidia_modprobe//kmod": "enforce", "virt-aa-helper": "enforce", "Xorg": "complain", "plasmashell": "complain", "plasmashell//QtWebEngineProcess": "complain", "sbuild": "complain", "sbuild-abort": "complain", "sbuild-adduser": "complain", "sbuild-apt": "complain", "sbuild-checkpackages": "complain", "sbuild-clean": "complain", "sbuild-createchroot": "complain", "sbuild-destroychroot": "complain", "sbuild-distupgrade": "complain", "sbuild-hold": "complain", "sbuild-shell": "complain", "sbuild-unhold": "complain", "sbuild-update": "complain", "sbuild-upgrade": "complain", "transmission-cli": "complain", "transmission-daemon": "complain", "transmission-gtk": "complain", "transmission-qt": "complain", "unix-chkpwd": "complain", "unprivileged_userns": "complain", "1password": "unconfined", "Discord": "unconfined", "MongoDB Compass": "unconfined", "QtWebEngineProcess": "unconfined", "balena-etcher": "unconfined", "brave": "unconfined", "buildah": "unconfined", "busybox": "unconfined", "cam": "unconfined", "ch-checkns": "unconfined", "ch-run": "unconfined", "chrome": "unconfined", "chromium": "unconfined", "crun": "unconfined", "devhelp": "unconfined", "element-desktop": "unconfined", "epiphany": "unconfined", "evolution": "unconfined", "firefox": "unconfined", "flatpak": "unconfined", "foliate": "unconfined", "geary": "unconfined", "github-desktop": "unconfined", "goldendict": "unconfined", "ipa_verify": "unconfined", "kchmviewer": "unconfined", "keybase": "unconfined", "lc-compliance": "unconfined", "libcamerify": "unconfined", "linux-sandbox": "unconfined", "loupe": "unconfined", "lxc-attach": "unconfined", "lxc-create": "unconfined", "lxc-destroy": "unconfined", "lxc-execute": "unconfined", "lxc-stop": "unconfined", "lxc-unshare": "unconfined", "lxc-usernsexec": "unconfined", "mmdebstrap": "unconfined", "msedge": "unconfined", "nautilus": "unconfined", "notepadqq": "unconfined", "obsidian": "unconfined", "opam": "unconfined", "opera": "unconfined", "pageedit": "unconfined", "polypane": "unconfined", "privacybrowser": "unconfined", "qcam": "unconfined", "qmapshack": "unconfined", "qutebrowser": "unconfined", "rootlesskit": "unconfined", "rpm": "unconfined", "rssguard": "unconfined", "runc": "unconfined", "scide": "unconfined", "signal-desktop": "unconfined", "slack": "unconfined", "slirp4netns": "unconfined", "steam": "unconfined", "stress-ng": "unconfined", "surfshark": "unconfined", "systemd-coredump": "unconfined", "toybox": "unconfined", "trinity": "unconfined", "tup": "unconfined", "tuxedo-control-center": "unconfined", "userbindmount": "unconfined", "uwsgi-core": "unconfined", "vdens": "unconfined", "virtiofsd": "unconfined", "vivaldi-bin": "unconfined", "vpnns": "unconfined", "vscode": "unconfined", "wike": "unconfined", "wpcom": "unconfined"}, "processes": {"/portainer": [{"profile": "docker-default", "pid": "1607926", "status": "enforce"}], "/usr/sbin/chronyd": [{"profile": "/usr/sbin/chronyd", "pid": "1858", "status": "enforce"}, {"profile": "/usr/sbin/chronyd", "pid": "1861", "status": "enforce"}]}}`

func TestParseApparmorStatus(t *testing.T) {
	var status apparmorStatus
	err := json.Unmarshal([]byte(testApparmorJSON), &status)
	require.NoError(t, err)

	assert.Equal(t, "2", status.Version)
	assert.Len(t, status.Profiles, 114)
	assert.Equal(t, "enforce", status.Profiles["/usr/bin/man"])
	assert.Equal(t, "complain", status.Profiles["Xorg"])
	assert.Equal(t, "unconfined", status.Profiles["firefox"])

	assert.Len(t, status.Processes, 2)

	portainer := status.Processes["/portainer"]
	require.Len(t, portainer, 1)
	assert.Equal(t, "docker-default", portainer[0].Profile)
	assert.Equal(t, "1607926", portainer[0].PID)
	assert.Equal(t, "enforce", portainer[0].Status)

	chronyd := status.Processes["/usr/sbin/chronyd"]
	require.Len(t, chronyd, 2)
	assert.Equal(t, "1858", chronyd[0].PID)
	assert.Equal(t, "1861", chronyd[1].PID)
}

func TestParseApparmorStatusEmpty(t *testing.T) {
	var status apparmorStatus
	err := json.Unmarshal([]byte(`{"version": "2", "profiles": {}, "processes": {}}`), &status)
	require.NoError(t, err)

	assert.Equal(t, "2", status.Version)
	assert.Empty(t, status.Profiles)
	assert.Empty(t, status.Processes)
}

// AppArmor 3.0.8 (Debian 12) leaves out the comma between the process lists of
// two modes. Captured from a host running sweepd and sweep-named in enforce mode
// and sweepc in complain mode.
func TestParseApparmorStatusJSONMissingComma(t *testing.T) {
	data, err := os.ReadFile("testdata/apparmor/aa-status-3.0.8-debian12.json")
	require.NoError(t, err)

	var raw apparmorStatus
	require.Error(t, json.Unmarshal(data, &raw), "the captured output must be the invalid one")

	status, err := parseApparmorStatusJSON(string(data))
	require.NoError(t, err)
	assert.Equal(t, "2", status.Version)
	assert.True(t, status.versionKnown)
	assert.Equal(t, "enforce", status.Profiles["sweep-named"])
	assert.False(t, status.hasLegacyProcesses())

	require.Len(t, status.Processes, 3)
	sweepc := status.Processes["/usr/local/bin/sweepc"]
	require.Len(t, sweepc, 1)
	assert.Equal(t, apparmorProcInfo{Profile: "/usr/local/bin/sweepc", PID: "10279", Status: "complain"}, sweepc[0])
	sweepn := status.Processes["/usr/local/bin/sweepn"]
	require.Len(t, sweepn, 1)
	assert.Equal(t, apparmorProcInfo{Profile: "sweep-named", PID: "10282", Status: "enforce"}, sweepn[0])
}

func TestRepairApparmorStatusJSON(t *testing.T) {
	// a bracket and quote inside a string are not a missing comma
	in := `{"processes": {"/a]\"b": [{"pid": "1"}]"/c": [{"pid": "2"}]}}`
	assert.Equal(t, `{"processes": {"/a]\"b": [{"pid": "1"}],"/c": [{"pid": "2"}]}}`, repairApparmorStatusJSON(in))

	valid := `{"version": "2", "profiles": {}, "processes": {"/a": [{"pid": "1"}], "/b": []}}`
	assert.Equal(t, valid, repairApparmorStatusJSON(valid))
}

func TestParseApparmorStatusJSONInvalid(t *testing.T) {
	_, err := parseApparmorStatusJSON("apparmor module is not loaded.")
	assert.Error(t, err)
}

// AppArmor 2.13 (Debian 10 and 11) reports version 1 and already names the
// profile in each process entry.
func TestParseApparmorStatusJSONVersion1CurrentShape(t *testing.T) {
	data, err := os.ReadFile("testdata/apparmor/aa-status-2.13-debian10.json")
	require.NoError(t, err)

	status, err := parseApparmorStatusJSON(string(data))
	require.NoError(t, err)
	assert.Equal(t, "1", status.Version)
	assert.False(t, status.hasLegacyProcesses())

	sweepn := status.Processes["/usr/local/bin/sweepn"]
	require.Len(t, sweepn, 1)
	assert.Equal(t, "sweep-named", sweepn[0].Profile)
}

// AppArmor 2.11 (Debian 9) keys each process list by profile name and leaves
// the profile out of the entries. sweep-named confines /usr/local/bin/sweepn.
func TestResolveLegacyApparmorProcesses(t *testing.T) {
	data, err := os.ReadFile("testdata/apparmor/aa-status-2.11-debian9.json")
	require.NoError(t, err)

	status, err := parseApparmorStatusJSON(string(data))
	require.NoError(t, err)
	assert.Equal(t, "1", status.Version)
	require.True(t, status.hasLegacyProcesses())

	status.resolveLegacyProcesses([]*processmgr.OSProcess{
		{Pid: 818, Executable: "sweepd", Command: "/usr/local/bin/sweepd"},
		{Pid: 824, Executable: "sweepn", Command: "/usr/local/bin/sweepn"},
		// pid 821 (sweepc) exited after aa-status ran
	})

	require.Len(t, status.Processes, 2)
	assert.NotContains(t, status.Processes, "sweep-named")
	assert.NotContains(t, status.Processes, "/usr/local/bin/sweepc")

	sweepn := status.Processes["/usr/local/bin/sweepn"]
	require.Len(t, sweepn, 1)
	assert.Equal(t, apparmorProcInfo{Profile: "sweep-named", PID: "824", Status: "enforce"}, sweepn[0])

	sweepd := status.Processes["/usr/local/bin/sweepd"]
	require.Len(t, sweepd, 1)
	assert.Equal(t, apparmorProcInfo{Profile: "/usr/local/bin/sweepd", PID: "818", Status: "enforce"}, sweepd[0])
}

func TestParseApparmorProfileLine(t *testing.T) {
	name, mode, ok := parseApparmorProfileLine("/usr/sbin/chronyd (enforce)")
	require.True(t, ok)
	assert.Equal(t, "/usr/sbin/chronyd", name)
	assert.Equal(t, "enforce", mode)

	name, mode, ok = parseApparmorProfileLine("MongoDB Compass (unconfined)")
	require.True(t, ok)
	assert.Equal(t, "MongoDB Compass", name)
	assert.Equal(t, "unconfined", mode)

	_, _, ok = parseApparmorProfileLine("apparmor module is loaded.")
	assert.False(t, ok)
}

func TestParseApparmorCurrentLabel(t *testing.T) {
	profile, status, ok := parseApparmorCurrentLabel("/usr/sbin/chronyd (complain)\n")
	require.True(t, ok)
	assert.Equal(t, "/usr/sbin/chronyd", profile)
	assert.Equal(t, "complain", status)

	profile, status, ok = parseApparmorCurrentLabel("unconfined\n")
	require.True(t, ok)
	assert.Equal(t, "unconfined", profile)
	assert.Equal(t, "unconfined", status)

	profile, status, ok = parseApparmorCurrentLabel("MongoDB Compass (unconfined)\x00")
	require.True(t, ok)
	assert.Equal(t, "MongoDB Compass", profile)
	assert.Equal(t, "unconfined", status)
}

func TestReadApparmorProfilesFromFS(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := fs.MkdirAll("/sys/kernel/security/apparmor", 0o755)
	require.NoError(t, err)
	err = afero.WriteFile(fs, apparmorProfilesPath, []byte(""+
		"/usr/sbin/chronyd (enforce)\n"+
		"MongoDB Compass (unconfined)\n"+
		"/usr/sbin/dnsmasq (complain)\n"), 0o444)
	require.NoError(t, err)

	profiles, err := readApparmorProfilesFromFS(fs)
	require.NoError(t, err)
	require.Len(t, profiles, 3)
	assert.Equal(t, "enforce", profiles["/usr/sbin/chronyd"])
	assert.Equal(t, "unconfined", profiles["MongoDB Compass"])
	assert.Equal(t, "complain", profiles["/usr/sbin/dnsmasq"])
}

func TestReadApparmorProcessesFromFS(t *testing.T) {
	fs := afero.NewMemMapFs()

	require.NoError(t, fs.MkdirAll("/proc/1/attr/apparmor", 0o755))
	require.NoError(t, fs.MkdirAll("/proc/2/attr/apparmor", 0o755))
	require.NoError(t, fs.MkdirAll("/proc/3/attr", 0o755))

	require.NoError(t, afero.WriteFile(fs, "/proc/1/attr/apparmor/current", []byte("/usr/sbin/chronyd (complain)\n"), 0o444))
	require.NoError(t, afero.WriteFile(fs, "/proc/2/attr/apparmor/current", []byte("unconfined\n"), 0o444))
	require.NoError(t, afero.WriteFile(fs, "/proc/3/attr/current", []byte("docker-default (enforce)\n"), 0o444))

	procs := []*processmgr.OSProcess{
		{Pid: 1, Executable: "/usr/sbin/chronyd"},
		{Pid: 2, Executable: "/usr/bin/firefox"},
		{Pid: 3, Executable: "/portainer"},
		{Pid: 4, Executable: "/usr/bin/ignored"},
	}

	processes := readApparmorProcessesFromFS(fs, procs)
	require.Len(t, processes, 2)

	chronyd := processes["/usr/sbin/chronyd"]
	require.Len(t, chronyd, 1)
	assert.Equal(t, "complain", chronyd[0].Status)
	assert.Equal(t, "/usr/sbin/chronyd", chronyd[0].Profile)

	// a process without a profile is not confined, as aa-status sees it
	assert.NotContains(t, processes, "/usr/bin/firefox")

	portainer := processes["/portainer"]
	require.Len(t, portainer, 1)
	assert.Equal(t, "enforce", portainer[0].Status)
	assert.Equal(t, "docker-default", portainer[0].Profile)
}

func TestApparmorProcessExecutable(t *testing.T) {
	assert.Equal(t, "/usr/sbin/chronyd", apparmorProcessExecutable(&processmgr.OSProcess{
		Pid:        1,
		Executable: "chronyd",
		Command:    "/usr/sbin/chronyd -d",
	}))

	assert.Equal(t, "dockerd", apparmorProcessExecutable(&processmgr.OSProcess{
		Pid:        2,
		Executable: "dockerd",
		Command:    "dockerd --debug",
	}))

	assert.Equal(t, "3", apparmorProcessExecutable(&processmgr.OSProcess{Pid: 3}))
}

// securityfs enforces CAP_MAC_ADMIN regardless of the mode bits, so an
// unprivileged scan gets EACCES on a world-readable profiles list. Container-
// Optimized OS is such a host: the file is mode 444 and stat-able, aa-status
// and apparmor_status are not installed at all, and the read fails. Swallowing
// that error reported zero profiles on a host running an enforcing one.
func TestFetchStatusFromKernelUnreadableProfiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/sys/kernel/security/apparmor", 0o755))
	require.NoError(t, afero.WriteFile(fs, apparmorProfilesPath, []byte("docker-default (enforce)\n"), 0o444))

	// the list is present and stat-able, but every open of it fails
	blocked := &openDeniedFs{Fs: fs, path: apparmorProfilesPath}

	exists, err := afero.Exists(blocked, apparmorProfilesPath)
	require.NoError(t, err)
	require.True(t, exists, "the profiles list must still stat")

	profiles, err := readApparmorProfilesFromFS(blocked)
	require.Error(t, err, "an unreadable profiles list must not read as an empty one")
	assert.Nil(t, profiles)
}

// openDeniedFs stats normally but refuses to open one path, the way securityfs
// behaves for a caller without CAP_MAC_ADMIN.
type openDeniedFs struct {
	afero.Fs
	path string
}

func (f *openDeniedFs) Open(name string) (afero.File, error) {
	if name == f.path {
		return nil, os.ErrPermission
	}
	return f.Fs.Open(name)
}

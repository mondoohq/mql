// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/filesfind"
	"go.mondoo.com/mql/utils/syncx"
)

// newPamRuntimeWithFiles builds a runtime backed by a mock filesystem whose
// files have the given contents, so the full files -> entries pipeline runs.
func newPamRuntimeWithFiles(t *testing.T, files map[string]string) *plugin.Runtime {
	t.Helper()

	fileData := map[string]*mock.MockFileData{}
	for path, content := range files {
		fileData[path] = &mock.MockFileData{Path: path, Content: content}
	}

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "arch", Family: []string{"arch", "linux"}},
	}, mock.WithData(&mock.TomlData{Files: fileData}))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// newPamEntry builds a parsed service-entry resource directly for unit tests.
func newPamEntry(pamType, control, module string, options []any) *mqlPamConfServiceEntry {
	set := plugin.StateIsSet
	return &mqlPamConfServiceEntry{
		PamType: plugin.TValue[string]{Data: pamType, State: set},
		Control: plugin.TValue[string]{Data: control, State: set},
		Module:  plugin.TValue[string]{Data: module, State: set},
		Options: plugin.TValue[[]any]{Data: options, State: set},
	}
}

// newPamRuntime builds a runtime backed by a mock filesystem containing the
// given files, so pam.conf.exists can be exercised for both the present and
// absent cases without disturbing the shared LinuxMock recording.
func newPamRuntime(t *testing.T, files ...string) *plugin.Runtime {
	t.Helper()

	fileData := map[string]*mock.MockFileData{}
	for _, f := range files {
		fileData[f] = &mock.MockFileData{Path: f}
	}

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "arch", Family: []string{"arch", "linux"}},
	}, mock.WithData(&mock.TomlData{Files: fileData}))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func TestPamConfExists(t *testing.T) {
	t.Run("true when /etc/pam.conf is present", func(t *testing.T) {
		pam := &mqlPamConf{MqlRuntime: newPamRuntime(t, "/etc/pam.conf")}
		got, err := pam.exists()
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("true when the /etc/pam.d directory is present", func(t *testing.T) {
		pam := &mqlPamConf{MqlRuntime: newPamRuntime(t, "/etc/pam.d")}
		got, err := pam.exists()
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("false without erroring when no PAM config is present", func(t *testing.T) {
		pam := &mqlPamConf{MqlRuntime: newPamRuntime(t)}
		got, err := pam.exists()
		require.NoError(t, err)
		assert.False(t, got)
	})
}

func TestPamConfPrefersPamDirOverPamConf(t *testing.T) {
	// When /etc/pam.d exists, Linux-PAM ignores /etc/pam.conf entirely. Our
	// parsing must do the same: only the pam.d files are read, and a service
	// defined only in /etc/pam.conf must not appear.
	findCmd := filesfind.BuildFilesFindCmd(defaultPamDir, false, "file", "", 0, "", nil, true)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "arch", Family: []string{"arch", "linux", "unix"}},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			defaultPamDir:         {Path: defaultPamDir, StatData: mock.FileInfo{Mode: os.ModeDir | 0o755}},
			defaultPamDir + "/su": {Path: defaultPamDir + "/su", Content: "auth required pam_wheel.so use_uid\n"},
			defaultPamConf:        {Path: defaultPamConf, Content: "login auth required pam_unix.so\n"},
		},
		Commands: map[string]*mock.Command{
			"find --version": {Stdout: "find (GNU findutils) 4.9.0\n"},
			findCmd:          {Stdout: defaultPamDir + "/su\n"},
		},
	}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	pam := &mqlPamConf{MqlRuntime: rt}

	files := pam.GetFiles()
	require.NoError(t, files.Error)
	paths := make([]string, 0, len(files.Data))
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.Equal(t, []string{defaultPamDir + "/su"}, paths,
		"only /etc/pam.d files are read; /etc/pam.conf is ignored")

	entries := pam.GetEntries()
	require.NoError(t, entries.Error)
	_, hasPamDirService := entries.Data[defaultPamDir+"/su"]
	assert.True(t, hasPamDirService, "the pam.d service is parsed")
	_, hasPamConfService := entries.Data["login"]
	assert.False(t, hasPamConfService,
		"the /etc/pam.conf service must not be parsed while /etc/pam.d exists")
}

func TestPamConfServiceModules(t *testing.T) {
	svc := &mqlPamConfService{
		MqlRuntime: newPamRuntime(t),
		Name:       plugin.TValue[string]{Data: "su", State: plugin.StateIsSet},
		Entries: plugin.TValue[[]any]{Data: []any{
			newPamEntry("auth", "required", "pam_wheel.so", []any{"use_uid", "group=sugroup"}),
			newPamEntry("auth", "required", "pam_unix.so", []any{}),
		}, State: plugin.StateIsSet},
	}

	mods, err := svc.modules()
	require.NoError(t, err)

	wheel, ok := mods["pam_wheel"].(*mqlPamModule)
	require.True(t, ok, "pam_wheel keyed by canonical name (no .so)")
	assert.True(t, wheel.Enabled.Data)
	assert.Equal(t, "sugroup", wheel.Params.Data["group"])
	assert.Equal(t, "", wheel.Params.Data["use_uid"], "bare flag present as empty string")
	// Scoped cache key so a per-service module never collides with the global
	// pam.module aggregation across all services.
	assert.Equal(t, "pam.module/su/pam_wheel", wheel.__id)

	_, hasUnix := mods["pam_unix"]
	assert.True(t, hasUnix)
}

func TestPamConfServiceMissing(t *testing.T) {
	// No PAM configuration on the host: the service resolves to an empty husk
	// rather than erroring, so audits guarded by pam.conf.exists stay clean.
	args, res, err := initPamConfService(newPamRuntime(t), map[string]*llx.RawData{
		"name": llx.StringData("su"),
	})
	require.NoError(t, err)
	require.Nil(t, res)
	assert.Equal(t, "su", args["name"].Value)
	assert.Equal(t, "", args["path"].Value)
	assert.Empty(t, args["entries"].Value)
}

func TestPamConfSingleFile(t *testing.T) {
	// Legacy single-file /etc/pam.conf: every line is prefixed with the
	// service name. With no /etc/pam.d directory present, files() falls back
	// to this file and entries() must split off the service column.
	content := strings.Join([]string{
		"# legacy single-file pam.conf",
		"su    auth required pam_wheel.so use_uid group=sugroup",
		"su    auth required pam_unix.so",
		"sshd  auth required pam_unix.so",
		"",
	}, "\n")
	rt := newPamRuntimeWithFiles(t, map[string]string{"/etc/pam.conf": content})

	pam := &mqlPamConf{MqlRuntime: rt}
	entries := pam.GetEntries()
	require.NoError(t, entries.Error)

	// Keyed by service name (not the file path), one service per first column.
	suList, ok := entries.Data["su"].([]any)
	require.True(t, ok, "entries keyed by service name 'su'")
	assert.Len(t, suList, 2)
	_, hasSshd := entries.Data["sshd"]
	assert.True(t, hasSshd)
	assert.Equal(t, "auth", suList[0].(*mqlPamConfServiceEntry).PamType.Data,
		"service column stripped, not misparsed as pamType")

	// pam.conf.service resolves the single-file service and reports the
	// source file as its path. Run the init hook (as the executor does) then
	// create from the resolved args.
	args, _, err := initPamConfService(rt, map[string]*llx.RawData{
		"name": llx.StringData("su"),
	})
	require.NoError(t, err)
	res, err := CreateResource(rt, "pam.conf.service", args)
	require.NoError(t, err)
	svc := res.(*mqlPamConfService)
	assert.Equal(t, "/etc/pam.conf", svc.GetPath().Data)

	mods := svc.GetModules()
	require.NoError(t, mods.Error)
	wheel, ok := mods.Data["pam_wheel"].(*mqlPamModule)
	require.True(t, ok)
	assert.True(t, wheel.Enabled.Data)
	assert.Equal(t, "sugroup", wheel.Params.Data["group"])
	assert.Equal(t, "", wheel.Params.Data["use_uid"])
}

func TestPamConfSkipsMalformedLine(t *testing.T) {
	// A single malformed line (too few fields for pam.ParseLine to accept)
	// must not abort parsing of the whole configuration. The bad line is
	// skipped and the valid entries around it are still returned, matching how
	// the other config parsers in this package (modprobe, rsyslog) behave.
	content := strings.Join([]string{
		"su auth required pam_env.so",
		"su auth required", // malformed: only two fields after the service column
		"su account required pam_permit.so",
		"",
	}, "\n")
	rt := newPamRuntimeWithFiles(t, map[string]string{"/etc/pam.conf": content})

	pam := &mqlPamConf{MqlRuntime: rt}
	entries := pam.GetEntries()
	require.NoError(t, entries.Error, "malformed line must not fail the whole parse")

	suList, ok := entries.Data["su"].([]any)
	require.True(t, ok, "expected entries for service 'su'")
	require.Len(t, suList, 2, "the two valid lines survive; the malformed one is skipped")

	modules := []string{
		suList[0].(*mqlPamConfServiceEntry).Module.Data,
		suList[1].(*mqlPamConfServiceEntry).Module.Data,
	}
	assert.ElementsMatch(t, []string{"pam_env.so", "pam_permit.so"}, modules)
}

func TestPamConfServiceEntryParams(t *testing.T) {
	se := &mqlPamConfServiceEntry{}

	t.Run("key=value and bare flags", func(t *testing.T) {
		got, err := se.params([]any{"use_uid", "group=wheel"})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"use_uid": "", "group": "wheel"}, got)
	})

	t.Run("duplicate keys: last occurrence wins", func(t *testing.T) {
		got, err := se.params([]any{"group=wheel", "group=admin"})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"group": "admin"}, got)
	})

	t.Run("no options yields an empty map", func(t *testing.T) {
		got, err := se.params([]any{})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{}, got)
	})
}

func TestCanonicalizePamModuleName(t *testing.T) {
	cases := []struct {
		in       string
		expected string
	}{
		{"pam_unix.so", "pam_unix"},
		{"/lib/security/pam_faillock.so", "pam_faillock"},
		{"pam_unix", "pam_unix"},
		{"/lib64/security/pam_pwquality.so", "pam_pwquality"},
		{"", ""},
		{"pam_faillock", "pam_faillock"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.expected, canonicalizePamModuleName(tc.in))
		})
	}
}

func TestAggregatePamParams(t *testing.T) {
	t.Run("single entry simple key=value", func(t *testing.T) {
		got := aggregatePamParams([]any{"deny=5"})
		assert.Equal(t, map[string]any{"deny": "5"}, got)
	})

	t.Run("last-write-wins across entries", func(t *testing.T) {
		got := aggregatePamParams(
			[]any{"deny=3"},
			[]any{"deny=5"},
		)
		assert.Equal(t, map[string]any{"deny": "5"}, got)
	})

	t.Run("bare option recorded as existence marker", func(t *testing.T) {
		got := aggregatePamParams([]any{"use_authtok"})
		assert.Equal(t, map[string]any{"use_authtok": ""}, got)
	})

	t.Run("mixed bare and key=value", func(t *testing.T) {
		got := aggregatePamParams([]any{"use_authtok", "deny=5", "unlock_time=900"})
		assert.Equal(t, map[string]any{
			"use_authtok": "",
			"deny":        "5",
			"unlock_time": "900",
		}, got)
	})

	t.Run("case-normalized keys", func(t *testing.T) {
		got := aggregatePamParams([]any{"Deny=5"})
		assert.Equal(t, map[string]any{"deny": "5"}, got)
	})

	t.Run("empty input produces empty map", func(t *testing.T) {
		got := aggregatePamParams()
		assert.Equal(t, map[string]any{}, got)
	})

	t.Run("value contains equals sign is preserved", func(t *testing.T) {
		// Bracketed forms like `default=die` aren't options — they live in
		// the control column — but if a value itself contains an `=`, we
		// keep everything after the first `=` as the value.
		got := aggregatePamParams([]any{"group=admin,wheel"})
		assert.Equal(t, map[string]any{"group": "admin,wheel"}, got)
	})

	t.Run("multi-list aggregation in order", func(t *testing.T) {
		got := aggregatePamParams(
			[]any{"unlock_time=600", "deny=3"},
			[]any{"deny=5", "even_deny_root"},
		)
		assert.Equal(t, map[string]any{
			"unlock_time":    "600",
			"deny":           "5",
			"even_deny_root": "",
		}, got)
	})
}

func TestIsPamControlEnabled(t *testing.T) {
	cases := []struct {
		control  string
		expected bool
	}{
		{"required", true},
		{"requisite", true},
		{"sufficient", true},
		{"optional", true},
		{"substack", true},
		{"include", true},
		{"[success=1 default=ignore]", false},
		{"[default=ignore]", false},
		{"[default=skip]", false},
		{"[default=die]", true},
		{"[success=ok default=bad]", true},
		{"", false},
	}

	for _, tc := range cases {
		t.Run(tc.control, func(t *testing.T) {
			assert.Equal(t, tc.expected, isPamControlEnabled(tc.control))
		})
	}
}

// newPamDirRuntime builds a runtime whose /etc/pam.d directory contains a
// single "su" service, alongside a legacy /etc/pam.conf. It mirrors the mock
// wiring of TestPamConfPrefersPamDirOverPamConf so the path-selected and the
// default form can be compared against the same host.
func newPamDirRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()

	findCmd := filesfind.BuildFilesFindCmd(defaultPamDir, false, "file", "", 0, "", nil, true)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "arch", Family: []string{"arch", "linux", "unix"}},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			defaultPamDir:         {Path: defaultPamDir, StatData: mock.FileInfo{Mode: os.ModeDir | 0o755}},
			defaultPamDir + "/su": {Path: defaultPamDir + "/su", Content: "auth required pam_wheel.so use_uid\n"},
			defaultPamConf:        {Path: defaultPamConf, Content: "login auth required pam_unix.so\n"},
		},
		Commands: map[string]*mock.Command{
			"find --version": {Stdout: "find (GNU findutils) 4.9.0\n"},
			findCmd:          {Stdout: defaultPamDir + "/su\n"},
		},
	}))
	require.NoError(t, err)

	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func pamPaths(t *testing.T, res plugin.Resource) []string {
	t.Helper()
	files := res.(*mqlPamConf).GetFiles()
	require.NoError(t, files.Error)
	paths := make([]string, 0, len(files.Data))
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	return paths
}

func TestPamConfPathSelectsSingleFile(t *testing.T) {
	// pam.conf("<path>") used to set an arg named 'file', which pam.conf does
	// not have (only files []file), so every parameterized use failed with
	// "cannot set 'file' in resource 'pam.conf', field not found".
	rt := newPamDirRuntime(t)

	res, err := NewResource(rt, "pam.conf", map[string]*llx.RawData{
		"path": llx.StringData(defaultPamConf),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{defaultPamConf}, pamPaths(t, res),
		"a path-selected pam.conf reads exactly the requested file")

	// The legacy single-file layout still parses: entries are keyed by the
	// service column rather than the file path.
	entries := res.(*mqlPamConf).GetEntries()
	require.NoError(t, entries.Error)
	_, hasLogin := entries.Data["login"]
	assert.True(t, hasLogin, "the /etc/pam.conf 'login' service is parsed")
}

func TestPamConfPathDoesNotHijackDefault(t *testing.T) {
	// The parameterized form must not change what the bare pam.conf reads,
	// and the two must not share a cache key.
	rt := newPamDirRuntime(t)

	selected, err := NewResource(rt, "pam.conf", map[string]*llx.RawData{
		"path": llx.StringData(defaultPamConf),
	})
	require.NoError(t, err)

	bare, err := NewResource(rt, "pam.conf", map[string]*llx.RawData{})
	require.NoError(t, err)

	assert.Equal(t, []string{defaultPamDir + "/su"}, pamPaths(t, bare),
		"the bare form still enumerates /etc/pam.d and ignores /etc/pam.conf")
	assert.Equal(t, []string{defaultPamConf}, pamPaths(t, selected))
	assert.NotEqual(t, bare.MqlID(), selected.MqlID(),
		"a path-selected pam.conf must not collide with the default instance")
}

func TestPamConfPathMissingFile(t *testing.T) {
	// A path that does not exist still constructs; the absence surfaces as
	// exists == false rather than as an error, so guarded audits stay clean.
	rt := newPamRuntime(t)

	res, err := NewResource(rt, "pam.conf", map[string]*llx.RawData{
		"path": llx.StringData("/etc/pam.d/does-not-exist"),
	})
	require.NoError(t, err)

	exists := res.(*mqlPamConf).GetExists()
	require.NoError(t, exists.Error)
	assert.False(t, exists.Data)
}

// newPamVendorRuntime builds a runtime whose per-service PAM directories hold
// the given service files (path -> content). Every directory named by a key
// is created, and the find listing for it is recorded so getSortedPathFiles
// enumerates it. A legacy /etc/pam.conf is always present, so tests can prove
// it stays ignored in directory mode.
func newPamVendorRuntime(t *testing.T, services map[string]string) *plugin.Runtime {
	t.Helper()

	files := map[string]*mock.MockFileData{
		defaultPamConf: {Path: defaultPamConf, Content: "login auth required pam_unix.so\n"},
	}
	listings := map[string][]string{}
	for path, content := range services {
		files[path] = &mock.MockFileData{Path: path, Content: content}
		dir := filepath.Dir(path)
		listings[dir] = append(listings[dir], path)
	}
	commands := map[string]*mock.Command{
		"find --version": {Stdout: "find (GNU findutils) 4.9.0\n"},
	}
	for dir, paths := range listings {
		files[dir] = &mock.MockFileData{Path: dir, StatData: mock.FileInfo{Mode: os.ModeDir | 0o755}}
		findCmd := filesfind.BuildFilesFindCmd(dir, false, "file", "", 0, "", nil, true)
		commands[findCmd] = &mock.Command{Stdout: strings.Join(paths, "\n") + "\n"}
	}

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "opensuse-leap", Family: []string{"suse", "linux", "unix"}},
	}, mock.WithData(&mock.TomlData{Files: files, Commands: commands}))
	require.NoError(t, err)

	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestPamConfFallsBackToVendorDirs(t *testing.T) {
	// openSUSE Leap 16 ships su only as /usr/lib/pam.d/su. PAM loads the first
	// file named after the service across /etc/pam.d, /usr/lib/pam.d and
	// /usr/etc/pam.d, so an /etc/pam.d copy shadows the vendor one.
	rt := newPamVendorRuntime(t, map[string]string{
		"/etc/pam.d/login":     "auth required pam_faillock.so deny=3\n",
		"/usr/lib/pam.d/login": "auth required pam_unix.so\n",
		"/usr/lib/pam.d/su":    "auth required pam_wheel.so use_uid\n",
		"/usr/etc/pam.d/su":    "auth sufficient pam_rootok.so\n",
		"/usr/etc/pam.d/sshd":  "auth include common-auth\n",
	})

	res, err := NewResource(rt, "pam.conf", map[string]*llx.RawData{})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/etc/pam.d/login",
		"/usr/lib/pam.d/su",
		"/usr/etc/pam.d/sshd",
	}, pamPaths(t, res), "one file per service, first directory wins")

	entries := res.(*mqlPamConf).GetEntries()
	require.NoError(t, entries.Error)
	_, hasPamConfService := entries.Data["login"]
	assert.False(t, hasPamConfService,
		"/etc/pam.conf must not be parsed while a pam.d directory exists")

	svc, err := NewResource(rt, "pam.conf.service", map[string]*llx.RawData{
		"name": llx.StringData("su"),
	})
	require.NoError(t, err)
	su := svc.(*mqlPamConfService)
	assert.Equal(t, "/usr/lib/pam.d/su", su.Path.Data)
	mods := su.GetModules()
	require.NoError(t, mods.Error)
	wheel, ok := mods.Data["pam_wheel"].(*mqlPamModule)
	require.True(t, ok, "pam_wheel from the vendor su file is visible")
	assert.Equal(t, map[string]any{"use_uid": ""}, wheel.Params.Data)
	_, hasRootok := mods.Data["pam_rootok"]
	assert.False(t, hasRootok, "the shadowed /usr/etc/pam.d/su is not read")
}

func TestPamConfVendorDirWithoutEtcPamD(t *testing.T) {
	// With no /etc/pam.d at all, PAM still runs in directory mode when a
	// vendor directory exists, and /etc/pam.conf stays ignored.
	rt := newPamVendorRuntime(t, map[string]string{
		"/usr/lib/pam.d/su": "auth required pam_wheel.so use_uid\n",
	})

	res, err := NewResource(rt, "pam.conf", map[string]*llx.RawData{})
	require.NoError(t, err)
	pam := res.(*mqlPamConf)

	exists := pam.GetExists()
	require.NoError(t, exists.Error)
	assert.True(t, exists.Data)
	assert.Equal(t, []string{"/usr/lib/pam.d/su"}, pamPaths(t, res))
}

func TestPamConfPathSelectsVendorFile(t *testing.T) {
	// A path-selected vendor file is a per-service file, not the single-file
	// layout: its lines carry no leading service column.
	rt := newPamVendorRuntime(t, map[string]string{
		"/usr/lib/pam.d/su": "auth required pam_wheel.so use_uid\n",
	})

	res, err := NewResource(rt, "pam.conf", map[string]*llx.RawData{
		"path": llx.StringData("/usr/lib/pam.d/su"),
	})
	require.NoError(t, err)
	entries := res.(*mqlPamConf).GetEntries()
	require.NoError(t, entries.Error)
	list, ok := entries.Data["/usr/lib/pam.d/su"].([]any)
	require.True(t, ok)
	require.Len(t, list, 1)
	assert.Equal(t, "pam_wheel.so", list[0].(*mqlPamConfServiceEntry).Module.Data)
}

func TestIsPamServiceDir(t *testing.T) {
	assert.True(t, isPamServiceDir("/etc/pam.d/su"))
	assert.True(t, isPamServiceDir("/usr/lib/pam.d/su"))
	assert.True(t, isPamServiceDir("/usr/etc/pam.d/su"))
	assert.False(t, isPamServiceDir("/etc/pam.conf"))
	assert.False(t, isPamServiceDir("/etc/pam.d/sub/su"))
}

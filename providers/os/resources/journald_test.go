// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func TestJournaldConfigIncludesDropins(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/etc/systemd/journald.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
Storage=persistent
Compress=Yes
ForwardToSyslog=no

[Upload]
URL=http://base.example.test
`,
		},
		"/etc/systemd/journald.conf.d": {
			StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
		},
		"/etc/systemd/journald.conf.d/10-forward.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
ForwardToSyslog=YES
Compress=NO
`,
		},
		"/etc/systemd/journald.conf.d/20-upload.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Upload]
URL=https://dropin.example.test
`,
		},
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	config := raw.(*mqlJournaldConfig)
	sections := config.GetSections()
	require.NoError(t, sections.Error)

	requireJournaldParam(t, sections.Data, "Journal", "Storage", "persistent")
	requireJournaldParam(t, sections.Data, "Journal", "ForwardToSyslog", "yes")
	requireJournaldParam(t, sections.Data, "Journal", "Compress", "no")
	requireJournaldParam(t, sections.Data, "Upload", "URL", "https://dropin.example.test")

	params := config.GetParams()
	require.NoError(t, params.Error)
	require.Equal(t, "yes", params.Data["ForwardToSyslog"])
}

func TestJournaldConfigUsesSystemdConfigSearchPath(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/usr/lib/systemd/journald.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
Storage=auto
`,
		},
		"/usr/lib/systemd/journald.conf.d": {
			StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
		},
		"/usr/lib/systemd/journald.conf.d/10-vendor.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
ForwardToSyslog=YES
Compress=YES
`,
		},
		"/usr/local/lib/systemd/journald.conf.d": {
			StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
		},
		"/usr/local/lib/systemd/journald.conf.d/20-local-vendor.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
Compress=NO
`,
		},
		"/run/systemd/journald.conf.d": {
			StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
		},
		"/run/systemd/journald.conf.d/30-runtime.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
Storage=volatile
`,
		},
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	config := raw.(*mqlJournaldConfig)
	file := config.GetFile()
	require.NoError(t, file.Error)
	path := file.Data.GetPath()
	require.NoError(t, path.Error)
	require.Equal(t, "/usr/lib/systemd/journald.conf", path.Data)

	sections := config.GetSections()
	require.NoError(t, sections.Error)

	requireJournaldParam(t, sections.Data, "Journal", "Storage", "volatile")
	requireJournaldParam(t, sections.Data, "Journal", "ForwardToSyslog", "yes")
	requireJournaldParam(t, sections.Data, "Journal", "Compress", "no")
}

func TestJournaldConfigDropinsUseSystemdFilenameOrdering(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/etc/systemd/journald.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
ForwardToSyslog=yes
`,
		},
		"/etc/systemd/journald.conf.d": {
			StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
		},
		"/etc/systemd/journald.conf.d/10-local.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
ForwardToSyslog=no
`,
		},
		"/usr/lib/systemd/journald.conf.d": {
			StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
		},
		"/usr/lib/systemd/journald.conf.d/90-vendor.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
ForwardToSyslog=YES
`,
		},
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	config := raw.(*mqlJournaldConfig)
	sections := config.GetSections()
	require.NoError(t, sections.Error)

	requireJournaldParam(t, sections.Data, "Journal", "ForwardToSyslog", "yes")
}

func TestJournaldConfigDropinsMaskSameFilenamesByDirectoryPriority(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/etc/systemd/journald.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
Storage=auto
`,
		},
		"/usr/lib/systemd/journald.conf.d": {
			StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
		},
		"/usr/lib/systemd/journald.conf.d/50-forward.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
ForwardToSyslog=no
`,
		},
		"/etc/systemd/journald.conf.d": {
			StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
		},
		"/etc/systemd/journald.conf.d/50-forward.conf": {
			StatData: mock.FileInfo{Mode: 0o644},
			Content: `[Journal]
ForwardToSyslog=YES
`,
		},
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	config := raw.(*mqlJournaldConfig)
	sections := config.GetSections()
	require.NoError(t, sections.Error)

	requireJournaldParam(t, sections.Data, "Journal", "ForwardToSyslog", "yes")
}

func journaldMockRuntime(t *testing.T, files map[string]*mock.MockFileData) *plugin.Runtime {
	t.Helper()

	for path, file := range files {
		file.Path = path
	}

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "linux",
			Family:  []string{"linux", "unix", "os"},
			Version: "test",
		},
	}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{},
		Files:    files,
	}))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func requireJournaldParam(t *testing.T, sections []any, sectionName, paramName, expected string) {
	t.Helper()

	for _, sectionAny := range sections {
		section := sectionAny.(*mqlJournaldConfigSection)
		name := section.GetName()
		require.NoError(t, name.Error)
		if name.Data != sectionName {
			continue
		}

		params := section.GetParams()
		require.NoError(t, params.Error)
		for _, paramAny := range params.Data {
			param := paramAny.(*mqlJournaldConfigSectionParam)
			name := param.GetName()
			require.NoError(t, name.Error)
			if name.Data != paramName {
				continue
			}

			value := param.GetValue()
			require.NoError(t, value.Error)
			require.Equal(t, expected, value.Data)
			return
		}
	}

	require.Failf(t, "journald parameter not found", "%s.%s", sectionName, paramName)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestNewVscodeExtensionPurl(t *testing.T) {
	cases := []struct {
		name      string
		publisher string
		extName   string
		version   string
		want      string
	}{
		{
			name:      "Roo Code (real marketplace extension)",
			publisher: "RooVeterinaryInc",
			extName:   "roo-cline",
			version:   "3.34.7",
			want:      "pkg:vscode-extension/RooVeterinaryInc/roo-cline@3.34.7",
		},
		{
			name:      "Microsoft Python (well-known prebuilt extension)",
			publisher: "ms-python",
			extName:   "python",
			version:   "2026.6.0",
			want:      "pkg:vscode-extension/ms-python/python@2026.6.0",
		},
		{
			name:      "version omitted (unknown / dev build)",
			publisher: "golang",
			extName:   "go",
			version:   "",
			want:      "pkg:vscode-extension/golang/go",
		},
		{
			name:      "empty publisher (incomplete metadata) yields empty PURL",
			publisher: "",
			extName:   "go",
			version:   "0.50.0",
			want:      "",
		},
		{
			name:      "empty name (incomplete metadata) yields empty PURL",
			publisher: "golang",
			extName:   "",
			version:   "0.50.0",
			want:      "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := newVscodeExtensionPurl(tc.publisher, tc.extName, tc.version)
			assert.Equal(t, tc.want, got)
		})
	}
}

// Full account enumeration deliberately fails. Extension discovery must only
// read the profiles, including domain and Entra profiles absent from local SAM.
func vscodeProfileRuntime(t *testing.T, profiles map[string]string) (*plugin.Runtime, afero.Fs) {
	t.Helper()
	mem := afero.NewMemMapFs()
	runtime := memFSRuntime(t, mem)
	runtime.Connection.(shared.Connection).UpdateAsset(&inventory.Asset{
		Platform: &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}},
	})
	seedUsersCache(t, runtime)
	users, ok := runtime.Resources.Get("users\x00")
	require.True(t, ok)
	users.(*mqlUsers).List.Error = errors.New("full account enumeration must not be used")

	root, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(windowsProfileListPath),
	})
	require.NoError(t, err)
	sids := make([]string, 0, len(profiles))
	for sid := range profiles {
		sids = append(sids, sid)
	}
	sort.Strings(sids)
	children := make([]any, 0, len(sids))
	for _, sid := range sids {
		children = append(children, sid)
		key, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
			"path": llx.StringData(windowsProfileListPath + `\` + sid),
		})
		require.NoError(t, err)
		key.(*mqlRegistrykey).Items = plugin.TValue[[]any]{State: plugin.StateIsSet, Data: []any{
			&mqlRegistrykeyProperty{
				Name:  plugin.TValue[string]{State: plugin.StateIsSet, Data: "ProfileImagePath"},
				Value: plugin.TValue[string]{State: plugin.StateIsSet, Data: profiles[sid]},
			},
		}}
	}
	root.(*mqlRegistrykey).Children = plugin.TValue[[]any]{State: plugin.StateIsSet, Data: children}
	return runtime, mem
}

func TestVscodeWindowsProfilePaths(t *testing.T) {
	runtime, _ := vscodeProfileRuntime(t, map[string]string{
		"S-1-5-18":                 `C:\Users\system`,
		"S-1-5-21-1-2-3-1001":      `C:\Users\alice`,
		"S-1-5-21-1-2-3-1002":      `c:/users/ALICE/`,
		"S-1-5-21-10-20-30-1001":   `C:\Users\domain.user`,
		"S-1-12-1-111-222-333-444": `C:\Users\entra.user`,
		"S-1-5-21-1-2-3-1003":      `C:\Users\Public\`,
		"S-1-5-21-1-2-3-1004":      `C:\Windows\ServiceProfiles\service`,
		"S-1-5-21-1-2-3-1005":      "",
	})
	homes, err := vscodeUserHomePaths(runtime)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{`C:\Users\alice`, `C:\Users\domain.user`, `C:\Users\entra.user`}, homes)
}

func TestVscodeExtensionsWindowsProfiles(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "installed"}[installed], func(t *testing.T) {
			runtime, mem := vscodeProfileRuntime(t, map[string]string{
				"S-1-5-21-1-2-3-1001": `C:\Users\alice`,
				"S-1-5-21-9-8-7-1001": `C:\Users\domain.user`,
			})
			extensionsDir := filepath.Join(`C:\Users\domain.user`, ".vscode/extensions")
			if installed {
				writeMemFSFile(t, mem, filepath.Join(extensionsDir, "supermaven.supermaven-1.0.0", "package.json"), []byte(`{"publisher":"supermaven","name":"supermaven","version":"1.0.0"}`))
			}
			resource, err := CreateResource(runtime, "vscode", map[string]*llx.RawData{})
			require.NoError(t, err)
			vscode := resource.(*mqlVscode)
			extensions := vscode.GetExtensions()
			require.NoError(t, extensions.Error)
			paths := vscode.GetPaths()
			require.NoError(t, paths.Error)
			if installed {
				require.Len(t, extensions.Data, 1)
				extension := extensions.Data[0].(*mqlVscodeExtension)
				assert.Equal(t, "supermaven.supermaven", extension.GetIdentifier().Data)
				assert.Equal(t, "1.0.0", extension.GetVersion().Data)
				assert.Equal(t, []any{extensionsDir}, paths.Data)
			} else {
				assert.Empty(t, extensions.Data)
				assert.Empty(t, paths.Data)
			}
		})
	}
}

func TestVscodeWindowsProfileReadErrors(t *testing.T) {
	for _, rootDenied := range []bool{true, false} {
		t.Run(map[bool]string{true: "profile list", false: "profile"}[rootDenied], func(t *testing.T) {
			runtime, _ := vscodeProfileRuntime(t, map[string]string{"S-1-5-21-1-2-3-1001": `C:\Users\alice`})
			denied := llx.Forbidden(errors.New("registry access denied"))
			path := windowsProfileListPath
			if !rootDenied {
				path += `\S-1-5-21-1-2-3-1001`
			}
			resource, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{"path": llx.StringData(path)})
			require.NoError(t, err)
			key := resource.(*mqlRegistrykey)
			if rootDenied {
				key.Children.Error = denied
			} else {
				key.Items.Error = denied
			}
			vscode, err := CreateResource(runtime, "vscode", map[string]*llx.RawData{})
			require.NoError(t, err)
			result := vscode.(*mqlVscode).GetExtensions()
			require.ErrorIs(t, result.Error, llx.ErrForbidden)
			assert.Nil(t, result.Data, "unreadable profiles must not report an empty extension inventory")
		})
	}
}

func TestVscodeWindowsProfileEnvironment(t *testing.T) {
	runtime, _ := vscodeProfileRuntime(t, map[string]string{"S-1-5-21-1-2-3-1001": `%SystemDrive%\Users\alice`})
	osResource, err := CreateResource(runtime, "os.base", map[string]*llx.RawData{})
	require.NoError(t, err)
	osResource.(*mqlOsBase).Env = plugin.TValue[map[string]any]{State: plugin.StateIsSet, Data: map[string]any{"SYSTEMDRIVE": "C:"}}
	homes, err := vscodeUserHomePaths(runtime)
	require.NoError(t, err)
	assert.Equal(t, []string{`C:\Users\alice`}, homes)
}

func TestVscodeWindowsProfileValueError(t *testing.T) {
	runtime, _ := vscodeProfileRuntime(t, map[string]string{"S-1-5-21-1-2-3-1001": `C:\Users\alice`})
	key, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(windowsProfileListPath + `\S-1-5-21-1-2-3-1001`),
	})
	require.NoError(t, err)
	property := key.(*mqlRegistrykey).Items.Data[0].(*mqlRegistrykeyProperty)
	property.Value.Error = errors.New("could not decode profile path")
	homes, err := vscodeUserHomePaths(runtime)
	require.ErrorContains(t, err, "could not decode profile path")
	assert.Nil(t, homes)
}

func TestVscodeWindowsProfilePathsRemote(t *testing.T) {
	profilePath := windowsProfileListPath + `\S-1-5-21-1-2-3-1001`
	runtime, conn := newRemoteWindowsRuntime(t, map[string]*mock.Command{
		powershell.Encode(registry.GetRegistryKeyChildItemsScript(windowsProfileListPath)): {
			Stdout: `[{"name":"S-1-5-21-1-2-3-1001"}]`,
		},
		powershell.Encode(registry.GetRegistryKeyItemScript(profilePath)): {
			Stdout: `[{"key":"profileimagepath","value":{"data":"C:\\Users\\alice","type":"REG_SZ"}}]`,
		},
	})
	homes, err := vscodeUserHomePaths(runtime)
	require.NoError(t, err)
	assert.Equal(t, []string{`C:\Users\alice`}, homes)
	assert.Equal(t, int32(2), conn.commands.Load(), "only registry reads, no account enumeration")
}

func TestVscodeUserHomePathsUnix(t *testing.T) {
	runtime := memFSRuntime(t, afero.NewMemMapFs())
	seedUsersCache(t, runtime, &mqlUser{
		Name: plugin.TValue[string]{State: plugin.StateIsSet, Data: "alice"},
		Home: plugin.TValue[string]{State: plugin.StateIsSet, Data: "/home/alice"},
		Uid:  plugin.TValue[int64]{State: plugin.StateIsSet, Data: 1000},
	})
	homes, err := vscodeUserHomePaths(runtime)
	require.NoError(t, err)
	assert.Equal(t, []string{"/home/alice"}, homes)
}

func TestReadVSCodePackageJSONRejectsSpecialOrOversize(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		size int64
	}{
		{"fifo", os.ModeNamedPipe, 0}, {"oversize", 0o644, maxExtensionManifestSize + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(mem, "/package.json", []byte(`{"publisher":"example","name":"extension"}`), 0o644))
			fs := &boundedReadFS{Fs: mem, path: "/package.json", mode: tc.mode, size: tc.size}
			pkg, err := readVSCodePackageJSON(&afero.Afero{Fs: fs}, "/package.json")
			require.Error(t, err)
			assert.Nil(t, pkg)
			assert.Zero(t, fs.opens)
		})
	}
}

func TestVscodeExtensionsUnreadableManifestErrors(t *testing.T) {
	for _, mode := range []os.FileMode{os.ModeNamedPipe, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			mem := afero.NewMemMapFs()
			home := "/home/alice"
			manifest := filepath.Join(home, ".vscode", "extensions", "example.extension-1.0.0", "package.json")
			writeMemFSFile(t, mem, manifest, []byte(`{"publisher":"example","name":"extension"}`))
			size := int64(0)
			if mode.IsRegular() {
				size = maxExtensionManifestSize + 1
			}
			fs := &boundedReadFS{Fs: mem, path: manifest, mode: mode, size: size}
			runtime := memFSRuntime(t, fs)
			seedUsersCache(t, runtime, &mqlUser{Name: plugin.TValue[string]{Data: "alice", State: plugin.StateIsSet}, Home: plugin.TValue[string]{Data: home, State: plugin.StateIsSet}})
			raw, err := CreateResource(runtime, "vscode", nil)
			require.NoError(t, err)
			result := raw.(*mqlVscode).GetExtensions()
			require.Error(t, result.Error, "an incomplete inventory must not satisfy a none() assertion")
			assert.Nil(t, result.Data)
			assert.Zero(t, fs.opens)
		})
	}
}

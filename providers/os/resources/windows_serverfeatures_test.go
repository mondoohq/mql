// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/utils/syncx"
)

// win11GetWindowsFeatureStderr is the stderr of the Get-WindowsFeature query
// on Windows 11 Pro 24H2 and 25H2 over WinRM (exit status 1). Client editions
// do not ship the ServerManager module that provides the cmdlet.
const win11GetWindowsFeatureStderr = `#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">Get-WindowsFeature : The term 'Get-WindowsFeature' is not recognized as the name of a cmdlet, function, script file, _x000D__x000A_</S><S S="Error">or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and _x000D__x000A_</S><S S="Error">try again._x000D__x000A_</S><S S="Error">At line:1 char:40_x000D__x000A_</S><S S="Error">+ $ProgressPreference='SilentlyContinue';Get-WindowsFeature | Select-Ob ..._x000D__x000A_</S><S S="Error">+                                        ~~~~~~~~~~~~~~~~~~_x000D__x000A_</S><S S="Error">    + CategoryInfo          : ObjectNotFound: (Get-WindowsFeature:String) [], CommandNotFoundException_x000D__x000A_</S><S S="Error">    + FullyQualifiedErrorId : CommandNotFoundException_x000D__x000A_</S><S S="Error"> _x000D__x000A_</S></Objs>`

func newServerFeaturesWindows(t *testing.T, productType string, cmd *mock.Command) *mqlWindows {
	t.Helper()
	pf := &inventory.Platform{
		Name:   "windows",
		Family: []string{"windows"},
		Labels: map[string]string{},
	}
	if productType != "" {
		pf.Labels["windows.mondoo.com/product-type"] = productType
	}
	cmds := map[string]*mock.Command{}
	if cmd != nil {
		cmds[powershell.Encode(windows.QUERY_FEATURES)] = cmd
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, mock.WithData(&mock.TomlData{Commands: cmds}))
	require.NoError(t, err)
	return &mqlWindows{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
}

// A Windows client edition has no server roles or features, so the field is
// an empty list, not the CommandNotFoundException Get-WindowsFeature raises.
func TestWindowsServerFeatures_ClientIsEmpty(t *testing.T) {
	w := newServerFeaturesWindows(t, "1", &mock.Command{
		Stderr:     win11GetWindowsFeatureStderr,
		ExitStatus: 1,
	})

	features, err := w.serverFeatures()
	require.NoError(t, err)
	require.NotNil(t, features, "an empty list, not null")
	assert.Empty(t, features)
}

// Windows Server keeps querying Get-WindowsFeature through the unchanged
// command and parser. The fixture is the windows.serverFeatures result of a
// Windows Server 2022 Datacenter EC2 instance, written back in the property
// names Get-WindowsFeature's ConvertTo-Json emits.
func TestWindowsServerFeatures_Server2022(t *testing.T) {
	data, err := os.ReadFile("./windows/testdata/features-ws2022.json")
	require.NoError(t, err)

	for _, productType := range []string{"3", "2"} {
		t.Run("product-type "+productType, func(t *testing.T) {
			w := newServerFeaturesWindows(t, productType, &mock.Command{Stdout: string(data)})

			features, err := w.serverFeatures()
			require.NoError(t, err)
			require.Len(t, features, 269)

			installed := map[string]*mqlWindowsServerFeature{}
			for _, f := range features {
				sf := f.(*mqlWindowsServerFeature)
				if sf.Installed.Data {
					installed[sf.Name.Data] = sf
				}
			}
			assert.Len(t, installed, 12)
			ps, ok := installed["PowerShell"]
			require.True(t, ok)
			assert.Equal(t, `Windows PowerShell\Windows PowerShell 5.1`, ps.Path.Data)
			assert.Equal(t, "Windows PowerShell 5.1", ps.DisplayName.Data)
			assert.Equal(t, int64(1), ps.InstallState.Data)
		})
	}
}

// A failing Get-WindowsFeature on a server, or on a host whose edition was not
// detected, is still an error rather than an empty list.
func TestWindowsServerFeatures_FailureIsError(t *testing.T) {
	for _, productType := range []string{"3", ""} {
		t.Run("product-type "+productType, func(t *testing.T) {
			w := newServerFeaturesWindows(t, productType, &mock.Command{
				Stderr:     win11GetWindowsFeatureStderr,
				ExitStatus: 1,
			})

			_, err := w.serverFeatures()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to retrieve features")
		})
	}
}

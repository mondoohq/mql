// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// testdata/aix73_tunables.txt is the output of no, vmo, ioo, schedo and raso
// -a on AIX 7.3 TL4 SP2 after `no -p -o tcp_keepidle=7201`, `no -p -o
// ipforwarding=1` and `ioo -p -o j2_maxPageReadAhead=256`, under the [command]
// lines AixTunablesCommand prints. nfso printed nothing.
func TestParseAixTunables(t *testing.T) {
	f, err := os.Open("testdata/aix73_tunables.txt")
	require.NoError(t, err)
	defer f.Close()

	params, err := ParseAixTunables(f)
	require.NoError(t, err)
	assert.Len(t, params, 301)

	assert.Equal(t, "7201", params["no.tcp_keepidle"])
	assert.Equal(t, "1", params["no.ipforwarding"])
	assert.Equal(t, "256", params["ioo.j2_maxPageReadAhead"])
	assert.Equal(t, "1", params["raso.kernel_noexec"])
	_, ok := params["tcp_keepidle"]
	assert.False(t, ok, "a tunable is named after its command")
}

func TestParseAixTunablesSkipsLinesOutsideACommand(t *testing.T) {
	params, err := ParseAixTunables(strings.NewReader("stray = 1\n[no]\n  tcp_keepidle = 7200\n##Restricted tunables\n  arpqsize = 1024\n"))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"no.tcp_keepidle": "7200", "no.arpqsize": "1024"}, params)
}

func TestAixKernelManagerParameters(t *testing.T) {
	out, err := os.ReadFile("testdata/aix73_tunables.txt")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "aix", Family: []string{"unix", "os"}},
	}, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{
		AixTunablesCommand: {Stdout: string(out)},
	}}))
	require.NoError(t, err)

	mm, err := ResolveManager(conn)
	require.NoError(t, err)
	params, err := mm.Parameters()
	require.NoError(t, err)
	assert.Equal(t, "7201", params["no.tcp_keepidle"])
}

// testdata/aix73_nextboot.txt is /etc/tunables/nextboot from the same host.
func TestParseAixNextboot(t *testing.T) {
	f, err := os.Open("testdata/aix73_nextboot.txt")
	require.NoError(t, err)
	defer f.Close()

	config := NewSysctlConfig()
	require.NoError(t, config.ParseAixNextboot(f, AixNextbootFile))
	assert.Equal(t, []string{"no.ipforwarding", "no.tcp_keepidle", "ioo.j2_maxPageReadAhead"}, config.Names())

	assignments, effective := config.Lookup("no.tcp_keepidle")
	require.Equal(t, 0, effective)
	assert.Equal(t, "7201", assignments[0].Value)
	assert.Equal(t, "tcp_keepidle", assignments[0].Key)
	assert.Equal(t, AixNextbootFile, assignments[0].File)
	assert.Equal(t, 7, assignments[0].Line)
}

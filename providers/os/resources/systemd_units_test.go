// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func newSystemdUnitsTestRuntime(t *testing.T, commands map[string]*mock.Command) *plugin.Runtime {
	t.Helper()

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "ubuntu",
			Version: "22.04",
			Family:  []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func TestInitSystemdTimerMissingResource(t *testing.T) {
	runtime := newSystemdUnitsTestRuntime(t, map[string]*mock.Command{
		"systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description missing.timer": {
			Stdout: strings.Join([]string{
				"Id=missing.timer",
				"Description=missing.timer",
				"LoadState=not-found",
				"ActiveState=inactive",
				"UnitFileState=",
				"",
			}, "\n"),
		},
	})

	for _, input := range []string{"missing", "missing.timer"} {
		t.Run(input, func(t *testing.T) {
			_, res, err := initSystemdTimer(runtime, map[string]*llx.RawData{"name": llx.StringData(input)})
			require.NoError(t, err)
			require.NotNil(t, res)

			timer := res.(*mqlSystemdTimer)
			assert.Equal(t, "missing", timer.Name.Data)
			assert.False(t, timer.Installed.Data)
			assert.False(t, timer.Enabled.Data)
			assert.False(t, timer.Running.Data)
		})
	}
}

func TestInitSystemdSocketMissingResource(t *testing.T) {
	runtime := newSystemdUnitsTestRuntime(t, map[string]*mock.Command{
		"systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description missing.socket": {
			Stdout: strings.Join([]string{
				"Id=missing.socket",
				"Description=missing.socket",
				"LoadState=not-found",
				"ActiveState=inactive",
				"UnitFileState=",
				"",
			}, "\n"),
		},
	})

	for _, input := range []string{"missing", "missing.socket"} {
		t.Run(input, func(t *testing.T) {
			_, res, err := initSystemdSocket(runtime, map[string]*llx.RawData{"name": llx.StringData(input)})
			require.NoError(t, err)
			require.NotNil(t, res)

			socket := res.(*mqlSystemdSocket)
			assert.Equal(t, "missing", socket.Name.Data)
			assert.False(t, socket.Installed.Data)
			assert.False(t, socket.Enabled.Data)
			assert.False(t, socket.Running.Data)
		})
	}
}

func TestSystemdTimerPersistentBooleanForms(t *testing.T) {
	// systemctl show emits "yes"/"no", but the filesystem path forwards the raw
	// unit-file value, which may be true/1/on. All truthy forms must report true.
	for _, v := range []string{"yes", "true", "1", "on"} {
		timer := &mqlSystemdTimer{}
		timer.fetched = true
		timer.props = map[string]string{"Persistent": v}
		got, err := timer.persistent()
		require.NoError(t, err)
		assert.True(t, got, "Persistent=%q should be true", v)
	}

	for _, v := range []string{"no", "false", "0", "off", ""} {
		timer := &mqlSystemdTimer{}
		timer.fetched = true
		timer.props = map[string]string{"Persistent": v}
		got, err := timer.persistent()
		require.NoError(t, err)
		assert.False(t, got, "Persistent=%q should be false", v)
	}
}

func TestSystemdSocketAcceptBooleanForms(t *testing.T) {
	for _, v := range []string{"yes", "true", "1", "on"} {
		socket := &mqlSystemdSocket{}
		socket.fetched = true
		socket.props = map[string]string{"Accept": v}
		got, err := socket.accept()
		require.NoError(t, err)
		assert.True(t, got, "Accept=%q should be true", v)
	}

	for _, v := range []string{"no", "false", "0", "off", ""} {
		socket := &mqlSystemdSocket{}
		socket.fetched = true
		socket.props = map[string]string{"Accept": v}
		got, err := socket.accept()
		require.NoError(t, err)
		assert.False(t, got, "Accept=%q should be false", v)
	}
}

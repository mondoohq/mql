// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package id

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/id/ids"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestGatherPlatformInfoSentinelOneAgent(t *testing.T) {
	// Synthetic values in the formats measured on real agents (2026-11-21):
	// Linux and macOS dashed, Windows 32 hex digits.
	const (
		linuxUUID = "4f6b2c1e-8a3d-4e5f-9b7a-1c2d3e4f5a6b"
		macUUID   = "7d2e9c4a-1b3f-5a6e-8c0d-2f4a6b8c0e1d"
		prefix    = "//platformid.api.mondoo.app/runtime/sentinelone/agents/"
		basicConf = "/opt/sentinelone/configuration/basic.conf"
		bundle    = "/Library/Sentinel/sentinel-agent.bundle"
		ioreg     = "ioreg -rd1 -c IOPlatformExpertDevice"
		winUUID   = "9c8b7a6f5e4d43c2b1a0f9e8d7c6b5a4"
		script    = `(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SentinelMonitor\Config' -Name 'AgentUID' -ErrorAction SilentlyContinue).AgentUID`
	)
	linux := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	mac := &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}
	windows := &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}}
	gather := func(t *testing.T, data *mock.TomlData, pf *inventory.Platform) []string {
		t.Helper()
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(data))
		require.NoError(t, err)
		info, err := gatherPlatformInfo(conn, pf, ids.IdDetector_SentinelOneAgent)
		require.NoError(t, err)
		return info.IDs
	}
	conf := func(content string) *mock.TomlData {
		return &mock.TomlData{Files: map[string]*mock.MockFileData{basicConf: {Path: basicConf, Content: content}}}
	}
	// The shape of the Linux agent's basic.conf, other values replaced.
	const liveConf = `{"mgmt_device-type": 1, "mgmt_site-key": "0000000000000000", "mgmt_url": "https://console.example.net", "mgmt_uuid": "` + linuxUUID + `"}`
	ioregOut := `+-o J457AP  <class IOPlatformExpertDevice>
    {
      "IOPlatformSerialNumber" = "C02XXXXXXXXX"
      "IOPlatformUUID" = "7D2E9C4A-1B3F-5A6E-8C0D-2F4A6B8C0E1D"
    }`
	macWith := func(agent bool) *mock.TomlData {
		d := &mock.TomlData{Commands: map[string]*mock.Command{ioreg: {Stdout: ioregOut}}}
		if agent {
			d.Files = map[string]*mock.MockFileData{bundle: {Path: bundle, StatData: mock.FileInfo{IsDir: true}}}
		}
		return d
	}

	// Synthetic: no agent installed.
	t.Run("linux without an agent yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, &mock.TomlData{}, linux))
	})
	// Measured: Linux agent 26.3, 2026-11-21 (basic.conf is JSON with mgmt_uuid; values synthetic).
	t.Run("linux reads mgmt_uuid from the agent's configuration", func(t *testing.T) {
		assert.Equal(t, []string{prefix + linuxUUID}, gather(t, conf(liveConf), linux))
	})
	// Synthetic: a corrupt configuration file.
	t.Run("a configuration that is not JSON yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, conf("mgmt_uuid="+linuxUUID), linux))
	})
	// Synthetic: an unexpected value.
	t.Run("a mgmt_uuid that is not a UUID yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, conf(`{"mgmt_uuid":"not-a-uuid"}`), linux))
	})
	// Synthetic: an unregistered agent could write a zero UUID.
	t.Run("an all-zero mgmt_uuid yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, conf(`{"mgmt_uuid":"00000000-0000-0000-0000-000000000000"}`), linux))
	})
	// Synthetic: containers carry no agent of their own.
	t.Run("a container yields no id", func(t *testing.T) {
		pf := &inventory.Platform{Name: "ubuntu", Kind: "container", Family: []string{"debian", "linux", "unix", "os"}}
		assert.Empty(t, gather(t, conf(liveConf), pf))
	})
	// Measured: macOS agent 26.2, 2026-11-21 (the agent UUID is the IOPlatformUUID; values synthetic).
	t.Run("macos with the agent reports the platform UUID in lower case", func(t *testing.T) {
		assert.Equal(t, []string{prefix + macUUID}, gather(t, macWith(true), mac))
	})
	// Synthetic: ioreg exits non-zero.
	t.Run("macos where ioreg fails yields no id", func(t *testing.T) {
		d := macWith(true)
		d.Commands[ioreg] = &mock.Command{Stdout: ioregOut, ExitStatus: 1}
		assert.Empty(t, gather(t, d, mac))
	})
	// Synthetic: no agent bundle, so ioreg is never run.
	t.Run("macos without the agent yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, macWith(false), mac))
	})
	registry := func(stdout string) *mock.TomlData {
		return &mock.TomlData{Commands: map[string]*mock.Command{powershell.Encode(script): {Stdout: stdout}}}
	}
	// Synthetic: no SentinelMonitor key.
	t.Run("windows without an agent yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, registry(""), windows))
	})
	// Measured: Windows agent 26.2, 2026-11-21 (AgentUID is 32 hex digits; value synthetic).
	t.Run("windows reads AgentUID, 32 hex digits without dashes", func(t *testing.T) {
		assert.Equal(t, []string{prefix + winUUID}, gather(t, registry(winUUID+"\r\n"), windows))
	})
	// Synthetic: a zero AgentUID.
	t.Run("windows with 32 zeros yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, registry("00000000000000000000000000000000"), windows))
	})
	// Synthetic: upper-case output is lower-cased.
	t.Run("windows in upper case matches the console's form", func(t *testing.T) {
		assert.Equal(t, []string{prefix + winUUID}, gather(t, registry("9C8B7A6F5E4D43C2B1A0F9E8D7C6B5A4"), windows))
	})
}

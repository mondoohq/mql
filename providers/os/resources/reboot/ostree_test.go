// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// `rpm-ostree status --json` on CentOS Stream 10 bootc after
// `rpm-ostree kargs --append=...`, trimmed to the fields read.
const rpmOstreeStatusStaged = `{
  "deployments": [
    {
      "id": "default-d07d73d1259fa8465ccfd8e874f7f330b3b20d8d6cb4bae2176d0438a1fa88c9.1",
      "osname": "default",
      "checksum": "d07d73d1259fa8465ccfd8e874f7f330b3b20d8d6cb4bae2176d0438a1fa88c9",
      "version": "10",
      "booted": false,
      "staged": true,
      "pinned": false
    },
    {
      "id": "default-d07d73d1259fa8465ccfd8e874f7f330b3b20d8d6cb4bae2176d0438a1fa88c9.0",
      "osname": "default",
      "checksum": "d07d73d1259fa8465ccfd8e874f7f330b3b20d8d6cb4bae2176d0438a1fa88c9",
      "version": "10",
      "booted": true,
      "staged": false,
      "pinned": false
    }
  ]
}`

// The same host with nothing staged: the booted deployment boots next.
const rpmOstreeStatusBooted = `{
  "deployments": [
    {
      "id": "default-d07d73d1259fa8465ccfd8e874f7f330b3b20d8d6cb4bae2176d0438a1fa88c9.0",
      "booted": true,
      "staged": false
    }
  ]
}`

// A deployment written to the bootloader entries without staging boots next
// and is neither booted nor staged.
const rpmOstreeStatusDeployed = `{
  "deployments": [
    {"id": "fedora-coreos-b2.0", "booted": false, "staged": false},
    {"id": "fedora-coreos-a1.0", "booted": true, "staged": false}
  ]
}`

func TestParseRpmOstreeStatus(t *testing.T) {
	pending, err := parseRpmOstreeStatus(strings.NewReader(rpmOstreeStatusStaged))
	require.NoError(t, err)
	assert.True(t, pending)

	pending, err = parseRpmOstreeStatus(strings.NewReader(rpmOstreeStatusDeployed))
	require.NoError(t, err)
	assert.True(t, pending)

	pending, err = parseRpmOstreeStatus(strings.NewReader(rpmOstreeStatusBooted))
	require.NoError(t, err)
	assert.False(t, pending)

	_, err = parseRpmOstreeStatus(strings.NewReader(`{"deployments": []}`))
	assert.Error(t, err)
	_, err = parseRpmOstreeStatus(strings.NewReader("error: Unknown option"))
	assert.Error(t, err)
}

// The CentOS Stream 10 bootc image: its rpm database is the booted
// deployment's and it ships no needs-restarting, so only the staged
// deployment shows the pending reboot.
func bootcRebootMock(t *testing.T, files map[string]*mock.MockFileData, commands map[string]*mock.Command) *RpmNewestKernel {
	if commands == nil {
		commands = map[string]*mock.Command{}
	}
	commands[rpmQueryKernelCmd] = &mock.Command{Stdout: "kernel 0:6.12.0-271.el10 x86_64__CentOS__The Linux kernel__GPL-2.0-only__1790668889\n"}
	commands["uname -r"] = &mock.Command{Stdout: "6.12.0-271.el10.x86_64\n"}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "centos",
			Version: "10",
			Family:  []string{"redhat", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{Commands: commands, Files: files}))
	require.NoError(t, err)
	return &RpmNewestKernel{conn: conn}
}

func TestRhelRebootOstreeStaged(t *testing.T) {
	booted := &mock.MockFileData{Path: ostreeBootedPath, Content: "{}"}

	lb := bootcRebootMock(t, map[string]*mock.MockFileData{
		ostreeBootedPath:           booted,
		ostreeStagedDeploymentPath: {Path: ostreeStagedDeploymentPath, Content: "{}"},
	}, nil)
	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.True(t, required)

	// nothing staged, rpm-ostree says the booted deployment boots next
	lb = bootcRebootMock(t, map[string]*mock.MockFileData{ostreeBootedPath: booted},
		map[string]*mock.Command{rpmOstreeStatusCmd: {Stdout: rpmOstreeStatusBooted}})
	required, err = lb.RebootPending()
	require.NoError(t, err)
	assert.False(t, required)

	// nothing staged, a deployment written straight to the boot entries
	lb = bootcRebootMock(t, map[string]*mock.MockFileData{ostreeBootedPath: booted},
		map[string]*mock.Command{rpmOstreeStatusCmd: {Stdout: rpmOstreeStatusDeployed}})
	required, err = lb.RebootPending()
	require.NoError(t, err)
	assert.True(t, required)
}

// A staged deployment file left in /run on a host that is not booted from
// ostree is not read.
func TestRhelRebootNotOstree(t *testing.T) {
	lb := bootcRebootMock(t, map[string]*mock.MockFileData{
		ostreeStagedDeploymentPath: {Path: ostreeStagedDeploymentPath, Content: "{}"},
	}, nil)
	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.False(t, required)
}

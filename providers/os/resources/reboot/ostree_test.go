// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

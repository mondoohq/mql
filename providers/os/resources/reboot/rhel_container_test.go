// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// captureLog swaps the global logger for one writing into a buffer, so a test
// can assert on what a scan actually prints.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	buf := &bytes.Buffer{}
	previous := log.Logger
	previousLevel := zerolog.GlobalLevel()
	log.Logger = zerolog.New(buf)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		log.Logger = previous
		zerolog.SetGlobalLevel(previousLevel)
	})
	return buf
}

const rpmQueryKernel = "rpm -q kernel --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}\n'"

// A container has no kernel package, so `rpm -q kernel` exits 1 and prints
// "package kernel is not installed" on stdout. That sentence used to reach the
// rpm package parser, which counted it as a package line it could not parse and
// warned that packages were missing from the inventory -- on every scan of
// every rpm-based container, with nothing actually missing.
func TestRhelRebootWithoutKernelPackage(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "almalinux",
			Version: "9.8",
			Family:  []string{"redhat", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			rpmQueryKernel: {
				Stdout:     "package kernel is not installed\n",
				ExitStatus: 1,
			},
			"uname -r": {Stdout: "6.12.0-55.el9.aarch64\n"},
		},
	}))
	require.NoError(t, err)

	logs := captureLog(t)

	pending, err := (&RpmNewestKernel{conn: conn}).RebootPending()
	require.NoError(t, err)
	assert.False(t, pending)

	assert.NotContains(t, logs.String(), "packages are missing from the inventory",
		"a container with no kernel package must not be reported as a short package inventory")
}

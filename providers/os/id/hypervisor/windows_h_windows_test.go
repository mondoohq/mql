// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package hypervisor_test

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
	subject "go.mondoo.com/mql/providers/os/id/hypervisor"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

// On a real host, the input built from the natively read SMBIOS data equals
// what the CIM query prints, field by field, and both map to the same
// hypervisor, with MONDOO_WINDOWS_NATIVE set and unset.
func TestWindowsHypervisorNativeEqualsCIM(t *testing.T) {
	conn := local.NewConnection(1, &inventory.Config{}, &inventory.Asset{})
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	cmd, err := conn.RunCommand(powershell.Encode(subject.WindowsDetectionCommand))
	require.NoError(t, err)
	out, err := io.ReadAll(cmd.Stdout)
	require.NoError(t, err)
	fromCIM := strings.TrimSpace(string(out))

	mgr, err := smbios.ResolveManager(conn, platform)
	require.NoError(t, err)
	info, err := mgr.Info()
	require.NoError(t, err)
	fromSMBIOS := subject.WindowsDetectionInfo(info)

	assert.Equal(t, strings.Split(fromCIM, "|"), strings.Split(fromSMBIOS, "|"))

	t.Setenv(shared.WindowsNativeEnv, "")
	viaCIM, okCIM := subject.Hypervisor(conn, platform)
	t.Setenv(shared.WindowsNativeEnv, "1")
	viaNative, okNative := subject.Hypervisor(conn, platform)
	assert.Equal(t, okCIM, okNative)
	assert.Equal(t, viaCIM, viaNative)
}

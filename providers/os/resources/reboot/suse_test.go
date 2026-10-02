// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func suseConn(t *testing.T, cmd *mock.Command) *mock.Connection {
	t.Helper()

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "opensuse-leap",
			Version: "15.6",
			Family:  []string{"suse", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"zypper --non-interactive needs-rebooting": cmd,
		},
	}))
	require.NoError(t, err)
	return conn
}

func TestSuseResolvesToZypper(t *testing.T) {
	r, err := New(suseConn(t, &mock.Command{}))
	require.NoError(t, err)

	_, ok := r.(*ZypperNeedsRebooting)
	assert.True(t, ok, "SUSE resolves to the zypper reboot check")
}

func TestZypperNoRebootNeeded(t *testing.T) {
	conn := suseConn(t, &mock.Command{
		Stdout: "No core libraries or services have been updated since the last system boot.\n" +
			"Reboot is probably not necessary.\n",
	})

	pending, err := (&ZypperNeedsRebooting{conn: conn}).RebootPending()
	require.NoError(t, err)
	assert.False(t, pending)
}

func TestZypperRebootNeeded(t *testing.T) {
	conn := suseConn(t, &mock.Command{
		Stdout: "Since the last system boot core libraries or services have been updated.\n" +
			"Reboot is suggested to ensure that your system benefits from these updates.\n",
		// zypper(8): 102 ZYPPER_EXIT_INF_REBOOT_NEEDED, as zypper 1.14 exits
		// on SLES 15/16 and Leap 15/16 with /run/reboot-needed present
		ExitStatus: 102,
	})

	pending, err := (&ZypperNeedsRebooting{conn: conn}).RebootPending()
	require.NoError(t, err)
	assert.True(t, pending)
}

// 103 is ZYPPER_EXIT_INF_RESTART_NEEDED: zypper updated itself and wants to be
// rerun. That is not a pending reboot of the machine.
func TestZypperRestartNeededIsNotReboot(t *testing.T) {
	conn := suseConn(t, &mock.Command{ExitStatus: 103})

	pending, err := (&ZypperNeedsRebooting{conn: conn}).RebootPending()
	require.Error(t, err)
	assert.False(t, pending)
	assert.Contains(t, err.Error(), "exited 103")
}

// An exit code that is neither of the two documented ones is reported rather
// than read as "no reboot pending" -- a zypper too old for the subcommand exits
// 1, and answering "you are fine" there would be an answer nothing measured.
func TestZypperUnknownExitIsReported(t *testing.T) {
	conn := suseConn(t, &mock.Command{
		Stderr:     "Unknown command 'needs-rebooting'\n",
		ExitStatus: 1,
	})

	_, err := (&ZypperNeedsRebooting{conn: conn}).RebootPending()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exited 1")
	assert.Contains(t, err.Error(), "Unknown command")
}

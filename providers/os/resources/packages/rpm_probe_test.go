// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// sudoHostConn answers commands the way a host does when every command line
// is run as `sudo <line>`: sudo executes the first word as a program, so a
// shell builtin such as `command` is not found.
type sudoHostConn struct {
	shared.Connection
	answers map[string]string
}

func (c *sudoHostConn) RunCommand(command string) (*shared.Command, error) {
	res := &shared.Command{Command: command, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	argv0 := strings.Fields(command)[0]
	if argv0 == "command" {
		res.Stderr = bytes.NewBufferString("sudo: command: command not found\n")
		res.ExitStatus = 1
		return res, nil
	}
	if out, ok := c.answers[command]; ok {
		res.Stdout = bytes.NewBufferString(out)
		return res, nil
	}
	res.Stderr = bytes.NewBufferString("sudo: " + argv0 + ": command not found\n")
	res.ExitStatus = 1
	return res, nil
}

// Over SSH with --sudo the probe ran `sudo command -v rpm`, failed, and the
// manager read the rpm database statically on every rpm host, where it has
// no update check.
func TestRpmProbeUnderSudo(t *testing.T) {
	base, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)

	t.Run("rpm runs", func(t *testing.T) {
		conn := &sudoHostConn{Connection: base, answers: map[string]string{
			// rpm 4.17 on SLES 15 SP7
			"rpm --version": "RPM version 4.17.1.1\n",
		}}
		rpm := &RpmPkgManager{conn: conn}
		assert.False(t, rpm.isStaticAnalysis())
	})

	t.Run("rpm is not installed", func(t *testing.T) {
		rpm := &RpmPkgManager{conn: &sudoHostConn{Connection: base}}
		assert.True(t, rpm.isStaticAnalysis())
	})
}

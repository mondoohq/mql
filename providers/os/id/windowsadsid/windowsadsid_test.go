// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windowsadsid

import (
	"bytes"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestParseSIDOutput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"valid SID", "S-1-5-21-1004336348-1177238915-682003330-1014", "S-1-5-21-1004336348-1177238915-682003330-1014"},
		{"trailing newline", "S-1-5-21-1004336348-1177238915-682003330-1014\r\n", "S-1-5-21-1004336348-1177238915-682003330-1014"},
		{"leading and trailing whitespace", "  S-1-5-21-1-2-3-1001  ", "S-1-5-21-1-2-3-1001"},
		{"empty", "", ""},
		{"whitespace only", "  \r\n  ", ""},
		{"PowerShell exception text", "Exception calling \"Translate\" with \"1\" argument(s): \"Some or all identity references could not be translated.\"", ""},
		{"missing S prefix", "1-5-21-1-2-3-1001", ""},
		{"too few subauthorities", "S-1", ""},
		{"non-numeric component", "S-1-5-21-foo-bar-baz-1001", ""},
		{"trailing dash", "S-1-5-21-1-2-3-", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSIDOutput(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWindowsADSID_NonWindowsPlatform(t *testing.T) {
	conn := newStubConn(t, "", 0)
	pf := &inventory.Platform{Name: "ubuntu", Family: []string{"linux", "unix"}}

	sid, err := WindowsADSID(conn, pf)
	require.NoError(t, err)
	assert.Empty(t, sid)
	assert.Zero(t, conn.callCount, "non-windows platforms must not run a command")
}

func TestWindowsADSID_NilPlatform(t *testing.T) {
	conn := newStubConn(t, "", 0)
	sid, err := WindowsADSID(conn, nil)
	require.NoError(t, err)
	assert.Empty(t, sid)
}

func TestWindowsADSID_DomainJoinedHostReturnsSID(t *testing.T) {
	conn := newStubConn(t, "S-1-5-21-1004336348-1177238915-682003330-1014\r\n", 0)
	pf := &inventory.Platform{Name: "windows", Family: []string{"windows"}}

	sid, err := WindowsADSID(conn, pf)
	require.NoError(t, err)
	assert.Equal(t, "S-1-5-21-1004336348-1177238915-682003330-1014", sid)
	assert.Equal(t, 1, conn.callCount)
}

func TestWindowsADSID_WorkgroupHostReturnsEmpty(t *testing.T) {
	// The PartOfDomain check in the PowerShell script exits early with no output
	// on workgroup/standalone hosts.
	conn := newStubConn(t, "", 0)
	pf := &inventory.Platform{Name: "windows", Family: []string{"windows"}}

	sid, err := WindowsADSID(conn, pf)
	require.NoError(t, err)
	assert.Empty(t, sid)
}

func TestWindowsADSID_NonZeroExitReturnsEmpty(t *testing.T) {
	conn := newStubConn(t, "powershell error", 1)
	pf := &inventory.Platform{Name: "windows", Family: []string{"windows"}}

	sid, err := WindowsADSID(conn, pf)
	require.NoError(t, err)
	assert.Empty(t, sid)
}

func TestWindowsADSID_GarbledOutputReturnsEmpty(t *testing.T) {
	// guards against PowerShell exception text reaching stdout via misconfigured
	// ErrorActionPreference or pipeline output.
	conn := newStubConn(t, "Exception calling \"Translate\"...", 0)
	pf := &inventory.Platform{Name: "windows", Family: []string{"windows"}}

	sid, err := WindowsADSID(conn, pf)
	require.NoError(t, err)
	assert.Empty(t, sid)
}

// stubConn is a minimal shared.Connection that returns a canned stdout/exit
// status for any command, recording how many times RunCommand was invoked.
type stubConn struct {
	t         *testing.T
	stdout    string
	exitCode  int
	callCount int
}

func newStubConn(t *testing.T, stdout string, exitCode int) *stubConn {
	return &stubConn{t: t, stdout: stdout, exitCode: exitCode}
}

func (c *stubConn) RunCommand(command string) (*shared.Command, error) {
	c.callCount++
	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(c.stdout),
		Stderr:     bytes.NewBuffer(nil),
		ExitStatus: c.exitCode,
	}, nil
}

func (c *stubConn) ID() uint32                         { return 1 }
func (c *stubConn) ParentID() uint32                   { return 0 }
func (c *stubConn) Name() string                       { return "stub" }
func (c *stubConn) Type() shared.ConnectionType        { return shared.Type_Local }
func (c *stubConn) Asset() *inventory.Asset            { return &inventory.Asset{} }
func (c *stubConn) UpdateAsset(asset *inventory.Asset) {}
func (c *stubConn) Capabilities() shared.Capabilities  { return shared.Capability_RunCommand }
func (c *stubConn) FileSystem() afero.Fs               { return afero.NewMemMapFs() }
func (c *stubConn) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, nil
}

// Asserts that stubConn implements the shared.Connection interface.
var _ shared.Connection = (*stubConn)(nil)

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseWindowsSmbShares(t *testing.T) {
	// Array result.
	shares, err := ParseWindowsSmbShares(strings.NewReader(`[
		{"Name":"C$","Path":"C:\\","Description":"Default share","ScopeName":"*","ShareType":"FileSystemDirectory"},
		{"Name":"SAP_Export","Path":"D:\\exports\\sap","Description":"","ScopeName":"*","ShareType":"FileSystemDirectory"}
	]`))
	require.NoError(t, err)
	require.Len(t, shares, 2)
	require.Equal(t, WindowsSmbShare{Name: "C$", Path: "C:\\", Description: "Default share", ScopeName: "*", ShareType: "FileSystemDirectory"}, shares[0])
	require.Equal(t, "SAP_Export", shares[1].Name)

	// PowerShell emits a bare object for a single result.
	single, err := ParseWindowsSmbShares(strings.NewReader(`{"Name":"C$","Path":"C:\\","Description":"d","ScopeName":"*","ShareType":"FileSystemDirectory"}`))
	require.NoError(t, err)
	require.Len(t, single, 1)
	require.Equal(t, "C$", single[0].Name)

	// Empty output.
	empty, err := ParseWindowsSmbShares(strings.NewReader(""))
	require.NoError(t, err)
	require.Empty(t, empty)
}

func TestParseWindowsSmbSessions(t *testing.T) {
	// Two concurrent sessions from the same client+user — distinguished only
	// by SessionId, which the resource uses to key them apart.
	sessions, err := ParseWindowsSmbSessions(strings.NewReader(`[
		{"SessionId":4123456789012345,"ClientComputerName":"192.168.1.50","ClientUserName":"CORP\\alice","Dialect":"3.1.1","NumOpens":3},
		{"SessionId":4123456789012346,"ClientComputerName":"192.168.1.50","ClientUserName":"CORP\\alice","Dialect":"3.1.1","NumOpens":1}
	]`))
	require.NoError(t, err)
	require.Len(t, sessions, 2)
	require.Equal(t, WindowsSmbSession{SessionId: 4123456789012345, ClientComputerName: "192.168.1.50", ClientUserName: "CORP\\alice", Dialect: "3.1.1", NumOpens: 3}, sessions[0])
	require.NotEqual(t, sessions[0].SessionId, sessions[1].SessionId)
}

func TestParseWindowsSmbConnections(t *testing.T) {
	connections, err := ParseWindowsSmbConnections(strings.NewReader(`[
		{"ServerName":"fs01","ShareName":"SAP_Export","UserName":"CORP\\bob","Dialect":"3.1.1"}
	]`))
	require.NoError(t, err)
	require.Len(t, connections, 1)
	require.Equal(t, WindowsSmbConnection{ServerName: "fs01", ShareName: "SAP_Export", UserName: "CORP\\bob", Dialect: "3.1.1"}, connections[0])
}

// The SMB cmdlets report a failure as a non-terminating error: stderr gets the
// message, stdout gets nothing, and the exit status stays 0. The provider only
// treats a non-zero exit as a failure, so without this guard a cmdlet that read
// nothing is indistinguishable from a host that genuinely has no shares, and
// the resource reports an empty list either way. An empty list satisfies every
// assertion made about a collection, so the wrong answer passes silently.
func TestSmbCommandsFailLoudly(t *testing.T) {
	for name, cmd := range map[string]string{
		"shares":      SMB_SHARES,
		"sessions":    SMB_SESSIONS,
		"connections": SMB_CONNECTIONS,
	} {
		require.True(t, strings.HasPrefix(cmd, "$ErrorActionPreference='Stop'\n"),
			"%s must turn a cmdlet failure into a non-zero exit, or it degrades to an empty list", name)
		require.LessOrEqual(t, len(cmd), PSMaxScriptLength, "%s", name)
	}
}

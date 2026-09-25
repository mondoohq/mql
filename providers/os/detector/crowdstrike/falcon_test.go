// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package crowdstrike

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	testAID = "4d7f5b8b9e0b4c2a8d1e2f3a4b5c6d7e"
	testCID = "0123456789abcdef0123456789abcdef"
)

var (
	linuxPlatform   = &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	macosPlatform   = &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}
	windowsPlatform = &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}}
	linuxCommand    = linuxFalconctl + " -g --aid --cid"
	macosCommand    = macosFalconctl + " stats agent_info"
)

// countingConn wraps the mock connection to count commands and optionally
// drop the RunCommand capability.
type countingConn struct {
	*mock.Connection
	calls       int
	noRunCmdCap bool
}

func (c *countingConn) RunCommand(command string) (*shared.Command, error) {
	c.calls++
	return c.Connection.RunCommand(command)
}

func (c *countingConn) Capabilities() shared.Capabilities {
	if c.noRunCmdCap {
		return shared.Capability_File
	}
	return c.Connection.Capabilities()
}

func newConn(t *testing.T, files []string, commands map[string]*mock.Command) *countingConn {
	t.Helper()
	data := &mock.TomlData{
		Files:    map[string]*mock.MockFileData{},
		Commands: commands,
	}
	for _, f := range files {
		data.Files[f] = &mock.MockFileData{Path: f, StatData: mock.FileInfo{Mode: 0o750}}
	}
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(data))
	require.NoError(t, err)
	return &countingConn{Connection: conn}
}

func TestNormalizeID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain lowercase hex", testCID, testCID},
		{"uppercase hex", "0123456789ABCDEF0123456789ABCDEF", testCID},
		{"CID with checksum suffix", "0123456789ABCDEF0123456789ABCDEF-E2", testCID},
		{"UUID form (macOS AID)", "FEDCBA98-7654-3210-FEDC-BA9876543210", "fedcba9876543210fedcba9876543210"},
		{"surrounding whitespace and quotes", "  \"" + testAID + "\"\n", testAID},
		{"empty", "", ""},
		{"not set message", "is not set", ""},
		{"too short", "0123456789abcdef", ""},
		{"non hex", "zz0123456789abcdef0123456789abcd", ""},
		{"all zero", "00000000000000000000000000000000", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeID(tt.in))
		})
	}
}

func TestBinaryToID(t *testing.T) {
	// REG_BINARY bytes of AG as the registry returns them
	raw := []byte{0x4d, 0x7f, 0x5b, 0x8b, 0x9e, 0x0b, 0x4c, 0x2a, 0x8d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e}
	assert.Equal(t, testAID, binaryToID(raw))
	assert.Equal(t, "", binaryToID(nil))
	assert.Equal(t, "", binaryToID([]byte{0x01, 0x02}))
	assert.Equal(t, "", binaryToID(make([]byte, 16)))
}

func TestParseLinuxFalconctl(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want Identity
	}{
		{"aid and cid", `cid="` + testCID + `", aid="` + testAID + `".` + "\n", Identity{AID: testAID, CID: testCID}},
		{"aid only", `aid="` + testAID + `".`, Identity{AID: testAID}},
		{"aid not set", `cid="` + testCID + `", aid is not set.`, Identity{CID: testCID}},
		{"nothing set", "cid is not set, aid is not set.", Identity{}},
		{"uppercase cid with checksum", `cid="0123456789ABCDEF0123456789ABCDEF-E2", aid="` + testAID + `".`, Identity{AID: testAID, CID: testCID}},
		{"garbage value", `aid="not-an-aid".`, Identity{}},
		{"empty", "", Identity{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, *parseLinuxFalconctl(tt.out))
		})
	}
}

func TestParseMacosAgentInfo(t *testing.T) {
	out := `agent_info:
  version: 7.10.18302.0
  agentID: FEDCBA98-7654-3210-FEDC-BA9876543210
  customerID: 01234567-89AB-CDEF-0123-456789ABCDEF
  sensor_operational: true
`
	assert.Equal(t, Identity{AID: "fedcba9876543210fedcba9876543210", CID: testCID}, *parseMacosAgentInfo(out))

	noCID := "agent_info:\n  agentID: FEDCBA98-7654-3210-FEDC-BA9876543210\n"
	assert.Equal(t, Identity{AID: "fedcba9876543210fedcba9876543210"}, *parseMacosAgentInfo(noCID))

	assert.Equal(t, Identity{}, *parseMacosAgentInfo("Error: operation requires root\n"))
}

func TestParseWindowsScriptOutput(t *testing.T) {
	assert.Equal(t, Identity{AID: testAID, CID: testCID}, *parseWindowsScriptOutput("aid=" + testAID + "\r\ncid=" + testCID + "\r\n"))
	assert.Equal(t, Identity{AID: testAID}, *parseWindowsScriptOutput("aid=" + testAID + "\r\n"))
	assert.Equal(t, Identity{}, *parseWindowsScriptOutput(""))
}

func TestDetectLinux(t *testing.T) {
	t.Run("sensor installed", func(t *testing.T) {
		conn := newConn(t, []string{linuxFalconctl}, map[string]*mock.Command{
			linuxCommand: {Stdout: `cid="` + testCID + `", aid="` + testAID + `".` + "\n"},
		})
		assert.Equal(t, &Identity{AID: testAID, CID: testCID}, Detect(conn, linuxPlatform))
	})

	t.Run("sensor absent runs no command", func(t *testing.T) {
		conn := newConn(t, nil, map[string]*mock.Command{
			linuxCommand: {Stdout: `aid="` + testAID + `".`},
		})
		assert.Nil(t, Detect(conn, linuxPlatform))
		assert.Zero(t, conn.calls)
	})

	t.Run("not root", func(t *testing.T) {
		conn := newConn(t, []string{linuxFalconctl}, map[string]*mock.Command{
			linuxCommand: {Stderr: "This program must be run as root.\n", ExitStatus: 1},
		})
		assert.Nil(t, Detect(conn, linuxPlatform))
		assert.Equal(t, 1, conn.calls)
	})

	t.Run("aid not set", func(t *testing.T) {
		conn := newConn(t, []string{linuxFalconctl}, map[string]*mock.Command{
			linuxCommand: {Stdout: `cid="` + testCID + `", aid is not set.`},
		})
		assert.Nil(t, Detect(conn, linuxPlatform))
	})

	t.Run("connection without command execution", func(t *testing.T) {
		conn := newConn(t, []string{linuxFalconctl}, map[string]*mock.Command{
			linuxCommand: {Stdout: `aid="` + testAID + `".`},
		})
		conn.noRunCmdCap = true
		assert.Nil(t, Detect(conn, linuxPlatform))
		assert.Zero(t, conn.calls)
	})

	t.Run("container", func(t *testing.T) {
		conn := newConn(t, []string{linuxFalconctl}, map[string]*mock.Command{
			linuxCommand: {Stdout: `aid="` + testAID + `".`},
		})
		pf := &inventory.Platform{Name: "ubuntu", Kind: "container", Family: linuxPlatform.Family}
		assert.Nil(t, Detect(conn, pf))
		assert.Zero(t, conn.calls)
	})
}

func TestDetectMacos(t *testing.T) {
	t.Run("sensor installed", func(t *testing.T) {
		conn := newConn(t, []string{macosFalconctl}, map[string]*mock.Command{
			macosCommand: {Stdout: "agent_info:\n  agentID: FEDCBA98-7654-3210-FEDC-BA9876543210\n"},
		})
		assert.Equal(t, &Identity{AID: "fedcba9876543210fedcba9876543210"}, Detect(conn, macosPlatform))
	})

	t.Run("sensor absent runs no command", func(t *testing.T) {
		conn := newConn(t, nil, nil)
		assert.Nil(t, Detect(conn, macosPlatform))
		assert.Zero(t, conn.calls)
	})

	t.Run("not root", func(t *testing.T) {
		conn := newConn(t, []string{macosFalconctl}, map[string]*mock.Command{
			macosCommand: {Stderr: "Error: must be run as root\n", ExitStatus: 1},
		})
		assert.Nil(t, Detect(conn, macosPlatform))
	})
}

func TestDetectWindows(t *testing.T) {
	windowsCommand := powershell.Encode(windowsIdentityScript)

	t.Run("sensor installed", func(t *testing.T) {
		conn := newConn(t, nil, map[string]*mock.Command{
			windowsCommand: {Stdout: "aid=" + testAID + "\r\ncid=" + testCID + "\r\n"},
		})
		assert.Equal(t, &Identity{AID: testAID, CID: testCID}, Detect(conn, windowsPlatform))
	})

	t.Run("sensor absent or not admin", func(t *testing.T) {
		// the script prints nothing when the key is absent or unreadable
		conn := newConn(t, nil, map[string]*mock.Command{
			windowsCommand: {Stdout: ""},
		})
		assert.Nil(t, Detect(conn, windowsPlatform))
	})

	t.Run("script reads both sensor key locations", func(t *testing.T) {
		assert.Contains(t, windowsIdentityScript, `'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default'`)
		assert.Contains(t, windowsIdentityScript, `'HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim'`)
	})
}

func TestApplyLabels(t *testing.T) {
	t.Run("sets aid and cid labels", func(t *testing.T) {
		conn := newConn(t, []string{linuxFalconctl}, map[string]*mock.Command{
			linuxCommand: {Stdout: `cid="` + testCID + `", aid="` + testAID + `".`},
		})
		pf := &inventory.Platform{Name: "ubuntu", Family: linuxPlatform.Family}
		ApplyLabels(conn, pf)
		assert.Equal(t, testAID, pf.Labels["crowdstrike.com/aid"])
		assert.Equal(t, testCID, pf.Labels["crowdstrike.com/cid"])
		assert.Equal(t, "//platformid.api.mondoo.app/runtime/crowdstrike/cids/"+testCID+"/aids/"+testAID, FromLabels(pf).PlatformID())
	})

	t.Run("no cid label when cid is unknown", func(t *testing.T) {
		conn := newConn(t, []string{macosFalconctl}, map[string]*mock.Command{
			macosCommand: {Stdout: "agentID: FEDCBA98-7654-3210-FEDC-BA9876543210\n"},
		})
		pf := &inventory.Platform{Name: "macos", Family: macosPlatform.Family}
		ApplyLabels(conn, pf)
		assert.Equal(t, "fedcba9876543210fedcba9876543210", pf.Labels["crowdstrike.com/aid"])
		_, ok := pf.Labels["crowdstrike.com/cid"]
		assert.False(t, ok)
		assert.Equal(t, "", FromLabels(pf).PlatformID(), "no platform id without a cid")
	})

	t.Run("no labels without sensor", func(t *testing.T) {
		conn := newConn(t, nil, nil)
		pf := &inventory.Platform{Name: "ubuntu", Family: linuxPlatform.Family}
		ApplyLabels(conn, pf)
		assert.Nil(t, pf.Labels)
		assert.Nil(t, FromLabels(pf))
	})
}

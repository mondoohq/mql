// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package defender

import (
	"errors"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Synthetic IDs in the shapes the sensor writes: a 40 hex character machine
// ID and a GUID organization ID.
const (
	testMachineID = "0123456789abcdef0123456789abcdef01234567"
	testOrgID     = "01234567-89ab-cdef-0123-456789abcdef"
)

func str(key, value string) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: key, Value: registry.RegistryKeyValue{Kind: registry.SZ, String: value}}
}

func dword(key string, value int64) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: key, Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: value}}
}

// fakeKeys serves key values from a map; a missing key reads as not found,
// the way the registry reports a host without the sensor.
type fakeKeys map[string][]registry.RegistryKeyItem

func (f fakeKeys) Items(path string) ([]registry.RegistryKeyItem, error) {
	items, ok := f[path]
	if !ok {
		return nil, errors.New("registry key not found")
	}
	return items, nil
}

func TestNormalizeMachineID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase hex", testMachineID, testMachineID},
		{"uppercase hex", "0123456789ABCDEF0123456789ABCDEF01234567", testMachineID},
		{"whitespace and quotes", "  \"" + testMachineID + "\"\r\n", testMachineID},
		{"empty", "", ""},
		{"too short", "0123456789abcdef", ""},
		{"GUID is not a machine ID", testOrgID, ""},
		{"non hex", "zz23456789abcdef0123456789abcdef01234567", ""},
		{"all zero", "0000000000000000000000000000000000000000", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeMachineID(tt.in))
		})
	}
}

func TestNormalizeOrgID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase GUID", testOrgID, testOrgID},
		{"uppercase GUID", "01234567-89AB-CDEF-0123-456789ABCDEF", testOrgID},
		{"braced GUID", "{01234567-89ab-cdef-0123-456789abcdef}", testOrgID},
		{"empty", "", ""},
		{"unavailable", "unavailable", ""},
		{"no dashes", "0123456789abcdef0123456789abcdef", ""},
		{"all zero", "00000000-0000-0000-0000-000000000000", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeOrgID(tt.in))
		})
	}
}

func TestFromKeys(t *testing.T) {
	t.Run("onboarded sensor", func(t *testing.T) {
		keys := fakeKeys{
			sensorKey: {str("senseGuid", "fedcba98-7654-3210-fedc-ba9876543210"), str("senseId", "0123456789ABCDEF0123456789ABCDEF01234567")},
			statusKey: {dword("OnboardingState", 1), str("OrgId", testOrgID)},
		}
		assert.Equal(t, &Identity{MachineID: testMachineID, OrgID: testOrgID}, fromKeys(keys))
	})

	t.Run("value names are case-insensitive", func(t *testing.T) {
		keys := fakeKeys{
			sensorKey: {str("SenseId", testMachineID)},
			statusKey: {dword("onboardingstate", 1), str("orgid", testOrgID)},
		}
		assert.Equal(t, &Identity{MachineID: testMachineID, OrgID: testOrgID}, fromKeys(keys))
	})

	t.Run("machine ID under the status key", func(t *testing.T) {
		keys := fakeKeys{
			statusKey: {dword("OnboardingState", 1), str("SenseId", testMachineID), str("OrgId", testOrgID)},
		}
		assert.Equal(t, &Identity{MachineID: testMachineID, OrgID: testOrgID}, fromKeys(keys))
	})

	t.Run("without an organization", func(t *testing.T) {
		keys := fakeKeys{
			sensorKey: {str("senseId", testMachineID)},
			statusKey: {dword("OnboardingState", 1)},
		}
		assert.Equal(t, &Identity{MachineID: testMachineID}, fromKeys(keys))
	})

	t.Run("offboarded sensor keeps its machine ID but has no identity", func(t *testing.T) {
		keys := fakeKeys{
			sensorKey: {str("senseId", testMachineID)},
			statusKey: {dword("OnboardingState", 0), str("OrgId", testOrgID)},
		}
		assert.Nil(t, fromKeys(keys))
	})

	t.Run("onboarding state not reported", func(t *testing.T) {
		keys := fakeKeys{
			sensorKey: {str("senseId", testMachineID)},
			statusKey: {str("OrgId", testOrgID)},
		}
		assert.Nil(t, fromKeys(keys))
	})

	t.Run("organization without machine ID", func(t *testing.T) {
		keys := fakeKeys{
			statusKey: {dword("OnboardingState", 1), str("OrgId", testOrgID)},
		}
		assert.Nil(t, fromKeys(keys))
	})

	t.Run("never onboarded", func(t *testing.T) {
		assert.Nil(t, fromKeys(fakeKeys{}))
	})
}

type fakeHive struct {
	fakeKeys
	ids []string
}

func (h *fakeHive) GetNativeRegistryKeyItems(id, path string) ([]registry.RegistryKeyItem, error) {
	h.ids = append(h.ids, id)
	return h.Items(path)
}

func TestHiveKeysReadTheSoftwareHive(t *testing.T) {
	hive := &fakeHive{fakeKeys: fakeKeys{
		sensorKey: {str("senseId", testMachineID)},
		statusKey: {dword("OnboardingState", 1), str("OrgId", testOrgID)},
	}}
	assert.Equal(t, &Identity{MachineID: testMachineID, OrgID: testOrgID}, fromKeys(hiveKeys{rh: hive}))
	for _, id := range hive.ids {
		assert.Equal(t, registry.Software, id)
	}
}

func TestParsePowershellOutput(t *testing.T) {
	assert.Equal(t, &Identity{MachineID: testMachineID, OrgID: testOrgID},
		parsePowershellOutput("onboardingstate=1\r\nsenseid="+testMachineID+"\r\norgid="+testOrgID+"\r\n"))
	assert.Equal(t, &Identity{MachineID: testMachineID},
		parsePowershellOutput("onboardingstate=1\r\nsenseid="+testMachineID+"\r\n"))
	assert.Nil(t, parsePowershellOutput("onboardingstate=0\r\nsenseid="+testMachineID+"\r\norgid="+testOrgID+"\r\n"))
	assert.Nil(t, parsePowershellOutput("onboardingstate=1\r\norgid="+testOrgID+"\r\n"))
	assert.Nil(t, parsePowershellOutput(""))
}

func TestPowershellScriptReadsDocumentedKeys(t *testing.T) {
	assert.Contains(t, powershellScript, `'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'`)
	assert.Contains(t, powershellScript, `'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection'`)
	assert.Contains(t, powershellScript, `$s.OnboardingState`)
	assert.Contains(t, powershellScript, `$k.senseId`)
	assert.Contains(t, powershellScript, `$s.OrgId`)
}

type fsConn struct {
	*mock.Connection
}

func (fsConn) Type() shared.ConnectionType { return shared.Type_FileSystem }

func TestDetect(t *testing.T) {
	command := powershell.Encode(powershellScript)
	newConn := func(t *testing.T, commands map[string]*mock.Command) *mock.Connection {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{Commands: commands}))
		require.NoError(t, err)
		return conn
	}

	t.Run("remote onboarded sensor", func(t *testing.T) {
		conn := newConn(t, map[string]*mock.Command{
			command: {Stdout: "onboardingstate=1\r\nsenseid=" + testMachineID + "\r\norgid=" + testOrgID + "\r\n"},
		})
		assert.Equal(t, &Identity{MachineID: testMachineID, OrgID: testOrgID}, Detect(conn))
	})

	t.Run("remote host without the sensor", func(t *testing.T) {
		conn := newConn(t, map[string]*mock.Command{command: {Stdout: ""}})
		assert.Nil(t, Detect(conn))
	})

	t.Run("script failure", func(t *testing.T) {
		conn := newConn(t, map[string]*mock.Command{command: {Stderr: "access denied", ExitStatus: 1}})
		assert.Nil(t, Detect(conn))
	})

	t.Run("offline image without a SOFTWARE hive", func(t *testing.T) {
		assert.Nil(t, Detect(fsConn{newConn(t, nil)}))
	})

	t.Run("offline hive cannot be loaded off Windows", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("loads a real hive on Windows")
		}
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{Files: map[string]*mock.MockFileData{
			registry.SoftwareRegPath: {Path: registry.SoftwareRegPath},
		}}))
		require.NoError(t, err)
		assert.Nil(t, Detect(fsConn{conn}))
	})

	t.Run("nil connection", func(t *testing.T) {
		assert.Nil(t, Detect(nil))
	})
}

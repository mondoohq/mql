// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// When a registrykey.property is created without its fields pre-populated by
// initRegistrykeyProperty — e.g. replaying a recording that did not capture
// them — the compute fallbacks must fail cleanly (false / empty / null) rather
// than erroring, so that policies querying a missing property fail gracefully
// instead of erroring the whole check.
func TestRegistrykeyProperty_FallbacksFailGracefully(t *testing.T) {
	p := &mqlRegistrykeyProperty{}

	exists, err := p.exists()
	require.NoError(t, err)
	require.False(t, exists)

	data, err := p.data()
	require.NoError(t, err)
	require.Nil(t, data)

	val, err := p.value()
	require.NoError(t, err)
	require.Equal(t, "", val)

	typ, err := p.compute_type()
	require.NoError(t, err)
	require.Equal(t, "", typ)
}

func TestUserHivePath(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	tests := []struct {
		name    string
		subPath string
		want    string
	}{
		{"root", "", `HKEY_USERS\` + sid},
		{"sub-path", `Software\Policies\Microsoft`, `HKEY_USERS\` + sid + `\Software\Policies\Microsoft`},
		{"trims surrounding backslashes", `\Software\`, `HKEY_USERS\` + sid + `\Software`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, userHivePath(sid, tc.subPath))
		})
	}
}

// The id of a per-user key/property folds in the SID so that two users reading
// the same hive-relative path cache (and report) separately.
func TestRegistrykeyID_PerUser(t *testing.T) {
	t.Run("plain key keeps the absolute path as id", func(t *testing.T) {
		k := &mqlRegistrykey{Path: plugin.TValue[string]{Data: `HKLM\Software\Foo`}}
		id, err := k.id()
		require.NoError(t, err)
		require.Equal(t, `HKLM\Software\Foo`, id)
	})

	t.Run("per-user key folds the SID into the id", func(t *testing.T) {
		a := &mqlRegistrykey{
			Path:    plugin.TValue[string]{Data: `Software\Policies`},
			UserSid: plugin.TValue[string]{Data: "S-1-5-21-1-2-3-1001"},
		}
		b := &mqlRegistrykey{
			Path:    plugin.TValue[string]{Data: `Software\Policies`},
			UserSid: plugin.TValue[string]{Data: "S-1-5-21-1-2-3-1002"},
		}
		idA, err := a.id()
		require.NoError(t, err)
		idB, err := b.id()
		require.NoError(t, err)
		require.Equal(t, `HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Policies`, idA)
		require.NotEqual(t, idA, idB, "different users with the same hive path must have distinct ids")
	})
}

func TestRegistrykeyPropertyID_PerUser(t *testing.T) {
	t.Run("plain property", func(t *testing.T) {
		p := &mqlRegistrykeyProperty{
			Path: plugin.TValue[string]{Data: `HKLM\Software\Foo`},
			Name: plugin.TValue[string]{Data: "Bar"},
		}
		id, err := p.id()
		require.NoError(t, err)
		require.Equal(t, `HKLM\Software\Foo - Bar`, id)
	})

	t.Run("per-user property folds the SID into the id", func(t *testing.T) {
		a := &mqlRegistrykeyProperty{
			Path:    plugin.TValue[string]{Data: `Software\Policies`},
			Name:    plugin.TValue[string]{Data: "Bar"},
			UserSid: plugin.TValue[string]{Data: "S-1-5-21-1-2-3-1001"},
		}
		b := &mqlRegistrykeyProperty{
			Path:    plugin.TValue[string]{Data: `Software\Policies`},
			Name:    plugin.TValue[string]{Data: "Bar"},
			UserSid: plugin.TValue[string]{Data: "S-1-5-21-1-2-3-1002"},
		}
		idA, err := a.id()
		require.NoError(t, err)
		idB, err := b.id()
		require.NoError(t, err)
		require.Equal(t, `HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Policies - Bar`, idA)
		require.NotEqual(t, idA, idB, "different users with the same property must have distinct ids")
	})
}

// The typed Windows resources read Value.Number directly, so a value that
// could not be read has to fail their read instead of arriving as 0: on a host
// where AppLocker blocks reg.exe under Constrained Language Mode, every value is
// untyped and LSA would otherwise report limitBlankPasswordUse as false.
func TestRegistryValueError(t *testing.T) {
	path := `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
	readable := registry.RegistryKeyItem{Key: "LimitBlankPasswordUse", Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: 1}}
	unread := registry.RegistryKeyItem{Key: "NoLMHash", Value: registry.RegistryKeyValue{Err: errors.New("could not determine the registry value type")}}

	require.NoError(t, registryValueError(path, nil))
	require.NoError(t, registryValueError(path, []registry.RegistryKeyItem{readable}))

	err := registryValueError(path, []registry.RegistryKeyItem{readable, unread})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NoLMHash")
	assert.Contains(t, err.Error(), path)
	assert.Contains(t, err.Error(), "could not determine the registry value type")
}

func readStderrFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("./testdata/windows-registry/stderr/" + name)
	require.NoError(t, err)
	return string(data)
}

// The fixtures are the stderr of GetRegistryKeyItemScript on Windows 11: as
// the SSH transport hands it over (decoded) and as powershell.exe writes it
// (CLIXML), which is what a transport without decoding passes on.
func TestClassifyRegistryStderr(t *testing.T) {
	const denied = `HKEY_LOCAL_MACHINE\SECURITY`
	const missing = `HKEY_LOCAL_MACHINE\SOFTWARE\NoSuchKey`

	for _, name := range []string{"win11-access-denied.txt", "win11-access-denied.clixml.txt"} {
		t.Run(name, func(t *testing.T) {
			absent, err := classifyRegistryStderr(denied, readStderrFixture(t, name))
			assert.False(t, absent, "a refused key is not a missing key")
			require.Error(t, err)
			assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
			assert.Equal(t, `could not read registry key HKEY_LOCAL_MACHINE\SECURITY: Requested registry access is not allowed.`, err.Error())
		})
	}
	for _, name := range []string{"win11-not-found.txt", "win11-not-found.clixml.txt"} {
		t.Run(name, func(t *testing.T) {
			absent, err := classifyRegistryStderr(missing, readStderrFixture(t, name))
			assert.True(t, absent)
			assert.NoError(t, err)
		})
	}

	t.Run("anything else stays unclassified and keeps its message", func(t *testing.T) {
		absent, err := classifyRegistryStderr(denied, "Get-Item : The network path was not found.\r\n    + CategoryInfo          : ReadError: (:) [Get-Item], IOException\r\n")
		assert.False(t, absent)
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
		assert.Equal(t, `could not read registry key HKEY_LOCAL_MACHINE\SECURITY: The network path was not found.`, err.Error())
	})

	t.Run("empty stderr", func(t *testing.T) {
		absent, err := classifyRegistryStderr(denied, "")
		assert.False(t, absent)
		assert.EqualError(t, err, `could not read registry key HKEY_LOCAL_MACHINE\SECURITY`)
	})
}

func TestRegistryApplicable(t *testing.T) {
	onPlatform := func(name string, family ...string) shared.Connection {
		return &mockConn{asset: &inventory.Asset{Platform: &inventory.Platform{Name: name, Family: family}}}
	}

	assert.NoError(t, registryApplicable(onPlatform("windows", "windows", "os")))

	err := registryApplicable(onPlatform("macos", "darwin", "bsd", "unix", "os"))
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))

	// before detection there is no platform to rule the read out
	assert.NoError(t, registryApplicable(&mockConn{asset: &inventory.Asset{}}))
	assert.NoError(t, registryApplicable(&mockConn{}))
}

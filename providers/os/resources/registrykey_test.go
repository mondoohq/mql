// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/utils/syncx"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
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
	t.Run("plain key uses the folded absolute path as id", func(t *testing.T) {
		k := &mqlRegistrykey{Path: plugin.TValue[string]{Data: `HKLM\Software\Foo`}}
		id, err := k.id()
		require.NoError(t, err)
		require.Equal(t, `hkey_local_machine\software\foo`, id)
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
		require.Equal(t, `hkey_users\s-1-5-21-1-2-3-1001\software\policies`, idA)
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
		require.Equal(t, `hkey_local_machine\software\foo - bar`, id)
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
		require.Equal(t, `hkey_users\s-1-5-21-1-2-3-1001\software\policies - bar`, idA)
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

// Registry paths and value names are case-insensitive, so every spelling of a
// key is one resource (#11257): a remote scan then reads it with one PowerShell
// run instead of one per spelling.
func TestRegistryIDPath(t *testing.T) {
	same := []string{
		`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		`HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient`,
		`hkey_local_machine\software\policies\microsoft\windows nt\dnsclient`,
		`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\`,
		`HKLM\\SOFTWARE\Policies\\Microsoft\Windows NT\DNSClient`,
	}
	for _, p := range same {
		require.Equal(t, `hkey_local_machine\software\policies\microsoft\windows nt\dnsclient`, registryIDPath(p), p)
	}
	require.Equal(t, `hkey_current_user\software`, registryIDPath(`HKCU\Software`))
	require.Equal(t, `hkey_current_user\software`, registryIDPath(`HKEY_CURRENT_USER\Software`))

	// Different keys stay apart: the fold never drops or joins path segments.
	different := []string{
		`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT`,
		`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT`,
		`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		`HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows NT`,
		`HKEY_USERS\SOFTWARE\Policies\Microsoft\Windows NT`,
	}
	seen := map[string]string{}
	for _, p := range different {
		id := registryIDPath(p)
		if other, ok := seen[id]; ok {
			t.Fatalf("%q and %q share the id %q", p, other, id)
		}
		seen[id] = p
	}
}

func TestRegistrykeyCaseVariantsShareOneResource(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	create := func(args map[string]*llx.RawData) *mqlRegistrykey {
		t.Helper()
		res, err := CreateResource(runtime, "registrykey", args)
		require.NoError(t, err)
		return res.(*mqlRegistrykey)
	}

	a := create(map[string]*llx.RawData{"path": llx.StringData(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System`)})
	b := create(map[string]*llx.RawData{"path": llx.StringData(`HKLM\Software\Policies\Microsoft\Windows\System`)})
	require.Same(t, a, b, "two spellings of one key must be one resource")
	// The first query's spelling is the resource's path.
	require.Equal(t, `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System`, b.Path.Data)

	c := create(map[string]*llx.RawData{"path": llx.StringData(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer`)})
	require.NotSame(t, a, c, "different keys must not share a resource")

	// Per-user keys: the same user in two spellings is one resource, two users
	// are two.
	u1 := create(map[string]*llx.RawData{"path": llx.StringData(`Software\Policies`), "userSid": llx.StringData("S-1-5-21-1-2-3-1001")})
	u1b := create(map[string]*llx.RawData{"path": llx.StringData(`SOFTWARE\POLICIES`), "userSid": llx.StringData("S-1-5-21-1-2-3-1001")})
	u2 := create(map[string]*llx.RawData{"path": llx.StringData(`Software\Policies`), "userSid": llx.StringData("S-1-5-21-1-2-3-1002")})
	require.Same(t, u1, u1b)
	require.NotSame(t, u1, u2)
	require.NotSame(t, a, u1)
}

// Spellings that differ only in separators share one resource, so the key is
// read with its separators collapsed, whichever spelling created it. On
// Windows, HKLM\\SOFTWARE (an empty segment after the hive) reads as missing
// through PowerShell and as an invalid path through RegOpenKeyEx, while the
// collapsed path reads the key in both.
func TestRegistryReadPath(t *testing.T) {
	for in, want := range map[string]string{
		`HKLM\\SOFTWARE\Microsoft\Windows NT`:  `HKLM\SOFTWARE\Microsoft\Windows NT`,
		`HKLM\SOFTWARE\\\Microsoft\`:           `HKLM\SOFTWARE\Microsoft`,
		`\HKEY_LOCAL_MACHINE\Software\`:        `HKEY_LOCAL_MACHINE\Software`,
		`hkcu\Software\Policies`:               `hkcu\Software\Policies`,
		`HKEY_LOCAL_MACHINE\SOFTWARE\Policies`: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies`,
		``:                                     ``,
	} {
		assert.Equal(t, want, registryReadPath(in), in)
	}

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	res, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{"path": llx.StringData(`HKLM\\SOFTWARE\Policies`)})
	require.NoError(t, err)
	key := res.(*mqlRegistrykey)
	assert.Equal(t, `HKLM\\SOFTWARE\Policies`, key.Path.Data, "path keeps the query's spelling")
	assert.Equal(t, `HKLM\SOFTWARE\Policies`, key.readPath())
}

// A key the native API cannot find is absent, as on the PowerShell path; any
// other error, and the values of a key that exists, pass through.
func TestNativeItemsOrAbsent(t *testing.T) {
	items, err := nativeItemsOrAbsent(nil, status.Error(codes.NotFound, `registry key not found: Software\Policies\Missing`))
	require.NoError(t, err)
	assert.Nil(t, items)

	denied := errors.New("Access is denied.")
	_, err = nativeItemsOrAbsent(nil, denied)
	assert.Equal(t, denied, err)

	values := []registry.RegistryKeyItem{{Key: "a", Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: 1}}}
	items, err = nativeItemsOrAbsent(values, nil)
	require.NoError(t, err)
	assert.Equal(t, values, items)
}

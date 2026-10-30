// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
)

// multiSz builds a registry item map entry holding a REG_MULTI_SZ value.
func multiSz(name string, v ...string) (string, registry.RegistryKeyItem) {
	return name, registry.RegistryKeyItem{
		Key:   name,
		Value: registry.RegistryKeyValue{Kind: registry.MULTI_SZ, MultiString: v},
	}
}

func regMap(entries ...func() (string, registry.RegistryKeyItem)) map[string]registry.RegistryKeyItem {
	m := map[string]registry.RegistryKeyItem{}
	for _, e := range entries {
		k, v := e()
		m[k] = v
	}
	return m
}

func ms(name string, v ...string) func() (string, registry.RegistryKeyItem) {
	return func() (string, registry.RegistryKeyItem) { return multiSz(name, v...) }
}

func TestSmbResolveInt_NullWhenAbsent(t *testing.T) {
	policy := map[string]registry.RegistryKeyItem{}
	params := map[string]registry.RegistryKeyItem{}

	// absent everywhere -> nil (rendered as MQL null)
	assert.Nil(t, smbResolveInt(policy, params, "AutoDisconnect"))

	// an explicit 0 must NOT be confused with absent
	params = regMap(d("autodisconnect", 0))
	got := smbResolveInt(policy, params, "AutoDisconnect")
	require.NotNil(t, got)
	assert.Equal(t, int64(0), *got)
}

func TestSmbResolveInt_PolicyWins(t *testing.T) {
	policy := regMap(d("autodisconnect", 15))
	params := regMap(d("autodisconnect", 99))

	got := smbResolveInt(policy, params, "AutoDisconnect")
	require.NotNil(t, got)
	assert.Equal(t, int64(15), *got, "the policy value must override the parameters value")
}

func TestSmbResolveInt_FallsThroughToParams(t *testing.T) {
	policy := map[string]registry.RegistryKeyItem{}
	params := regMap(d("autodisconnect", 15))

	got := smbResolveInt(policy, params, "AutoDisconnect")
	require.NotNil(t, got)
	assert.Equal(t, int64(15), *got)
}

func TestSmbResolveBool(t *testing.T) {
	// absent -> nil
	assert.Nil(t, smbResolveBool(map[string]registry.RegistryKeyItem{}, map[string]registry.RegistryKeyItem{}, "RequireSecuritySignature"))

	// explicit 0 -> false (not nil) so it is distinguishable from absent
	got := smbResolveBool(map[string]registry.RegistryKeyItem{}, regMap(d("enableplaintextpassword", 0)), "EnablePlainTextPassword")
	require.NotNil(t, got)
	assert.False(t, *got)

	// value 1 -> true
	got = smbResolveBool(map[string]registry.RegistryKeyItem{}, regMap(d("requiresecuritysignature", 1)), "RequireSecuritySignature")
	require.NotNil(t, got)
	assert.True(t, *got)

	// any non-1 value -> false
	got = smbResolveBool(map[string]registry.RegistryKeyItem{}, regMap(d("requiresecuritysignature", 2)), "RequireSecuritySignature")
	require.NotNil(t, got)
	assert.False(t, *got)
}

func TestSmbResolveMultiString(t *testing.T) {
	// absent -> empty slice
	assert.Empty(t, smbResolveMultiString(map[string]registry.RegistryKeyItem{}, map[string]registry.RegistryKeyItem{}, "NullSessionPipes"))

	// from params
	got := smbResolveMultiString(map[string]registry.RegistryKeyItem{}, regMap(ms("nullsessionpipes", "PIPE1", "PIPE2")), "NullSessionPipes")
	assert.Equal(t, []string{"PIPE1", "PIPE2"}, got)

	// policy wins over params
	got = smbResolveMultiString(regMap(ms("nullsessionpipes", "POLICY")), regMap(ms("nullsessionpipes", "PARAM")), "NullSessionPipes")
	assert.Equal(t, []string{"POLICY"}, got)
}

func TestComputeSmbServerConfig_Hardened(t *testing.T) {
	params := regMap(
		d("requiresecuritysignature", 1),
		d("enablesecuritysignature", 1),
		d("smb1", 0),
		d("restrictnullsessaccess", 1),
		ms("nullsessionpipes"),
		ms("nullsessionshares"),
		d("autodisconnect", 15),
		d("enableforcedlogoff", 1),
		d("smbservernamehardeninglevel", 1),
		d("enableauthratelimiter", 1),
		d("invalidauthenticationdelaytimeinms", 2000),
		d("auditclientdoesnotsupportsigning", 1),
		d("auditclientdoesnotsupportencryption", 1),
	)
	service := regMap(d("start", 2))

	cfg := computeSmbServerConfig(map[string]registry.RegistryKeyItem{}, params, service)

	require.NotNil(t, cfg.requireSecuritySignature)
	assert.True(t, *cfg.requireSecuritySignature)
	require.NotNil(t, cfg.smb1Enabled)
	assert.False(t, *cfg.smb1Enabled, "SMB1=0 must report smb1Enabled=false, not null")
	require.NotNil(t, cfg.restrictNullSessionAccess)
	assert.True(t, *cfg.restrictNullSessionAccess)
	assert.Empty(t, cfg.nullSessionPipes)
	assert.Empty(t, cfg.nullSessionShares)
	require.NotNil(t, cfg.autoDisconnectMinutes)
	assert.Equal(t, int64(15), *cfg.autoDisconnectMinutes)
	require.NotNil(t, cfg.serverNameHardeningLevel)
	assert.Equal(t, int64(1), *cfg.serverNameHardeningLevel)
	require.NotNil(t, cfg.invalidAuthenticationDelayMs)
	assert.Equal(t, int64(2000), *cfg.invalidAuthenticationDelayMs)
	require.NotNil(t, cfg.serviceStart)
	assert.Equal(t, int64(2), *cfg.serviceStart)
}

func TestComputeSmbServerConfig_AllAbsentIsNull(t *testing.T) {
	empty := map[string]registry.RegistryKeyItem{}
	cfg := computeSmbServerConfig(empty, empty, empty)

	assert.Nil(t, cfg.requireSecuritySignature)
	assert.Nil(t, cfg.enableSecuritySignature)
	assert.Nil(t, cfg.smb1Enabled)
	assert.Nil(t, cfg.restrictNullSessionAccess)
	assert.Empty(t, cfg.nullSessionPipes)
	assert.Empty(t, cfg.nullSessionShares)
	assert.Nil(t, cfg.autoDisconnectMinutes)
	assert.Nil(t, cfg.enableForcedLogoff)
	assert.Nil(t, cfg.serverNameHardeningLevel)
	assert.Nil(t, cfg.enableAuthRateLimiter)
	assert.Nil(t, cfg.invalidAuthenticationDelayMs)
	assert.Nil(t, cfg.auditClientDoesNotSupportSigning)
	assert.Nil(t, cfg.auditClientDoesNotSupportEncryption)
	assert.Nil(t, cfg.serviceStart)
}

func TestComputeSmbServerConfig_PolicyOverridesParams(t *testing.T) {
	policy := regMap(d("requiresecuritysignature", 1))
	params := regMap(d("requiresecuritysignature", 0))
	cfg := computeSmbServerConfig(policy, params, map[string]registry.RegistryKeyItem{})

	require.NotNil(t, cfg.requireSecuritySignature)
	assert.True(t, *cfg.requireSecuritySignature, "policy RequireSecuritySignature=1 must win over params=0")
}

func TestComputeSmbClientConfig_Hardened(t *testing.T) {
	params := regMap(
		d("requiresecuritysignature", 1),
		d("enablesecuritysignature", 1),
		d("enableplaintextpassword", 0),
		d("allowinsecureguestauth", 0),
		d("requireencryption", 1),
		d("minsmb2dialect", 768), // 0x300 = SMB 3.0
		d("auditinsecureguestlogon", 1),
		d("auditserverdoesnotsupportsigning", 1),
		d("auditserverdoesnotsupportencryption", 1),
	)
	service := regMap(d("start", 2))

	cfg := computeSmbClientConfig(map[string]registry.RegistryKeyItem{}, params, service)

	require.NotNil(t, cfg.enablePlainTextPassword)
	assert.False(t, *cfg.enablePlainTextPassword, "EnablePlainTextPassword=0 must report false, not null")
	require.NotNil(t, cfg.allowInsecureGuestAuth)
	assert.False(t, *cfg.allowInsecureGuestAuth, "AllowInsecureGuestAuth=0 must report false, not null")
	require.NotNil(t, cfg.requireEncryption)
	assert.True(t, *cfg.requireEncryption)
	require.NotNil(t, cfg.minSmb2Dialect)
	assert.Equal(t, int64(768), *cfg.minSmb2Dialect)
	require.NotNil(t, cfg.serviceStart)
	assert.Equal(t, int64(2), *cfg.serviceStart)
}

func TestComputeSmbClientConfig_AllAbsentIsNull(t *testing.T) {
	empty := map[string]registry.RegistryKeyItem{}
	cfg := computeSmbClientConfig(empty, empty, empty)

	assert.Nil(t, cfg.requireSecuritySignature)
	assert.Nil(t, cfg.enableSecuritySignature)
	assert.Nil(t, cfg.enablePlainTextPassword)
	assert.Nil(t, cfg.allowInsecureGuestAuth)
	assert.Nil(t, cfg.requireEncryption)
	assert.Nil(t, cfg.minSmb2Dialect)
	assert.Nil(t, cfg.auditInsecureGuestLogon)
	assert.Nil(t, cfg.auditServerDoesNotSupportSigning)
	assert.Nil(t, cfg.auditServerDoesNotSupportEncryption)
	assert.Nil(t, cfg.serviceStart)
}

func TestComputeSmbV1Enabled(t *testing.T) {
	// disabled driver: Start == 4 -> not enabled
	assert.False(t, computeSmbV1Enabled(regMap(d("start", 4))))

	// automatic start (2) -> enabled
	assert.True(t, computeSmbV1Enabled(regMap(d("start", 2))))

	// manual start (3) -> enabled
	assert.True(t, computeSmbV1Enabled(regMap(d("start", 3))))

	// boot start (0) and system start (1) -> enabled
	assert.True(t, computeSmbV1Enabled(regMap(d("start", 0))))
	assert.True(t, computeSmbV1Enabled(regMap(d("start", 1))))

	// An absent service key means the SMB1Protocol optional feature was
	// removed, which deletes the mrxsmb10 key outright. That is not-installed,
	// so not enabled. Server 2019, 2022 and 2025 are all in this state on a
	// stock install; reading it as enabled meant the field could not return
	// false on any of them.
	assert.False(t, computeSmbV1Enabled(map[string]registry.RegistryKeyItem{}))
	assert.False(t, computeSmbV1Enabled(nil))

	// A key present but carrying no Start value cannot say the driver will
	// load, so it is not reported as enabled either.
	assert.False(t, computeSmbV1Enabled(regMap(d("type", 2))))
}

// windows.smb.serverConfiguration and windows.smb.clientConfiguration are each
// both a field path on windows.smb and a resource name, which is the condition
// that makes an Init necessary: the compiler resolves the resource name first,
// so the dotted form skips the parent's accessor and every field the parent
// would have populated stays unset.
func TestWindowsSmbSingletonsAreReachableByTheirOwnPath(t *testing.T) {
	for _, path := range []string{
		"windows.smb.serverConfiguration",
		"windows.smb.clientConfiguration",
	} {
		t.Run(path, func(t *testing.T) {
			_, isField := getDataFields[path]
			require.True(t, isField, "%s should be a field path on its parent", path)

			factory, isResource := resourceFactories[path]
			require.True(t, isResource, "%s should also be a registered resource name", path)

			assert.NotNil(t, factory.Init,
				"%s resolves to the resource, not the field, so without an Init every field reads null", path)
		})
	}
}

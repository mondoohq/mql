// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveRdpValue(t *testing.T) {
	t.Run("group policy value wins over the effective value", func(t *testing.T) {
		policy := map[string]int64{"userauthentication": 0}
		effective := map[string]int64{"userauthentication": 1}
		assert.Equal(t, int64(0), resolveRdpValue(policy, effective, "UserAuthentication", 1))
	})

	t.Run("effective value is used when policy is unset", func(t *testing.T) {
		effective := map[string]int64{"securitylayer": 2}
		assert.Equal(t, int64(2), resolveRdpValue(nil, effective, "SecurityLayer", 1))
	})

	t.Run("default is used when neither policy nor effective is set", func(t *testing.T) {
		assert.Equal(t, int64(2), resolveRdpValue(nil, nil, "MinEncryptionLevel", 2))
	})

	t.Run("value name matching is case insensitive", func(t *testing.T) {
		policy := map[string]int64{"fdisablecdm": 1}
		assert.Equal(t, int64(1), resolveRdpValue(policy, nil, "fDisableCdm", 0))
	})

	t.Run("an explicit zero is honored, not treated as unset", func(t *testing.T) {
		policy := map[string]int64{"fencryptrpctraffic": 0}
		// default is 1, but the policy explicitly disables it
		assert.Equal(t, int64(0), resolveRdpValue(policy, nil, "fEncryptRPCTraffic", 1))
	})
}

// TestRdpSettingDefaults locks in the Windows default each newly added field
// resolves to when neither group policy nor the effective key is configured.
func TestRdpSettingDefaults(t *testing.T) {
	cases := []struct {
		name string
		def  int64
	}{
		{"fDenyTSConnections", 1},
		{"fSingleSessionPerUser", 1},
		{"PerSessionTempDir", 1},
		{"fAllowToGetHelp", 0},
		{"fAllowUnsolicited", 0},
		{"fDisableWebAuthn", 0},
		{"fDisableLocationRedir", 0},
		{"EnableUiaRedirection", 0},
		{"SCClipLevel", 3},
		{"fResetBroken", 0},
		{"DisableCloudClipboardIntegration", 0},
	}
	for _, c := range cases {
		t.Run(c.name+" default", func(t *testing.T) {
			assert.Equal(t, c.def, resolveRdpValue(nil, nil, c.name, c.def))
		})
		t.Run(c.name+" policy overrides default", func(t *testing.T) {
			policy := map[string]int64{toLowerASCII(c.name): 2}
			assert.Equal(t, int64(2), resolveRdpValue(policy, nil, c.name, c.def))
		})
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// Remote Assistance keeps its local setting under Control\Remote Assistance,
// not under Control\Terminal Server. The local map below is what Windows 10
// 22H2 and Windows 11 25H2 client installs hold there (Remote Assistance on,
// no policy), read with Get-ItemProperty.
func TestRdpSolicitedRemoteAssistanceAllowed(t *testing.T) {
	clientDefault := map[string]int64{"fallowtogethelp": 1, "fallowfullcontrol": 1}

	t.Run("local setting applies without a policy", func(t *testing.T) {
		assert.True(t, rdpSolicitedRemoteAssistanceAllowed(map[string]int64{}, clientDefault))
		assert.False(t, rdpSolicitedRemoteAssistanceAllowed(map[string]int64{}, map[string]int64{"fallowtogethelp": 0}))
	})

	t.Run("policy wins over the local setting in both directions", func(t *testing.T) {
		assert.False(t, rdpSolicitedRemoteAssistanceAllowed(map[string]int64{"fallowtogethelp": 0}, clientDefault))
		assert.True(t, rdpSolicitedRemoteAssistanceAllowed(map[string]int64{"fallowtogethelp": 1}, map[string]int64{"fallowtogethelp": 0}))
	})

	t.Run("off when neither key sets it", func(t *testing.T) {
		assert.False(t, rdpSolicitedRemoteAssistanceAllowed(nil, nil))
	})

	t.Run("does not read the offer setting", func(t *testing.T) {
		assert.False(t, rdpSolicitedRemoteAssistanceAllowed(nil, map[string]int64{"fallowunsolicited": 1}))
	})
}

func TestRdpOfferRemoteAssistanceAllowed(t *testing.T) {
	t.Run("off on a client default install, where only solicited help is on", func(t *testing.T) {
		assert.False(t, rdpOfferRemoteAssistanceAllowed(map[string]int64{}, map[string]int64{"fallowtogethelp": 1, "fallowfullcontrol": 1}))
	})

	t.Run("local setting applies without a policy", func(t *testing.T) {
		assert.True(t, rdpOfferRemoteAssistanceAllowed(nil, map[string]int64{"fallowunsolicited": 1}))
	})

	t.Run("policy wins over the local setting", func(t *testing.T) {
		assert.False(t, rdpOfferRemoteAssistanceAllowed(map[string]int64{"fallowunsolicited": 0}, map[string]int64{"fallowunsolicited": 1}))
		assert.True(t, rdpOfferRemoteAssistanceAllowed(map[string]int64{"fallowunsolicited": 1}, nil))
	})
}

// DisablePasswordSaving is a Group Policy-only setting. Microsoft documents the
// unconfigured behavior as "the user will be able to save passwords using
// Remote Desktop Connection", so an absent value means saving is allowed and
// the field is false. Defaulting to true claimed the hardened state on every
// host that had not set the policy, which is the direction that lets a check
// pass without reading anything.
func TestPasswordSavingDefaultsToAllowed(t *testing.T) {
	assert.Equal(t, int64(0), resolveRdpValue(nil, nil, "DisablePasswordSaving", 0))

	// the policy still wins when it is set, in both directions
	enabled := map[string]int64{"disablepasswordsaving": 1}
	assert.Equal(t, int64(1), resolveRdpValue(enabled, nil, "DisablePasswordSaving", 0))

	disabled := map[string]int64{"disablepasswordsaving": 0}
	assert.Equal(t, int64(0), resolveRdpValue(disabled, nil, "DisablePasswordSaving", 0))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/registry"
)

// spoolerRegItems builds a name->RegistryKeyItem map from a map of DWORD values,
// mirroring how readSpoolerKey lower-cases the lookup keys while preserving the
// original-cased value name.
func spoolerRegItems(values map[string]int64) map[string]registry.RegistryKeyItem {
	items := make(map[string]registry.RegistryKeyItem, len(values))
	for name, v := range values {
		items[strings.ToLower(name)] = registry.RegistryKeyItem{
			Key:   name,
			Value: registry.RegistryKeyValue{Number: v},
		}
	}
	return items
}

func TestRegBoolDefault(t *testing.T) {
	items := spoolerRegItems(map[string]int64{"DisableHTTPPrinting": 1, "ForceKerberosForRpc": 0})

	t.Run("value of 1 is true", func(t *testing.T) {
		assert.True(t, regBoolDefault(items, "DisableHTTPPrinting", false))
	})

	t.Run("an explicit zero is honored over the default", func(t *testing.T) {
		assert.False(t, regBoolDefault(items, "ForceKerberosForRpc", true))
	})

	t.Run("an absent value falls back to the default", func(t *testing.T) {
		assert.True(t, regBoolDefault(items, "RpcAuthnLevelPrivacyEnabled", true))
		assert.False(t, regBoolDefault(items, "DisableWebPnPDownload", false))
	})

	t.Run("lookups are case insensitive", func(t *testing.T) {
		assert.True(t, regBoolDefault(items, "disablehttpprinting", false))
	})
}

func TestSpoolerStartMode(t *testing.T) {
	t.Run("present start type", func(t *testing.T) {
		v := spoolerStartMode(spoolerRegItems(map[string]int64{"Start": 4}))
		if assert.NotNil(t, v) {
			assert.Equal(t, int64(4), *v)
		}
	})

	t.Run("automatic start type", func(t *testing.T) {
		v := spoolerStartMode(spoolerRegItems(map[string]int64{"Start": 2}))
		if assert.NotNil(t, v) {
			assert.Equal(t, int64(2), *v)
		}
	})

	t.Run("absent start type yields nil", func(t *testing.T) {
		assert.Nil(t, spoolerStartMode(spoolerRegItems(map[string]int64{})))
	})
}

func TestSpoolerDisabled(t *testing.T) {
	t.Run("Start == 4 is disabled", func(t *testing.T) {
		assert.True(t, spoolerDisabled(spoolerRegItems(map[string]int64{"Start": 4})))
	})

	t.Run("Start == 2 (automatic) is not disabled", func(t *testing.T) {
		assert.False(t, spoolerDisabled(spoolerRegItems(map[string]int64{"Start": 2})))
	})

	t.Run("absent start type is not disabled", func(t *testing.T) {
		assert.False(t, spoolerDisabled(spoolerRegItems(map[string]int64{})))
	})
}

func TestSpoolerPointAndPrintArgs(t *testing.T) {
	t.Run("hardened defaults when nothing is configured", func(t *testing.T) {
		args := spoolerPointAndPrintArgs(spoolerRegItems(map[string]int64{}))
		// restrictDriverInstallationToAdministrators defaults to true
		assert.Equal(t, true, args["restrictDriverInstallationToAdministrators"].Value)
		// nullable ints are null (NilData) when absent
		assert.Nil(t, args["noWarningNoElevationOnInstall"].Value)
		assert.Nil(t, args["updatePromptSettings"].Value)
	})

	t.Run("explicit zero on prompt settings is preserved, not null", func(t *testing.T) {
		args := spoolerPointAndPrintArgs(spoolerRegItems(map[string]int64{
			"NoWarningNoElevationOnInstall": 0,
			"UpdatePromptSettings":          0,
		}))
		assert.Equal(t, false, args["noWarningNoElevationOnInstall"].Value)
		assert.Equal(t, int64(0), args["updatePromptSettings"].Value)
	})

	t.Run("noWarningNoElevationOnInstall non-zero resolves to true", func(t *testing.T) {
		args := spoolerPointAndPrintArgs(spoolerRegItems(map[string]int64{
			"NoWarningNoElevationOnInstall": 1,
		}))
		assert.Equal(t, true, args["noWarningNoElevationOnInstall"].Value)
	})

	t.Run("explicit restrict=false overrides the default", func(t *testing.T) {
		args := spoolerPointAndPrintArgs(spoolerRegItems(map[string]int64{
			"RestrictDriverInstallationToAdministrators": 0,
		}))
		assert.Equal(t, false, args["restrictDriverInstallationToAdministrators"].Value)
	})
}

func TestSpoolerRpcArgs(t *testing.T) {
	t.Run("all ints null and forceKerberos default when unconfigured", func(t *testing.T) {
		args := spoolerRpcArgs(spoolerRegItems(map[string]int64{}))
		assert.Nil(t, args["useNamedPipeProtocol"].Value)
		assert.Nil(t, args["authentication"].Value)
		assert.Nil(t, args["protocols"].Value)
		assert.Nil(t, args["tcpPort"].Value)
		assert.Equal(t, false, args["forceKerberos"].Value)
	})

	t.Run("compliant useNamedPipeProtocol=false is preserved", func(t *testing.T) {
		args := spoolerRpcArgs(spoolerRegItems(map[string]int64{
			"RpcUseNamedPipeProtocol": 0,
			"RpcAuthentication":       1,
			"ForceKerberosForRpc":     1,
		}))
		assert.Equal(t, false, args["useNamedPipeProtocol"].Value)
		assert.Equal(t, int64(1), args["authentication"].Value)
		assert.Equal(t, true, args["forceKerberos"].Value)
	})
}

func TestSpoolerIppArgs(t *testing.T) {
	t.Run("certificate checks default to false when unconfigured", func(t *testing.T) {
		args := spoolerIppArgs(spoolerRegItems(map[string]int64{}))
		assert.Equal(t, false, args["requireIpps"].Value)
		assert.Equal(t, false, args["blockUnknownCA"].Value)
		assert.Equal(t, false, args["blockCertWrongUsage"].Value)
		assert.Equal(t, false, args["blockCertDateInvalid"].Value)
		assert.Equal(t, false, args["blockCertCNInvalid"].Value)
	})

	t.Run("enforced checks resolve to true", func(t *testing.T) {
		args := spoolerIppArgs(spoolerRegItems(map[string]int64{
			"RequireIpps":                       1,
			"SecurityFlagsBlockUnknownCA":       1,
			"SecurityFlagsBlockCertWrongUsage":  1,
			"SecurityFlagsBlockCertDateInvalid": 1,
			"SecurityFlagsBlockCertCNInvalid":   1,
		}))
		assert.Equal(t, true, args["requireIpps"].Value)
		assert.Equal(t, true, args["blockUnknownCA"].Value)
		assert.Equal(t, true, args["blockCertWrongUsage"].Value)
		assert.Equal(t, true, args["blockCertDateInvalid"].Value)
		assert.Equal(t, true, args["blockCertCNInvalid"].Value)
	})
}

// spoolerEnumCase is one registry reading of a policy enumeration and the bool it
// must decode to; a nil want means the field reads null.
type spoolerEnumCase struct {
	name  string
	value *int64
	want  *bool
}

func runSpoolerEnumCases(t *testing.T, valueName string, decode func(map[string]registry.RegistryKeyItem) *bool, cases []spoolerEnumCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]int64{}
			if tc.value != nil {
				values[valueName] = *tc.value
			}
			assert.Equal(t, tc.want, decode(spoolerRegItems(values)))
		})
	}
}

// Values from the Printers Policy CSP / Printing.admx. Every policy here uses
// a non-zero value for at least one "off" state, which a non-zero test read
// as true.
func TestSpoolerRegisterRemoteRpcEndpoint(t *testing.T) {
	runSpoolerEnumCases(t, "RegisterSpoolerRemoteRpcEndPoint", spoolerRegisterRemoteRpcEndpoint, []spoolerEnumCase{
		{"enabled (1) accepts client connections", new(int64(1)), new(true)},
		{"disabled (2) is the hardened state", new(int64(2)), new(false)},
		{"0 is not a defined value", new(int64(0)), nil},
		{"unknown value", new(int64(5)), nil},
		{"not configured", nil, nil},
	})
}

func TestSpoolerRedirectionGuardEnabled(t *testing.T) {
	runSpoolerEnumCases(t, "RedirectionguardPolicy", spoolerRedirectionGuardEnabled, []spoolerEnumCase{
		{"enabled (1)", new(int64(1)), new(true)},
		{"disabled (0)", new(int64(0)), new(false)},
		{"audit (2) does not block redirections", new(int64(2)), new(false)},
		{"unknown value", new(int64(3)), nil},
		{"not configured", nil, nil},
	})
}

func TestSpoolerCopyFilesRestricted(t *testing.T) {
	runSpoolerEnumCases(t, "CopyFilesPolicy", spoolerCopyFilesRestricted, []spoolerEnumCase{
		{"do not allow queue-specific files (0)", new(int64(0)), new(true)},
		{"limit to color profiles (1)", new(int64(1)), new(true)},
		{"allow all (2) is unrestricted", new(int64(2)), new(false)},
		{"unknown value", new(int64(3)), nil},
		{"not configured", nil, nil},
	})
}

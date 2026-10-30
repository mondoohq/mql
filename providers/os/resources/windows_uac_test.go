// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
)

// uacBoolFields maps each on/off UAC registry value, spelled as Microsoft
// documents it, to the field that must carry it. A value wired to the wrong
// field, or a misspelled value name, fails the per-value cases below.
var uacBoolFields = map[string]func(uacValues) *bool{
	"EnableLUA":                     func(v uacValues) *bool { return v.EnableLua },
	"FilterAdministratorToken":      func(v uacValues) *bool { return v.FilterAdministratorToken },
	"EnableInstallerDetection":      func(v uacValues) *bool { return v.EnableInstallerDetection },
	"EnableSecureUIAPaths":          func(v uacValues) *bool { return v.EnableSecureUiaPaths },
	"EnableUIADesktopToggle":        func(v uacValues) *bool { return v.EnableUiaDesktopToggle },
	"EnableVirtualization":          func(v uacValues) *bool { return v.EnableVirtualization },
	"LocalAccountTokenFilterPolicy": func(v uacValues) *bool { return v.LocalAccountTokenFilterPolicy },
	"PromptOnSecureDesktop":         func(v uacValues) *bool { return v.PromptOnSecureDesktop },
	"ValidateAdminCodeSignatures":   func(v uacValues) *bool { return v.ValidateAdminCodeSignatures },
}

var uacIntFields = map[string]func(uacValues) *int64{
	"ConsentPromptBehaviorAdmin": func(v uacValues) *int64 { return v.ConsentPromptBehaviorAdmin },
	"ConsentPromptBehaviorUser":  func(v uacValues) *int64 { return v.ConsentPromptBehaviorUser },
}

func TestComputeUacBoolValues(t *testing.T) {
	for name, get := range uacBoolFields {
		t.Run(name, func(t *testing.T) {
			t.Run("absent is null, not false", func(t *testing.T) {
				assert.Nil(t, get(computeUac(items())))
			})

			t.Run("0 is false", func(t *testing.T) {
				p := get(computeUac(items(d(name, 0))))
				require.NotNil(t, p)
				assert.False(t, *p)
			})

			t.Run("1 is true", func(t *testing.T) {
				p := get(computeUac(items(d(name, 1))))
				require.NotNil(t, p)
				assert.True(t, *p)
			})

			t.Run("out of range non-zero is true", func(t *testing.T) {
				p := get(computeUac(items(d(name, 2))))
				require.NotNil(t, p)
				assert.True(t, *p)

				p = get(computeUac(items(d(name, 0xFFFFFFFF))))
				require.NotNil(t, p)
				assert.True(t, *p)
			})

			t.Run("value name matches case-insensitively", func(t *testing.T) {
				m := map[string]registry.RegistryKeyItem{}
				k, v := dword(name, 1)
				m[lower(k)] = v
				p := get(computeUac(m))
				require.NotNil(t, p)
				assert.True(t, *p)
			})

			t.Run("does not read a sibling value", func(t *testing.T) {
				// every other UAC value set to 1 must leave this field null
				var pairs []func() (string, registry.RegistryKeyItem)
				for other := range uacBoolFields {
					if other != name {
						pairs = append(pairs, d(other, 1))
					}
				}
				for other := range uacIntFields {
					pairs = append(pairs, d(other, 1))
				}
				assert.Nil(t, get(computeUac(items(pairs...))))
			})
		})
	}
}

func TestComputeUacPromptBehaviors(t *testing.T) {
	for name, get := range uacIntFields {
		t.Run(name, func(t *testing.T) {
			t.Run("absent is null, not 0", func(t *testing.T) {
				// 0 means "elevate without prompting" for administrators, the
				// weakest setting, so an absent value must never read as 0
				assert.Nil(t, get(computeUac(items())))
			})

			for _, want := range []int64{0, 1, 2, 3, 4, 5} {
				p := get(computeUac(items(d(name, want))))
				require.NotNil(t, p)
				assert.Equal(t, want, *p)
			}

			t.Run("out of range is reported as read", func(t *testing.T) {
				p := get(computeUac(items(d(name, 7))))
				require.NotNil(t, p)
				assert.Equal(t, int64(7), *p)
			})

			t.Run("does not read a sibling value", func(t *testing.T) {
				var pairs []func() (string, registry.RegistryKeyItem)
				for other := range uacIntFields {
					if other != name {
						pairs = append(pairs, d(other, 4))
					}
				}
				for other := range uacBoolFields {
					pairs = append(pairs, d(other, 1))
				}
				assert.Nil(t, get(computeUac(items(pairs...))))
			})
		})
	}
}

// TestComputeUacFromLiveCaptures decodes the real Policies\System key captured
// from stock Windows Server hosts with the same PowerShell script the
// registrykey resource runs over WinRM.
func TestComputeUacFromLiveCaptures(t *testing.T) {
	for _, v := range []string{"ws2016", "ws2022"} {
		t.Run(v, func(t *testing.T) {
			uac := computeUac(loadFixtureItems(t, v, "uac-items"))

			// values a stock Windows Server writes
			require.NotNil(t, uac.EnableLua)
			assert.True(t, *uac.EnableLua)
			require.NotNil(t, uac.ConsentPromptBehaviorAdmin)
			assert.Equal(t, int64(5), *uac.ConsentPromptBehaviorAdmin)
			require.NotNil(t, uac.ConsentPromptBehaviorUser)
			assert.Equal(t, int64(3), *uac.ConsentPromptBehaviorUser)
			require.NotNil(t, uac.EnableInstallerDetection)
			assert.True(t, *uac.EnableInstallerDetection)
			require.NotNil(t, uac.EnableSecureUiaPaths)
			assert.True(t, *uac.EnableSecureUiaPaths)
			require.NotNil(t, uac.EnableUiaDesktopToggle)
			assert.False(t, *uac.EnableUiaDesktopToggle)
			require.NotNil(t, uac.EnableVirtualization)
			assert.True(t, *uac.EnableVirtualization)
			require.NotNil(t, uac.PromptOnSecureDesktop)
			assert.True(t, *uac.PromptOnSecureDesktop)
			require.NotNil(t, uac.ValidateAdminCodeSignatures)
			assert.False(t, *uac.ValidateAdminCodeSignatures)

			// LocalAccountTokenFilterPolicy is absent on both releases and must
			// read null, not a configured false
			assert.Nil(t, uac.LocalAccountTokenFilterPolicy)
		})
	}

	// FilterAdministratorToken is the value that tells the two captures apart:
	// Windows Server 2016 writes an explicit 0, Windows Server 2022 leaves it
	// absent. Both must be kept distinct rather than collapsed to false.
	t.Run("FilterAdministratorToken explicit 0 on ws2016", func(t *testing.T) {
		uac := computeUac(loadFixtureItems(t, "ws2016", "uac-items"))
		require.NotNil(t, uac.FilterAdministratorToken)
		assert.False(t, *uac.FilterAdministratorToken)
	})
	t.Run("FilterAdministratorToken absent on ws2022", func(t *testing.T) {
		uac := computeUac(loadFixtureItems(t, "ws2022", "uac-items"))
		assert.Nil(t, uac.FilterAdministratorToken)
	})
}

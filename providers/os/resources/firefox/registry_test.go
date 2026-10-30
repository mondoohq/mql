// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package firefox

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sz(name, data string) RegistryValue {
	return RegistryValue{Name: name, Kind: "string", Data: data}
}

func dword(name string, data int64) RegistryValue {
	return RegistryValue{Name: name, Kind: "dword", Data: data}
}

// The whole point of the resource is that a check written once works on every
// platform, which means the registry has to come out in exactly the shape the
// JSON file produces. Each shape below was confirmed against a real Windows
// host with Firefox installed.

func TestNormalizeRegistry_FlatValues(t *testing.T) {
	// Shape 1 and 2: the value name is the policy name, and a DWORD carries the
	// boolean.
	params := NormalizeRegistry(RegistryKey{
		Values: []RegistryValue{
			sz("SSLVersionMin", "tls1.2"),
			dword("DisableTelemetry", 1),
			dword("DisableFirefoxScreenshots", 0),
		},
	})

	assert.Equal(t, "tls1.2", params["SSLVersionMin"])

	// A DWORD backing a boolean policy has to become a bool. Left as an int,
	// the same check would need `== true` on Linux and `== 1` on Windows, and
	// the resource would have bought nothing.
	assert.Equal(t, true, params["DisableTelemetry"])
	assert.Equal(t, false, params["DisableFirefoxScreenshots"])
}

func TestNormalizeRegistry_PreferencesSubkey(t *testing.T) {
	// Shape 3: Mozilla's ADMX stores Preferences as one registry value *per
	// preference*, not as one blob for all of them, and each value's data is a
	// JSON object.
	params := NormalizeRegistry(RegistryKey{
		Children: []RegistryKey{{
			Name: "Preferences",
			Values: []RegistryValue{
				sz("security.default_personal_cert", `{"Value":"Ask Every Time","Status":"locked"}`),
				sz("browser.tabs.warnOnClose", `{"Value":false,"Status":"locked"}`),
			},
		}},
	})

	prefs, ok := params["Preferences"].(map[string]any)
	require.True(t, ok, "Preferences must be an object keyed by preference name")

	cert, ok := prefs["security.default_personal_cert"].(map[string]any)
	require.True(t, ok, "each preference's JSON data must be parsed, not left as a string")
	assert.Equal(t, "Ask Every Time", cert["Value"])
	assert.Equal(t, "locked", cert["Status"])

	// Parsing rather than regex-matching the raw string is what lets a check
	// tell the boolean false from the string "false".
	warn := prefs["browser.tabs.warnOnClose"].(map[string]any)
	assert.Equal(t, false, warn["Value"])
}

func TestNormalizeRegistry_NamedSubkey(t *testing.T) {
	// Shape 4: a named sub-key holding several values that must agree, which
	// becomes one nested object instead of nine separate property lookups.
	params := NormalizeRegistry(RegistryKey{
		Children: []RegistryKey{{
			Name: "SanitizeOnShutdown",
			Values: []RegistryValue{
				dword("Cache", 1),
				dword("Cookies", 0),
				dword("Downloads", 1),
				dword("Locked", 1),
			},
		}},
	})

	assert.Equal(t, map[string]any{
		"Cache":     true,
		"Cookies":   false,
		"Downloads": true,
		"Locked":    true,
	}, params["SanitizeOnShutdown"])
}

func TestNormalizeRegistry_MatchesTheFileShape(t *testing.T) {
	// The contract in one assertion: the same policy expressed in the registry
	// and in a policies.json file must produce the same dict, so a check does
	// not have to know which platform it is running on.
	fromRegistry := NormalizeRegistry(RegistryKey{
		Values: []RegistryValue{
			sz("SSLVersionMin", "tls1.2"),
			dword("DisableTelemetry", 1),
		},
		Children: []RegistryKey{
			{
				Name: "SanitizeOnShutdown",
				Values: []RegistryValue{
					dword("Cache", 1),
					dword("Cookies", 0),
					dword("Locked", 1),
				},
			},
			{
				Name: "Preferences",
				Values: []RegistryValue{
					sz("security.default_personal_cert", `{"Value":"Ask Every Time","Status":"locked"}`),
				},
			},
		},
	})

	fromFile, err := ParsePolicyFile([]byte(`{
	  "policies": {
	    "SSLVersionMin": "tls1.2",
	    "DisableTelemetry": true,
	    "SanitizeOnShutdown": { "Cache": true, "Cookies": false, "Locked": true },
	    "Preferences": {
	      "security.default_personal_cert": { "Value": "Ask Every Time", "Status": "locked" }
	    }
	  }
	}`))
	require.NoError(t, err)

	// Compare through JSON so the int/float distinction of the two decoders
	// does not mask a real structural difference.
	registryJSON, err := json.Marshal(fromRegistry)
	require.NoError(t, err)
	fileJSON, err := json.Marshal(fromFile)
	require.NoError(t, err)
	assert.JSONEq(t, string(fileJSON), string(registryJSON))
}

func TestNormalizeRegistry_NumericPolicies(t *testing.T) {
	// PrivateBrowsingModeAvailability is one of only two number-typed top-level
	// policies, and its enum includes 0 and 1 — exactly the values that would
	// otherwise be mistaken for a boolean.
	t.Run("a genuinely numeric policy keeps its number", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{
			Values: []RegistryValue{dword("PrivateBrowsingModeAvailability", 1)},
		})
		assert.Equal(t, int64(1), params["PrivateBrowsingModeAvailability"])
	})

	t.Run("a nested numeric policy keeps its number", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{
			Children: []RegistryKey{{
				Name:   "Proxy",
				Values: []RegistryValue{dword("SOCKSVersion", 0)},
			}},
		})
		assert.Equal(t, map[string]any{"SOCKSVersion": int64(0)}, params["Proxy"])
	})

	t.Run("a number that cannot be a boolean stays a number", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{
			Values: []RegistryValue{dword("DefaultSerialGuardSetting", 3)},
		})
		assert.Equal(t, int64(3), params["DefaultSerialGuardSetting"])
	})
}

func TestNormalizeRegistry_StringHandling(t *testing.T) {
	t.Run("a plain string policy is left alone", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{Values: []RegistryValue{sz("SSLVersionMin", "tls1.2")}})
		assert.Equal(t, "tls1.2", params["SSLVersionMin"])
	})

	// Only a value that opens as a JSON object or array is parsed. Parsing
	// everything would turn the string "true" into a bool that was never in the
	// registry.
	t.Run("a string that merely looks boolean stays a string", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{Values: []RegistryValue{sz("SomeStringPolicy", "true")}})
		assert.Equal(t, "true", params["SomeStringPolicy"])
	})

	t.Run("a JSON array in a string value is parsed", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{
			Values: []RegistryValue{sz("DisabledCiphers", `["TLS_RSA_WITH_AES_128_CBC_SHA"]`)},
		})
		assert.Equal(t, []any{"TLS_RSA_WITH_AES_128_CBC_SHA"}, params["DisabledCiphers"])
	})

	t.Run("a string that opens like JSON but is broken stays a string", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{Values: []RegistryValue{sz("Broken", `{"a":`)}})
		assert.Equal(t, `{"a":`, params["Broken"])
	})

	t.Run("REG_MULTI_SZ is always JSON", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{
			Values: []RegistryValue{{
				Name: "WebsiteFilter",
				Kind: "multistring",
				Data: []any{`{"Block":`, `["<all_urls>"]}`},
			}},
		})
		assert.Equal(t, map[string]any{"Block": []any{"<all_urls>"}}, params["WebsiteFilter"])
	})
}

func TestNormalizeRegistry_Arrays(t *testing.T) {
	// Firefox reads a key whose entries are named "1", "2", … as an array
	// rather than an object.
	t.Run("values named 1..n become an array in order", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{
			Children: []RegistryKey{{
				Name: "Bookmarks",
				// Deliberately out of order: enumeration order is not something
				// we control when reading off-host.
				Values: []RegistryValue{sz("2", "second"), sz("1", "first"), sz("3", "third")},
			}},
		})
		assert.Equal(t, []any{"first", "second", "third"}, params["Bookmarks"])
	})

	t.Run("sub-keys named 1..n become an array of objects", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{
			Children: []RegistryKey{{
				Name: "Handlers",
				Children: []RegistryKey{
					{Name: "1", Values: []RegistryValue{sz("Name", "one")}},
					{Name: "2", Values: []RegistryValue{sz("Name", "two")}},
				},
			}},
		})
		assert.Equal(t, []any{
			map[string]any{"Name": "one"},
			map[string]any{"Name": "two"},
		}, params["Handlers"])
	})

	t.Run("a gap in the numbering is an object, not a truncated array", func(t *testing.T) {
		params := NormalizeRegistry(RegistryKey{
			Children: []RegistryKey{{
				Name:   "NotAnArray",
				Values: []RegistryValue{sz("1", "first"), sz("3", "third")},
			}},
		})
		assert.Equal(t, map[string]any{"1": "first", "3": "third"}, params["NotAnArray"])
	})
}

func TestNormalizeRegistry_ExtensionSettingsMerge(t *testing.T) {
	// ExtensionSettings can arrive both as a JSON-bearing value and as a
	// sub-key of the same name. Firefox merges the two with the value winning,
	// so neither form silently drops the other.
	params := NormalizeRegistry(RegistryKey{
		Values: []RegistryValue{
			sz("ExtensionSettings", `{"*":{"installation_mode":"blocked"}}`),
		},
		Children: []RegistryKey{{
			Name: "ExtensionSettings",
			Values: []RegistryValue{
				sz("uBlock0@raymondhill.net", `{"installation_mode":"force_installed"}`),
			},
		}},
	})

	settings, ok := params["ExtensionSettings"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, settings, "*", "the value form must survive the sub-key")
	assert.Contains(t, settings, "uBlock0@raymondhill.net", "the sub-key form must survive the value")
}

func TestNormalizeRegistry_Empty(t *testing.T) {
	// An unmanaged Windows host has no Mozilla policy key. That has to resolve
	// to nothing at all rather than an empty object, so the resource can report
	// it as null and a check reads false instead of passing vacuously.
	t.Run("an empty key contributes nothing", func(t *testing.T) {
		assert.Nil(t, NormalizeRegistry(RegistryKey{}))
	})

	t.Run("a key holding only empty sub-keys contributes nothing", func(t *testing.T) {
		assert.Nil(t, NormalizeRegistry(RegistryKey{
			Children: []RegistryKey{{Name: "SanitizeOnShutdown"}},
		}))
	})
}

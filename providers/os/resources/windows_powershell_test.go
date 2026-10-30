// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/registry"
)

// szItems builds the ordered value entries of a registry key holding REG_SZ
// values, preserving the original value-name casing the way readPowershellEntries
// does.
func szItems(pairs ...[2]string) []registry.RegistryKeyItem {
	items := make([]registry.RegistryKeyItem, 0, len(pairs))
	for _, kv := range pairs {
		items = append(items, registry.RegistryKeyItem{
			Key:   kv[0],
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: kv[1]},
		})
	}
	return items
}

// stringItems builds a name->item map mirroring readPowershellKey's lower-cased
// keys for string registry values.
func stringItems(kv map[string]string) map[string]registry.RegistryKeyItem {
	items := map[string]registry.RegistryKeyItem{}
	for k, v := range kv {
		items[k] = registry.RegistryKeyItem{
			Key:   k,
			Value: registry.RegistryKeyValue{String: v},
		}
	}
	return items
}

func TestPowershellBoolPtr(t *testing.T) {
	t.Run("present and 1 returns pointer to true", func(t *testing.T) {
		items := dwordItems(map[string]int64{"enablescriptblocklogging": 1})
		got := powershellBoolPtr(items, "EnableScriptBlockLogging")
		require.NotNil(t, got)
		assert.True(t, *got)
	})

	t.Run("present and explicit 0 returns pointer to false (not nil)", func(t *testing.T) {
		// nullable correctness: an explicit false must be distinguishable from absent
		items := dwordItems(map[string]int64{"enablescriptblocklogging": 0})
		got := powershellBoolPtr(items, "EnableScriptBlockLogging")
		require.NotNil(t, got)
		assert.False(t, *got)
	})

	t.Run("absent returns nil", func(t *testing.T) {
		assert.Nil(t, powershellBoolPtr(dwordItems(nil), "EnableScriptBlockLogging"))
		assert.Nil(t, powershellBoolPtr(nil, "EnableTranscripting"))
	})

	t.Run("value name matching is case insensitive", func(t *testing.T) {
		items := dwordItems(map[string]int64{"enabletranscripting": 1})
		got := powershellBoolPtr(items, "EnableTranscripting")
		require.NotNil(t, got)
		assert.True(t, *got)
	})

	t.Run("unrelated value names do not match", func(t *testing.T) {
		items := dwordItems(map[string]int64{"someothervalue": 1})
		assert.Nil(t, powershellBoolPtr(items, "EnableScriptBlockLogging"))
	})
}

func TestPowershellStringPtr(t *testing.T) {
	t.Run("present returns pointer to value", func(t *testing.T) {
		items := stringItems(map[string]string{"executionpolicy": "AllSigned"})
		got := powershellStringPtr(items, "ExecutionPolicy")
		require.NotNil(t, got)
		assert.Equal(t, "AllSigned", *got)
	})

	t.Run("present and explicit empty string returns pointer (not nil)", func(t *testing.T) {
		// nullable correctness: an explicit "" must be distinguishable from absent
		items := stringItems(map[string]string{"executionpolicy": ""})
		got := powershellStringPtr(items, "ExecutionPolicy")
		require.NotNil(t, got)
		assert.Equal(t, "", *got)
	})

	t.Run("absent returns nil", func(t *testing.T) {
		assert.Nil(t, powershellStringPtr(stringItems(nil), "ExecutionPolicy"))
		assert.Nil(t, powershellStringPtr(nil, "ExecutionPolicy"))
	})

	t.Run("value name matching is case insensitive", func(t *testing.T) {
		items := stringItems(map[string]string{"executionpolicy": "RemoteSigned"})
		got := powershellStringPtr(items, "ExecutionPolicy")
		require.NotNil(t, got)
		assert.Equal(t, "RemoteSigned", *got)
	})
}

func TestPowershellModuleNames(t *testing.T) {
	t.Run("value names are the module names", func(t *testing.T) {
		// Group Policy writes one value per module, named after the module
		entries := szItems(
			[2]string{"PSReadLine", "PSReadLine"},
			[2]string{"Microsoft.PowerShell.Management", "Microsoft.PowerShell.Management"},
		)
		assert.Equal(t,
			[]string{"Microsoft.PowerShell.Management", "PSReadLine"},
			powershellModuleNames(entries))
	})

	t.Run("the wildcard entry is reported as a module name", func(t *testing.T) {
		// "*" selects every module and is the most common real-world entry; it
		// must survive as a name rather than being read as a glob or dropped
		entries := szItems([2]string{"*", "*"})
		assert.Equal(t, []string{"*"}, powershellModuleNames(entries))
	})

	t.Run("the wildcard is kept alongside named modules", func(t *testing.T) {
		entries := szItems(
			[2]string{"PSReadLine", "PSReadLine"},
			[2]string{"*", "*"},
		)
		assert.Equal(t, []string{"*", "PSReadLine"}, powershellModuleNames(entries))
	})

	t.Run("names come from the value name, not its data", func(t *testing.T) {
		// the data is not always a copy of the name; the name is authoritative
		entries := szItems([2]string{"PSReadLine", ""})
		assert.Equal(t, []string{"PSReadLine"}, powershellModuleNames(entries))
	})

	t.Run("casing of the module name is preserved", func(t *testing.T) {
		entries := szItems([2]string{"Microsoft.PowerShell.Utility", "Microsoft.PowerShell.Utility"})
		assert.Equal(t, []string{"Microsoft.PowerShell.Utility"}, powershellModuleNames(entries))
	})

	t.Run("the default registry value carries no module name", func(t *testing.T) {
		// a key's unnamed default value is not a module selection
		entries := szItems([2]string{"", "whatever"}, [2]string{"PSReadLine", "PSReadLine"})
		assert.Equal(t, []string{"PSReadLine"}, powershellModuleNames(entries))
	})

	t.Run("a subkey with no values yields an empty list, not nil", func(t *testing.T) {
		// an enabled policy that names no module logs nothing; that is an empty
		// list, and it is a different fact from an absent subkey (null)
		got := powershellModuleNames(nil)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("the order is stable regardless of enumeration order", func(t *testing.T) {
		a := powershellModuleNames(szItems(
			[2]string{"Zeta", "Zeta"}, [2]string{"Alpha", "Alpha"}))
		b := powershellModuleNames(szItems(
			[2]string{"Alpha", "Alpha"}, [2]string{"Zeta", "Zeta"}))
		assert.Equal(t, a, b)
	})
}

func TestPowershellNewPolicyValuesAreNullWhenAbsent(t *testing.T) {
	// these are Group Policy values: on an unmanaged host the key is absent, and
	// absent means "not configured", never "disabled". Each new field must read
	// nil so it renders as null rather than a fabricated false or empty string.
	t.Run("script block invocation logging", func(t *testing.T) {
		assert.Nil(t, powershellBoolPtr(dwordItems(nil), "EnableScriptBlockInvocationLogging"))
	})

	t.Run("module logging", func(t *testing.T) {
		assert.Nil(t, powershellBoolPtr(dwordItems(nil), "EnableModuleLogging"))
	})

	t.Run("transcription invocation header", func(t *testing.T) {
		assert.Nil(t, powershellBoolPtr(dwordItems(nil), "EnableInvocationHeader"))
	})

	t.Run("transcript output directory", func(t *testing.T) {
		assert.Nil(t, powershellStringPtr(stringItems(nil), "OutputDirectory"))
	})

	t.Run("lockdown policy", func(t *testing.T) {
		assert.Nil(t, powershellLockdownPolicy(stringItems(nil)))
		assert.Nil(t, powershellLockdownPolicy(nil))
	})

	t.Run("a key holding only unrelated values still reads null", func(t *testing.T) {
		// the ScriptBlockLogging key exists with only EnableScriptBlockLogging
		// set: invocation logging is still "not configured"
		items := dwordItems(map[string]int64{"enablescriptblocklogging": 1})
		assert.Nil(t, powershellBoolPtr(items, "EnableScriptBlockInvocationLogging"))
	})
}

func TestPowershellNewPolicyValuesWhenPresent(t *testing.T) {
	t.Run("an explicit 0 is false, not null", func(t *testing.T) {
		items := dwordItems(map[string]int64{
			"enablescriptblockinvocationlogging": 0,
			"enablemodulelogging":                0,
			"enableinvocationheader":             0,
		})
		for _, name := range []string{
			"EnableScriptBlockInvocationLogging",
			"EnableModuleLogging",
			"EnableInvocationHeader",
		} {
			got := powershellBoolPtr(items, name)
			require.NotNil(t, got, name)
			assert.False(t, *got, name)
		}
	})

	t.Run("an enabled value is true", func(t *testing.T) {
		items := dwordItems(map[string]int64{
			"enablescriptblockinvocationlogging": 1,
			"enablemodulelogging":                1,
			"enableinvocationheader":             1,
		})
		for _, name := range []string{
			"EnableScriptBlockInvocationLogging",
			"EnableModuleLogging",
			"EnableInvocationHeader",
		} {
			got := powershellBoolPtr(items, name)
			require.NotNil(t, got, name)
			assert.True(t, *got, name)
		}
	})

	t.Run("the transcript output directory is read verbatim", func(t *testing.T) {
		items := stringItems(map[string]string{"outputdirectory": `\\logs\transcripts`})
		got := powershellStringPtr(items, "OutputDirectory")
		require.NotNil(t, got)
		assert.Equal(t, `\\logs\transcripts`, *got)
	})
}

func TestPowershellLockdownPolicy(t *testing.T) {
	lockdown := func(kind int, str string, num int64) map[string]registry.RegistryKeyItem {
		return map[string]registry.RegistryKeyItem{
			"__pslockdownpolicy": {
				Key:   powershellLockdownValue,
				Value: registry.RegistryKeyValue{Kind: kind, String: str, Number: num},
			},
		}
	}

	t.Run("a machine environment variable decodes from its string value", func(t *testing.T) {
		// __PSLockdownPolicy is an environment variable, so it is a REG_SZ whose
		// data is the number in text form
		got := powershellLockdownPolicy(lockdown(registry.SZ, "4", 0))
		require.NotNil(t, got)
		assert.Equal(t, int64(4), *got)
	})

	t.Run("an expandable string decodes the same way", func(t *testing.T) {
		got := powershellLockdownPolicy(lockdown(registry.EXPAND_SZ, "8", 0))
		require.NotNil(t, got)
		assert.Equal(t, int64(8), *got)
	})

	t.Run("surrounding whitespace is tolerated", func(t *testing.T) {
		got := powershellLockdownPolicy(lockdown(registry.SZ, " 4 ", 0))
		require.NotNil(t, got)
		assert.Equal(t, int64(4), *got)
	})

	t.Run("a DWORD decodes from its numeric value", func(t *testing.T) {
		// not how Windows writes an environment variable, but it is written this
		// way by hand often enough that reading the empty string would be wrong
		got := powershellLockdownPolicy(lockdown(registry.DWORD, "", 4))
		require.NotNil(t, got)
		assert.Equal(t, int64(4), *got)
	})

	t.Run("an explicit 0 is a value, not an absence", func(t *testing.T) {
		got := powershellLockdownPolicy(lockdown(registry.SZ, "0", 0))
		require.NotNil(t, got)
		assert.Equal(t, int64(0), *got)
	})

	t.Run("a non-numeric value reads null", func(t *testing.T) {
		// PowerShell converts the value to a uint and cannot use it otherwise,
		// so nothing can be claimed about the lockdown state
		assert.Nil(t, powershellLockdownPolicy(lockdown(registry.SZ, "enabled", 0)))
	})

	t.Run("an empty string reads null", func(t *testing.T) {
		assert.Nil(t, powershellLockdownPolicy(lockdown(registry.SZ, "", 0)))
	})

	t.Run("the value name matches case insensitively", func(t *testing.T) {
		// readPowershellKey lower-cases the name; the lookup must agree
		got := powershellLockdownPolicy(lockdown(registry.SZ, "4", 0))
		require.NotNil(t, got)
	})

	t.Run("an unrelated environment variable does not match", func(t *testing.T) {
		items := stringItems(map[string]string{"path": `C:\Windows`})
		assert.Nil(t, powershellLockdownPolicy(items))
	})
}

func TestPowershellLanguageMode(t *testing.T) {
	// the mapping mirrors PowerShell's GetLockdownPolicyForResult: the audit flag
	// (0x8) is tested before the enforcement flag (0x4), and only enforcement
	// constrains the session
	t.Run("the enforcement flag constrains the session", func(t *testing.T) {
		assert.Equal(t, "ConstrainedLanguage", powershellLanguageMode(4))
	})

	t.Run("the audit flag does not constrain the session", func(t *testing.T) {
		assert.Equal(t, "FullLanguage", powershellLanguageMode(8))
	})

	t.Run("audit wins over enforcement when both flags are set", func(t *testing.T) {
		assert.Equal(t, "FullLanguage", powershellLanguageMode(12))
	})

	t.Run("no flag leaves the session unrestricted", func(t *testing.T) {
		assert.Equal(t, "FullLanguage", powershellLanguageMode(0))
	})

	t.Run("unrelated state bits do not constrain the session", func(t *testing.T) {
		// 0x1 is secure boot and 0x2 is debug policy; neither is a language-mode
		// decision, and 0x80000000 only marks the state as defined
		assert.Equal(t, "FullLanguage", powershellLanguageMode(1))
		assert.Equal(t, "FullLanguage", powershellLanguageMode(2))
		assert.Equal(t, "FullLanguage", powershellLanguageMode(3))
	})

	t.Run("the enforcement flag is honored alongside unrelated bits", func(t *testing.T) {
		assert.Equal(t, "ConstrainedLanguage", powershellLanguageMode(4|1))
		assert.Equal(t, "ConstrainedLanguage", powershellLanguageMode(4|2))
	})
}

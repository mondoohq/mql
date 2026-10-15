// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestSingleQuote(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"plain", `HKLM\Software\Mondoo`, `'HKLM\Software\Mondoo'`},
		{"empty", "", "''"},
		{"space", `C:\Program Files\app`, `'C:\Program Files\app'`},
		{"trailing backslash stays literal", `C:\dir\`, `'C:\dir\'`},
		{"dollar is not expanded", `C:\$env:SystemRoot`, `'C:\$env:SystemRoot'`},
		{"quote is doubled", `key's name`, `'key''s name'`},
		{"quote plus terminator", `x';whoami;'`, `'x'';whoami;'''`},
		{"double quote needs no escape", `say "hi"`, `'say "hi"'`},
		// pwsh 7.6 printed "C:\x" then "INJECTED" for the unescaped form
		{"right single quotation mark is doubled", "C:\\x\u2019;whoami;\u2019", "'C:\\x\u2019\u2019;whoami;\u2019\u2019'"},
		{"left single quotation mark is doubled", "a\u2018b", "'a\u2018\u2018b'"},
		{"low-9 quotation mark is doubled", "a\u201ab", "'a\u201a\u201ab'"},
		{"reversed-9 quotation mark is doubled", "a\u201bb", "'a\u201b\u201bb'"},
		{"double quotation marks need no escape", "a\u201cb\u201d", "'a\u201cb\u201d'"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, powershell.SingleQuote(test.value))
		})
	}
}

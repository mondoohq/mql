// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestClassifyOpenKeyError(t *testing.T) {
	const path = `SECURITY`

	// RegOpenKeyEx on HKLM\SECURITY for anyone but SYSTEM
	denied := classifyOpenKeyError(path, syscall.Errno(5))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(denied))
	assert.Contains(t, denied.Error(), path)
	assert.True(t, errors.Is(denied, syscall.Errno(5)), "the Win32 error must stay reachable")

	// ERROR_INVALID_HANDLE says nothing the user can act on
	other := classifyOpenKeyError(path, syscall.Errno(6))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(other))
	assert.Contains(t, other.Error(), path)
}

// A value neither reg.exe nor GetValueKind() could type is a refusal only when
// the session ran outside FullLanguage.
func TestUntypedValueKind(t *testing.T) {
	tests := []struct {
		languageMode string
		want         llx.ErrorKind
	}{
		{`"ConstrainedLanguage"`, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{`"RestrictedLanguage"`, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{`"FullLanguage"`, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{`null`, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.languageMode, func(t *testing.T) {
			payload := `[{"key":"日本","value":{"data":7,"type":null,"kind":null,"languageMode":` + tt.languageMode + `}}]`
			items, err := ParsePowershellRegistryKeyItems(strings.NewReader(payload))
			require.NoError(t, err)
			require.Len(t, items, 1)
			require.Error(t, items[0].Value.Err)
			assert.Equal(t, tt.want, llx.KindOf(items[0].Value.Err))
			assert.Contains(t, items[0].Value.Err.Error(), "could not determine the registry value type")
		})
	}
}

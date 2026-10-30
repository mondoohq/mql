// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordState(t *testing.T) {
	st := parseFile(t, "testdata/passwd_aix73.txt")
	for name, want := range map[string][2]string{
		// the stock PowerVS image ships root without a password
		"root":     {StateEmpty, ""},
		"daemon":   {StateDisabled, ""},
		"mqluser1": {StateHashed, "ssha512"},
		"legacy":   {StateHashed, "crypt"},
		"nopass":   {StateMissing, ""},
	} {
		stanza := st.Get(name)
		require.NotNil(t, stanza, name)
		v, ok := stanza.Get("password")
		state, algo := PasswordState(v, ok)
		assert.Equal(t, want[0], state, name)
		assert.Equal(t, want[1], algo, name)
	}
}

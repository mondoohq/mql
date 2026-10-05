// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cli_errors "go.mondoo.com/mql/cli/errors"
)

func TestLoginCmd_ProvidersURLFlagRemoved(t *testing.T) {
	// providers-url was deprecated in favor of updates-url and removed in v14.
	// Guard against it being reintroduced.
	assert.Nil(t, LoginCmd.Flags().Lookup("providers-url"),
		"providers-url was removed in v14; use updates-url instead")
}

func TestLoginCmd_UpdatesURLFlag(t *testing.T) {
	flag := LoginCmd.Flags().Lookup("updates-url")
	require.NotNil(t, flag, "updates-url flag should be defined")
	assert.Equal(t, "", flag.DefValue, "updates-url default value should be empty")
	assert.Equal(t, "string", flag.Value.Type(), "updates-url should be a string flag")
}

func TestLoginCmd_GetUpdatesURLFromFlag(t *testing.T) {
	// Reset any previous flag values
	err := LoginCmd.Flags().Set("updates-url", "")
	require.NoError(t, err)

	// Test setting the flag value
	err = LoginCmd.Flags().Set("updates-url", "https://internal.example.com")
	require.NoError(t, err)

	// Retrieve the value
	updatesURL, err := LoginCmd.Flags().GetString("updates-url")
	require.NoError(t, err)
	assert.Equal(t, "https://internal.example.com", updatesURL)

	// Reset the flag for other tests
	err = LoginCmd.Flags().Set("updates-url", "")
	require.NoError(t, err)
}

func TestLoginCmd_AllFlags(t *testing.T) {
	// Verify all expected flags are present on LoginCmd
	expectedFlags := []struct {
		name         string
		shorthand    string
		defaultValue string
		flagType     string
	}{
		{"token", "t", "", "string"},
		{"annotation", "", "[]", "stringToString"},
		{"updates-url", "", "", "string"},
		{"name", "", "", "string"},
		{"api-endpoint", "", "", "string"},
		{"timer", "", "0", "int"},
		{"splay", "", "0", "int"},
	}

	for _, ef := range expectedFlags {
		t.Run(ef.name, func(t *testing.T) {
			flag := LoginCmd.Flags().Lookup(ef.name)
			require.NotNil(t, flag, "flag %s should be defined", ef.name)
			assert.Equal(t, ef.defaultValue, flag.DefValue, "flag %s default value mismatch", ef.name)
			assert.Equal(t, ef.flagType, flag.Value.Type(), "flag %s type mismatch", ef.name)
			if ef.shorthand != "" {
				assert.Equal(t, ef.shorthand, flag.Shorthand, "flag %s shorthand mismatch", ef.name)
			}
		})
	}
}

// A token rejected before registration must fail the command (exit 1), not
// return nil: scripts check the exit code.
func TestLoginCmd_RejectedTokenExitsNonZero(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	expired := b64([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		b64([]byte(`{"exp":1,"space":"//captain.api.mondoo.app/spaces/test"}`)) + ".sig"

	for name, token := range map[string]string{
		"expired":     expired,
		"unparseable": "not-a-jwt",
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, LoginCmd.Flags().Set("token", token))
			// LoginCmd is package-level: reset what RunE mutates so each case
			// asserts its own effect. Not t.Parallel() for the same reason.
			t.Cleanup(func() {
				_ = LoginCmd.Flags().Set("token", "")
				LoginCmd.SilenceUsage = false
				LoginCmd.SilenceErrors = false
			})

			err := LoginCmd.RunE(LoginCmd, nil)
			assert.Equal(t, cli_errors.ExitCode1WithoutError, err)
			assert.True(t, LoginCmd.SilenceUsage, "a rejected token is not a usage error")
		})
	}
}

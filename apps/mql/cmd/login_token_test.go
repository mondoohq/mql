// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginCmd_DeviceFlagRemoved(t *testing.T) {
	// The login mode is picked automatically; --no-browser is the only override.
	assert.Nil(t, LoginCmd.Flags().Lookup("device"))
}

func TestRegistrationToken(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}

	token, source := registrationToken("flag-token", env(map[string]string{registrationTokenEnv: "env-token"}))
	assert.Equal(t, "flag-token", token, "--token wins over the environment")
	assert.Equal(t, "--token", source)

	token, source = registrationToken("", env(map[string]string{registrationTokenEnv: " env-token\n"}))
	assert.Equal(t, "env-token", token)
	assert.Equal(t, registrationTokenEnv, source)

	token, source = registrationToken("  ", env(map[string]string{registrationTokenEnv: "env-token"}))
	assert.Equal(t, "env-token", token, "a blank flag falls back to the environment")
	assert.Equal(t, registrationTokenEnv, source)

	token, source = registrationToken("", env(nil))
	assert.Empty(t, token)
	assert.Empty(t, source)
}

func TestCheckCanLogInInteractively(t *testing.T) {
	assert.NoError(t, checkCanLogInInteractively(oauthLoginFlags{interactive: true}))

	err := checkCanLogInInteractively(oauthLoginFlags{interactive: false, binaryName: "cnspec"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errNoCredentials))
	assert.Equal(t, "no credentials: run `cnspec login` in a terminal, or pass a registration token with --token or MONDOO_REGISTRATION_TOKEN", err.Error())
}

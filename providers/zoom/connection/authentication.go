// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Flag options
const (
	OPTION_ACCOUNT_ID    = "account-id"
	OPTION_CLIENT_ID     = "client-id"
	OPTION_CLIENT_SECRET = "client-secret"
)

// Zoom Server-to-Server OAuth environment variables
const (
	ZOOM_ACCOUNT_ID_VAR    = "ZOOM_ACCOUNT_ID"
	ZOOM_CLIENT_ID_VAR     = "ZOOM_CLIENT_ID"
	ZOOM_CLIENT_SECRET_VAR = "ZOOM_CLIENT_SECRET"
)

// GetAccountID returns the Zoom account ID, preferring the environment
// variable over the --account-id flag.
func GetAccountID(conf *inventory.Config) (string, bool) {
	return getOptionValueFrom(conf.Options, ZOOM_ACCOUNT_ID_VAR, OPTION_ACCOUNT_ID)
}

// GetClientID returns the Server-to-Server OAuth client ID, preferring the
// environment variable over the --client-id flag.
func GetClientID(conf *inventory.Config) (string, bool) {
	return getOptionValueFrom(conf.Options, ZOOM_CLIENT_ID_VAR, OPTION_CLIENT_ID)
}

// GetClientSecret returns the Server-to-Server OAuth client secret. It
// checks the environment variable, then a password credential (as injected
// by --client-secret or the vault), in that order.
func GetClientSecret(conf *inventory.Config) (string, bool) {
	if secret := os.Getenv(ZOOM_CLIENT_SECRET_VAR); secret != "" {
		return secret, true
	}
	if cred, ok := firstPasswordCredential(conf); ok {
		return string(cred), true
	}
	return "", false
}

// firstPasswordCredential returns the secret bytes of the first non-empty
// password credential in conf, or false if none is present.
func firstPasswordCredential(conf *inventory.Config) ([]byte, bool) {
	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			log.Warn().
				Str("credential-type", cred.Type.String()).
				Msg("unsupported credential type for Zoom provider")
			continue
		}
		if len(cred.Secret) == 0 {
			log.Warn().
				Str("credential-type", cred.Type.String()).
				Msg("empty credentials")
			continue
		}
		return cred.Secret, true
	}
	return nil, false
}

// getOptionValueFrom resolves a value that may be set through an environment
// variable or a CLI flag, giving the environment variable precedence over the
// flag. This matches the doc comments on GetAccountID/GetClientID and the
// env-first behavior of GetClientSecret.
func getOptionValueFrom(options map[string]string, envVar string, option string) (string, bool) {
	// flag first
	value := ""
	if v, ok := options[option]; ok && len(v) != 0 {
		value = v
	}
	// environment variable takes precedence
	if envVal := os.Getenv(envVar); envVal != "" {
		value = envVal
	}
	return value, len(value) != 0
}

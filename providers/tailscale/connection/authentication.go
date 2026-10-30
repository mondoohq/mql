// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// There are two authentication methods
//
// 1. API access token
// 2. OAuth client (id and secret)
//
// We give precedence to OAuth client auth method
type AuthMethod int

const (
	NoAuthMethod AuthMethod = iota
	TokenAuthMethod
	OAuthMethod
)

func AuthenticationMethod(conf *inventory.Config) AuthMethod {
	if _, ok := GetClientID(conf); ok {
		return OAuthMethod
	}
	if _, ok := GetClientSecret(conf); ok {
		return OAuthMethod
	}
	if _, ok := GetToken(conf); ok {
		return TokenAuthMethod
	}
	return NoAuthMethod
}

func GetToken(conf *inventory.Config) (string, bool) {
	// env variable
	token, set := getOptionValueFrom(conf.Options, TAILSCALE_API_KEY_VAR, OPTION_TOKEN)

	// special case for tokens that are passed as credentials. When an OAuth
	// client id is configured the password credential is the client secret, not
	// the API token, so we only fall back to credentials in token mode.
	if _, oauth := getOptionValueFrom(conf.Options, TAILSCALE_OAUTH_CLIENT_ID_VAR, OPTION_CLIENT_ID); !oauth {
		if cred, ok := firstPasswordCredential(conf); ok {
			token = string(cred)
			set = true
		}
	}

	return token, set
}
func GetClientID(conf *inventory.Config) (string, bool) {
	return getOptionValueFrom(conf.Options, TAILSCALE_OAUTH_CLIENT_ID_VAR, OPTION_CLIENT_ID)
}
func GetClientSecret(conf *inventory.Config) (string, bool) {
	secret, set := getOptionValueFrom(conf.Options, TAILSCALE_OAUTH_CLIENT_SECRET_VAR, OPTION_CLIENT_SECRET)

	// special case for OAuth client secrets that are passed as credentials. We
	// only treat password credentials as the client secret when an OAuth client
	// id is configured — otherwise the credential is the API token (see
	// GetToken).
	if _, oauth := getOptionValueFrom(conf.Options, TAILSCALE_OAUTH_CLIENT_ID_VAR, OPTION_CLIENT_ID); oauth {
		if cred, ok := firstPasswordCredential(conf); ok {
			secret = string(cred)
			set = true
		}
	}

	return secret, set
}

// firstPasswordCredential returns the secret bytes of the first non-empty
// password credential in conf, or false if none is present.
func firstPasswordCredential(conf *inventory.Config) ([]byte, bool) {
	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			log.Warn().
				Str("credential-type", cred.Type.String()).
				Msg("unsupported credential type for Tailscale provider")
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
func GetBaseURL(conf *inventory.Config) (string, bool) {
	return getOptionValueFrom(conf.Options, TAILSCALE_BASE_URL_VAR, OPTION_BASE_URL)
}
func GetTailnet(conf *inventory.Config) (string, bool) {
	return getOptionValueFrom(conf.Options, TAILSCALE_TAILNET_VAR, OPTION_TAILNET)
}

func getOptionValueFrom(options map[string]string, envVar string, option string) (string, bool) {
	// env variable
	value := os.Getenv(envVar)
	// flag
	v, ok := options[option]
	if ok && len(v) != 0 {
		value = string(v)
	}
	return value, len(value) != 0
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	OPTION_TOKEN    = "token"
	OPTION_ENDPOINT = "endpoint"

	HCLOUD_TOKEN_VAR    = "HCLOUD_TOKEN"
	HCLOUD_ENDPOINT_VAR = "HCLOUD_ENDPOINT"
)

// GetToken resolves the Hetzner Cloud API token in this order:
// 1. password credential attached to the inventory config
// 2. --token flag (Options[OPTION_TOKEN])
// 3. HCLOUD_TOKEN environment variable
func GetToken(conf *inventory.Config) (string, bool) {
	token, set := getOptionValueFrom(conf.Options, HCLOUD_TOKEN_VAR, OPTION_TOKEN)

	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			log.Warn().Str("credential-type", cred.Type.String()).Msg("hetzner> unsupported credential type")
			continue
		}
		if len(cred.Secret) == 0 {
			continue
		}
		token = string(cred.Secret)
		set = true
	}
	return token, set
}

func GetEndpoint(conf *inventory.Config) (string, bool) {
	return getOptionValueFrom(conf.Options, HCLOUD_ENDPOINT_VAR, OPTION_ENDPOINT)
}

func getOptionValueFrom(options map[string]string, envVar, option string) (string, bool) {
	value := os.Getenv(envVar)
	if v, ok := options[option]; ok && len(v) != 0 {
		value = v
	}
	return value, len(value) != 0
}

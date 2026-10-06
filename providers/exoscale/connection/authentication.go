// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	OPTION_API_KEY    = "api-key"
	OPTION_API_SECRET = "api-secret"
	OPTION_ZONES      = "zones"

	// EXOSCALE_API_KEY and EXOSCALE_API_SECRET are what the Exoscale CLI,
	// SDK, and Terraform provider read. The short EXOSCALE_KEY and
	// EXOSCALE_SECRET are the legacy names the Terraform provider still
	// accepts, so both are honored.
	EXOSCALE_API_KEY_VAR       = "EXOSCALE_API_KEY"
	EXOSCALE_API_SECRET_VAR    = "EXOSCALE_API_SECRET"
	EXOSCALE_LEGACY_KEY_VAR    = "EXOSCALE_KEY"
	EXOSCALE_LEGACY_SECRET_VAR = "EXOSCALE_SECRET"
	EXOSCALE_ZONES_VAR         = "EXOSCALE_ZONES"
)

// GetCredentials resolves the API key and secret in this order, a later
// source overriding an earlier one:
//  1. EXOSCALE_KEY / EXOSCALE_SECRET (legacy names)
//  2. EXOSCALE_API_KEY / EXOSCALE_API_SECRET
//  3. a password credential on the inventory config (user = key, secret = secret)
func GetCredentials(conf *inventory.Config) (string, string) {
	key := firstEnv(EXOSCALE_API_KEY_VAR, EXOSCALE_LEGACY_KEY_VAR)
	secret := firstEnv(EXOSCALE_API_SECRET_VAR, EXOSCALE_LEGACY_SECRET_VAR)

	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			log.Warn().Str("credential-type", cred.Type.String()).Msg("exoscale> unsupported credential type")
			continue
		}
		if cred.User != "" {
			key = cred.User
		}
		if len(cred.Secret) != 0 {
			secret = string(cred.Secret)
		}
	}
	return key, secret
}

// GetZones returns the zones the connection is restricted to, or nil for
// every zone the organization can reach.
func GetZones(conf *inventory.Config) []string {
	raw := os.Getenv(EXOSCALE_ZONES_VAR)
	if v, ok := conf.Options[OPTION_ZONES]; ok && v != "" {
		raw = v
	}
	return splitList(raw)
}

func splitList(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

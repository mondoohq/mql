// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	OptionAPIKeyFile = "api-key-file"
	OptionRegions    = "regions"

	// IBMCLOUD_API_KEY is what the ibmcloud CLI and the IBM SDKs read; the
	// Terraform provider also accepts IC_API_KEY, so both are honored.
	APIKeyEnvVar       = "IBMCLOUD_API_KEY"
	LegacyAPIKeyEnvVar = "IC_API_KEY"
	RegionsEnvVar      = "IBMCLOUD_REGIONS"
)

// apiKeyFile is the JSON document `ibmcloud iam api-key-create --file` and the
// IBM Cloud console download write.
type apiKeyFile struct {
	APIKey string `json:"apikey"`
}

// GetAPIKey resolves the API key in this order, a later source overriding an
// earlier one:
//  1. IC_API_KEY (legacy name)
//  2. IBMCLOUD_API_KEY
//  3. the file named by --api-key-file
//  4. a password credential on the inventory config (--api-key)
func GetAPIKey(conf *inventory.Config) (string, error) {
	key := firstEnv(APIKeyEnvVar, LegacyAPIKeyEnvVar)

	if path := conf.Options[OptionAPIKeyFile]; path != "" {
		k, err := readAPIKeyFile(path)
		if err != nil {
			return "", err
		}
		key = k
	}

	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password {
			log.Warn().Str("credential-type", cred.Type.String()).Msg("ibm> unsupported credential type")
			continue
		}
		if len(cred.Secret) != 0 {
			key = string(cred.Secret)
		}
	}
	return key, nil
}

func readAPIKeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading the API key file: %w", err)
	}
	var f apiKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return "", fmt.Errorf("the API key file %s is not an IBM Cloud API key JSON document: %w", path, err)
	}
	if f.APIKey == "" {
		return "", errors.New("the API key file " + path + " has no apikey field")
	}
	return f.APIKey, nil
}

// GetRegions returns the VPC regions the connection is restricted to, or nil
// for every region the account can reach.
func GetRegions(conf *inventory.Config) []string {
	raw := os.Getenv(RegionsEnvVar)
	if v := conf.Options[OptionRegions]; v != "" {
		raw = v
	}
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

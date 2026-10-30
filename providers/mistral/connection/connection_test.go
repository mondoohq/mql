// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestTokenFromConfig(t *testing.T) {
	passwordCred := vault.NewPasswordCredential("", "from-credential")
	otherCred := &vault.Credential{Type: vault.CredentialType_json, Secret: []byte("ignored")}

	tests := []struct {
		name      string
		apiKeyEnv string
		keyEnv    string
		conf      *inventory.Config
		want      string
	}{
		{
			name:      "MISTRAL_API_KEY env",
			apiKeyEnv: "from-api-key-env",
			conf:      &inventory.Config{},
			want:      "from-api-key-env",
		},
		{
			name:   "MISTRAL_KEY fallback when API key empty",
			keyEnv: "from-key-env",
			conf:   &inventory.Config{},
			want:   "from-key-env",
		},
		{
			name:      "option overrides env",
			apiKeyEnv: "from-env",
			conf:      &inventory.Config{Options: map[string]string{OptionToken: "from-option"}},
			want:      "from-option",
		},
		{
			name:      "credential overrides option and env",
			apiKeyEnv: "from-env",
			conf: &inventory.Config{
				Options:     map[string]string{OptionToken: "from-option"},
				Credentials: []*vault.Credential{passwordCred},
			},
			want: "from-credential",
		},
		{
			name: "non-password credential is ignored",
			conf: &inventory.Config{
				Options:     map[string]string{OptionToken: "from-option"},
				Credentials: []*vault.Credential{otherCred},
			},
			want: "from-option",
		},
		{
			name:      "surrounding whitespace trimmed",
			apiKeyEnv: "  spaced-token  ",
			conf:      &inventory.Config{},
			want:      "spaced-token",
		},
		{
			name: "nothing configured yields empty",
			conf: &inventory.Config{},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Neutralize any host env, then apply the case's values.
			t.Setenv("MISTRAL_API_KEY", tc.apiKeyEnv)
			t.Setenv("MISTRAL_KEY", tc.keyEnv)

			assert.Equal(t, tc.want, tokenFromConfig(tc.conf))
		})
	}
}

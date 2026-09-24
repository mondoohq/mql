// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"os"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Secret resolves the API token a connection authenticates with, in the order a
// hosted scan and a CLI scan respectively supply it:
//
//  1. an inventory VAULT CREDENTIAL, which is how a server-driven scan delivers
//     it — the runner resolves the vault reference and hands the plaintext in
//     `conf.Credentials`, and it never appears in the job's options;
//  2. the connection OPTION, which is what `ParseCLI` writes from the --flag;
//  3. the ENVIRONMENT variable, the documented flagless path.
//
// The vault credential comes first on purpose. An option is the weaker source of
// the two — it travels in the job payload, is logged wherever options are, and a
// hosted scan has no reason to use it — so when both are present the credential
// is the one that was meant.
//
// Only `password` credentials are read. Every Atlassian secret this provider
// takes is a bearer token or a basic-auth password; a private key handed to an
// Atlassian connection is a misconfiguration, and warning is what makes it
// visible rather than silently falling through to an empty token.
func Secret(conf *inventory.Config, option, envVar string) string {
	for _, cred := range conf.GetCredentials() {
		if cred == nil {
			continue
		}
		if cred.Type != vault.CredentialType_password {
			log.Warn().
				Str("credential-type", cred.Type.String()).
				Msg("unsupported credential type for the Atlassian provider")
			continue
		}
		if len(cred.Secret) > 0 {
			return string(cred.Secret)
		}
		// A password credential whose Password field was set rather than its
		// Secret bytes. Both shapes reach providers, so reading only one of them
		// is how a credential that resolved fine looks empty.
		if cred.Password != "" {
			return cred.Password
		}
	}
	if v := conf.GetOptions()[option]; v != "" {
		return v
	}
	return os.Getenv(envVar)
}

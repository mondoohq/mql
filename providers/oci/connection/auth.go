// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
)

// Authentication methods accepted by the --auth-method flag.
//
// api-key is the default and covers both explicit credentials and the
// ~/.oci/config file. The rest let the scanner run without a long-lived private
// key on disk, which is the deployment OCI's own guidance recommends: an
// instance principal for a compute instance, a resource principal for Functions,
// a workload identity for an OKE pod, and a security token for a
// `oci session authenticate` profile.
const (
	authMethodAPIKey            = "api-key"
	authMethodInstancePrincipal = "instance-principal"
	authMethodResourcePrincipal = "resource-principal"
	authMethodWorkloadIdentity  = "workload-identity"
	authMethodSecurityToken     = "security-token"
)

// SupportedAuthMethods lists every accepted --auth-method value, for CLI
// validation and error messages.
var SupportedAuthMethods = []string{
	authMethodAPIKey,
	authMethodInstancePrincipal,
	authMethodResourcePrincipal,
	authMethodWorkloadIdentity,
	authMethodSecurityToken,
}

// usesPrincipalAuth reports whether the caller selected one of the keyless
// principal flows rather than the default API-key path. The argument is the
// --auth-method flag value, already validated against SupportedAuthMethods by
// ParseCLI - it names an authentication method, and carries no secret material.
func usesPrincipalAuth(method string) bool {
	switch method {
	case "", authMethodAPIKey:
		return false
	default:
		return true
	}
}

// defaultOciConfigPath reports the SDK's default configuration file location.
func defaultOciConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Join(errors.New("cannot determine the home directory for the default OCI config file"), err)
	}
	return filepath.Join(home, ".oci", "config"), nil
}

// principalConfigProvider builds a configuration provider for one of the
// non-API-key authentication methods.
func principalConfigProvider(method, profile string) (common.ConfigurationProvider, error) {
	switch method {
	case authMethodInstancePrincipal:
		return auth.InstancePrincipalConfigurationProvider()
	case authMethodResourcePrincipal:
		return auth.ResourcePrincipalConfigurationProvider()
	case authMethodWorkloadIdentity:
		return auth.OkeWorkloadIdentityConfigurationProvider()
	case authMethodSecurityToken:
		configFile, err := defaultOciConfigPath()
		if err != nil {
			return nil, err
		}
		if profile == "" {
			profile = "DEFAULT"
		}
		return common.ConfigurationProviderForSessionTokenWithProfile(configFile, profile, "")
	default:
		return nil, errors.New("unsupported OCI auth-method: " + method)
	}
}

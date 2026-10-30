// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/utils/v2/openstack/clientconfig"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// authResult is the resolved auth configuration after merging clouds.yaml,
// OS_* env vars, CLI flags, and inventory credentials.
type authResult struct {
	authOpts gophercloud.AuthOptions
	region   string
}

// resolveAuth merges flag values, password credentials, and clientconfig's
// clouds.yaml/env-var resolution into a single AuthOptions.
//
// Passwords are deliberately NOT read from conf.Options; they must arrive
// either as a vault password credential (preferred — ParseCLI routes the
// --password flag here) or through OS_PASSWORD / clouds.yaml, both of which
// clientconfig resolves itself. Putting the password in conf.Options would
// risk it persisting to the inventory file or leaking through debug logs.
//
// Precedence (highest to lowest):
//  1. CLI flags for non-secret fields (set via Options)
//  2. password credential attached to the inventory config (--password, --ask-pass)
//  3. clouds.yaml entry referenced by --cloud, then OS_* env vars
func resolveAuth(conf *inventory.Config) (*authResult, error) {
	opts := conf.Options
	if opts == nil {
		opts = map[string]string{}
	}

	authInfo := &clientconfig.AuthInfo{
		AuthURL:                     opts[OPTION_AUTH_URL],
		Username:                    opts[OPTION_USERNAME],
		ProjectName:                 opts[OPTION_PROJECT_NAME],
		ProjectID:                   opts[OPTION_PROJECT_ID],
		UserDomainName:              opts[OPTION_USER_DOMAIN_NAME],
		UserDomainID:                opts[OPTION_USER_DOMAIN_ID],
		ProjectDomainName:           opts[OPTION_PROJECT_DOMAIN_NAME],
		ProjectDomainID:             opts[OPTION_PROJECT_DOMAIN_ID],
		ApplicationCredentialID:     opts[OPTION_APPLICATION_CREDENTIAL_ID],
		ApplicationCredentialName:   opts[OPTION_APPLICATION_CREDENTIAL_NAME],
		ApplicationCredentialSecret: opts[OPTION_APPLICATION_CREDENTIAL_SECRET],
	}

	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password && len(cred.Secret) > 0 {
			authInfo.Password = string(cred.Secret)
		}
	}

	clientOpts := &clientconfig.ClientOpts{
		Cloud:      opts[OPTION_CLOUD],
		AuthInfo:   authInfo,
		RegionName: opts[OPTION_REGION],
	}

	authOpts, err := clientconfig.AuthOptions(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve OpenStack auth: %w", err)
	}
	authOpts.AllowReauth = true

	// Fall back to the clouds.yaml region when the caller didn't supply
	// --region. clientOpts.RegionName is just the explicit input; the
	// resolved region from clouds.yaml lives on the Cloud record.
	region := opts[OPTION_REGION]
	if region == "" {
		if cloud, cerr := clientconfig.GetCloudFromYAML(clientOpts); cerr == nil && cloud != nil {
			region = cloud.RegionName
		}
	}

	return &authResult{authOpts: *authOpts, region: region}, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"go.mondoo.com/mql/providers-sdk/v1/util/azauth"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// EntraScope asks Entra for a token that Azure DevOps accepts. The prefix
	// is the well-known application id of Azure DevOps.
	EntraScope = "499b84ac-1321-427f-aa17-267ca6975798/.default"

	// GitCredentialUser is the user name sent with a token over git smart-HTTP.
	// Azure DevOps ignores the user name, but go-git falls back to putting the
	// token in the user name when it is empty. Which non-empty value the Entra
	// token needs has not been proven against a real organization; the clone
	// check in the plan settles it.
	GitCredentialUser = "oauth2"

	// tokenRefreshFraction is how much of an Entra token's lifetime may pass
	// before the next request mints a new one.
	tokenRefreshFraction = 0.8
)

// AuthMode says how requests to Azure DevOps are authenticated.
type AuthMode string

const (
	// AuthEntra is an Entra service principal using the client-credentials
	// flow. The token is sent as a bearer token.
	AuthEntra AuthMode = "entra"
	// AuthPAT is a personal access token. It is sent as the Basic password.
	AuthPAT AuthMode = "pat"
)

// AuthOptions selects and configures the authentication mode.
//
// With a TenantID and a ClientID the mode is Entra, and Credential is the
// client secret (or certificate). Without them Credential is a PAT.
type AuthOptions struct {
	TenantID   string
	ClientID   string
	Credential *vault.Credential

	// TokenCredential replaces the Entra credential built from the options.
	// Tests inject a fake here.
	TokenCredential azcore.TokenCredential
	// Now replaces the clock. Tests inject a fake here.
	Now func() time.Time
}

// Authenticator produces the credentials for REST calls and for git clones.
// It is safe for concurrent use.
type Authenticator struct {
	mode AuthMode
	cred azcore.TokenCredential
	pat  string
	now  func() time.Time

	mu        sync.Mutex
	token     string
	mintedAt  time.Time
	expiresAt time.Time
}

// NewAuthenticator picks the mode from the options.
func NewAuthenticator(opts AuthOptions) (*Authenticator, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	switch {
	case opts.TenantID != "" && opts.ClientID != "":
		cred := opts.TokenCredential
		if cred == nil {
			var err error
			cred, err = azauth.GetTokenFromCredential(opts.Credential, &azauth.ChainedTokenOptions{
				TenantID: opts.TenantID,
				ClientID: opts.ClientID,
				Source:   "azuredevops-connection",
			})
			if err != nil {
				return nil, fmt.Errorf("azure devops: cannot build the Entra credential: %w", err)
			}
		}
		return &Authenticator{mode: AuthEntra, cred: cred, now: now}, nil

	case opts.TenantID != "" || opts.ClientID != "":
		return nil, errors.New("azure devops: tenant-id and client-id must be set together")
	}

	// Without a tenant and client only a personal access token can sign in. A
	// credential of another kind is not "no credentials": name its type so the
	// user knows what was received. Only the type is named, never the secret.
	if opts.Credential != nil && opts.Credential.Type != vault.CredentialType_password {
		return nil, fmt.Errorf("azure devops: credential type %s is not supported; supply a personal access token, "+
			"or a tenant id and client id with a client secret or certificate", opts.Credential.Type)
	}
	if opts.Credential == nil || len(opts.Credential.Secret) == 0 {
		return nil, errors.New("azure devops: no credentials, pass --token (or set AZURE_DEVOPS_TOKEN) " +
			"or pass --tenant-id and --client-id with a client secret")
	}
	return &Authenticator{mode: AuthPAT, pat: string(opts.Credential.Secret), now: now}, nil
}

// Mode reports how this authenticator signs requests.
func (a *Authenticator) Mode() AuthMode {
	return a.mode
}

// Token returns the secret to present: the PAT, or an Entra access token that
// is minted on first use and again once 80% of its lifetime has passed.
func (a *Authenticator) Token(ctx context.Context) (string, error) {
	if a.mode == AuthPAT {
		return a.pat, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	if a.token != "" && now.Before(a.refreshAt()) {
		return a.token, nil
	}

	tk, err := a.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{EntraScope}})
	if err != nil {
		return "", fmt.Errorf("azure devops: cannot mint an Entra token: %w", err)
	}
	if tk.Token == "" {
		return "", errors.New("azure devops: Entra returned an empty token")
	}
	a.token = tk.Token
	a.mintedAt = now
	a.expiresAt = tk.ExpiresOn
	return a.token, nil
}

// refreshAt is when the cached token is due for a refresh. A token without a
// usable expiry is refreshed on every call.
func (a *Authenticator) refreshAt() time.Time {
	lifetime := a.expiresAt.Sub(a.mintedAt)
	if lifetime <= 0 {
		return a.mintedAt
	}
	return a.mintedAt.Add(time.Duration(float64(lifetime) * tokenRefreshFraction))
}

// AuthorizationHeader is the value of the Authorization header for REST calls.
func (a *Authenticator) AuthorizationHeader(ctx context.Context) (string, error) {
	tok, err := a.Token(ctx)
	if err != nil {
		return "", err
	}
	if a.mode == AuthPAT {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+tok)), nil
	}
	return "Bearer " + tok, nil
}

// GitCredential is the credential a git clone presents as the Basic password.
// It is built at call time, so a child cloned later gets a refreshed token.
func (a *Authenticator) GitCredential(ctx context.Context) (*vault.Credential, error) {
	tok, err := a.Token(ctx)
	if err != nil {
		return nil, err
	}
	return vault.NewPasswordCredential(GitCredentialUser, tok), nil
}

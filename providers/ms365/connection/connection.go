// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"

	azcore "github.com/Azure/azure-sdk-for-go/sdk/azcore"
	errors "github.com/cockroachdb/errors"
	msgrapgh_org "github.com/microsoftgraph/msgraph-sdk-go/organization"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/azauth"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	OptionTenantID      = "tenant-id"
	OptionClientID      = "client-id"
	OptionOrganization  = "organization"
	OptionSharepointUrl = "sharepoint-url"
	// OptionAuthMethod names the sign-in method(s) to use when no client secret
	// or certificate is supplied, as a comma-separated list of
	// azauth.CredentialMethod values. Unset means try all of them.
	OptionAuthMethod = "auth-method"
)

type Ms365Connection struct {
	plugin.Connection
	Conf          *inventory.Config
	asset         *inventory.Asset
	token         azcore.TokenCredential
	tenantId      string
	clientId      string
	organization  string
	sharepointUrl string

	adminPrincipalsMu sync.Mutex
	adminPrincipals   map[string]struct{}
}

// AdminPrincipalIDs returns the set of principal IDs that hold an active
// Microsoft Entra directory role. The set is computed once per connection via
// load and cached for the connection's lifetime, so it is not recomputed for
// every user. Errors are not cached, so a transient failure is retried on the
// next call.
func (p *Ms365Connection) AdminPrincipalIDs(load func() (map[string]struct{}, error)) (map[string]struct{}, error) {
	p.adminPrincipalsMu.Lock()
	defer p.adminPrincipalsMu.Unlock()

	if p.adminPrincipals != nil {
		return p.adminPrincipals, nil
	}

	set, err := load()
	if err != nil {
		return nil, err
	}
	p.adminPrincipals = set
	return set, nil
}

// The credentials this process has built, by the identity each signs in as and
// the key material it signs in with.
//
// A credential owns its token cache -- azidentity keeps it inside the instance
// -- so building one per connection asks Entra for a token per connection, for
// an identity that already had a perfectly good one.
//
// Keyed by identity rather than shared outright: an inventory can hold Microsoft
// 365 assets under several tenants, and handing tenant A's token to tenant B's
// asset would not fail cleanly, it would read the wrong tenant. The key also
// carries a fingerprint of the credential itself (see credentialCacheKey), so a
// rotated secret, or a certificate beside a secret for the same app, builds its
// own credential instead of reusing the first one seen. The map is bounded by
// the credentials a process signs in with.
var (
	credentialMu    sync.Mutex
	credentialCache = map[string]azcore.TokenCredential{}
)

// credentialCacheKey names everything that decides which credential gets
// built: the tenant and client, the credential type, the secret or certificate
// bytes and the certificate password, or, without any of those, the sign-in
// methods the chain tries. The key material goes in as a SHA-256 digest, so the
// map never holds a secret in its keys.
func credentialCacheKey(tenantId, clientId string, cred *vault.Credential, methods azauth.CredentialMethods) string {
	h := sha256.New()
	// every part is length-prefixed so that no two different inputs can
	// concatenate to the same stream
	write := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	write([]byte(tenantId))
	write([]byte(clientId))
	if cred == nil {
		write([]byte("chain"))
		for _, m := range methods.Effective() {
			write([]byte(m.Name()))
		}
	} else {
		write([]byte(cred.Type.String()))
		write(cred.Secret)
		write([]byte(cred.Password))
	}
	return tenantId + "/" + clientId + "/" + hex.EncodeToString(h.Sum(nil))
}

// selectMs365Credential builds the credential this connection signs in with, or
// hands back the one already built for the same identity and key material. It
// also returns the cache key, so a caller that finds the credential does not
// work can forget it.
//
// Without a client secret or certificate it falls back to the sign-in chain,
// which probes every method in turn. A keyless connection that knows how it
// authenticates can name the method with auth-method and skip straight to it.
func selectMs365Credential(conf *inventory.Config) (azcore.TokenCredential, string, error) {
	tenantId := conf.Options[OptionTenantID]
	clientId := conf.Options[OptionClientID]

	// parsed before the cache is consulted: an unusable auth-method is an error
	// for the connection that names it, whether or not this identity already has
	// a credential someone else built
	methods, err := azauth.ParseCredentialMethods(conf.Options[OptionAuthMethod])
	if err != nil {
		return nil, "", err
	}

	var cred *vault.Credential
	if len(conf.Credentials) > 0 {
		cred = conf.Credentials[0]
	}

	// held across the build, which is local -- constructing a credential
	// contacts nothing -- so concurrent connects queue briefly rather than each
	// building a chain of their own
	key := credentialCacheKey(tenantId, clientId, cred, methods)
	credentialMu.Lock()
	defer credentialMu.Unlock()
	if cached, ok := credentialCache[key]; ok {
		return cached, key, nil
	}

	token, err := azauth.GetTokenFromCredential(cred, &azauth.ChainedTokenOptions{
		TenantID: tenantId,
		ClientID: clientId,
		Methods:  methods,
		Source:   "ms365-connection",
	})
	if err != nil {
		// a failed build is not worth remembering: the next connection may be
		// configured differently, and caching the failure would deny it its own try
		return nil, "", err
	}

	credentialCache[key] = token
	return token, key, nil
}

// forgetMs365Credential drops a cached credential that failed to sign in, so the
// next connection builds a fresh one. It removes the entry only while it still
// holds the credential that failed.
func forgetMs365Credential(key string, token azcore.TokenCredential) {
	credentialMu.Lock()
	defer credentialMu.Unlock()
	if cached, ok := credentialCache[key]; ok && cached == token {
		delete(credentialCache, key)
	}
}

// connectMs365Credential selects the credential for conf and proves it with
// verify. Building a credential contacts nothing, so a wrong secret only shows
// up here; a credential that fails verify is evicted from the cache rather than
// handed to every later connection with the same configuration.
func connectMs365Credential(conf *inventory.Config, verify func(azcore.TokenCredential) error) (azcore.TokenCredential, error) {
	token, key, err := selectMs365Credential(conf)
	if err != nil {
		return nil, errors.Wrap(err, "cannot fetch credentials for ms365 provider")
	}
	if err := verify(token); err != nil {
		forgetMs365Credential(key, token)
		return nil, errors.Wrap(err, "authentication failed")
	}
	return token, nil
}

// verifyGraphAccess reads the organization with token, the cheapest call that
// proves the credential signs in to Microsoft Graph.
func verifyGraphAccess(token azcore.TokenCredential) error {
	client, err := graphClient(token)
	if err != nil {
		return err
	}
	_, err = client.Organization().Get(context.Background(), &msgrapgh_org.OrganizationRequestBuilderGetRequestConfiguration{})
	return err
}

func NewMs365Connection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*Ms365Connection, error) {
	tenantId := conf.Options[OptionTenantID]
	clientId := conf.Options[OptionClientID]
	organization := conf.Options[OptionOrganization]
	sharepointUrl := conf.Options[OptionSharepointUrl]
	if len(tenantId) == 0 {
		return nil, errors.New("ms365 provider requires a tenant-id")
	}

	token, err := connectMs365Credential(conf, verifyGraphAccess)
	if err != nil {
		return nil, err
	}
	return &Ms365Connection{
		Connection:    plugin.NewConnection(id, asset),
		Conf:          conf,
		asset:         asset,
		token:         token,
		tenantId:      tenantId,
		clientId:      clientId,
		organization:  organization,
		sharepointUrl: sharepointUrl,
	}, nil
}

func (h *Ms365Connection) Name() string {
	return "ms365"
}

func (p *Ms365Connection) Asset() *inventory.Asset {
	return p.asset
}

func (p *Ms365Connection) Token() azcore.TokenCredential {
	return p.token
}

func (p *Ms365Connection) TenantId() string {
	return p.tenantId
}

func (p *Ms365Connection) ClientId() string {
	return p.clientId
}

func (p *Ms365Connection) PlatformId() string {
	return "//platformid.api.mondoo.app/runtime/ms365/tenant/" + p.tenantId
}

func (p *Ms365Connection) SharepointUrl() string {
	return p.sharepointUrl
}

func (p *Ms365Connection) Organization() string {
	return p.organization
}

// indicates if a certificate credential is provided
func (p *Ms365Connection) IsCertProvided() bool {
	return len(p.Conf.Credentials) > 0 && p.Conf.Credentials[0].Type == vault.CredentialType_pkcs12
}

func (p *Ms365Connection) RunPowershellScript(script string) (*shared.Command, error) {
	var encodedCmd string
	if runtime.GOOS == "windows" {
		encodedCmd = powershell.Encode(script)
	} else {
		encodedCmd = powershell.EncodeUnix(script)
	}
	return p.RunCmd(encodedCmd)
}

func (p *Ms365Connection) RunCmd(cmd string) (*shared.Command, error) {
	cmdR := local.CommandRunner{}
	if runtime.GOOS == "windows" {
		cmdR.Shell = []string{"powershell", "-c"}
	} else {
		cmdR.Shell = []string{"sh", "-c"}
	}
	return cmdR.Exec(cmd, []string{})
}

func (p *Ms365Connection) CheckPowershellAvailable() (bool, error) {
	if runtime.GOOS == "windows" {
		// assume powershell is always present on windows
		return true, nil
	}
	// for unix, we need to check if pwsh is available
	cmd := "which pwsh"
	res, err := p.RunCmd(cmd)
	if err != nil {
		return false, err
	}

	return res.ExitStatus == 0, nil
}

func (p *Ms365Connection) CheckAndRunPowershellScript(script string) (*shared.Command, error) {
	pwshAvailable, err := p.CheckPowershellAvailable()
	if err != nil {
		return nil, err
	}
	if !pwshAvailable {
		return nil, fmt.Errorf("powershell is not available")
	}
	return p.RunPowershellScript(script)
}

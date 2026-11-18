// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"golang.org/x/net/publicsuffix"
)

// DefaultAPIURL is the API of the Codesphere SaaS installation. Private Cloud
// installations serve the same API under their own host.
const DefaultAPIURL = "https://cloud.codesphere.com/api"

// Connection option keys. The filter keys come from CLI flags and narrow what
// the root lists; the scope keys pin a discovered child asset to one object.
const (
	OptionAPIURL          = "api-url"
	OptionOrgFilter       = "org"
	OptionResourceGroupID = "resource-group"

	OptionScopeOrganization  = "organizationId"
	OptionScopeResourceGroup = "resourceGroupId"
	OptionScopeWorkspace     = "workspaceId"
)

type CodesphereConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	apiURL *url.URL
	token  string
	client *cs.APIClient
}

func NewCodesphereConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*CodesphereConnection, error) {
	apiURL, err := ParseAPIURL(conf.Options[OptionAPIURL])
	if err != nil {
		return nil, err
	}

	token := os.Getenv("CS_TOKEN")
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password && len(cred.Secret) > 0 {
			token = string(cred.Secret)
		}
	}
	if token == "" {
		return nil, errors.New("a Codesphere API token is required (set CS_TOKEN or use --token)")
	}

	cfg := cs.NewConfiguration()
	cfg.HTTPClient = newHTTPClient(apiURL)
	cfg.Servers = cs.ServerConfigurations{{URL: apiURL.String()}}

	return &CodesphereConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		apiURL:     apiURL,
		token:      token,
		client:     cs.NewAPIClient(cfg),
	}, nil
}

// ParseAPIURL validates the API URL from the --api flag or CS_API, falling
// back to the SaaS installation. Only http and https URLs with a host are
// accepted, and a trailing slash is dropped so the host-derived asset identity
// stays stable.
func ParseAPIURL(raw string) (*url.URL, error) {
	if raw == "" {
		raw = os.Getenv("CS_API")
	}
	if raw == "" {
		raw = DefaultAPIURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid Codesphere API URL " + strconv.Quote(raw) + ": " + err.Error())
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("invalid Codesphere API URL " + strconv.Quote(raw) + ": expected http(s)://host/path")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

// newHTTPClient returns a client that keeps the API token across redirects to
// the installation's own data centers. The API redirects some calls to the
// host of the data center that serves the object, and the default client drops
// the Authorization header on any redirect to another host, which turns every
// such call into a 401. trustedRedirect decides which targets get it back.
func newHTTPClient(api *url.URL) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			auth := via[0].Header.Get("Authorization")
			if auth != "" && req.Header.Get("Authorization") == "" && trustedRedirect(api, req.URL) {
				req.Header.Set("Authorization", auth)
			}
			return nil
		},
	}
}

// trustedRedirect reports whether a redirect target may receive the API
// token. All of these must hold:
//
//   - the scheme does not downgrade from https;
//   - the path stays under the API's base path (/api), so the target is an API
//     endpoint and not some other page;
//   - the host is the API host, or a sibling of it: the same parent domain and
//     the same depth, as with cloud.codesphere.com and 2.codesphere.com.
//
// Deeper hosts are never trusted, since workspaces serve user-controlled
// applications on subdomains of the installation's domain. Siblings are not
// trusted when the parent domain is a public suffix, and an IP address only
// matches itself.
func trustedRedirect(api, target *url.URL) bool {
	if api.Scheme == "https" && target.Scheme != "https" {
		return false
	}
	if base := api.EscapedPath(); base != "" {
		p := target.EscapedPath()
		if p != base && !strings.HasPrefix(p, base+"/") {
			return false
		}
	}

	apiHost, targetHost := strings.ToLower(api.Hostname()), strings.ToLower(target.Hostname())
	if apiHost == targetHost {
		return true
	}
	if net.ParseIP(apiHost) != nil || net.ParseIP(targetHost) != nil {
		return false
	}
	apiParent, ok := parentDomain(apiHost)
	if !ok {
		return false
	}
	targetParent, ok := parentDomain(targetHost)
	return ok && apiParent == targetParent
}

// parentDomain returns a host without its first label, when that parent is a
// registrable domain or below one, so it can be shared by siblings.
func parentDomain(host string) (string, bool) {
	i := strings.IndexByte(host, '.')
	if i <= 0 {
		return "", false
	}
	parent := host[i+1:]
	if _, err := publicsuffix.EffectiveTLDPlusOne(parent); err != nil {
		return "", false
	}
	return parent, true
}

func (c *CodesphereConnection) Name() string {
	return "codesphere"
}

func (c *CodesphereConnection) Asset() *inventory.Asset {
	return c.asset
}

// API returns the generated Codesphere API client.
func (c *CodesphereConnection) API() *cs.APIClient {
	return c.client
}

// Context returns a request context that carries the API token.
func (c *CodesphereConnection) Context() context.Context {
	return context.WithValue(context.Background(), cs.ContextAccessToken, c.token)
}

// Host returns the host that identifies the installation.
func (c *CodesphereConnection) Host() string {
	return strings.ToLower(c.apiURL.Host)
}

// APIURL returns the API URL of the installation.
func (c *CodesphereConnection) APIURL() string {
	return c.apiURL.String()
}

func (c *CodesphereConnection) option(key string) string {
	if c.Conf == nil || c.Conf.Options == nil {
		return ""
	}
	return c.Conf.Options[key]
}

func (c *CodesphereConnection) intOption(key string) int {
	id, _ := strconv.Atoi(c.option(key))
	return id
}

// OrgFilter returns the organization ID that --org restricts the scan to.
func (c *CodesphereConnection) OrgFilter() string {
	return c.option(OptionOrgFilter)
}

// ResourceGroupFilter returns the resource group ID that --resource-group
// restricts the scan to, or 0 when unset.
func (c *CodesphereConnection) ResourceGroupFilter() int {
	return c.intOption(OptionResourceGroupID)
}

// ScopedOrganization returns the organization a discovered child asset is
// pinned to.
func (c *CodesphereConnection) ScopedOrganization() string {
	return c.option(OptionScopeOrganization)
}

// ScopedResourceGroup returns the resource group a discovered child asset is
// pinned to, or 0.
func (c *CodesphereConnection) ScopedResourceGroup() int {
	return c.intOption(OptionScopeResourceGroup)
}

// ScopedWorkspace returns the workspace a discovered child asset is pinned
// to, or 0.
func (c *CodesphereConnection) ScopedWorkspace() int {
	return c.intOption(OptionScopeWorkspace)
}

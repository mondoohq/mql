// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/weaviate/weaviate-go-client/v5/weaviate"
	"github.com/weaviate/weaviate-go-client/v5/weaviate/auth"
	"github.com/weaviate/weaviate-go-client/v5/weaviate/rbac"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// WeaviateConnection holds the settings to reach a Weaviate server and, once
// dialed, the shared REST client. A single client can query the whole server,
// so there is one shared handle.
type WeaviateConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string
	port        int
	scheme      string
	apiKey      string
	tlsCA       string
	tlsInsecure bool

	// scopedCollection is set when the asset is a single discovered collection.
	scopedCollection string

	clientOnce sync.Once
	client     *weaviate.Client
	clientErr  error

	rolesOnce   sync.Once
	roles       []rbac.Role
	rolesByName map[string]*rbac.Role
	rolesErr    error
}

func NewWeaviateConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*WeaviateConnection, error) {
	conn := &WeaviateConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	if conf.Options == nil {
		conf.Options = make(map[string]string)
	}

	conn.host = conf.Options[OptionHost]
	if conn.host == "" {
		conn.host = conf.Host
	}
	conn.scheme = conf.Options[OptionScheme]
	if conn.scheme == "" {
		conn.scheme = "http"
	}
	conn.tlsCA = conf.Options[OptionTLSCA]
	conn.tlsInsecure = conf.Options[OptionTLSInsecure] == "true"
	conn.scopedCollection = conf.Options[OptionScopedCollection]

	conn.port = 8080
	if p := conf.Options[OptionPort]; p != "" {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid port %q: %v", p, err)
		}
		conn.port = v
	} else if conf.Port > 0 {
		conn.port = int(conf.Port)
	}

	for i := range conf.Credentials {
		cred := conf.Credentials[i]
		if cred.Type == vault.CredentialType_password {
			conn.apiKey = string(cred.Secret)
		}
	}

	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for weaviate connection")
	}

	return conn, nil
}

func (c *WeaviateConnection) Name() string {
	return "weaviate"
}

func (c *WeaviateConnection) Asset() *inventory.Asset {
	return c.asset
}

// ScopedCollection returns the single collection this asset is scoped to, or an
// empty string when the asset is the whole server.
func (c *WeaviateConnection) ScopedCollection() string {
	return c.scopedCollection
}

// ServerID returns a stable identifier for the server, used to build asset
// platform ids.
func (c *WeaviateConnection) ServerID() string {
	return c.scheme + "://" + net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// httpClient builds an HTTP client carrying the TLS configuration for an https
// connection. Every request, including response reads, has a finite budget.
func (c *WeaviateConnection) httpClient() (*http.Client, error) {
	if c.scheme != "https" || (c.tlsCA == "" && !c.tlsInsecure) {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	cfg := &tls.Config{InsecureSkipVerify: c.tlsInsecure}
	if c.tlsCA != "" {
		pem, err := os.ReadFile(c.tlsCA)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to read tls-ca %q: %v", c.tlsCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, status.Errorf(codes.InvalidArgument, "no certificates found in tls-ca %q", c.tlsCA)
		}
		cfg.RootCAs = pool
	}
	var transport *http.Transport
	if defaults, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaults.Clone()
	} else {
		// A custom RoundTripper cannot carry this connection's TLS settings.
		transport = &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		}
	}
	transport.TLSClientConfig = cfg
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

// AnonymousAccessEnabled probes /v1/meta without credentials. Only an explicit
// authentication refusal proves anonymous access is disabled; failed probes
// remain errors rather than turning an incomplete audit into a clean result.
func (c *WeaviateConnection) AnonymousAccessEnabled() (bool, error) {
	client, err := c.httpClient()
	if err != nil {
		return false, err
	}
	return probeAnonymousAccess(context.Background(), client, c.ServerID()+"/v1/meta")
}

func probeAnonymousAccess(ctx context.Context, client *http.Client, endpoint string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("anonymous access probe failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, nil
	}
	return false, fmt.Errorf("anonymous access probe returned HTTP %d", resp.StatusCode)
}

// Roles returns every role defined on the server, with its permissions, read
// once per connection and shared by every caller. Three of them need the same
// answer: the instance's role list, the probe that decides whether role-based
// access control is enabled, and the lookup that turns a role named by a user
// into that role's permissions. The error is remembered too, so a credential
// that cannot read roles costs one request rather than one per caller.
//
// The request deliberately runs on a background context rather than one passed
// in by a caller. Because the result is shared, whichever caller happened to
// arrive first would otherwise decide the deadline and cancellation for every
// later caller, which is a hard failure to attribute once any caller starts
// passing a context that can be cancelled.
func (c *WeaviateConnection) Roles() ([]rbac.Role, error) {
	c.loadRoles()
	return c.roles, c.rolesErr
}

// RoleByName returns the server's definition of one role. Resolving a role that
// something else named by name alone happens once per user-to-role edge, so the
// lookup is an index built alongside the list rather than a scan of it.
//
// Only the server's own role list feeds this map, and nothing writes to it
// afterwards, so a name-only role reference can never displace a populated role
// here.
func (c *WeaviateConnection) RoleByName(name string) (*rbac.Role, bool) {
	c.loadRoles()
	if c.rolesErr != nil {
		return nil, false
	}
	role, ok := c.rolesByName[name]
	return role, ok
}

func (c *WeaviateConnection) loadRoles() {
	c.rolesOnce.Do(func() {
		client, err := c.Client()
		if err != nil {
			c.rolesErr = err
			return
		}
		c.roles, c.rolesErr = client.Roles().AllGetter().Do(context.Background())
		if c.rolesErr != nil {
			return
		}
		c.rolesByName = make(map[string]*rbac.Role, len(c.roles))
		for i := range c.roles {
			c.rolesByName[c.roles[i].Name] = &c.roles[i]
		}
	})
}

// Client returns the shared Weaviate client, dialing on first use.
func (c *WeaviateConnection) Client() (*weaviate.Client, error) {
	c.clientOnce.Do(func() {
		httpClient, err := c.httpClient()
		if err != nil {
			c.clientErr = err
			return
		}
		cfg := weaviate.Config{
			Host:             net.JoinHostPort(c.host, strconv.Itoa(c.port)),
			Scheme:           c.scheme,
			ConnectionClient: httpClient,
			Timeout:          30 * time.Second,
		}
		if c.apiKey != "" {
			if c.scheme != "https" || (c.tlsCA == "" && !c.tlsInsecure) {
				// The SDK rejects AuthConfig together with ConnectionClient.
				// Its own client uses cfg.Timeout, preserving API-key/cloud headers.
				cfg.ConnectionClient = nil
				cfg.AuthConfig = auth.ApiKey{Value: c.apiKey}
			} else {
				// API-key auth only supplies headers. Keep the bounded TLS client
				// when a private CA or explicit TLS override is required.
				_, cfg.Headers, c.clientErr = (auth.ApiKey{Value: c.apiKey}).GetAuthInfo(nil)
				if c.clientErr != nil {
					return
				}
			}
		}
		client, err := weaviate.NewClient(cfg)
		if err != nil {
			c.clientErr = err
			return
		}
		c.client = client
	})
	return c.client, c.clientErr
}

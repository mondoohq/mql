// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

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

	rolesOnce sync.Once
	roles     []rbac.Role
	rolesErr  error
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
// connection, or nil to use the default client for plain http.
func (c *WeaviateConnection) httpClient() (*http.Client, error) {
	if c.scheme != "https" || (c.tlsCA == "" && !c.tlsInsecure) {
		return nil, nil
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
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}

// AnonymousAccessEnabled probes whether the server answers an unauthenticated
// request. It issues a GET to /v1/meta with no credentials: a 2xx response
// means anonymous access is enabled, anything else (typically 401) means
// authentication is required. Any transport error is reported as not enabled.
func (c *WeaviateConnection) AnonymousAccessEnabled() bool {
	httpClient, err := c.httpClient()
	if err != nil {
		return false
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	req, err := http.NewRequest(http.MethodGet, c.ServerID()+"/v1/meta", nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// Roles returns every role defined on the server, with its permissions, read
// once per connection and shared by every caller. Three of them need the same
// answer: the instance's role list, the probe that decides whether role-based
// access control is enabled, and the lookup that turns a role named by a user
// into that role's permissions. The error is remembered too, so a credential
// that cannot read roles costs one request rather than one per caller.
func (c *WeaviateConnection) Roles(ctx context.Context) ([]rbac.Role, error) {
	c.rolesOnce.Do(func() {
		client, err := c.Client()
		if err != nil {
			c.rolesErr = err
			return
		}
		c.roles, c.rolesErr = client.Roles().AllGetter().Do(ctx)
	})
	return c.roles, c.rolesErr
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
		}
		if c.apiKey != "" {
			cfg.AuthConfig = auth.ApiKey{Value: c.apiKey}
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

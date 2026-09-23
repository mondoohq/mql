// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	opensearch "github.com/opensearch-project/opensearch-go/v5"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// OpensearchConnection holds the settings to reach an OpenSearch cluster and,
// once dialed, the shared REST client.
type OpensearchConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string
	port        int
	scheme      string
	user        string
	password    string
	tlsCA       string
	tlsInsecure bool

	clientOnce sync.Once
	client     *opensearch.Client
	clientErr  error
}

func NewOpensearchConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*OpensearchConnection, error) {
	conn := &OpensearchConnection{
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
		conn.scheme = "https"
	}
	conn.tlsCA = conf.Options[OptionTLSCA]
	conn.tlsInsecure = conf.Options[OptionTLSInsecure] == "true"

	conn.port = 9200
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
			conn.user = cred.User
			conn.password = string(cred.Secret)
		}
	}

	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for opensearch connection")
	}

	return conn, nil
}

func (c *OpensearchConnection) Name() string {
	return "opensearch"
}

func (c *OpensearchConnection) Asset() *inventory.Asset {
	return c.asset
}

// address returns the cluster's base URL.
func (c *OpensearchConnection) address() string {
	return c.scheme + "://" + net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// ServerID returns a stable identifier for the target, used as a fallback
// cluster id when the cluster UUID is unavailable.
func (c *OpensearchConnection) ServerID() string {
	return net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// Context returns a background context for requests.
func (c *OpensearchConnection) Context() context.Context {
	return context.Background()
}

// Client returns the shared OpenSearch client, dialing on first use.
func (c *OpensearchConnection) Client() (*opensearch.Client, error) {
	c.clientOnce.Do(func() {
		cfg := opensearch.Config{
			Addresses:          []string{c.address()},
			Username:           c.user,
			Password:           c.password,
			InsecureSkipVerify: c.tlsInsecure,
		}
		if c.tlsCA != "" {
			pem, err := os.ReadFile(c.tlsCA)
			if err != nil {
				c.clientErr = status.Errorf(codes.InvalidArgument, "failed to read tls-ca %q: %v", c.tlsCA, err)
				return
			}
			cfg.CACert = pem
		}
		client, err := opensearch.NewClient(cfg)
		if err != nil {
			c.clientErr = err
			return
		}
		c.client = client
	})
	return c.client, c.clientErr
}

// Get issues a GET to the given REST path and decodes the JSON body into out.
// It returns a PermissionError when the cluster answers 401/403 so callers can
// degrade gracefully, and an error carrying the status for other non-2xx codes.
func (c *OpensearchConnection) Get(path string, out any) error {
	client, err := c.Client()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(c.Context(), http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	res, err := client.Request(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return &PermissionError{Path: path, StatusCode: res.StatusCode}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("opensearch GET %s: status %d: %s", path, res.StatusCode, string(body))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// PermissionError indicates the connecting credential is not authorized for a
// path (HTTP 401 or 403).
type PermissionError struct {
	Path       string
	StatusCode int
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("opensearch GET %s: not authorized (status %d)", e.Path, e.StatusCode)
}

// IsPermissionError reports whether err is an authorization failure, including
// when it has been wrapped with fmt.Errorf("%w", ...).
func IsPermissionError(err error) bool {
	var pe *PermissionError
	return errors.As(err, &pe)
}

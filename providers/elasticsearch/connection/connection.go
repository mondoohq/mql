// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	elasticsearch "github.com/elastic/go-elasticsearch/v9"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// ElasticsearchConnection holds the settings to reach an Elasticsearch cluster
// and, once dialed, the shared REST client.
type ElasticsearchConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	host        string
	port        int
	scheme      string
	user        string
	password    string
	apiKey      string
	tlsCA       string
	tlsInsecure bool

	clientOnce sync.Once
	client     *elasticsearch.Client
	clientErr  error
}

func NewElasticsearchConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ElasticsearchConnection, error) {
	conn := &ElasticsearchConnection{
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
		switch cred.Type {
		case vault.CredentialType_password:
			conn.user = cred.User
			conn.password = string(cred.Secret)
		}
	}
	// The API key is carried as an option rather than a credential so it can
	// coexist with (or replace) basic auth.
	conn.apiKey = conf.Options[OptionAPIKey]

	if conn.host == "" {
		return nil, status.Error(codes.InvalidArgument, "missing host for elasticsearch connection")
	}

	return conn, nil
}

func (c *ElasticsearchConnection) Name() string {
	return "elasticsearch"
}

func (c *ElasticsearchConnection) Asset() *inventory.Asset {
	return c.asset
}

// address returns the cluster's base URL.
func (c *ElasticsearchConnection) address() string {
	return c.scheme + "://" + net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// ServerID returns a stable identifier for the target, used as a fallback
// cluster id when the cluster UUID is unavailable.
func (c *ElasticsearchConnection) ServerID() string {
	return net.JoinHostPort(c.host, strconv.Itoa(c.port))
}

// Context returns a background context for requests.
func (c *ElasticsearchConnection) Context() context.Context {
	return context.Background()
}

// transport builds an HTTP transport carrying the TLS configuration for an
// https connection, or nil to use the client default.
func (c *ElasticsearchConnection) transport() (*http.Transport, error) {
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
	return &http.Transport{TLSClientConfig: cfg}, nil
}

// retryOnError decides whether the transport retries a failed request. The
// connection has a single address, so retrying a failed dial reaches the same
// unreachable host again: with the default three retries a blackholed host
// took four 30 s dial timeouts (2 minutes) to fail. Errors after the
// connection was made are still retried.
func retryOnError(_ *http.Request, err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return false
	}
	return true
}

// Client returns the shared Elasticsearch client, dialing on first use.
func (c *ElasticsearchConnection) Client() (*elasticsearch.Client, error) {
	c.clientOnce.Do(func() {
		tr, err := c.transport()
		if err != nil {
			c.clientErr = err
			return
		}
		opts := []elasticsearch.Option{elasticsearch.WithAddresses(c.address())}
		if c.user != "" || c.password != "" {
			opts = append(opts, elasticsearch.WithBasicAuth(c.user, c.password))
		}
		if c.apiKey != "" {
			opts = append(opts, elasticsearch.WithAPIKey(c.apiKey))
		}
		if tr != nil {
			opts = append(opts, elasticsearch.WithTransportOptions(elastictransport.WithTransport(tr)))
		}
		opts = append(opts, elasticsearch.WithTransportOptions(elastictransport.WithRetryOnError(retryOnError)))
		client, err := elasticsearch.New(opts...)
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
func (c *ElasticsearchConnection) Get(path string, out any) error {
	client, err := c.Client()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(c.Context(), http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	res, err := client.Perform(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return &PermissionError{Path: path, StatusCode: res.StatusCode, Reason: errorReason(body)}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("elasticsearch GET %s: status %d: %s", path, res.StatusCode, string(body))
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
	// Reason is the cluster's own explanation, which for a 403 names the
	// privileges that would grant the action.
	Reason string
}

func (e *PermissionError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("elasticsearch GET %s: not authorized (status %d): %s", e.Path, e.StatusCode, e.Reason)
	}
	return fmt.Sprintf("elasticsearch GET %s: not authorized (status %d)", e.Path, e.StatusCode)
}

// IsPermissionError reports whether err is an authorization failure.
func IsPermissionError(err error) bool {
	var pe *PermissionError
	return errors.As(err, &pe)
}

// errorReason extracts error.reason from an Elasticsearch error body, for
// example "action [cluster:admin/xpack/security/user/get] is unauthorized for
// user [monuser] ..., this action is granted by the cluster privileges
// [read_security,manage_security,all]". It returns "" for any other body.
func errorReason(body []byte) string {
	var e struct {
		Error struct {
			Reason string `json:"reason"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error.Reason
}

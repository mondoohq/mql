// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	OptionURL = "url"

	EnvURLVar    = "N8N_URL"
	EnvAPIKeyVar = "N8N_API_KEY"

	// apiKeyHeader carries the API key on every Public API request.
	apiKeyHeader = "X-N8N-API-KEY"

	// httpTimeout bounds a single request. Without it a stalled instance
	// blocks the field forever.
	httpTimeout = 60 * time.Second
)

type N8nConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	instanceURL string
	client      *Client
}

func NewN8nConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*N8nConnection, error) {
	instanceURL := conf.Options[OptionURL]
	if instanceURL == "" {
		instanceURL = os.Getenv(EnvURLVar)
	}
	instanceURL, err := normalizeInstanceURL(instanceURL)
	if err != nil {
		return nil, err
	}

	apiKey := os.Getenv(EnvAPIKeyVar)
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password && len(cred.Secret) > 0 {
			apiKey = string(cred.Secret)
		}
	}
	if apiKey == "" {
		return nil, errors.New("an n8n API key is required (set " + EnvAPIKeyVar + " or use --api-key)")
	}

	return &N8nConnection{
		Connection:  plugin.NewConnection(id, asset),
		Conf:        conf,
		asset:       asset,
		instanceURL: instanceURL,
		client: &Client{
			baseURL: instanceURL,
			apiKey:  apiKey,
			http: &http.Client{
				Timeout:       httpTimeout,
				CheckRedirect: sameOriginRedirects,
			},
		},
	}, nil
}

// sameOriginRedirects refuses a redirect that leaves the scheme and host of
// the first request. Go drops Authorization and Cookie on such a redirect but
// forwards custom headers, so following it would hand the API key to the
// redirect target.
func sameOriginRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("n8n API: stopped after 10 redirects")
	}
	first := via[0].URL
	if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		return fmt.Errorf("n8n API redirected from %s://%s to %s://%s; not following it with the API key, use the instance URL it redirects to",
			first.Scheme, first.Host, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// normalizeInstanceURL turns what the user typed into the instance root the
// API path is appended to: a scheme is added when missing, and a trailing
// slash or a pasted /api/v1 suffix is dropped.
func normalizeInstanceURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("an n8n instance URL is required (set " + EnvURLVar + " or pass it as the first argument)")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid n8n instance URL: " + err.Error())
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("invalid n8n instance URL: scheme must be http or https")
	}
	if u.Host == "" {
		return "", errors.New("invalid n8n instance URL: missing host")
	}
	// The URL is reported as the instance's url field and keys the asset, so
	// credentials in it would be exposed. The API key is the credential.
	if u.User != nil {
		return "", errors.New("invalid n8n instance URL: remove the user name and password from it, the API key authenticates")
	}
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1")
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func (c *N8nConnection) Name() string {
	return "n8n"
}

func (c *N8nConnection) Asset() *inventory.Asset {
	return c.asset
}

// InstanceURL is the root URL of the n8n instance, without the API path.
func (c *N8nConnection) InstanceURL() string {
	return c.instanceURL
}

func (c *N8nConnection) Client() *Client {
	return c.client
}

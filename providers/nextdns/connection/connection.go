// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// DefaultBaseURL is the root of the NextDNS management API.
	DefaultBaseURL = "https://api.nextdns.io"

	// OptionProfile scopes a connection to a single discovered profile.
	OptionProfile = "profile"
	// OptionAccount marks a connection as the account root.
	OptionAccount = "account"
)

type NextdnsConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	apiKey  string
	baseURL string
	client  *http.Client

	// accountID is a stable fingerprint of the API key. NextDNS exposes no
	// account object, so we derive a deterministic id to identify the account
	// asset across scans. Note the coupling: the id is derived from the key, so
	// rotating the API key yields a new account identity and breaks asset
	// continuity (platform ids change) across scans.
	accountID string
}

func NewNextdnsConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*NextdnsConnection, error) {
	// Prefer credentials from the config (e.g. vault-injected) and only fall
	// back to the environment, so a stale env var never shadows a real one.
	var apiKey string
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password && len(cred.Secret) > 0 {
			apiKey = string(cred.Secret)
		}
	}
	if apiKey == "" {
		apiKey = os.Getenv("NEXTDNS_API_KEY")
	}
	if apiKey == "" {
		return nil, errors.New("a valid NextDNS API key is required (set NEXTDNS_API_KEY or use --api-key)")
	}

	baseURL := DefaultBaseURL
	if v := conf.Options["base-url"]; v != "" {
		baseURL = v
	}

	sum := sha256.Sum256([]byte(apiKey))

	conn := &NextdnsConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		apiKey:     apiKey,
		baseURL:    baseURL,
		client:     &http.Client{Timeout: 30 * time.Second},
		accountID:  hex.EncodeToString(sum[:])[:16],
	}

	return conn, nil
}

func (c *NextdnsConnection) Name() string {
	return "nextdns"
}

func (c *NextdnsConnection) Asset() *inventory.Asset {
	return c.asset
}

// AccountID returns the stable fingerprint of the API key's account.
func (c *NextdnsConnection) AccountID() string {
	return c.accountID
}

// ProfileID returns the profile this connection is scoped to, or "" for an
// account-level connection that sees all profiles.
func (c *NextdnsConnection) ProfileID() string {
	return c.Conf.Options[OptionProfile]
}

// Get fetches path (e.g. "/profiles") and unmarshals the response body into out.
func (c *NextdnsConnection) Get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("nextdns API request to %s failed with status %d: %s", path, resp.StatusCode, string(body))
	}

	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

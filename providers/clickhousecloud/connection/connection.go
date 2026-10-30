// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

const defaultAPIURL = "https://api.clickhouse.cloud/v1"

// ClickhousecloudConnection holds the settings to reach the ClickHouse Cloud
// control-plane API for one organization.
type ClickhousecloudConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	apiURL    string
	orgID     string
	keyID     string
	keySecret string
	http      *http.Client
}

func NewClickhousecloudConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ClickhousecloudConnection, error) {
	conn := &ClickhousecloudConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		http:       &http.Client{Timeout: 30 * time.Second},
	}

	if conf.Options == nil {
		conf.Options = make(map[string]string)
	}

	conn.orgID = conf.Options[OptionOrg]
	conn.apiURL = conf.Options[OptionAPIURL]
	if conn.apiURL == "" {
		conn.apiURL = defaultAPIURL
	}
	conn.apiURL = strings.TrimRight(conn.apiURL, "/")

	for i := range conf.Credentials {
		cred := conf.Credentials[i]
		if cred.Type == vault.CredentialType_password {
			conn.keyID = cred.User
			conn.keySecret = string(cred.Secret)
		}
	}

	if conn.orgID == "" {
		return nil, status.Error(codes.InvalidArgument, "missing organization ID for clickhousecloud connection (use --organization-id)")
	}
	if conn.keyID == "" || conn.keySecret == "" {
		return nil, status.Error(codes.InvalidArgument, "missing API key for clickhousecloud connection (use --api-key and --api-secret)")
	}

	return conn, nil
}

func (c *ClickhousecloudConnection) Name() string {
	return "clickhousecloud"
}

func (c *ClickhousecloudConnection) Asset() *inventory.Asset {
	return c.asset
}

// OrgID returns the connected organization ID.
func (c *ClickhousecloudConnection) OrgID() string {
	return c.orgID
}

// ServerID returns a stable identifier for the target organization.
func (c *ClickhousecloudConnection) ServerID() string {
	return c.orgID
}

// Context returns a background context for requests.
func (c *ClickhousecloudConnection) Context() context.Context {
	return context.Background()
}

// PermissionError marks an authorization failure so privilege-gated reads can
// degrade gracefully.
type PermissionError struct{ msg string }

func (e *PermissionError) Error() string { return e.msg }

// IsPermissionError reports whether an error is a ClickHouse Cloud authorization
// failure (HTTP 401/403), even when wrapped.
func IsPermissionError(err error) bool {
	var pe *PermissionError
	return errors.As(err, &pe)
}

// apiEnvelope is the wrapper every ClickHouse Cloud API response uses.
type apiEnvelope struct {
	Result json.RawMessage `json:"result"`
}

// Get performs a GET against the organization-scoped API and decodes the
// response's `result` field into out. Paths are relative to the org, for
// example "/services" or "/keys".
func (c *ClickhousecloudConnection) Get(ctx context.Context, path string, out any) error {
	url := c.apiURL + "/organizations/" + c.orgID + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.keyID, c.keySecret)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Cap the body but detect the cap so a truncated response surfaces as a clear
	// error rather than a confusing JSON parse failure.
	const maxBody = 16 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return fmt.Errorf("clickhousecloud: response for %s exceeds %d bytes", path, maxBody)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &PermissionError{msg: fmt.Sprintf("clickhousecloud: not authorized for %s (HTTP %d)", path, resp.StatusCode)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("clickhousecloud: GET %s returned HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var env apiEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("clickhousecloud: cannot decode response for %s: %w", path, err)
	}
	if len(env.Result) == 0 {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

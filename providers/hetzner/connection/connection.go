// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// requestTimeout bounds a single Hetzner API request. hcloud.NewClient
// defaults to &http.Client{}, which has no timeout at all, and the plugin
// runtime hands resources no context to carry a deadline instead: GetData
// takes none, so every call site uses context.Background(). Without this a
// request that never answers hangs the scan indefinitely.
//
// hcloud issues each retry as its own request, so this bounds an attempt
// rather than the whole retried operation.
// They are vars so tests can shrink them.
var (
	requestTimeout = 30 * time.Second

	// maxRetries matches hcloud's own default. It is set explicitly because
	// it multiplies requestTimeout: a completely unresponsive endpoint costs
	// roughly maxRetries attempts plus hcloud's exponential backoff before
	// the call gives up, so the two numbers only make sense together.
	maxRetries = 5
)

var PlatformIdHetznerProject = "//platformid.api.mondoo.app/runtime/hetzner/project/"

type HetznerConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	client *hcloud.Client
	token  string
}

func NewHetznerConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*HetznerConnection, error) {
	conn := &HetznerConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	token, set := GetToken(conf)
	if !set {
		return nil, fmt.Errorf("a Hetzner Cloud API token is required. "+
			"Use the --%s flag or set the %s environment variable.",
			OPTION_TOKEN, HCLOUD_TOKEN_VAR)
	}

	opts := []hcloud.ClientOption{
		hcloud.WithToken(token),
		hcloud.WithHTTPClient(&http.Client{Timeout: requestTimeout}),
		hcloud.WithRetryOpts(hcloud.RetryOpts{MaxRetries: maxRetries}),
	}
	if endpoint, ok := GetEndpoint(conf); ok {
		opts = append(opts, hcloud.WithEndpoint(endpoint))
	}
	conn.client = hcloud.NewClient(opts...)
	conn.token = token

	return conn, nil
}

// Verify makes a cheap API call to confirm the token is valid.
// Locations is a free, always-available endpoint that doesn't require any
// project-specific permissions.
func (c *HetznerConnection) Verify() error {
	_, _, err := c.client.Location.List(context.Background(), hcloud.LocationListOpts{
		PerPage: 1,
	})
	if err == nil {
		return nil
	}
	if hErr, ok := errors.AsType[hcloud.Error](err); ok {
		switch hErr.Code {
		case hcloud.ErrorCodeUnauthorized, hcloud.ErrorCodeForbidden:
			return errors.New("invalid Hetzner Cloud token; verify your credentials")
		}
	}
	if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
		return errors.New("invalid Hetzner Cloud token; verify your credentials")
	}
	log.Warn().Err(err).Msg("hetzner> verify call failed")
	return fmt.Errorf("failed to verify Hetzner Cloud connection: %w", err)
}

func (c *HetznerConnection) Asset() *inventory.Asset { return c.asset }
func (c *HetznerConnection) Name() string            { return "hetzner" }
func (c *HetznerConnection) Client() *hcloud.Client  { return c.client }

func (c *HetznerConnection) PlatformInfo() *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"cloud", "hetzner", "project"},
	}
	PlatformByName("hetzner-project").Apply(p)
	return p
}

// Identifier returns a stable platform ID for the project. Hetzner Cloud has
// no project-ID API, so we derive a short opaque hash of the token. This stays
// consistent for the same token and avoids leaking the secret.
func (c *HetznerConnection) Identifier() string {
	sum := sha256.Sum256([]byte(c.token))
	return PlatformIdHetznerProject + hex.EncodeToString(sum[:8])
}

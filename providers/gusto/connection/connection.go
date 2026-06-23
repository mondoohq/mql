// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/vault"
)

const (
	defaultAPIBase    = "https://api.gusto.com"
	defaultAPIVersion = "2024-04-01"
	userAgent         = "mql-gusto-provider"
)

type GustoConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	apiBase    string
	apiVersion string
	token      string
	httpClient *http.Client
	cache      listCache
}

func NewGustoConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*GustoConnection, error) {
	if conf.Type != "gusto" {
		return nil, errors.New("provider type does not match")
	}

	var token string
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			token = string(cred.Secret)
		} else {
			log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Gusto provider")
		}
	}
	if token == "" {
		return nil, errors.New("a valid Gusto API token is required, pass --token '<yourtoken>' or set GUSTO_API_TOKEN environment variable")
	}

	apiBase := defaultAPIBase
	if conf.Options != nil && conf.Options["api-base"] != "" {
		apiBase = strings.TrimRight(conf.Options["api-base"], "/")
	}

	apiVersion := defaultAPIVersion
	if conf.Options != nil && conf.Options["api-version"] != "" {
		apiVersion = conf.Options["api-version"]
	}

	apiHost, err := hostOf(apiBase)
	if err != nil {
		return nil, err
	}

	return &GustoConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		apiBase:    apiBase,
		apiVersion: apiVersion,
		token:      token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// Don't let a redirect leak the bearer token to a third-party
			// host. Strip Authorization on any cross-host hop.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				if !strings.EqualFold(req.URL.Host, apiHost) {
					req.Header.Del("Authorization")
				}
				return nil
			},
		},
	}, nil
}

func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", errors.New("Gusto api-base must include a host")
	}
	return u.Host, nil
}

func (c *GustoConnection) Name() string {
	return "gusto"
}

func (c *GustoConnection) Asset() *inventory.Asset {
	return c.asset
}

// Identifier returns a stable identifier for the accessible companies. Gusto
// tokens are scoped to one or more companies. A single-company token keeps its
// raw UUID for a readable platform id; a multi-company token hashes the sorted
// set of company UUIDs so the identifier is stable regardless of the order the
// API returns companies in (or which company happens to be listed first).
func (c *GustoConnection) Identifier(ctx context.Context) (string, error) {
	companies, err := c.ListCompanies(ctx)
	if err != nil {
		return "", err
	}
	if len(companies) == 0 {
		return "", errors.New("no companies accessible with the supplied Gusto token")
	}

	uuids := make([]string, len(companies))
	for i := range companies {
		uuids[i] = companies[i].UUID
	}
	sort.Strings(uuids)

	if len(uuids) == 1 {
		return uuids[0], nil
	}

	sum := sha256.Sum256([]byte(strings.Join(uuids, ",")))
	return hex.EncodeToString(sum[:]), nil
}

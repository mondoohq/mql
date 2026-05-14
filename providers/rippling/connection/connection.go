// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/vault"
	"golang.org/x/oauth2"
)

const (
	defaultAPIBase = "https://api.rippling.com"
	tokenPath      = "/auth/oauth2/token"
	userAgent      = "mql-rippling-provider"
)

type RipplingConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	apiBase    string
	httpClient *http.Client
}

func NewRipplingConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*RipplingConnection, error) {
	if conf.Type != "rippling" {
		return nil, errors.New("provider type does not match")
	}

	var clientID, clientSecret, refreshToken string
	for _, cred := range conf.Credentials {
		switch cred.Type {
		case vault.CredentialType_password:
			clientID = cred.User
			clientSecret = string(cred.Secret)
		case vault.CredentialType_bearer:
			refreshToken = string(cred.Secret)
		default:
			log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Rippling provider")
		}
	}
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		return nil, errors.New("Rippling OAuth credentials are required: pass --client-id, --client-secret and --refresh-token (or set RIPPLING_CLIENT_ID, RIPPLING_CLIENT_SECRET, and RIPPLING_REFRESH_TOKEN)")
	}

	apiBase := defaultAPIBase
	if conf.Options != nil && conf.Options["api-base"] != "" {
		apiBase = strings.TrimRight(conf.Options["api-base"], "/")
	}

	// Rippling uses the OAuth 2.0 authorization-code grant. mql is handed a
	// refresh token (obtained out of band by completing the authorization
	// once) and exchanges it for short-lived access tokens. The oauth2
	// transport refreshes them as needed and attaches the bearer header to
	// every API request.
	oauthConf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     oauth2.Endpoint{TokenURL: apiBase + tokenPath},
	}
	baseClient := &http.Client{Timeout: 30 * time.Second}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, baseClient)
	tokenSource := oauthConf.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	httpClient := oauth2.NewClient(ctx, tokenSource)
	httpClient.Timeout = 30 * time.Second

	return &RipplingConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		apiBase:    apiBase,
		httpClient: httpClient,
	}, nil
}

func (c *RipplingConnection) Name() string {
	return "rippling"
}

func (c *RipplingConnection) Asset() *inventory.Asset {
	return c.asset
}

// Identifier returns the company ID associated with the configured token.
// Rippling API tokens are scoped to a single company, so this is stable
// for a given token.
func (c *RipplingConnection) Identifier(ctx context.Context) (string, error) {
	me, err := c.GetMe(ctx)
	if err != nil {
		return "", err
	}
	if me.CompanyID == "" {
		return "", errors.New("Rippling /me did not return a company id; token may be invalid or lack platform scope")
	}
	return me.CompanyID, nil
}

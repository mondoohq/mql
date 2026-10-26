// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gql

import (
	"encoding/json"
	"net/http"
	"strings"

	mondoogql "go.mondoo.com/mondoo-go"
	"go.mondoo.com/mondoo-go/option"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
)

type MondooClient struct {
	*mondoogql.Client
}

// ClientOption customizes NewClient.
type ClientOption func(*clientSettings)

type clientSettings struct {
	provider string
}

// WithProvider names the provider making the calls. It is appended to the
// User-Agent, e.g. "mql/12.3.0 (provider os)".
func WithProvider(name string) ClientOption {
	return func(s *clientSettings) { s.provider = name }
}

// UserAgent returns the User-Agent mql sends on GraphQL calls:
// "mql/<version>", followed by " (provider <name>)" if a provider is given.
// The leading "mql/" is relied on by the server to classify traffic. In a
// provider plugin the version is the one stamped into that provider binary
// (the mql release it was built from), or the dev version for unstamped builds.
func UserAgent(provider string) string {
	ua := "mql/" + strings.TrimPrefix(mql.GetVersion(), "v")
	if provider != "" {
		ua += " (provider " + provider + ")"
	}
	return ua
}

// NewClient creates a new GraphQL client for the Mondoo API
// provide the http client used for rpc, to also pass in the proxy settings
func NewClient(upstream *upstream.UpstreamConfig, httpClient *http.Client, opts ...ClientOption) (*MondooClient, error) {
	var settings clientSettings
	for _, o := range opts {
		o(&settings)
	}
	gqlEndpoint := upstream.ApiEndpoint + "/query"
	creds, err := json.Marshal(upstream.Creds)
	if err != nil {
		return nil, err
	}
	// Initialize the client
	mondooClient, err := mondoogql.NewClient(
		option.WithEndpoint(gqlEndpoint),
		option.WithHTTPClient(httpClient),
		option.WithServiceAccount(creds),
		option.WithUserAgent(UserAgent(settings.provider)),
	)
	if err != nil {
		return nil, err
	}

	return &MondooClient{mondooClient}, nil
}

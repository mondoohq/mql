// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gql

import (
	"encoding/json"
	"net/http"

	mondoogql "go.mondoo.com/mondoo-go"
	"go.mondoo.com/mondoo-go/option"
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

// NewClient creates a new GraphQL client for the Mondoo API
// provide the http client used for rpc, to also pass in the proxy settings
func NewClient(cfg *upstream.UpstreamConfig, httpClient *http.Client, opts ...ClientOption) (*MondooClient, error) {
	var settings clientSettings
	for _, o := range opts {
		o(&settings)
	}
	gqlEndpoint := cfg.ApiEndpoint + "/query"
	creds, err := json.Marshal(cfg.Creds)
	if err != nil {
		return nil, err
	}
	// Initialize the client
	mondooClient, err := mondoogql.NewClient(
		option.WithEndpoint(gqlEndpoint),
		option.WithHTTPClient(httpClient),
		option.WithServiceAccount(creds),
		option.WithUserAgent(upstream.UserAgent(settings.provider)),
	)
	if err != nil {
		return nil, err
	}

	return &MondooClient{mondooClient}, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"fmt"

	mondoogql "go.mondoo.com/mondoo-go"
	"go.mondoo.com/mondoo-go/option"
	"go.mondoo.com/mql/mrn"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/utils/multierr"
)

type ConnType byte

const (
	ConnTypeOrganization ConnType = iota
	ConnTypeSpace
)

type Connection struct {
	plugin.Connection
	Upstream *upstream.UpstreamClient
	Client   *mondoogql.Client
	Type     ConnType
}

func New(id uint32, asset *inventory.Asset, conf *inventory.Config, upstreamClient *upstream.UpstreamClient) (*Connection, error) {
	creds := upstreamClient.GetCreds()
	rawCreds, err := json.Marshal(creds)
	if err != nil {
		return nil, multierr.Wrap(err, "failed to wrap credentials for Mondoo API client")
	}

	client, err := mondoogql.NewClient(
		option.UseUSRegion(),
		// option.WithAPIToken(os.Getenv("MONDOO_API_TOKEN")),
		option.WithHTTPClient(upstreamClient.HttpClient),
		option.WithServiceAccount(rawCreds),
		option.WithUserAgent(upstream.UserAgent("mondoo")),
	)
	if err != nil {
		return nil, multierr.Wrap(err, "failed to initialize Mondoo API client")
	}

	conn, err := determineConnType(upstreamClient.SpaceMrn)
	if err != nil {
		return nil, multierr.Wrap(err, "failed to determine connection type")
	}
	return &Connection{
		Connection: plugin.NewConnection(id, asset),
		Client:     client,
		Upstream:   upstreamClient,
		Type:       conn,
	}, nil
}

func (c Connection) Name() string {
	return "mondoo"
}

func determineConnType(mrnStr string) (ConnType, error) {
	m, err := mrn.NewMRN(mrnStr)
	if err != nil {
		return 0, err
	}
	_, err = m.ResourceID("spaces")
	if err == nil {
		return ConnTypeSpace, nil
	}

	_, err = m.ResourceID("organizations")
	if err == nil {
		return ConnTypeOrganization, nil
	}

	return 0, fmt.Errorf("cannot determine connection type for mrn %s", mrnStr)
}

func MrnBasenameOrMrn(m string) string {
	parsed, err := mrn.NewMRN(m)
	if err != nil {
		return m
	}
	base := parsed.Basename()
	if base == "" {
		return m
	}
	return base
}

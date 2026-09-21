// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jira

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"

	v2 "github.com/ctreminiom/go-atlassian/v2/jira/v2"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection/shared"
)

const (
	Jira shared.ConnectionType = "jira"
)

type JiraConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *v2.Client
	name   string
}

// normalizeAndValidateHost normalizes the host to https:// format and validates it's a proper domain
func normalizeAndValidateHost(val string) (string, error) {
	if val == "" {
		return "", errors.New("host cannot be empty")
	}

	// Add https:// scheme if not present
	if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
		val = "https://" + val
	}

	// Parse the URL to validate it
	u, err := url.Parse(val)
	if err != nil {
		return "", errors.New("invalid host format")
	}

	// Ensure we have a valid scheme and host
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid host format")
	}

	// Force https scheme
	u.Scheme = "https"

	return u.String(), nil
}

func NewConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*JiraConnection, error) {
	host := conf.Options["host"]
	if host == "" {
		host = os.Getenv("ATLASSIAN_HOST")
	}

	normalizedHost, err := normalizeAndValidateHost(host)
	if err != nil {
		return nil, errors.New("you must provide a valid Atlassian host e.g. via ATLASSIAN_HOST env or via the --host flag (e.g., 'foo.atlassian.net' or 'https://foo.atlassian.net')")
	}
	host = normalizedHost

	user := conf.Options["user"]
	if user == "" {
		user = os.Getenv("ATLASSIAN_USER")
	}
	if user == "" {
		return nil, errors.New("you must provide an Atlassian user e.g. via ATLASSIAN_USER env or via the --user flag")
	}

	// A hosted scan delivers the token as an inventory vault credential; the host
	// and user stay plain options either way — they are identifiers, not secrets.
	token := shared.Secret(conf, "user-token", "ATLASSIAN_USER_TOKEN")
	if token == "" {
		return nil, errors.New("you must provide an Atlassian user token e.g. via ATLASSIAN_USER_TOKEN env or via the --user-token flag")
	}

	client, err := v2.New(nil, host)
	if err != nil {
		return nil, err
	}

	client.Auth.SetBasicAuth(user, token)
	client.Auth.SetUserAgent("curl/7.54.0")

	if _, response, probeErr := client.MySelf.Details(context.Background(), nil); probeErr != nil {
		if response != nil && response.StatusCode == 401 {
			return nil, errors.New("failed to authenticate")
		}
		return nil, errors.New("failed to reach Jira: " + probeErr.Error())
	}

	return &JiraConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
		name:       host,
	}, nil
}

func (c *JiraConnection) Name() string {
	return c.name
}

func (c *JiraConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *JiraConnection) Client() *v2.Client {
	return c.client
}

func (p *JiraConnection) Type() shared.ConnectionType {
	return Jira
}

func (c *JiraConnection) ConnectionType() string {
	return "jira"
}

func (c *JiraConnection) Config() *inventory.Config {
	return c.Conf
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/jomei/notionapi"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Flag Options
const (
	OPTION_TOKEN = "token"
)

// NOTION_TOKEN_VAR is the environment variable that carries the internal
// integration token when --token is not passed on the CLI.
const NOTION_TOKEN_VAR = "NOTION_TOKEN"

// notionAPIVersion pins the Notion-Version header. The community SDK sends
// it on every request once configured here; bump it deliberately, since a
// version bump can change response shapes.
const notionAPIVersion = "2022-06-28"

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/notion.json so the CLI and generated docs can
// list what the provider supports. Add an entry here for every platform your
// asset discovery produces.
var Platforms = []*plugin.PlatformInfo{
	{Name: "notion", Title: "Notion", Family: []string{"notion"}, Kind: []string{"api"}, Runtime: []string{"notion"}},
}

type NotionConnection struct {
	plugin.Connection
	Conf    *inventory.Config
	asset   *inventory.Asset
	client  *notionapi.Client
	botUser *notionapi.User // captured during Verify(), backs notion.bot
}

func NewNotionConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*NotionConnection, error) {
	conn := &NotionConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	token := os.Getenv(NOTION_TOKEN_VAR)
	if t, ok := conf.Options[OPTION_TOKEN]; ok && t != "" {
		token = t
	}
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			token = string(cred.Secret)
		}
	}
	if token == "" {
		return nil, errors.New("a valid Notion internal integration token is required " +
			"(set NOTION_TOKEN or use --token)")
	}

	conn.client = notionapi.NewClient(notionapi.Token(token),
		notionapi.WithVersion(notionAPIVersion))

	return conn, nil
}

func (c *NotionConnection) Name() string {
	return "notion"
}

func (c *NotionConnection) Asset() *inventory.Asset {
	return c.asset
}

// Client returns the authenticated Notion API client.
func (c *NotionConnection) Client() *notionapi.Client {
	return c.client
}

// BotUser returns the integration's own bot identity, captured during
// Verify() so notion.bot never needs a second round trip.
func (c *NotionConnection) BotUser() *notionapi.User {
	return c.botUser
}

// isUnauthorized reports whether err is Notion's 401. It unwraps rather than
// asserting on the concrete type directly, so a wrapped error still resolves
// to the actionable "check your token" message instead of falling through to
// the generic one. This mirrors isRestrictedResource in the resources package.
func isUnauthorized(err error) bool {
	var apiErr *notionapi.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Status == http.StatusUnauthorized
}

// Verify calls users/me, the cheapest authenticated endpoint Notion offers,
// to confirm the token is valid and to capture the integration's own bot
// identity up front.
func (c *NotionConnection) Verify() error {
	me, err := c.client.User.Me(context.Background())
	if err != nil {
		if isUnauthorized(err) {
			return errors.New("invalid Notion integration token, verify the token and try again")
		}
		return errors.Wrap(err, "failed to verify Notion credentials")
	}
	c.botUser = me
	return nil
}

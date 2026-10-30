// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"os"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
	"go.mondoo.com/mql/logger/zerologadapter"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type SlackConnection struct {
	plugin.Connection
	Conf     *inventory.Config
	asset    *inventory.Asset
	client   *slack.Client
	teamInfo *slack.TeamInfo
}

func NewMockConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) *SlackConnection {
	return &SlackConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}
}

func NewSlackConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*SlackConnection, error) {
	sc := &SlackConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// if a secret was provided, it always overrides the env variable since it has precedence
	token := os.Getenv("SLACK_TOKEN")
	if len(conf.Credentials) > 0 {
		for i := range conf.Credentials {
			cred := conf.Credentials[i]
			if cred.Type == vault.CredentialType_password {
				token = string(cred.Secret)
			} else {
				log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Slack provider")
			}
		}
	}

	if token == "" {
		return nil, errors.New("a valid Slack token is required, pass --token '<yourtoken>' or set SLACK_TOKEN environment variable")
	}

	// retryablehttp is able to handle the Retry-After header, so we do not have to do it ourselves
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 5
	retryClient.Logger = zerologadapter.New(log.Logger)
	client := slack.New(token, slack.OptionHTTPClient(retryClient.StandardClient()))

	teamID := conf.Options["team-id"]
	ctx := context.Background()

	var teamInfo *slack.TeamInfo
	var err error
	if teamID != "" {
		teamInfo, err = client.GetOtherTeamInfoContext(ctx, teamID)
	} else {
		teamInfo, err = client.GetTeamInfoContext(ctx)
	}
	if err != nil {
		return nil, err
	}

	if teamInfo == nil {
		return nil, errors.New("could not retrieve team info")
	}

	sc.client = client
	sc.teamInfo = teamInfo
	sc.asset.Name = "Slack team " + teamInfo.Name
	return sc, nil
}

func (s *SlackConnection) Name() string {
	return "slack"
}

func (s *SlackConnection) Asset() *inventory.Asset {
	return s.asset
}

func (s *SlackConnection) Client() *slack.Client {
	return s.client
}

func (p *SlackConnection) TeamInfo() *slack.TeamInfo {
	return p.teamInfo
}

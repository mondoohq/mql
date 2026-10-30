// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"sync"

	"github.com/cockroachdb/errors"
	dropboxsdk "github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// Flag Options
const (
	OPTION_TOKEN = "token"
)

// DROPBOX_TEAM_TOKEN_VAR is the environment variable that carries the
// Dropbox Business team access token when it is not supplied via --token.
const DROPBOX_TEAM_TOKEN_VAR = "DROPBOX_TEAM_TOKEN"

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/dropbox.json so the CLI and generated docs can
// list what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "dropbox", Title: "Dropbox Business", Family: []string{"dropbox"}, Kind: []string{"api"}, Runtime: []string{"dropbox"}},
}

type DropboxConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client team.Client

	// teamID and teamName are captured during Verify (team/get_info) and
	// reused by asset detection so we don't issue the call twice.
	teamID   string
	teamName string

	// teamInfo caches the full team/get_info result captured during Verify so
	// the dropbox.team accessor can reuse it instead of re-issuing the call.
	teamInfoOnce sync.Once
	teamInfo     *team.TeamGetInfoResult
	teamInfoErr  error

	// devicesPages and linkedAppsPages cache the full, paginated result of
	// team/devices/list_members_devices and
	// team/linked_apps/list_members_linked_apps respectively. Both endpoints
	// return every member's devices/apps in one grouped, paginated call, so
	// we fetch each exactly once per connection and let both the flat
	// dropbox.devices()/dropbox.linkedApps() accessors and the per-member
	// dropbox.member.devices()/dropbox.member.linkedApps() accessors read
	// from the same cache instead of re-fetching per member.
	devicesOnce  sync.Once
	devicesPages []*team.MemberDevices
	devicesErr   error

	linkedAppsOnce  sync.Once
	linkedAppsPages []*team.MemberLinkedApps
	linkedAppsErr   error
}

func NewDropboxConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*DropboxConnection, error) {
	conn := &DropboxConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// if a secret was provided, it always overrides the env variable since it has precedence
	token := os.Getenv(DROPBOX_TEAM_TOKEN_VAR)
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			token = string(cred.Secret)
		}
	}
	if token == "" {
		return nil, errors.New("a valid Dropbox Business team access token is required (set " +
			DROPBOX_TEAM_TOKEN_VAR + " or use --token)")
	}

	config := dropboxsdk.Config{
		Token:    token,
		LogLevel: dropboxsdk.LogOff,
	}
	conn.client = team.New(config)

	return conn, nil
}

func (c *DropboxConnection) Name() string {
	return "dropbox"
}

func (c *DropboxConnection) Asset() *inventory.Asset {
	return c.asset
}

// Client returns the authenticated Dropbox Business team client.
func (c *DropboxConnection) Client() team.Client {
	return c.client
}

// Verify validates the team access token and captures the team identity used
// by asset detection, by issuing team/get_info, the cheapest authenticated
// call available on the team surface.
func (c *DropboxConnection) Verify() error {
	info, err := c.client.GetInfo()
	if err != nil {
		return errors.Wrap(err, "failed to verify Dropbox Business team access token")
	}
	c.teamID = info.TeamId
	c.teamName = info.Name
	c.teamInfo = info
	return nil
}

// TeamInfo returns the team/get_info result. It reuses the value captured
// during Verify when available and otherwise issues the call once.
func (c *DropboxConnection) TeamInfo() (*team.TeamGetInfoResult, error) {
	c.teamInfoOnce.Do(func() {
		if c.teamInfo != nil {
			return
		}
		info, err := c.client.GetInfo()
		if err != nil {
			c.teamInfoErr = err
			return
		}
		c.teamInfo = info
	})
	return c.teamInfo, c.teamInfoErr
}

// TeamID returns the team ID captured during Verify.
func (c *DropboxConnection) TeamID() string {
	return c.teamID
}

// TeamName returns the team name captured during Verify.
func (c *DropboxConnection) TeamName() string {
	return c.teamName
}

// DevicesByMember returns every team member's linked devices grouped by
// team_member_id, fetching and fully paginating
// team/devices/list_members_devices exactly once per connection.
func (c *DropboxConnection) DevicesByMember() ([]*team.MemberDevices, error) {
	c.devicesOnce.Do(func() {
		arg := &team.ListMembersDevicesArg{
			IncludeWebSessions:    true,
			IncludeDesktopClients: true,
			IncludeMobileClients:  true,
		}
		for {
			res, err := c.client.DevicesListMembersDevices(arg)
			if err != nil {
				c.devicesErr = errors.Wrap(err, "failed to list dropbox member devices")
				c.devicesPages = nil
				return
			}
			c.devicesPages = append(c.devicesPages, res.Devices...)
			if !res.HasMore {
				return
			}
			arg = &team.ListMembersDevicesArg{
				Cursor:                res.Cursor,
				IncludeWebSessions:    true,
				IncludeDesktopClients: true,
				IncludeMobileClients:  true,
			}
		}
	})
	return c.devicesPages, c.devicesErr
}

// LinkedAppsByMember returns every team member's linked third-party apps
// grouped by team_member_id, fetching and fully paginating
// team/linked_apps/list_members_linked_apps exactly once per connection.
func (c *DropboxConnection) LinkedAppsByMember() ([]*team.MemberLinkedApps, error) {
	c.linkedAppsOnce.Do(func() {
		arg := &team.ListMembersAppsArg{}
		for {
			res, err := c.client.LinkedAppsListMembersLinkedApps(arg)
			if err != nil {
				c.linkedAppsErr = errors.Wrap(err, "failed to list dropbox member linked apps")
				c.linkedAppsPages = nil
				return
			}
			c.linkedAppsPages = append(c.linkedAppsPages, res.Apps...)
			if !res.HasMore {
				return
			}
			arg = &team.ListMembersAppsArg{Cursor: res.Cursor}
		}
	})
	return c.linkedAppsPages, c.linkedAppsErr
}

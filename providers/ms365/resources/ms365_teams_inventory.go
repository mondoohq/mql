// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
)

type mqlMs365TeamsTeamInternal struct {
	fetched   bool
	teamCache models.Teamable
	lock      sync.Mutex
}

// teams lists the teams provisioned in the tenant. Only the cheap identity
// fields are populated here; the per-team settings are loaded lazily so a
// query that just enumerates teams does not pay a GET per team.
// requires Team.ReadBasic.All to list and TeamSettings.Read.All to read the
// per-team settings; channels require ChannelSettings.Read.All
func (r *mqlMs365Teams) teams() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Teams().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	teams, err := iterate[models.Teamable](ctx, resp, graphClient.GetAdapter(), models.CreateTeamCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, team := range teams {
		mqlTeam, err := CreateResource(r.MqlRuntime, "ms365.teams.team",
			map[string]*llx.RawData{
				"__id":        llx.StringDataPtr(team.GetId()),
				"id":          llx.StringDataPtr(team.GetId()),
				"displayName": llx.StringDataPtr(team.GetDisplayName()),
				"description": llx.StringDataPtr(team.GetDescription()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTeam)
	}
	return res, nil
}

// fetchTeam lazily loads the full team via a single GET, caching it so the
// per-field accessors share one Graph call.
func (t *mqlMs365TeamsTeam) fetchTeam() (models.Teamable, error) {
	if t.fetched {
		return t.teamCache, nil
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.fetched {
		return t.teamCache, nil
	}
	conn := t.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	team, err := graphClient.Teams().ByTeamId(t.Id.Data).Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}
	t.teamCache = team
	t.fetched = true
	return team, nil
}

func (t *mqlMs365TeamsTeam) memberSettings() (models.TeamMemberSettingsable, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return nil, err
	}
	return team.GetMemberSettings(), nil
}

func (t *mqlMs365TeamsTeam) guestSettings() (models.TeamGuestSettingsable, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return nil, err
	}
	return team.GetGuestSettings(), nil
}

func (t *mqlMs365TeamsTeam) messagingSettings() (models.TeamMessagingSettingsable, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return nil, err
	}
	return team.GetMessagingSettings(), nil
}

func (t *mqlMs365TeamsTeam) funSettings() (models.TeamFunSettingsable, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return nil, err
	}
	return team.GetFunSettings(), nil
}

func (t *mqlMs365TeamsTeam) visibility() (string, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return "", err
	}
	if v := team.GetVisibility(); v != nil {
		return v.String(), nil
	}
	return "", nil
}

func (t *mqlMs365TeamsTeam) isArchived() (bool, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return false, err
	}
	return convert.ToValue(team.GetIsArchived()), nil
}

func (t *mqlMs365TeamsTeam) specialization() (string, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return "", err
	}
	if s := team.GetSpecialization(); s != nil {
		return s.String(), nil
	}
	return "", nil
}

func (t *mqlMs365TeamsTeam) classification() (string, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return "", err
	}
	return convert.ToValue(team.GetClassification()), nil
}

func (t *mqlMs365TeamsTeam) createdDateTime() (*time.Time, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return nil, err
	}
	return team.GetCreatedDateTime(), nil
}

func (t *mqlMs365TeamsTeam) webUrl() (string, error) {
	team, err := t.fetchTeam()
	if err != nil {
		return "", err
	}
	return convert.ToValue(team.GetWebUrl()), nil
}

func (t *mqlMs365TeamsTeam) allowCreateUpdateChannels() (bool, error) {
	s, err := t.memberSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowCreateUpdateChannels()), nil
}

func (t *mqlMs365TeamsTeam) allowCreatePrivateChannels() (bool, error) {
	s, err := t.memberSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowCreatePrivateChannels()), nil
}

func (t *mqlMs365TeamsTeam) allowDeleteChannels() (bool, error) {
	s, err := t.memberSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowDeleteChannels()), nil
}

func (t *mqlMs365TeamsTeam) allowAddRemoveApps() (bool, error) {
	s, err := t.memberSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowAddRemoveApps()), nil
}

func (t *mqlMs365TeamsTeam) allowCreateUpdateRemoveTabs() (bool, error) {
	s, err := t.memberSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowCreateUpdateRemoveTabs()), nil
}

func (t *mqlMs365TeamsTeam) allowCreateUpdateRemoveConnectors() (bool, error) {
	s, err := t.memberSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowCreateUpdateRemoveConnectors()), nil
}

func (t *mqlMs365TeamsTeam) guestAllowCreateUpdateChannels() (bool, error) {
	s, err := t.guestSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowCreateUpdateChannels()), nil
}

func (t *mqlMs365TeamsTeam) guestAllowDeleteChannels() (bool, error) {
	s, err := t.guestSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowDeleteChannels()), nil
}

func (t *mqlMs365TeamsTeam) allowUserEditMessages() (bool, error) {
	s, err := t.messagingSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowUserEditMessages()), nil
}

func (t *mqlMs365TeamsTeam) allowUserDeleteMessages() (bool, error) {
	s, err := t.messagingSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowUserDeleteMessages()), nil
}

func (t *mqlMs365TeamsTeam) allowOwnerDeleteMessages() (bool, error) {
	s, err := t.messagingSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowOwnerDeleteMessages()), nil
}

func (t *mqlMs365TeamsTeam) allowTeamMentions() (bool, error) {
	s, err := t.messagingSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowTeamMentions()), nil
}

func (t *mqlMs365TeamsTeam) allowChannelMentions() (bool, error) {
	s, err := t.messagingSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowChannelMentions()), nil
}

func (t *mqlMs365TeamsTeam) allowGiphy() (bool, error) {
	s, err := t.funSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowGiphy()), nil
}

func (t *mqlMs365TeamsTeam) giphyContentRating() (string, error) {
	s, err := t.funSettings()
	if err != nil || s == nil {
		return "", err
	}
	if r := s.GetGiphyContentRating(); r != nil {
		return r.String(), nil
	}
	return "", nil
}

func (t *mqlMs365TeamsTeam) allowStickersAndMemes() (bool, error) {
	s, err := t.funSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowStickersAndMemes()), nil
}

func (t *mqlMs365TeamsTeam) allowCustomMemes() (bool, error) {
	s, err := t.funSettings()
	if err != nil || s == nil {
		return false, err
	}
	return convert.ToValue(s.GetAllowCustomMemes()), nil
}

// channels enumerates the team's channels.
func (t *mqlMs365TeamsTeam) channels() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Teams().ByTeamId(t.Id.Data).Channels().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	channels, err := iterate[models.Channelable](ctx, resp, graphClient.GetAdapter(), models.CreateChannelCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, ch := range channels {
		var membershipType *string
		if mt := ch.GetMembershipType(); mt != nil {
			s := mt.String()
			membershipType = &s
		}
		mqlChannel, err := CreateResource(t.MqlRuntime, "ms365.teams.channel",
			map[string]*llx.RawData{
				"__id":            llx.StringDataPtr(ch.GetId()),
				"id":              llx.StringDataPtr(ch.GetId()),
				"displayName":     llx.StringDataPtr(ch.GetDisplayName()),
				"description":     llx.StringDataPtr(ch.GetDescription()),
				"membershipType":  llx.StringDataPtr(membershipType),
				"email":           llx.StringDataPtr(ch.GetEmail()),
				"webUrl":          llx.StringDataPtr(ch.GetWebUrl()),
				"createdDateTime": graphTimeData(ch.GetCreatedDateTime()),
				"isArchived":      llx.BoolDataPtr(ch.GetIsArchived()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlChannel)
	}
	return res, nil
}

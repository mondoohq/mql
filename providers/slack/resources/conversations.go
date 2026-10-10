// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/slack/connection"
)

func (o *mqlSlackConversations) id() (string, error) {
	return "slack.conversations", nil
}

func (s *mqlSlackConversations) listChannels(excludeArchived bool, types ...string) ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.SlackConnection)
	client := conn.Client()
	if client == nil {
		return nil, errors.New("cannot retrieve new data while using a mock connection")
	}

	list := []any{}

	// https://docs.slack.dev/reference/methods/conversations.list/
	// scopes: channels:read, groups:read, im:read, mpim:read
	opts := &slack.GetConversationsParameters{
		Limit:           999, // use maximum, must be lower than 1000
		Types:           types,
		ExcludeArchived: excludeArchived,
	}

	for {
		conversations, cursor, err := client.GetConversations(opts)
		if err != nil {
			return nil, err
		}
		for i := range conversations {
			mqlUser, err := newMqlSlackConversation(s.MqlRuntime, conversations[i])
			if err != nil {
				return nil, err
			}
			list = append(list, mqlUser)
		}
		// check if we are at the end of pagination
		if cursor == "" {
			break
		}
		opts.Cursor = cursor
	}

	return list, nil
}

func (s *mqlSlackConversations) list() ([]any, error) {
	return s.listChannels(false, "public_channel", "private_channel", "mpim", "im")
}

func (s *mqlSlackConversations) privateChannels() ([]any, error) {
	return s.listChannels(true, "private_channel")
}

func (s *mqlSlackConversations) publicChannels() ([]any, error) {
	return s.listChannels(true, "public_channel")
}

func (s *mqlSlackConversations) directMessages() ([]any, error) {
	return s.listChannels(true, "mpim", "im")
}

type topic struct {
	Value   string     `json:"value"`
	Creator string     `json:"creator"`
	LastSet *time.Time `json:"lastSet"`
}

func newTopic(t slack.Topic) topic {
	lastSet := t.LastSet.Time()
	return topic{
		Value:   t.Value,
		Creator: t.Creator,
		LastSet: &lastSet,
	}
}

// custom object to make sure the json values match and the time is properly parsed

type purpose struct {
	Value   string     `json:"value"`
	Creator string     `json:"creator"`
	LastSet *time.Time `json:"lastSet"`
}

func newPurpose(p slack.Purpose) purpose {
	lastSet := p.LastSet.Time()
	return purpose{
		Value:   p.Value,
		Creator: p.Creator,
		LastSet: &lastSet,
	}
}

func newMqlSlackConversation(runtime *plugin.Runtime, conversation slack.Channel) (any, error) {
	topic, err := convert.JsonToDict(newTopic(conversation.Topic))
	if err != nil {
		return nil, err
	}

	purpose, err := convert.JsonToDict(newPurpose(conversation.Purpose))
	if err != nil {
		return nil, err
	}

	created := conversation.Created.Time()

	r, err := CreateResource(runtime, "slack.conversation", map[string]*llx.RawData{
		"id":                 llx.StringData(conversation.ID),
		"name":               llx.StringData(conversation.Name),
		"created":            llx.TimeData(created),
		"locale":             llx.StringData(conversation.Locale),
		"topic":              llx.DictData(topic),
		"purpose":            llx.DictData(purpose),
		"isArchived":         llx.BoolData(conversation.IsArchived),
		"isOpen":             llx.BoolData(conversation.IsOpen),
		"isPrivate":          llx.BoolData(conversation.IsPrivate),
		"isIM":               llx.BoolData(conversation.IsIM),
		"isMpim":             llx.BoolData(conversation.IsMpIM),
		"isGroup":            llx.BoolData(conversation.IsGroup),
		"isChannel":          llx.BoolData(conversation.IsChannel),
		"isShared":           llx.BoolData(conversation.IsShared),
		"isExtShared":        llx.BoolData(conversation.IsExtShared),
		"isPendingExtShared": llx.BoolData(conversation.IsPendingExtShared),
		"isOrgShared":        llx.BoolData(conversation.IsOrgShared),
		"priority":           llx.FloatData(conversation.Priority),
	})
	if err != nil {
		return nil, err
	}
	mqlConversation := r.(*mqlSlackConversation)
	mqlConversation.creatorId = conversation.Creator
	return mqlConversation, nil
}

type mqlSlackConversationInternal struct {
	creatorId string
}

func (x *mqlSlackConversation) id() (string, error) {
	return "slack.conversation/" + x.Id.Data, nil
}

func (s *mqlSlackConversation) creator() (*mqlSlackUser, error) {
	if s.creatorId == "" {
		s.Creator = plugin.TValue[*mqlSlackUser]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	r, err := NewResource(s.MqlRuntime, "slack.user", map[string]*llx.RawData{
		"id": llx.StringData(s.creatorId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSlackUser), nil
}

func (s *mqlSlackConversation) members() ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.SlackConnection)
	client := conn.Client()
	if client == nil {
		return nil, errors.New("cannot retrieve new data while using a mock connection")
	}

	// before we fetch the members, we need to fetch all users so that we save the time for individual lookups
	users, err := CreateResource(s.MqlRuntime, "slack.users", nil)
	if err != nil {
		return nil, err
	}
	mqlUsers := users.(*mqlSlackUsers)
	userEntries := mqlUsers.GetList()

	findUser := func(id string) *mqlSlackUser {
		for i := range userEntries.Data {
			user := userEntries.Data[i].(*mqlSlackUser)
			if user.Id.Data == id {
				return user
			}
		}
		return nil
	}

	var list []any
	isChannel := s.IsChannel.Data
	if !isChannel {
		return list, nil
	}

	opts := &slack.GetUsersInConversationParameters{
		ChannelID: s.Id.Data,
		Limit:     999, // must be less than 1000
	}

	for {
		members, cursor, err := client.GetUsersInConversation(opts)
		if err != nil {
			return nil, err
		}

		for i := range members {
			user := findUser(members[i])
			if user == nil {
				// The member is not part of this workspace's user list, which
				// happens for external participants in Slack Connect / shared
				// channels. Resolve them directly; skip only if that also fails,
				// rather than failing the entire members list.
				ext, err := NewResource(s.MqlRuntime, "slack.user", map[string]*llx.RawData{
					"id": llx.StringData(members[i]),
				})
				if err != nil {
					log.Warn().Str("user", members[i]).Str("channel", s.Id.Data).
						Msg("slack: skipping conversation member that could not be resolved")
					continue
				}
				user = ext.(*mqlSlackUser)
			}
			list = append(list, user)
		}

		// check if we are at the end of pagination
		if cursor == "" {
			break
		}
		opts.Cursor = cursor
	}

	return list, nil
}

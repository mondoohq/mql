// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/jomei/notionapi"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/notion/connection"
)

// id provides a defense-in-depth cache key fallback: mqlNotionUserFromAPI
// already sets "__id" explicitly on every CreateResource call, but should a
// future call site create a notion.user without it, this keeps distinct
// users from collapsing onto a single cache entry instead of silently
// colliding. It returns the bare user UUID to match the "__id" set by
// mqlNotionUserFromAPI, so both paths resolve to the same cache entry.
func (r *mqlNotionUser) id() (string, error) {
	return r.Id.Data, nil
}

// isRestrictedResource reports whether Notion refused the call because this
// token type may not reach the endpoint at all, rather than because the call
// failed. A personal (user-owned) integration token cannot list users: the
// API answers 403 restricted_resource, and no amount of retrying changes
// that.
func isRestrictedResource(err error) bool {
	var apiErr *notionapi.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Status == http.StatusForbidden && apiErr.Code == "restricted_resource"
}

// users lists the workspace members and bots visible to this integration.
//
// A token that may not list users reports null rather than failing. The
// distinction matters: an error here propagates out of every query that
// merely mentions users, including notion.workspace, so a token that cannot
// read one collection would take the readable ones down with it.
func (r *mqlNotion) users() ([]any, error) {
	conn := r.conn()
	list, err := listNotionUsers(conn)
	if err != nil {
		if isRestrictedResource(err) {
			log.Warn().Err(err).
				Msg("notion> this token may not list users, reporting null")
			r.Users.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(list))
	for _, u := range list {
		mqlUser, err := mqlNotionUserFromAPI(r.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}

// listNotionUsers paginates GET /v1/users to completion.
func listNotionUsers(conn *connection.NotionConnection) ([]*notionapi.User, error) {
	client := conn.Client()

	var all []*notionapi.User
	cursor := notionapi.Cursor("")
	for {
		resp, err := client.User.List(context.Background(), &notionapi.Pagination{
			StartCursor: cursor,
			PageSize:    100,
		})
		if err != nil {
			return nil, err
		}
		for i := range resp.Results {
			u := resp.Results[i]
			all = append(all, &u)
		}
		if !resp.HasMore || resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}
	return all, nil
}

// mqlNotionUserFromAPI maps a single *notionapi.User to its MQL resource.
// Used both by the users() lister and initNotionUser's lazy lookup.
func mqlNotionUserFromAPI(runtime *plugin.Runtime, u *notionapi.User) (*mqlNotionUser, error) {
	// Null rather than empty when there is nothing to report. An empty
	// string would say "this user has no email" / "this bot has no owner
	// type", which is a different claim from "Notion did not tell us": a
	// person-type user carries no bot owner at all, and the email is
	// withheld unless the integration holds the capability to read it.
	var email *string
	if u.Person != nil && u.Person.Email != "" {
		email = &u.Person.Email
	}

	var botOwnerType *string
	if u.Bot != nil && u.Bot.Owner.Type != "" {
		botOwnerType = &u.Bot.Owner.Type
	}

	res, err := CreateResource(runtime, "notion.user", map[string]*llx.RawData{
		"__id":         llx.StringData(string(u.ID)),
		"id":           llx.StringData(string(u.ID)),
		"name":         llx.StringData(u.Name),
		"avatarUrl":    llx.StringData(u.AvatarURL),
		"type":         llx.StringData(string(u.Type)),
		"email":        llx.StringDataPtr(email),
		"botOwnerType": llx.StringDataPtr(botOwnerType),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNotionUser), nil
}

// initNotionUser resolves a workspace member or bot by id on demand.
func initNotionUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("notion.user requires an id")
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("notion.user requires a valid id")
	}

	conn := runtime.Connection.(*connection.NotionConnection)
	u, err := conn.Client().User.Get(context.Background(), notionapi.UserID(id))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "notion.user with id %q not found", id)
	}

	res, err := mqlNotionUserFromAPI(runtime, u)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// botOwner resolves the individual owner of a bot-type user when
// botOwnerType is 'user'. As with notion.bot.owner, the community SDK's
// Owner struct does not decode the nested user object Notion returns
// inline, so the owning user's id is unavailable through this client and
// the field stays null.
func (u *mqlNotionUser) botOwner() (*mqlNotionUser, error) {
	u.BotOwner.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

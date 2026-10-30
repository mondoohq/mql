// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"maps"
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

type mqlPortainerStackInternal struct {
	cacheEndpointId      int64
	cacheCreatedByUserId string
	cacheCreatedByName   string
}

// autoUpdateFields maps a stack's GitOps auto-update settings. Every field is
// null when the stack has no auto-update configured, since "not configured"
// and "configured but not forcing a pull" are different answers.
func autoUpdateFields(a *models.PortainerAutoUpdateSettings) map[string]*llx.RawData {
	if a == nil {
		return map[string]*llx.RawData{
			"autoUpdateEnabled":        llx.BoolData(false),
			"autoUpdateInterval":       llx.NilData,
			"autoUpdateWebhook":        llx.NilData,
			"autoUpdateForcePullImage": llx.NilData,
			"autoUpdateForceUpdate":    llx.NilData,
		}
	}
	// An auto-update block drives a redeploy either on an interval or from its
	// own webhook. Report the interval only when one is set, so an empty string
	// is not read as "redeploys immediately".
	interval := &a.Interval
	if a.Interval == "" {
		interval = nil
	}
	return map[string]*llx.RawData{
		"autoUpdateEnabled":        llx.BoolData(true),
		"autoUpdateInterval":       llx.StringDataPtr(interval),
		"autoUpdateWebhook":        llx.BoolData(a.Webhook != ""),
		"autoUpdateForcePullImage": llx.BoolData(a.ForcePullImage),
		"autoUpdateForceUpdate":    llx.BoolData(a.ForceUpdate),
	}
}

// gitFields maps a stack's Git repository configuration. Every field is null
// for a stack that is not backed by a repository, so a missing repository is
// never reported as an empty URL with verification enabled.
func gitFields(g *models.GittypesRepoConfig) map[string]*llx.RawData {
	if g == nil {
		return map[string]*llx.RawData{
			"gitUrl":                      llx.NilData,
			"gitReferenceName":            llx.NilData,
			"gitConfigFilePath":           llx.NilData,
			"gitTlsSkipVerify":            llx.NilData,
			"gitAuthenticationConfigured": llx.NilData,
		}
	}
	return map[string]*llx.RawData{
		"gitUrl":                      llx.StringData(g.URL),
		"gitReferenceName":            llx.StringData(g.ReferenceName),
		"gitConfigFilePath":           llx.StringData(g.ConfigFilePath),
		"gitTlsSkipVerify":            llx.BoolData(g.TlsskipVerify),
		"gitAuthenticationConfigured": llx.BoolData(g.Authentication != nil),
	}
}

func newMqlPortainerStack(runtime *plugin.Runtime, s *models.PortainereeStack) (*mqlPortainerStack, error) {
	args := map[string]*llx.RawData{
		"__id":              llx.StringData("portainer.stack/" + strconv.FormatInt(s.ID, 10)),
		"id":                llx.IntData(s.ID),
		"name":              llx.StringData(s.Name),
		"type":              llx.StringData(connection.StackType(s.Type)),
		"status":            llx.StringData(connection.StackStatus(s.Status)),
		"entryPoint":        llx.StringData(s.EntryPoint),
		"namespace":         llx.StringData(s.Namespace),
		"fromAppTemplate":   llx.BoolData(s.FromAppTemplate),
		"createdBy":         llx.StringData(s.CreatedBy),
		"creationDate":      llx.TimeDataPtr(unixTimePtr(s.CreationDate)),
		"updatedBy":         llx.StringData(s.UpdatedBy),
		"updateDate":        llx.TimeDataPtr(unixTimePtr(s.UpdateDate)),
		"webhookEnabled":    llx.BoolData(s.Webhook != ""),
		"isDetachedFromGit": llx.BoolData(s.IsDetachedFromGit),
	}
	maps.Copy(args, autoUpdateFields(s.AutoUpdate))
	maps.Copy(args, gitFields(s.GitConfig))

	res, err := CreateResource(runtime, "portainer.stack", args)
	if err != nil {
		return nil, err
	}
	mqlStack := res.(*mqlPortainerStack)
	mqlStack.cacheEndpointId = s.EndpointID
	mqlStack.cacheCreatedByUserId = s.CreatedByUserID
	mqlStack.cacheCreatedByName = s.CreatedBy
	return mqlStack, nil
}

func (r *mqlPortainer) stacks() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	stacks, err := conn.Stacks()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(stacks))
	for _, s := range stacks {
		mqlStack, err := newMqlPortainerStack(r.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlStack)
	}
	return res, nil
}

// environment resolves the environment the stack is deployed to.
func (r *mqlPortainerStack) environment() (*mqlPortainerEnvironment, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	return resolvePortainerEnvironment(r.MqlRuntime, conn, r.cacheEndpointId, &r.Environment)
}

// findStackCreator picks the account that created a stack out of the instance
// user list. The API reports the creator both as a numeric id (carried as a
// string) and as a login name; the id is authoritative, and the name is used
// when no id was recorded, which older stacks do not carry.
func findStackCreator(users []*models.PortainereeUser, userID, username string) *models.PortainereeUser {
	if id, err := strconv.ParseInt(userID, 10, 64); err == nil && id != 0 {
		for _, u := range users {
			if u.ID == id {
				return u
			}
		}
		// The id names an account the token cannot see or one that has since
		// been deleted. Falling back to the login name would risk attributing
		// the stack to a different account that reused the name.
		return nil
	}
	if username == "" {
		return nil
	}
	for _, u := range users {
		if u.Username == username {
			return u
		}
	}
	return nil
}

// createdByUser resolves the account that created the stack.
func (r *mqlPortainerStack) createdByUser() (*mqlPortainerUser, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	users, err := conn.Users()
	if err != nil {
		return nil, err
	}
	u := findStackCreator(users, r.cacheCreatedByUserId, r.cacheCreatedByName)
	if u == nil {
		r.CreatedByUser.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newMqlPortainerUser(r.MqlRuntime, u)
}

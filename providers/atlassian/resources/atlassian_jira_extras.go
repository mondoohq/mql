// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"github.com/cockroachdb/errors"
	"github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/atlassian/connection/jira"
	"go.mondoo.com/mql/types"
)

// ---------- Custom fields ----------

func (a *mqlAtlassianJira) customFields() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	fields, _, err := jiraClient.Issue.Field.Gets(context.Background())
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(fields))
	for _, f := range fields {
		if f == nil || !f.Custom {
			continue
		}
		schemaType, schemaItems, schemaSystem, schemaCustom := "", "", "", ""
		var schemaCustomId int64
		if f.Schema != nil {
			schemaType = f.Schema.Type
			schemaItems = f.Schema.Items
			schemaSystem = f.Schema.System
			schemaCustom = f.Schema.Custom
			schemaCustomId = int64(f.Schema.CustomID)
		}
		var lastUsed any
		if f.LastUsed != nil {
			lastUsed = map[string]any{
				"type":  f.LastUsed.Type,
				"value": f.LastUsed.Value,
			}
		}
		mqlField, err := CreateResource(a.MqlRuntime, "atlassian.jira.customField",
			map[string]*llx.RawData{
				"id":             llx.StringData(f.ID),
				"key":            llx.StringData(f.Key),
				"name":           llx.StringData(f.Name),
				"description":    llx.StringData(f.Description),
				"searcherKey":    llx.StringData(f.SearcherKey),
				"searchable":     llx.BoolData(f.Searchable),
				"navigable":      llx.BoolData(f.Navigable),
				"orderable":      llx.BoolData(f.Orderable),
				"isLocked":       llx.BoolData(f.IsLocked),
				"schemaType":     llx.StringData(schemaType),
				"schemaItems":    llx.StringData(schemaItems),
				"schemaSystem":   llx.StringData(schemaSystem),
				"schemaCustom":   llx.StringData(schemaCustom),
				"schemaCustomId": llx.IntData(schemaCustomId),
				"screensCount":   llx.IntData(int64(f.ScreensCount)),
				"contextsCount":  llx.IntData(int64(f.ContextsCount)),
				"lastUsed":       llx.DictData(lastUsed),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlField)
	}
	return res, nil
}

func (c *mqlAtlassianJiraCustomField) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return "atlassian.jira.customField/" + c.Id.Data, nil
}

// ---------- Workflows ----------

func (a *mqlAtlassianJira) workflows() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	res := []any{}
	startAt := 0
	const pageSize = 50
	for {
		page, _, err := jiraClient.Workflow.Gets(context.Background(), nil, startAt, pageSize)
		if err != nil {
			return nil, err
		}
		if page == nil {
			break
		}
		for _, wf := range page.Values {
			if wf == nil {
				continue
			}
			mqlWf, err := workflowToMql(a, wf)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlWf)
		}
		if page.IsLast || len(page.Values) == 0 {
			break
		}
		startAt += len(page.Values)
	}
	return res, nil
}

func workflowToMql(a *mqlAtlassianJira, wf *models.WorkflowScheme) (any, error) {
	id, name := "", ""
	if wf.ID != nil {
		id = wf.ID.EntityID
		name = wf.ID.Name
	}
	if id == "" {
		id = name
	}

	statuses := make([]any, 0, len(wf.Statuses))
	for _, s := range wf.Statuses {
		if s == nil {
			continue
		}
		statuses = append(statuses, s.Name)
	}

	transitions := make([]any, 0, len(wf.Transitions))
	for _, t := range wf.Transitions {
		if t == nil {
			continue
		}
		from := []any{}
		for _, f := range t.From {
			if f == nil {
				continue
			}
			from = append(from, f.StatusReference)
		}
		to := ""
		if t.To != nil {
			to = t.To.StatusReference
		}
		entry := map[string]any{
			"id":          t.ID,
			"name":        t.Name,
			"type":        t.Type,
			"description": t.Description,
			"from":        from,
			"to":          to,
			"conditions":  ruleConfigurationsToAny(t.Conditions),
			"validators":  ruleListToAny(t.Validators),
			"actions":     ruleListToAny(t.Actions),
			"triggers":    ruleListToAny(t.Triggers),
		}
		transitions = append(transitions, entry)
	}

	return CreateResource(a.MqlRuntime, "atlassian.jira.workflow",
		map[string]*llx.RawData{
			"id":          llx.StringData(id),
			"name":        llx.StringData(name),
			"description": llx.StringData(wf.Description),
			"isDefault":   llx.BoolData(wf.IsDefault),
			"statuses":    llx.ArrayData(statuses, "string"),
			"transitions": llx.ArrayData(transitions, "dict"),
		})
}

func ruleListToAny(rules []*models.WorkflowRuleConfigurationScheme) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		out = append(out, map[string]any{
			"id":         r.ID,
			"ruleKey":    r.RuleKey,
			"parameters": r.Parameters,
		})
	}
	return out
}

// maxConditionGroupDepth caps recursion through nested workflow condition
// groups. The Jira UI doesn't allow trees this deep in practice, so anything
// beyond this is almost certainly a malformed payload — truncate rather than
// risk an unbounded recursion.
const maxConditionGroupDepth = 20

func ruleConfigurationsToAny(cg *models.ConditionGroupConfigurationScheme) any {
	return ruleConfigurationsToAnyDepth(cg, 0)
}

func ruleConfigurationsToAnyDepth(cg *models.ConditionGroupConfigurationScheme, depth int) any {
	if cg == nil || depth >= maxConditionGroupDepth {
		return nil
	}
	groups := make([]any, 0, len(cg.ConditionGroups))
	for _, g := range cg.ConditionGroups {
		groups = append(groups, ruleConfigurationsToAnyDepth(g, depth+1))
	}
	return map[string]any{
		"operation":       cg.Operation,
		"conditions":      ruleListToAny(cg.Conditions),
		"conditionGroups": groups,
	}
}

func (w *mqlAtlassianJiraWorkflow) id() (string, error) {
	if w.Id.Error != nil {
		return "", w.Id.Error
	}
	return "atlassian.jira.workflow/" + w.Id.Data, nil
}

// ---------- Project roles ----------

func (a *mqlAtlassianJiraProject) roles() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	if a.Key.Error != nil {
		return nil, a.Key.Error
	}
	if a.Id.Error != nil {
		return nil, a.Id.Error
	}
	projectKey := a.Key.Data
	if projectKey == "" {
		projectKey = a.Id.Data
	}
	if projectKey == "" {
		return []any{}, nil
	}

	details, _, err := jiraClient.Project.Role.Details(context.Background(), projectKey)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(details))
	for _, d := range details {
		if d == nil {
			continue
		}
		// Fetch the full role to get actor assignments. A single role
		// failing (rate-limit, transient 5xx, permission edge case) shouldn't
		// fail the whole project — log and skip.
		role, _, err := jiraClient.Project.Role.Get(context.Background(), projectKey, d.ID)
		if err != nil {
			log.Warn().Err(err).Str("project", projectKey).Int("roleId", d.ID).Msg("failed to fetch project role details")
			continue
		}
		actors := []any{}
		if role != nil {
			for _, a := range role.Actors {
				if a == nil {
					continue
				}
				entry := map[string]any{
					"id":          a.ID,
					"type":        a.Type,
					"name":        a.Name,
					"displayName": a.DisplayName,
					"avatarUrl":   a.AvatarURL,
				}
				if a.ActorUser != nil {
					entry["accountId"] = a.ActorUser.AccountID
				}
				actors = append(actors, entry)
			}
		}
		mqlRole, err := CreateResource(a.MqlRuntime, "atlassian.jira.project.role",
			map[string]*llx.RawData{
				"id":               llx.StringData(projectKey + "/" + strconv.Itoa(d.ID)),
				"projectKey":       llx.StringData(projectKey),
				"roleId":           llx.IntData(int64(d.ID)),
				"name":             llx.StringData(d.Name),
				"description":      llx.StringData(d.Description),
				"admin":            llx.BoolData(d.Admin),
				"default":          llx.BoolData(d.Default),
				"roleConfigurable": llx.BoolData(d.RoleConfigurable),
				"actors":           llx.ArrayData(actors, "dict"),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	return res, nil
}

func (r *mqlAtlassianJiraProjectRole) id() (string, error) {
	if r.Id.Error != nil {
		return "", r.Id.Error
	}
	return "atlassian.jira.project.role/" + r.Id.Data, nil
}

// ---------- Filters ----------

func (a *mqlAtlassianJira) filters() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	res := []any{}
	startAt := 0
	for {
		page, _, err := jiraClient.Filter.Search(context.Background(),
			&models.FilterSearchOptionScheme{
				Expand: []string{"description", "owner", "jql", "viewUrl", "searchUrl", "sharePermissions", "favouritedCount", "subscriptions"},
			},
			startAt, JIRA_SEARCH_MAX_RESULTS)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Values) == 0 {
			break
		}
		for _, f := range page.Values {
			if f == nil {
				continue
			}
			owner, err := mqlJiraUser(a.MqlRuntime, f.Owner)
			if err != nil {
				return nil, err
			}
			mqlFilter, err := CreateResource(a.MqlRuntime, "atlassian.jira.filter",
				map[string]*llx.RawData{
					"id":               llx.StringData(f.ID),
					"name":             llx.StringData(f.Name),
					"jql":              llx.StringData(f.JQL),
					"viewUrl":          llx.StringData(f.ViewURL),
					"favouritedCount":  llx.IntData(int64(f.FavouritedCount)),
					"owner":            owner,
					"sharePermissions": llx.ArrayData(jiraSharePermissions(f.SharePermissions), types.Dict),
					"subscriptions":    llx.ArrayData(jiraFilterSubscriptions(f.Subscriptions), types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFilter)
		}
		if page.IsLast || len(page.Values) < JIRA_SEARCH_MAX_RESULTS {
			break
		}
		startAt += len(page.Values)
	}
	return res, nil
}

func (a *mqlAtlassianJiraFilter) id() (string, error) {
	return "atlassian.jira.filter/" + a.Id.Data, nil
}

func jiraFilterSubscriptions(items []*models.FilterSubscriptionScheme) []any {
	out := make([]any, 0, len(items))
	for _, s := range items {
		if s == nil {
			continue
		}
		row := map[string]any{
			"id": s.ID,
		}
		if s.User != nil {
			row["userAccountId"] = s.User.AccountID
			row["userName"] = s.User.DisplayName
		}
		if s.Group != nil {
			row["groupName"] = s.Group.Name
		}
		out = append(out, row)
	}
	return out
}

// jiraSharePermissions flattens a []*SharePermissionScheme into []dict rows
// shared by atlassian.jira.filter and atlassian.jira.dashboard. Each row has
// the holder type plus whichever id / name fields the type carries; callers
// can filter on `type` and inspect the appropriate fields without unwrapping
// nested objects.
func jiraSharePermissions(perms []*models.SharePermissionScheme) []any {
	out := make([]any, 0, len(perms))
	for _, p := range perms {
		if p == nil {
			continue
		}
		row := map[string]any{
			"id":   p.ID,
			"type": p.Type,
		}
		if p.Project != nil {
			row["projectId"] = p.Project.ID
			row["projectKey"] = p.Project.Key
		}
		if p.Role != nil {
			row["projectRoleId"] = p.Role.ID
			row["projectRoleName"] = p.Role.Name
		}
		if p.Group != nil {
			row["groupName"] = p.Group.Name
		}
		if p.User != nil {
			row["userAccountId"] = p.User.AccountID
			row["userName"] = p.User.DisplayName
		}
		out = append(out, row)
	}
	return out
}

// ---------- Dashboards ----------

func (a *mqlAtlassianJira) dashboards() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	res := []any{}
	startAt := 0
	total := JIRA_SEARCH_MAX_RESULTS
	for startAt < total {
		page, _, err := jiraClient.Dashboard.Gets(context.Background(), startAt, JIRA_SEARCH_MAX_RESULTS, "")
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Dashboards) == 0 {
			break
		}
		for _, d := range page.Dashboards {
			if d == nil {
				continue
			}
			owner, err := mqlJiraUser(a.MqlRuntime, d.Owner)
			if err != nil {
				return nil, err
			}
			mqlDashboard, err := CreateResource(a.MqlRuntime, "atlassian.jira.dashboard",
				map[string]*llx.RawData{
					"id":               llx.StringData(d.ID),
					"name":             llx.StringData(d.Name),
					"viewUrl":          llx.StringData(d.View),
					"popularity":       llx.IntData(int64(d.Popularity)),
					"owner":            owner,
					"sharePermissions": llx.ArrayData(jiraSharePermissions(d.SharePermissions), types.Dict),
					"editPermissions":  llx.ArrayData(jiraSharePermissions(d.EditPermission), types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDashboard)
		}
		total = page.Total
		startAt += len(page.Dashboards)
	}
	return res, nil
}

func (a *mqlAtlassianJiraDashboard) id() (string, error) {
	return "atlassian.jira.dashboard/" + a.Id.Data, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection/jira"
	"go.mondoo.com/mql/types"
)

const (
	JIRA_TIME_FORMAT        = "2006-01-02T15:04:05.999-0700"
	JIRA_SEARCH_MAX_RESULTS = 1000
)

func (a *mqlAtlassianJira) id() (string, error) {
	return "jira", nil
}

// parseJiraTime parses a Jira API timestamp, trying RFC 3339 first and then the
// Jira-specific layout. It returns nil for empty or unparseable input so the
// corresponding MQL field resolves to null rather than the zero time.
func parseJiraTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	if t, err := time.Parse(JIRA_TIME_FORMAT, s); err == nil {
		return &t
	}
	return nil
}

func (a *mqlAtlassianJira) users() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jira := conn.Client()

	res := []any{}
	startAt := 0

	for {
		users, _, err := jira.User.Search.Do(context.Background(), "", " ", startAt, JIRA_SEARCH_MAX_RESULTS)
		if err != nil {
			return nil, err
		}
		if len(users) == 0 {
			break
		}

		for _, user := range users {
			mqlAtlassianJiraUser, err := CreateResource(a.MqlRuntime, "atlassian.jira.user",
				map[string]*llx.RawData{
					"id":       llx.StringData(user.AccountID),
					"name":     llx.StringData(user.DisplayName),
					"type":     llx.StringData(user.AccountType),
					"picture":  llx.StringData(jiraUserAvatar(user)),
					"email":    llx.StringData(user.EmailAddress),
					"active":   llx.BoolData(user.Active),
					"timezone": llx.StringData(user.TimeZone),
					"locale":   llx.StringData(user.Locale),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAtlassianJiraUser)
		}

		startAt += len(users)
	}
	return res, nil
}

func (a *mqlAtlassianJiraUser) applicationRoles() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jira := conn.Client()
	expands := []string{"groups", "applicationRoles"}
	user, _, err := jira.User.Get(context.Background(), a.Id.Data, expands)
	if err != nil {
		return nil, err
	}
	// ApplicationRoles is an omitempty pointer; accounts with no application-role
	// assignment (app/customer account types) return it nil, so guard before
	// dereferencing Items.
	if user == nil || user.ApplicationRoles == nil {
		return []any{}, nil
	}
	roles := user.ApplicationRoles

	res := []any{}
	for _, role := range roles.Items {
		mqlAtlassianJiraUserRole, err := CreateResource(a.MqlRuntime, "atlassian.jira.applicationRole",
			map[string]*llx.RawData{
				"id":   llx.StringData(role.Key),
				"name": llx.StringData(role.Name),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAtlassianJiraUserRole)
	}
	return res, nil
}

// groups returns the groups this specific user is a member of. Uses the
// per-user /rest/api/2/user/groups endpoint — the original code called the
// global Group.Bulk which returned every group on the instance regardless of
// the user, breaking any membership-based audit. The per-user endpoint only
// exposes group names (not GroupIDs), so name doubles as the id here.
func (a *mqlAtlassianJiraUser) groups() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jiraClient := conn.Client()
	groups, _, err := jiraClient.User.Groups(context.Background(), a.Id.Data)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(groups))
	for _, group := range groups {
		if group == nil || group.Name == "" {
			continue
		}
		mqlGroup, err := CreateResource(a.MqlRuntime, "atlassian.jira.group",
			map[string]*llx.RawData{
				"id":   llx.StringData(group.Name),
				"name": llx.StringData(group.Name),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

// groups returns every group defined on the Jira instance, paginating through
// Group.Bulk. The previous implementation hardcoded maxResults=1000 and stopped
// after the first page, silently truncating large orgs.
func (a *mqlAtlassianJira) groups() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jiraClient := conn.Client()
	res := []any{}
	startAt := 0
	for {
		page, _, err := jiraClient.Group.Bulk(context.Background(), nil, startAt, JIRA_SEARCH_MAX_RESULTS)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Values) == 0 {
			break
		}
		for _, group := range page.Values {
			if group == nil {
				continue
			}
			mqlGroup, err := CreateResource(a.MqlRuntime, "atlassian.jira.group",
				map[string]*llx.RawData{
					"id":   llx.StringData(group.GroupID),
					"name": llx.StringData(group.Name),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
		if page.IsLast || len(page.Values) < JIRA_SEARCH_MAX_RESULTS {
			break
		}
		startAt += len(page.Values)
	}
	return res, nil
}

func (a *mqlAtlassianJira) serverInfos() (*mqlAtlassianJiraServerInfo, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jira := conn.Client()
	info, _, err := jira.Server.Info(context.Background())
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(a.MqlRuntime, "atlassian.jira.serverInfo",
		map[string]*llx.RawData{
			"baseUrl":        llx.StringData(info.BaseURL),
			"serverTitle":    llx.StringData(info.ServerTitle),
			"buildNumber":    llx.IntData(int64(info.BuildNumber)),
			"version":        llx.StringData(info.Version),
			"buildDate":      llx.TimeDataPtr(parseJiraTime(info.BuildDate)),
			"serverTime":     llx.TimeDataPtr(parseJiraTime(info.ServerTime)),
			"deploymentType": llx.StringData(info.DeploymentType),
		})
	return res.(*mqlAtlassianJiraServerInfo), err
}

func (a *mqlAtlassianJira) projects() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jira := conn.Client()

	res := []any{}
	startAt := 0
	total := JIRA_SEARCH_MAX_RESULTS
	options := &models.ProjectSearchOptionsScheme{Expand: []string{"lead"}}

	for startAt < total {
		projects, _, err := jira.Project.Search(context.Background(), options, startAt, JIRA_SEARCH_MAX_RESULTS)
		if err != nil {
			return nil, err
		}
		// Guard against empty pages with non-zero Total — without this an
		// upstream that returns []Values with Total>0 would spin forever.
		if projects == nil || len(projects.Values) == 0 {
			break
		}

		for _, project := range projects.Values {
			lead, err := mqlJiraUser(a.MqlRuntime, project.Lead)
			if err != nil {
				return nil, err
			}

			mqlAtlassianJiraProject, err := CreateResource(a.MqlRuntime, "atlassian.jira.project",
				map[string]*llx.RawData{
					"id":             llx.StringData(project.ID),
					"name":           llx.StringData(project.Name),
					"description":    llx.StringData(project.Description),
					"uuid":           llx.StringData(project.UUID),
					"key":            llx.StringData(project.Key),
					"url":            llx.StringData(project.URL),
					"email":          llx.StringData(project.Email),
					"projectTypeKey": llx.StringData(project.ProjectTypeKey),
					"private":        llx.BoolData(project.IsPrivate),
					"deleted":        llx.BoolData(project.Deleted),
					"archived":       llx.BoolData(project.Archived),
					"lead":           lead,
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAtlassianJiraProject)
		}

		total = projects.Total
		startAt += len(projects.Values)
	}
	return res, nil
}

func (a *mqlAtlassianJira) issues() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jira := conn.Client()
	validate := ""
	jql := "order by created DESC"
	fields := []string{
		"summary", "status", "project", "issuetype", "description", "labels",
		"priority", "resolution", "creator", "assignee", "reporter",
		"created", "updated", "resolutiondate", "duedate",
		"components", "fixVersions", "security", "watches", "votes", "comment",
	}
	expands := []string{"changelog", "renderedFields", "names", "schema", "transitions", "operations", "editmeta"}

	res := []any{}
	startAt := 0
	total := JIRA_SEARCH_MAX_RESULTS

	for startAt < total {
		issues, _, err := jira.Issue.Search.Get(context.Background(), jql, fields, expands, startAt, JIRA_SEARCH_MAX_RESULTS, validate)
		if err != nil {
			return nil, err
		}
		if issues == nil || len(issues.Issues) == 0 {
			break
		}
		for _, issue := range issues.Issues {
			// Fields is an omitempty pointer. A malformed/permission-restricted
			// search hit can carry no fields block at all; skip it rather than
			// panic (and crash the whole scan) on the derefs below.
			if issue == nil || issue.Fields == nil {
				continue
			}
			f := issue.Fields

			creator, err := mqlJiraUser(a.MqlRuntime, f.Creator)
			if err != nil {
				return nil, err
			}
			assignee, err := mqlJiraUser(a.MqlRuntime, f.Assignee)
			if err != nil {
				return nil, err
			}
			reporter, err := mqlJiraUser(a.MqlRuntime, f.Reporter)
			if err != nil {
				return nil, err
			}

			mqlAtlassianJiraIssue, err := CreateResource(a.MqlRuntime, "atlassian.jira.issue",
				map[string]*llx.RawData{
					"id":            llx.StringData(issue.ID),
					"key":           llx.StringData(issue.Key),
					"summary":       llx.StringData(f.Summary),
					"project":       llx.StringData(jiraProjectName(f.Project)),
					"projectKey":    llx.StringData(jiraProjectKey(f.Project)),
					"status":        llx.StringData(jiraStatusName(f.Status)),
					"description":   llx.StringData(f.Description),
					"priority":      llx.StringData(jiraPriorityName(f.Priority)),
					"resolution":    llx.StringData(jiraResolutionName(f.Resolution)),
					"labels":        llx.ArrayData(stringsToAny(f.Labels), types.String),
					"createdAt":     llx.TimeDataPtr(jiraDateTime(f.Created)),
					"updatedAt":     llx.TimeDataPtr(jiraDateTime(f.Updated)),
					"resolvedAt":    llx.TimeDataPtr(jiraDateTime(f.ResolutionDate)),
					"dueDate":       llx.TimeDataPtr(jiraDate(f.DueDate)),
					"creator":       creator,
					"assignee":      assignee,
					"reporter":      reporter,
					"typeName":      llx.StringData(jiraIssueTypeName(f.IssueType)),
					"components":    llx.ArrayData(jiraIssueComponents(f.Components), types.Dict),
					"fixVersions":   llx.ArrayData(jiraIssueVersions(f.FixVersions), types.Dict),
					"securityLevel": llx.DictData(jiraIssueSecurity(f.Security)),
					"watcherCount":  llx.IntData(int64(jiraWatcherCount(f.Watcher))),
					"voteCount":     llx.IntData(int64(jiraVoteCount(f.Votes))),
					"comments":      llx.ArrayData(jiraIssueComments(f.Comment), types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAtlassianJiraIssue)
		}

		total = issues.Total
		startAt += len(issues.Issues)
	}

	return res, nil
}

func mqlJiraUser(runtime *plugin.Runtime, user *models.UserScheme) (*llx.RawData, error) {
	if user == nil {
		return llx.NilData, nil
	}
	resource, err := CreateResource(runtime, "atlassian.jira.user",
		map[string]*llx.RawData{
			"id":       llx.StringData(user.AccountID),
			"name":     llx.StringData(user.DisplayName),
			"type":     llx.StringData(user.AccountType),
			"picture":  llx.StringData(jiraUserAvatar(user)),
			"email":    llx.StringData(user.EmailAddress),
			"active":   llx.BoolData(user.Active),
			"timezone": llx.StringData(user.TimeZone),
			"locale":   llx.StringData(user.Locale),
		})
	if err != nil {
		return nil, err
	}
	return llx.AnyData(resource), nil
}

func jiraUserAvatar(user *models.UserScheme) string {
	if user == nil || user.AvatarURLs == nil {
		return ""
	}
	return user.AvatarURLs.One6X16
}

func jiraPriorityName(p *models.PriorityScheme) string {
	if p == nil {
		return ""
	}
	return p.Name
}

func jiraResolutionName(r *models.ResolutionScheme) string {
	if r == nil {
		return ""
	}
	return r.Name
}

func jiraProjectName(p *models.ProjectScheme) string {
	if p == nil {
		return ""
	}
	return p.Name
}

func jiraProjectKey(p *models.ProjectScheme) string {
	if p == nil {
		return ""
	}
	return p.Key
}

func jiraStatusName(s *models.StatusScheme) string {
	if s == nil {
		return ""
	}
	return s.Name
}

func jiraIssueTypeName(it *models.IssueTypeScheme) string {
	if it == nil {
		return ""
	}
	return it.Name
}

func jiraDate(d *models.DateScheme) *time.Time {
	if d == nil {
		return nil
	}
	t := time.Time(*d).UTC()
	return &t
}

func jiraDateTime(d *models.DateTimeScheme) *time.Time {
	if d == nil {
		return nil
	}
	t := time.Time(*d).UTC()
	return &t
}

func stringsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func jiraIssueComponents(in []*models.ComponentScheme) []any {
	out := make([]any, 0, len(in))
	for _, c := range in {
		if c == nil {
			continue
		}
		out = append(out, map[string]any{
			"id":   c.ID,
			"name": c.Name,
		})
	}
	return out
}

func jiraIssueVersions(in []*models.VersionScheme) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		if v == nil {
			continue
		}
		out = append(out, map[string]any{
			"id":          v.ID,
			"name":        v.Name,
			"released":    v.Released,
			"archived":    v.Archived,
			"releaseDate": v.ReleaseDate,
		})
	}
	return out
}

func jiraIssueSecurity(s *models.SecurityScheme) any {
	if s == nil {
		return nil
	}
	return map[string]any{
		"id":          s.ID,
		"name":        s.Name,
		"description": s.Description,
	}
}

func jiraWatcherCount(w *models.IssueWatcherScheme) int {
	if w == nil {
		return 0
	}
	return w.WatchCount
}

func jiraVoteCount(v *models.IssueVoteScheme) int {
	if v == nil {
		return 0
	}
	return v.Votes
}

func jiraIssueComments(page *models.IssueCommentPageSchemeV2) []any {
	if page == nil {
		return []any{}
	}
	out := make([]any, 0, len(page.Comments))
	for _, c := range page.Comments {
		if c == nil {
			continue
		}
		authorID := ""
		authorName := ""
		if c.Author != nil {
			authorID = c.Author.AccountID
			authorName = c.Author.DisplayName
		}
		var visibility any
		if c.Visibility != nil {
			visibility = map[string]any{
				"type":  c.Visibility.Type,
				"value": c.Visibility.Value,
			}
		}
		out = append(out, map[string]any{
			"id":         c.ID,
			"body":       c.Body,
			"author":     authorID,
			"authorName": authorName,
			"created":    c.Created,
			"updated":    c.Updated,
			"visibility": visibility,
			"jsdPublic":  c.JSDPublic,
		})
	}
	return out
}

func (a *mqlAtlassianJiraIssue) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianJiraProject) properties() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jira := conn.Client()
	properties, _, err := jira.Project.Property.Gets(context.Background(), a.Id.Data)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, property := range properties.Keys {
		mqlAtlassianJiraProjectProperty, err := CreateResource(a.MqlRuntime, "atlassian.jira.project.property",
			map[string]*llx.RawData{
				"id": llx.StringData(property.Key),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAtlassianJiraProjectProperty)
	}
	return res, nil
}

func (a *mqlAtlassianJiraProjectProperty) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianJiraUser) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianJiraGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianJiraProject) id() (string, error) {
	return a.Id.Data, nil
}

// auditRecords fetches all Jira audit log records (most recent first), paginating
// through the Jira REST API in pages of up to 1000 records.
func (a *mqlAtlassianJira) auditRecords() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	res := []any{}
	offset := 0
	// Safety bound to guard against misbehaving servers that never signal end-of-results.
	const maxOffset = 100000

	for offset < maxOffset {
		page, _, err := jiraClient.Audit.Get(context.Background(), nil, offset, JIRA_SEARCH_MAX_RESULTS)
		if err != nil {
			return nil, err
		}
		if page == nil {
			break
		}

		for _, record := range page.Records {
			if record == nil {
				continue
			}

			var createdAt *time.Time
			if record.Created != "" {
				// Audit records use RFC3339-ish timestamps; tolerate parse failures.
				if t, perr := time.Parse(time.RFC3339, record.Created); perr == nil {
					ut := t.UTC()
					createdAt = &ut
				} else if t, perr := time.Parse(JIRA_TIME_FORMAT, record.Created); perr == nil {
					ut := t.UTC()
					createdAt = &ut
				}
			}

			var objectItem any
			if record.ObjectItem != nil {
				objectItem = map[string]any{
					"id":         record.ObjectItem.ID,
					"name":       record.ObjectItem.Name,
					"typeName":   record.ObjectItem.TypeName,
					"parentId":   record.ObjectItem.ParentID,
					"parentName": record.ObjectItem.ParentName,
				}
			}

			changedValues := []any{}
			for _, cv := range record.ChangedValues {
				if cv == nil {
					continue
				}
				changedValues = append(changedValues, map[string]any{
					"fieldName":   cv.FieldName,
					"changedFrom": cv.ChangedFrom,
					"changedTo":   cv.ChangedTo,
				})
			}

			associatedItems := []any{}
			for _, ai := range record.AssociatedItems {
				if ai == nil {
					continue
				}
				associatedItems = append(associatedItems, map[string]any{
					"id":         ai.ID,
					"name":       ai.Name,
					"typeName":   ai.TypeName,
					"parentId":   ai.ParentID,
					"parentName": ai.ParentName,
				})
			}

			args := map[string]*llx.RawData{
				"id":              llx.IntData(int64(record.ID)),
				"summary":         llx.StringData(record.Summary),
				"category":        llx.StringData(record.Category),
				"eventSource":     llx.StringData(record.EventSource),
				"description":     llx.StringData(record.Description),
				"authorKey":       llx.StringData(record.AuthorKey),
				"remoteAddress":   llx.StringData(record.RemoteAddress),
				"createdAt":       llx.TimeDataPtr(createdAt),
				"objectItem":      llx.DictData(objectItem),
				"changedValues":   llx.ArrayData(changedValues, types.Dict),
				"associatedItems": llx.ArrayData(associatedItems, types.Dict),
			}

			mqlAuditRecord, err := CreateResource(a.MqlRuntime, "atlassian.jira.auditRecord", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAuditRecord)
		}

		offset += len(page.Records)
		if len(page.Records) < JIRA_SEARCH_MAX_RESULTS {
			break
		}
	}
	return res, nil
}

func (a *mqlAtlassianJiraAuditRecord) id() (string, error) {
	return "atlassian.jira.auditRecord/" + strconv.FormatInt(a.Id.Data, 10), nil
}

// mqlAtlassianJiraPermissionSchemeInternal caches state needed by lazy methods.
// projectKey is the parent project's key, used by grants() to call the
// project-scoped permission API (which can return a different scheme/ID than
// the global Permission.Scheme.Get endpoint).
type mqlAtlassianJiraPermissionSchemeInternal struct {
	cacheProjectKey string
}

// permissionScheme returns the permission scheme assigned to this Jira project.
func (a *mqlAtlassianJiraProject) permissionScheme() (*mqlAtlassianJiraPermissionScheme, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	projectKey := a.Key.Data
	if projectKey == "" {
		projectKey = a.Id.Data
	}
	if projectKey == "" {
		a.PermissionScheme.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	scheme, _, err := jiraClient.Project.Permission.Get(context.Background(), projectKey, []string{"permissions", "user", "group", "projectRole", "field", "all"})
	if err != nil {
		return nil, err
	}
	if scheme == nil {
		a.PermissionScheme.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(a.MqlRuntime, "atlassian.jira.permissionScheme",
		map[string]*llx.RawData{
			"id":          llx.IntData(int64(scheme.ID)),
			"name":        llx.StringData(scheme.Name),
			"description": llx.StringData(scheme.Description),
		})
	if err != nil {
		return nil, err
	}

	mqlScheme := res.(*mqlAtlassianJiraPermissionScheme)
	// Cache the project key so the grants() fallback can re-fetch via the
	// project-scoped endpoint instead of the global one.
	mqlScheme.cacheProjectKey = projectKey
	// Cache the grants we already have so grants() doesn't have to call out again.
	if scheme.Permissions != nil {
		grants := []any{}
		for _, grant := range scheme.Permissions {
			if grant == nil {
				continue
			}
			holderType := ""
			holderParam := ""
			if grant.Holder != nil {
				holderType = grant.Holder.Type
				holderParam = grant.Holder.Parameter
			}
			mqlGrant, err := CreateResource(a.MqlRuntime, "atlassian.jira.permissionScheme.grant",
				map[string]*llx.RawData{
					"id":              llx.StringData(strconv.Itoa(grant.ID)),
					"permission":      llx.StringData(grant.Permission),
					"holderType":      llx.StringData(holderType),
					"holderParameter": llx.StringData(holderParam),
				})
			if err != nil {
				return nil, err
			}
			grants = append(grants, mqlGrant)
		}
		mqlScheme.Grants = plugin.TValue[[]any]{Data: grants, State: plugin.StateIsSet}
	}

	return mqlScheme, nil
}

func (a *mqlAtlassianJiraPermissionScheme) id() (string, error) {
	return "atlassian.jira.permissionScheme/" + strconv.FormatInt(a.Id.Data, 10), nil
}

// grants is a fallback if grants weren't pre-populated by permissionScheme().
// In practice this rarely runs because the parent caches grants on creation.
// Uses the project-scoped endpoint (matching the parent fetch) so the grant
// list aligns with the scheme returned for the project — the global
// Permission.Scheme.Get endpoint can return a different scheme/grant set.
func (a *mqlAtlassianJiraPermissionScheme) grants() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	if a.cacheProjectKey == "" {
		return []any{}, nil
	}

	scheme, _, err := jiraClient.Project.Permission.Get(context.Background(), a.cacheProjectKey, []string{"permissions", "user", "group", "projectRole", "field", "all"})
	if err != nil {
		return nil, err
	}
	res := []any{}
	if scheme == nil {
		return res, nil
	}
	for _, grant := range scheme.Permissions {
		if grant == nil {
			continue
		}
		holderType := ""
		holderParam := ""
		if grant.Holder != nil {
			holderType = grant.Holder.Type
			holderParam = grant.Holder.Parameter
		}
		mqlGrant, err := CreateResource(a.MqlRuntime, "atlassian.jira.permissionScheme.grant",
			map[string]*llx.RawData{
				"id":              llx.StringData(strconv.Itoa(grant.ID)),
				"permission":      llx.StringData(grant.Permission),
				"holderType":      llx.StringData(holderType),
				"holderParameter": llx.StringData(holderParam),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGrant)
	}
	return res, nil
}

func (a *mqlAtlassianJiraPermissionSchemeGrant) id() (string, error) {
	return "atlassian.jira.permissionScheme.grant/" + a.Id.Data, nil
}

func (a *mqlAtlassianJiraProject) components() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	projectKey := a.Key.Data
	if projectKey == "" {
		projectKey = a.Id.Data
	}
	if projectKey == "" {
		return []any{}, nil
	}

	components, _, err := jiraClient.Project.Component.Gets(context.Background(), projectKey)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(components))
	for _, c := range components {
		if c == nil {
			continue
		}
		lead, err := mqlJiraUser(a.MqlRuntime, c.Lead)
		if err != nil {
			return nil, err
		}
		assignee, err := mqlJiraUser(a.MqlRuntime, c.Assignee)
		if err != nil {
			return nil, err
		}
		mqlComponent, err := CreateResource(a.MqlRuntime, "atlassian.jira.project.component",
			map[string]*llx.RawData{
				"id":           llx.StringData(c.ID),
				"projectKey":   llx.StringData(projectKey),
				"name":         llx.StringData(c.Name),
				"description":  llx.StringData(c.Description),
				"assigneeType": llx.StringData(c.AssigneeType),
				"lead":         lead,
				"assignee":     assignee,
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlComponent)
	}
	return res, nil
}

func (a *mqlAtlassianJiraProjectComponent) id() (string, error) {
	return "atlassian.jira.project.component/" + a.Id.Data, nil
}

func (a *mqlAtlassianJiraProject) versions() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	jiraClient := conn.Client()

	projectKey := a.Key.Data
	if projectKey == "" {
		projectKey = a.Id.Data
	}
	if projectKey == "" {
		return []any{}, nil
	}

	res := []any{}
	startAt := 0
	for {
		page, _, err := jiraClient.Project.Version.Search(context.Background(), projectKey, nil, startAt, JIRA_SEARCH_MAX_RESULTS)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Values) == 0 {
			break
		}
		for _, v := range page.Values {
			if v == nil {
				continue
			}
			mqlVersion, err := CreateResource(a.MqlRuntime, "atlassian.jira.project.version",
				map[string]*llx.RawData{
					"id":          llx.StringData(v.ID),
					"projectKey":  llx.StringData(projectKey),
					"name":        llx.StringData(v.Name),
					"description": llx.StringData(v.Description),
					"released":    llx.BoolData(v.Released),
					"archived":    llx.BoolData(v.Archived),
					"releaseDate": llx.StringData(v.ReleaseDate),
					"overdue":     llx.BoolData(v.Overdue),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVersion)
		}
		if page.IsLast || len(page.Values) < JIRA_SEARCH_MAX_RESULTS {
			break
		}
		startAt += len(page.Values)
	}
	return res, nil
}

func (a *mqlAtlassianJiraProjectVersion) id() (string, error) {
	return "atlassian.jira.project.version/" + a.Id.Data, nil
}

const (
	// jiraGroupMemberPageSize matches the server-side cap on the group-member
	// endpoint. Requesting more does not raise it, and a page shorter than the
	// requested size would then look like the end of the list on every call.
	jiraGroupMemberPageSize = 50
	// jiraGroupMemberMaxPages bounds the membership walk so a server that never
	// sets isLast cannot page forever.
	jiraGroupMemberMaxPages = 2000
)

// mqlAtlassianJiraApplicationRoleInternal caches the full application-role
// record. The role list seeds it; a role reached through a user's assignments
// starts empty and fetches on first access to one of the seat or group fields.
type mqlAtlassianJiraApplicationRoleInternal struct {
	cacheRole  *models.ApplicationRoleScheme
	cachedRole bool
	lock       sync.Mutex
}

// seedRole stores an already-fetched role record so the accessors do not
// re-request it.
func (a *mqlAtlassianJiraApplicationRole) seedRole(role *models.ApplicationRoleScheme) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.cacheRole = role
	a.cachedRole = true
}

// ensureRole returns the full application-role record, fetching it on a cache
// miss. A permission failure is returned as an error: reporting "no default
// groups" for a role the caller was not allowed to read would look identical to
// a role that genuinely has none.
func (a *mqlAtlassianJiraApplicationRole) ensureRole() (*models.ApplicationRoleScheme, error) {
	if a.cachedRole {
		return a.cacheRole, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.cachedRole {
		return a.cacheRole, nil
	}
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	if a.Id.Data == "" {
		return nil, errors.New("atlassian.jira.applicationRole: id must be a non-empty role key")
	}
	role, _, err := conn.Client().Role.Get(context.Background(), a.Id.Data)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, errors.New("atlassian.jira.applicationRole with key " + a.Id.Data + " not found")
	}
	a.cacheRole = role
	a.cachedRole = true
	return role, nil
}

// applicationRoles returns every application role defined on the instance,
// seeding each one's cache so the seat and group fields cost no extra call.
func (a *mqlAtlassianJira) applicationRoles() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	roles, _, err := conn.Client().Role.Gets(context.Background())
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(roles))
	for _, role := range roles {
		if role == nil || role.Key == "" {
			continue
		}
		mqlRole, err := CreateResource(a.MqlRuntime, "atlassian.jira.applicationRole",
			map[string]*llx.RawData{
				"id":   llx.StringData(role.Key),
				"name": llx.StringData(role.Name),
			})
		if err != nil {
			return nil, err
		}
		mqlRole.(*mqlAtlassianJiraApplicationRole).seedRole(role)
		res = append(res, mqlRole)
	}
	return res, nil
}

func (a *mqlAtlassianJiraApplicationRole) groups() ([]any, error) {
	role, err := a.ensureRole()
	if err != nil {
		return nil, err
	}
	return stringsToAny(role.Groups), nil
}

func (a *mqlAtlassianJiraApplicationRole) defaultGroups() ([]any, error) {
	role, err := a.ensureRole()
	if err != nil {
		return nil, err
	}
	return stringsToAny(role.DefaultGroups), nil
}

func (a *mqlAtlassianJiraApplicationRole) selectedByDefault() (bool, error) {
	role, err := a.ensureRole()
	if err != nil {
		return false, err
	}
	return role.SelectedByDefault, nil
}

func (a *mqlAtlassianJiraApplicationRole) defined() (bool, error) {
	role, err := a.ensureRole()
	if err != nil {
		return false, err
	}
	return role.Defined, nil
}

func (a *mqlAtlassianJiraApplicationRole) numberOfSeats() (int64, error) {
	role, err := a.ensureRole()
	if err != nil {
		return 0, err
	}
	return int64(role.NumberOfSeats), nil
}

func (a *mqlAtlassianJiraApplicationRole) remainingSeats() (int64, error) {
	role, err := a.ensureRole()
	if err != nil {
		return 0, err
	}
	return int64(role.RemainingSeats), nil
}

func (a *mqlAtlassianJiraApplicationRole) userCount() (int64, error) {
	role, err := a.ensureRole()
	if err != nil {
		return 0, err
	}
	return int64(role.UserCount), nil
}

func (a *mqlAtlassianJiraApplicationRole) hasUnlimitedSeats() (bool, error) {
	role, err := a.ensureRole()
	if err != nil {
		return false, err
	}
	return role.HasUnlimitedSeats, nil
}

func (a *mqlAtlassianJiraApplicationRole) platform() (bool, error) {
	role, err := a.ensureRole()
	if err != nil {
		return false, err
	}
	return role.Platform, nil
}

// members returns the accounts in this group, including deactivated ones so a
// group named in a permission grant can be enumerated in full. The membership
// endpoint does not report avatars or locales, so those two fields are set to
// null rather than to an invented empty string.
func (a *mqlAtlassianJiraGroup) members() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*jira.JiraConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow jira access")
	}
	groupName := a.Name.Data
	if groupName == "" {
		return nil, errors.New("atlassian.jira.group: name is required to list members")
	}
	client := conn.Client()

	res := []any{}
	err := walkJiraGroupMembers(
		func(startAt int) (*models.GroupMemberPageScheme, error) {
			page, _, err := client.Group.Members(context.Background(), groupName, true, startAt, jiraGroupMemberPageSize)
			return page, err
		},
		func(member *models.GroupUserDetailScheme) error {
			mqlUser, err := CreateResource(a.MqlRuntime, "atlassian.jira.user",
				map[string]*llx.RawData{
					"id":       llx.StringData(member.AccountID),
					"name":     llx.StringData(member.DisplayName),
					"type":     llx.StringData(member.AccountType),
					"picture":  llx.StringDataPtr(nil),
					"email":    llx.StringData(member.EmailAddress),
					"active":   llx.BoolData(member.Active),
					"timezone": llx.StringData(member.TimeZone),
					"locale":   llx.StringDataPtr(nil),
				})
			if err != nil {
				return err
			}
			res = append(res, mqlUser)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// walkJiraGroupMembers pages a group's membership, handing each member to
// visit. The endpoint caps its page size server-side, so a page shorter than
// the one requested does not mean the end of the list: isLast is the signal,
// and treating a short page as the end would truncate every group larger than
// one page. An empty page and jiraGroupMemberMaxPages bound a server that never
// sets isLast.
func walkJiraGroupMembers(
	fetch func(startAt int) (*models.GroupMemberPageScheme, error),
	visit func(member *models.GroupUserDetailScheme) error,
) error {
	startAt := 0
	for range jiraGroupMemberMaxPages {
		members, err := fetch(startAt)
		if err != nil {
			return err
		}
		if members == nil || len(members.Values) == 0 {
			return nil
		}
		for _, member := range members.Values {
			if member == nil || member.AccountID == "" {
				continue
			}
			if err := visit(member); err != nil {
				return err
			}
		}
		if members.IsLast {
			return nil
		}
		startAt += len(members.Values)
	}
	return nil
}

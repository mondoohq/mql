// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection/confluence"
	"go.mondoo.com/mql/types"
)

const (
	CONFLUENCE_PAGE_LIMIT  = 250
	CONFLUENCE_SPACE_LIMIT = 250
)

func (a *mqlAtlassianConfluence) id() (string, error) {
	return "confluence", nil
}

func (a *mqlAtlassianConfluence) users() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*confluence.ConfluenceConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow confluence access")
	}
	client := conn.Client()
	cql := "type = user"
	res := []any{}
	startAt := 0
	for {
		page, _, err := client.Search.Users(context.Background(), cql, startAt, CONFLUENCE_PAGE_LIMIT, nil)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Results) == 0 {
			break
		}
		for _, hit := range page.Results {
			if hit == nil || hit.User == nil {
				continue
			}
			mqlUser, err := CreateResource(a.MqlRuntime, "atlassian.confluence.user",
				map[string]*llx.RawData{
					"id":   llx.StringData(hit.User.AccountID),
					"type": llx.StringData(hit.User.AccountType),
					"name": llx.StringData(hit.User.DisplayName),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlUser)
		}
		if len(page.Results) < CONFLUENCE_PAGE_LIMIT {
			break
		}
		startAt += len(page.Results)
	}
	return res, nil
}

func (a *mqlAtlassianConfluenceUser) id() (string, error) {
	return a.Id.Data, nil
}

// initAtlassianConfluenceUser supports creating a bare user reference from an
// account ID. The Confluence v1 SDK exposes no /user GET endpoint, so we cannot
// hydrate fields like name/type here — callers that traversed via a typed ref
// (e.g. permissionUsers, restriction.users) get the accountId only and any
// other accessed field will surface as null. Listing via atlassian.confluence.users
// remains the canonical way to enumerate user details.
func initAtlassianConfluenceUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// A bare resource (just an id) is a valid empty state.
	return args, nil, nil
}

func (a *mqlAtlassianConfluenceGroup) id() (string, error) {
	return "atlassian.confluence.group/" + a.Id.Data, nil
}

// initAtlassianConfluenceGroup supports creating a bare group reference from a
// group id or name. The Confluence v1 SDK exposes no standalone group GET, so
// we cannot hydrate additional fields here. Callers receive a typed handle they
// can compare/filter on.
func initAtlassianConfluenceGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// A bare resource (just an id/name) is a valid empty state.
	return args, nil, nil
}

// spaces fetches all Confluence spaces with permission expansion so callers can
// inspect anonymous-access settings and per-subject permissions inline.
func (a *mqlAtlassianConfluence) spaces() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*confluence.ConfluenceConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow confluence access")
	}
	client := conn.Client()

	options := &models.GetSpacesOptionScheme{Expand: []string{"permissions", "history", "homepage"}}
	res := []any{}
	startAt := 0

	for {
		page, _, err := client.Space.Gets(context.Background(), options, startAt, CONFLUENCE_SPACE_LIMIT)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Results) == 0 {
			break
		}

		for _, space := range page.Results {
			if space == nil {
				continue
			}

			anon := false
			unlicensed := false
			perms := []any{}
			for _, perm := range space.Permissions {
				if perm == nil {
					continue
				}
				if perm.AnonymousAccess {
					anon = true
				}
				if perm.UnlicensedAccess {
					unlicensed = true
				}

				operation := ""
				targetType := ""
				if perm.Operation != nil {
					operation = perm.Operation.Operation
					targetType = perm.Operation.TargetType
				}

				if perm.Subject != nil {
					if perm.Subject.User != nil {
						for _, u := range perm.Subject.User.Results {
							if u == nil {
								continue
							}
							perms = append(perms, map[string]any{
								"operation":   operation,
								"targetType":  targetType,
								"subjectType": "user",
								"subjectKey":  u.AccountID,
								"subjectName": u.DisplayName,
							})
						}
					}
					if perm.Subject.Group != nil {
						for _, g := range perm.Subject.Group.Results {
							if g == nil {
								continue
							}
							perms = append(perms, map[string]any{
								"operation":   operation,
								"targetType":  targetType,
								"subjectType": "group",
								"subjectKey":  g.ID,
								"subjectName": g.Name,
							})
						}
					}
				}

				// If neither anonymous nor a subject was set but flags fired, still surface a row
				// so the count is non-zero.
				if perm.AnonymousAccess && perm.Subject == nil {
					perms = append(perms, map[string]any{
						"operation":   operation,
						"targetType":  targetType,
						"subjectType": "anonymous",
						"subjectKey":  "",
						"subjectName": "",
					})
				}
			}

			homepage, err := mqlConfluencePageFromContent(a.MqlRuntime, space.HomePage, space.Key)
			if err != nil {
				return nil, err
			}
			createdBy, err := mqlConfluenceUserFromContent(a.MqlRuntime, spaceHistoryCreator(space))
			if err != nil {
				return nil, err
			}

			mqlSpace, err := CreateResource(a.MqlRuntime, "atlassian.confluence.space",
				map[string]*llx.RawData{
					"id":               llx.IntData(int64(space.ID)),
					"key":              llx.StringData(space.Key),
					"name":             llx.StringData(space.Name),
					"type":             llx.StringData(space.Type),
					"status":           llx.StringData(space.Status),
					"anonymousAccess":  llx.BoolData(anon),
					"unlicensedAccess": llx.BoolData(unlicensed),
					"permissions":      llx.ArrayData(perms, types.Dict),
					"homepage":         homepage,
					"createdBy":        createdBy,
					"createdAt":        llx.TimeDataPtr(parseConfluenceTime(spaceHistoryCreatedDate(space))),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSpace)
		}

		startAt += len(page.Results)
		if len(page.Results) < CONFLUENCE_SPACE_LIMIT {
			break
		}
	}
	return res, nil
}

func (a *mqlAtlassianConfluenceSpace) id() (string, error) {
	return "atlassian.confluence.space/" + a.Key.Data, nil
}

// confluenceUserIndex returns the instance's user accounts keyed by account ID.
// It reads them through the atlassian.confluence singleton, so the runtime
// memoizes the underlying search and one lookup serves every space permission
// and page restriction in a scan.
//
// A failure to read the directory is not fatal here: callers fall back to a
// reference carrying only the account ID, which leaves the account's name and
// type null rather than reporting an invented empty value for them.
func confluenceUserIndex(runtime *plugin.Runtime) map[string]*mqlAtlassianConfluenceUser {
	root, err := CreateResource(runtime, "atlassian.confluence", map[string]*llx.RawData{})
	if err != nil {
		log.Warn().Err(err).Msg("failed to reach the confluence resource to resolve user accounts")
		return nil
	}
	users := root.(*mqlAtlassianConfluence).GetUsers()
	if users.Error != nil {
		log.Warn().Err(users.Error).Msg("failed to list confluence users to resolve account types")
		return nil
	}
	idx := make(map[string]*mqlAtlassianConfluenceUser, len(users.Data))
	for _, raw := range users.Data {
		user, ok := raw.(*mqlAtlassianConfluenceUser)
		if !ok || user.Id.Data == "" {
			continue
		}
		idx[user.Id.Data] = user
	}
	return idx
}

// confluenceUserRef resolves an account ID against the directory index. A hit
// returns the already-populated account, which is what makes the account type
// readable and so distinguishes an external collaborator from a staff account.
// A miss returns a reference carrying only the ID, leaving the remaining fields
// null.
func confluenceUserRef(runtime *plugin.Runtime, index map[string]*mqlAtlassianConfluenceUser, accountID string) (plugin.Resource, error) {
	if user, ok := index[accountID]; ok {
		return user, nil
	}
	return NewResource(runtime, "atlassian.confluence.user",
		map[string]*llx.RawData{"id": llx.StringData(accountID)})
}

// permissionUsers returns the distinct typed atlassian.confluence.user resources
// referenced by this space's permissions list. The permissions field contains
// subjectType="user" rows whose subjectKey is the user's accountId.
func (a *mqlAtlassianConfluenceSpace) permissionUsers() ([]any, error) {
	index := confluenceUserIndex(a.MqlRuntime)
	seen := map[string]bool{}
	res := []any{}
	for _, p := range a.Permissions.Data {
		row, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := row["subjectType"].(string); t != "user" {
			continue
		}
		key, _ := row["subjectKey"].(string)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		mqlUser, err := confluenceUserRef(a.MqlRuntime, index, key)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}

// permissionGroups returns the distinct typed atlassian.confluence.group resources
// referenced by this space's permissions list. The permissions field contains
// subjectType="group" rows whose subjectKey is the group id (and subjectName is
// the group display name).
func (a *mqlAtlassianConfluenceSpace) permissionGroups() ([]any, error) {
	seen := map[string]bool{}
	res := []any{}
	for _, p := range a.Permissions.Data {
		row, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := row["subjectType"].(string); t != "group" {
			continue
		}
		key, _ := row["subjectKey"].(string)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		name, _ := row["subjectName"].(string)
		args := map[string]*llx.RawData{
			"id":   llx.StringData(key),
			"name": llx.StringData(name),
		}
		mqlGroup, err := NewResource(a.MqlRuntime, "atlassian.confluence.group", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

// pages lists all "page" content within this space. Trashed/draft pages are excluded
// (the SDK defaults to type=page, status=current via the search call).
func (a *mqlAtlassianConfluenceSpace) pages() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*confluence.ConfluenceConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow confluence access")
	}
	client := conn.Client()

	spaceKey := a.Key.Data
	if spaceKey == "" {
		return []any{}, nil
	}

	res := []any{}
	startAt := 0

	// Restrictions are loaded lazily by fetchRestrictions; requesting them in
	// the bulk expand without caching them here would just pay for data we
	// throw away. version/history/metadata.labels/ancestors are populated into
	// the Internal cache via cacheFromContent, which short-circuits the
	// per-page Content.Get round-trip.
	expand := []string{
		"version",
		"history",
		"metadata.labels",
		"ancestors",
	}

	for {
		// Use ContentByType so we get only pages and don't mix in blogposts, comments, attachments.
		// status="current" excludes trashed and draft pages — better for audit use cases.
		page, _, err := client.Space.ContentByType(context.Background(), spaceKey, "page", "current", expand, startAt, CONFLUENCE_PAGE_LIMIT)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Results) == 0 {
			break
		}
		for _, content := range page.Results {
			if content == nil {
				continue
			}
			mqlPage, err := CreateResource(a.MqlRuntime, "atlassian.confluence.page",
				map[string]*llx.RawData{
					"id":       llx.StringData(content.ID),
					"title":    llx.StringData(content.Title),
					"status":   llx.StringData(content.Status),
					"type":     llx.StringData(content.Type),
					"spaceKey": llx.StringData(spaceKey),
				})
			if err != nil {
				return nil, err
			}
			mqlPage.(*mqlAtlassianConfluencePage).cacheFromContent(content)
			res = append(res, mqlPage)
		}
		startAt += len(page.Results)
		if len(page.Results) < CONFLUENCE_PAGE_LIMIT {
			break
		}
	}
	return res, nil
}

func (a *mqlAtlassianConfluencePage) id() (string, error) {
	return "atlassian.confluence.page/" + a.Id.Data, nil
}

// hasRestrictions returns true if either the read or update operation has any
// explicit user or group entries.
func (a *mqlAtlassianConfluencePage) hasRestrictions() (bool, error) {
	restrictions, err := a.fetchRestrictions()
	if err != nil {
		return false, err
	}
	return contentHasRestrictions(restrictions), nil
}

func (a *mqlAtlassianConfluencePage) restrictions() ([]any, error) {
	return a.fetchRestrictions()
}

// fetchRestrictions loads page-level restrictions and caches them on first call.
// Both hasRestrictions() and restrictions() share this so we only call the API
// once. Uses the same lock as ensureFetched to make concurrent callers safe —
// without it, two goroutines hitting the page at the same time would both miss
// the cache and double up the API call (and racily clobber Restrictions.Data).
func (a *mqlAtlassianConfluencePage) fetchRestrictions() ([]any, error) {
	if a.Restrictions.State == plugin.StateIsSet {
		return a.Restrictions.Data, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.Restrictions.State == plugin.StateIsSet {
		return a.Restrictions.Data, nil
	}
	res, err := confluenceContentRestrictions(a.MqlRuntime, a.Id.Data)
	if err != nil {
		return nil, err
	}
	a.Restrictions = plugin.TValue[[]any]{Data: res, State: plugin.StateIsSet}
	return res, nil
}

func (a *mqlAtlassianConfluencePageRestriction) id() (string, error) {
	return "atlassian.confluence.page.restriction/" + a.Id.Data, nil
}

// users resolves the userIds list to typed atlassian.confluence.user references.
// Each id is treated as an accountId; the underlying user resource has no fetch
// endpoint so only the id is hydrated.
func (a *mqlAtlassianConfluencePageRestriction) users() ([]any, error) {
	index := confluenceUserIndex(a.MqlRuntime)
	res := []any{}
	for _, raw := range a.UserIds.Data {
		accountID, ok := raw.(string)
		if !ok || accountID == "" {
			continue
		}
		mqlUser, err := confluenceUserRef(a.MqlRuntime, index, accountID)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}

// groups resolves the groupNames list to typed atlassian.confluence.group references.
// Confluence page restrictions identify groups by name (not id), so we use the
// name as the resource id for caching.
func (a *mqlAtlassianConfluencePageRestriction) groups() ([]any, error) {
	res := []any{}
	for _, raw := range a.GroupNames.Data {
		name, ok := raw.(string)
		if !ok || name == "" {
			continue
		}
		mqlGroup, err := NewResource(a.MqlRuntime, "atlassian.confluence.group",
			map[string]*llx.RawData{
				"id":   llx.StringData(name),
				"name": llx.StringData(name),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

// parseConfluenceTime parses Confluence's RFC3339-style timestamps. Returns nil
// when the input is empty or unparseable.
func parseConfluenceTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		ut := t.UTC()
		return &ut
	}
	return nil
}

// spaceHistoryCreator returns the user who created the space, or nil when the
// History block is absent.
func spaceHistoryCreator(space *models.SpaceScheme) *models.ContentUserScheme {
	if space == nil || space.History == nil {
		return nil
	}
	return space.History.CreatedBy
}

// spaceHistoryCreatedDate returns the raw createdDate string from the space
// history, or "" when absent.
func spaceHistoryCreatedDate(space *models.SpaceScheme) string {
	if space == nil || space.History == nil {
		return ""
	}
	return space.History.CreatedDate
}

// mqlConfluenceUserFromContent builds a typed atlassian.confluence.user from a
// ContentUserScheme returned by content/history APIs. Returns NilData when the
// input is nil or has no accountId.
func mqlConfluenceUserFromContent(runtime *plugin.Runtime, user *models.ContentUserScheme) (*llx.RawData, error) {
	if user == nil || user.AccountID == "" {
		return llx.NilData, nil
	}
	mqlUser, err := NewResource(runtime, "atlassian.confluence.user",
		map[string]*llx.RawData{
			"id":   llx.StringData(user.AccountID),
			"name": llx.StringData(user.DisplayName),
			"type": llx.StringData(user.AccountType),
		})
	if err != nil {
		return nil, err
	}
	return llx.AnyData(mqlUser), nil
}

// mqlConfluencePageFromContent builds a typed atlassian.confluence.page from a
// ContentScheme. Used for space homepage and page ancestors. The spaceKey is
// passed in because the embedded Space pointer is not always populated.
func mqlConfluencePageFromContent(runtime *plugin.Runtime, content *models.ContentScheme, spaceKey string) (*llx.RawData, error) {
	if content == nil || content.ID == "" {
		return llx.NilData, nil
	}
	effectiveSpaceKey := spaceKey
	if effectiveSpaceKey == "" && content.Space != nil {
		effectiveSpaceKey = content.Space.Key
	}
	mqlPage, err := NewResource(runtime, "atlassian.confluence.page",
		map[string]*llx.RawData{
			"id":       llx.StringData(content.ID),
			"title":    llx.StringData(content.Title),
			"status":   llx.StringData(content.Status),
			"type":     llx.StringData(content.Type),
			"spaceKey": llx.StringData(effectiveSpaceKey),
		})
	if err != nil {
		return nil, err
	}
	return llx.AnyData(mqlPage), nil
}

// mqlAtlassianConfluencePageInternal caches metadata pulled from the Content
// API so the version/history/labels/parent methods can be served without a
// re-fetch when the page was loaded through space.pages() with the right
// expansions. Pages reached via space.homepage or page.parent start with an
// empty cache and trigger a lazy fetch on first access.
type mqlAtlassianConfluencePageInternal struct {
	fetched             bool
	lock                sync.Mutex
	cacheVersion        int64
	cacheCreatedAt      *time.Time
	cacheUpdatedAt      *time.Time
	cacheCreatedBy      *models.ContentUserScheme
	cacheUpdatedBy      *models.ContentUserScheme
	cacheVersionMessage string
	cacheMinorEdit      bool
	cacheParent         *models.ContentScheme
	cacheAncestorIds    []string
	cacheWebURL         string
	cacheLabels         []string
}

// cacheFromContent populates the Internal cache from a ContentScheme with the
// expected expansions (version, history, metadata.labels, ancestors).
func (a *mqlAtlassianConfluencePage) cacheFromContent(content *models.ContentScheme) {
	if content == nil {
		return
	}
	if content.Version != nil {
		a.cacheVersion = int64(content.Version.Number)
		a.cacheUpdatedBy = content.Version.By
		a.cacheVersionMessage = content.Version.Message
		a.cacheMinorEdit = content.Version.MinorEdit
	}
	if content.History != nil {
		a.cacheCreatedAt = parseConfluenceTime(content.History.CreatedDate)
		a.cacheCreatedBy = content.History.CreatedBy
	}
	if content.Version != nil && content.Version.When != "" {
		a.cacheUpdatedAt = parseConfluenceTime(content.Version.When)
	}
	if content.Links != nil && content.Links.Base != "" && content.Links.Webui != "" {
		// Webui is relative to the instance base; only build the URL when the
		// base is present so the field stays absolute (or empty), never a bare
		// relative path.
		a.cacheWebURL = content.Links.Base + content.Links.Webui
	}
	if content.Metadata != nil && content.Metadata.Labels != nil {
		labels := make([]string, 0, len(content.Metadata.Labels.Results))
		for _, l := range content.Metadata.Labels.Results {
			if l == nil || l.Name == "" {
				continue
			}
			labels = append(labels, l.Name)
		}
		a.cacheLabels = labels
	}
	if len(content.Ancestors) > 0 {
		// Direct parent is the last ancestor returned by the API.
		a.cacheParent = content.Ancestors[len(content.Ancestors)-1]
		// Ancestors are ordered root first, direct parent last.
		ids := make([]string, 0, len(content.Ancestors))
		for _, anc := range content.Ancestors {
			if anc == nil || anc.ID == "" {
				continue
			}
			ids = append(ids, anc.ID)
		}
		a.cacheAncestorIds = ids
	}
	a.fetched = true
}

// ensureFetched populates the Internal cache by calling Content.Get when the
// page was created without an inline expansion (e.g., via space.homepage or
// page.parent). It is safe to call repeatedly.
func (a *mqlAtlassianConfluencePage) ensureFetched() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	conn, ok := a.MqlRuntime.Connection.(*confluence.ConfluenceConnection)
	if !ok {
		return errors.New("Current connection does not allow confluence access")
	}
	client := conn.Client()

	contentID := a.Id.Data
	if contentID == "" {
		a.fetched = true
		return nil
	}

	content, _, err := client.Content.Get(context.Background(), contentID, []string{"version", "history", "metadata.labels", "ancestors"}, 0)
	if err != nil {
		return err
	}
	a.cacheFromContent(content)
	a.fetched = true
	return nil
}

func (a *mqlAtlassianConfluencePage) version() (int64, error) {
	if err := a.ensureFetched(); err != nil {
		return 0, err
	}
	return a.cacheVersion, nil
}

func (a *mqlAtlassianConfluencePage) createdAt() (*time.Time, error) {
	if err := a.ensureFetched(); err != nil {
		return nil, err
	}
	return a.cacheCreatedAt, nil
}

func (a *mqlAtlassianConfluencePage) updatedAt() (*time.Time, error) {
	if err := a.ensureFetched(); err != nil {
		return nil, err
	}
	return a.cacheUpdatedAt, nil
}

func (a *mqlAtlassianConfluencePage) createdBy() (*mqlAtlassianConfluenceUser, error) {
	if err := a.ensureFetched(); err != nil {
		return nil, err
	}
	if a.cacheCreatedBy == nil || a.cacheCreatedBy.AccountID == "" {
		a.CreatedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlUser, err := NewResource(a.MqlRuntime, "atlassian.confluence.user",
		map[string]*llx.RawData{
			"id":   llx.StringData(a.cacheCreatedBy.AccountID),
			"name": llx.StringData(a.cacheCreatedBy.DisplayName),
			"type": llx.StringData(a.cacheCreatedBy.AccountType),
		})
	if err != nil {
		return nil, err
	}
	return mqlUser.(*mqlAtlassianConfluenceUser), nil
}

func (a *mqlAtlassianConfluencePage) updatedBy() (*mqlAtlassianConfluenceUser, error) {
	if err := a.ensureFetched(); err != nil {
		return nil, err
	}
	if a.cacheUpdatedBy == nil || a.cacheUpdatedBy.AccountID == "" {
		a.UpdatedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlUser, err := NewResource(a.MqlRuntime, "atlassian.confluence.user",
		map[string]*llx.RawData{
			"id":   llx.StringData(a.cacheUpdatedBy.AccountID),
			"name": llx.StringData(a.cacheUpdatedBy.DisplayName),
			"type": llx.StringData(a.cacheUpdatedBy.AccountType),
		})
	if err != nil {
		return nil, err
	}
	return mqlUser.(*mqlAtlassianConfluenceUser), nil
}

func (a *mqlAtlassianConfluencePage) versionMessage() (string, error) {
	if err := a.ensureFetched(); err != nil {
		return "", err
	}
	return a.cacheVersionMessage, nil
}

func (a *mqlAtlassianConfluencePage) minorEdit() (bool, error) {
	if err := a.ensureFetched(); err != nil {
		return false, err
	}
	return a.cacheMinorEdit, nil
}

func (a *mqlAtlassianConfluencePage) ancestorIds() ([]any, error) {
	if err := a.ensureFetched(); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(a.cacheAncestorIds))
	for _, id := range a.cacheAncestorIds {
		out = append(out, id)
	}
	return out, nil
}

func (a *mqlAtlassianConfluencePage) depth() (int64, error) {
	if err := a.ensureFetched(); err != nil {
		return 0, err
	}
	return int64(len(a.cacheAncestorIds)), nil
}

func (a *mqlAtlassianConfluencePage) webUrl() (string, error) {
	if err := a.ensureFetched(); err != nil {
		return "", err
	}
	return a.cacheWebURL, nil
}

func (a *mqlAtlassianConfluencePage) parent() (*mqlAtlassianConfluencePage, error) {
	if err := a.ensureFetched(); err != nil {
		return nil, err
	}
	if a.cacheParent == nil || a.cacheParent.ID == "" {
		a.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlPage, err := NewResource(a.MqlRuntime, "atlassian.confluence.page",
		map[string]*llx.RawData{
			"id":       llx.StringData(a.cacheParent.ID),
			"title":    llx.StringData(a.cacheParent.Title),
			"status":   llx.StringData(a.cacheParent.Status),
			"type":     llx.StringData(a.cacheParent.Type),
			"spaceKey": llx.StringData(a.SpaceKey.Data),
		})
	if err != nil {
		return nil, err
	}
	return mqlPage.(*mqlAtlassianConfluencePage), nil
}

func (a *mqlAtlassianConfluencePage) labels() ([]any, error) {
	if err := a.ensureFetched(); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(a.cacheLabels))
	for _, l := range a.cacheLabels {
		out = append(out, l)
	}
	return out, nil
}

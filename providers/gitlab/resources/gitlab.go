// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// getRawJSON issues a GET through the SDK client and decodes the body into out.
// It exists because several GitLab responses carry security settings the SDK
// types as a plain bool or int64: on an instance that never sends the attribute
// those decode to false or 0, which reads as "explicitly disabled" rather than
// "not reported". Callers decode the same body twice, once into the SDK type
// for the bulk of the fields and once into a pointer-typed struct for the few
// where that difference changes the answer.
func getRawJSON(c *gitlab.Client, path string, opt any, out any) (*gitlab.Response, error) {
	req, err := c.NewRequest(http.MethodGet, path, opt, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req, out)
}

// nextPage returns the page to request after the one just read, or 0 when the
// walk is finished. GitLab reports the next page in a response header, and a
// server that repeats or rewinds that number would spin an offset walk forever,
// so a page number that does not advance ends the walk instead.
func nextPage(resp *gitlab.Response, current int64) int64 {
	if resp == nil || resp.NextPage <= current {
		return 0
	}
	return resp.NextPage
}

// listRawPages walks an offset-paginated GitLab collection through the SDK
// client and returns the raw JSON elements from every page, for callers that
// decode each element more than once.
func listRawPages(c *gitlab.Client, path string, perPage int64) ([]json.RawMessage, *gitlab.Response, error) {
	var all []json.RawMessage
	page := int64(1)

	for {
		var raw []json.RawMessage
		resp, err := getRawJSON(c, path, &gitlab.ListOptions{Page: page, PerPage: perPage}, &raw)
		if err != nil {
			return nil, resp, err
		}

		all = append(all, raw...)

		page = nextPage(resp, page)
		if page == 0 {
			return all, resp, nil
		}
	}
}

// hookPosture is the pointer-typed view of the hook attributes where absent and
// false are different answers. A hook with no secret token accepts a payload
// from anything that learns its URL, so an instance that does not report
// token_present has to leave the field null rather than report every hook as
// unauthenticated. repositoryUpdateEvents is here for the same reason: the group
// webhook field of that name shipped as a permanent false because the API never
// sent the attribute. It applies to instance, group, and project hooks alike,
// though not every tier answers with every attribute.
type hookPosture struct {
	TokenPresent           *bool `json:"token_present"`
	RepositoryUpdateEvents *bool `json:"repository_update_events"`
}

// decodeHooks decodes one page of hooks into the SDK type and the posture
// overlay, keeping the two slices index-aligned so callers can pair them up.
func decodeHooks[T any](raw []json.RawMessage) ([]*T, []hookPosture, error) {
	hooks := make([]*T, 0, len(raw))
	presence := make([]hookPosture, 0, len(raw))

	for _, item := range raw {
		hook := new(T)
		if err := json.Unmarshal(item, hook); err != nil {
			return nil, nil, err
		}
		token := hookPosture{}
		if err := json.Unmarshal(item, &token); err != nil {
			return nil, nil, err
		}
		hooks = append(hooks, hook)
		presence = append(presence, token)
	}

	return hooks, presence, nil
}

// isoTimePtr converts the SDK's date-only ISOTime into a *time.Time, keeping
// nil as nil. Callers must always set the resulting field (via
// llx.TimeDataPtr, which maps nil to a proper MQL null) rather than skipping
// the map key: an absent key leaves the field *unset* rather than null, and
// unset fields cross the plugin boundary as an empty DataRes that surfaces as
// "llx: encountered a primitive with no type information, coercing to null".
func isoTimePtr(t *gitlab.ISOTime) *time.Time {
	if t == nil {
		return nil
	}
	converted := time.Time(*t)
	return &converted
}

func mapAccessLevelToRole(accessLevel int) string {
	switch accessLevel {
	case 0:
		return "No access"
	case 5:
		return "Minimal Access"
	case 10:
		return "Guest"
	case 15:
		return "Planner"
	case 20:
		return "Reporter"
	case 30:
		return "Developer"
	case 40:
		return "Maintainer"
	case 50:
		return "Owner"
	case 60:
		return "Admin"
	default:
		return "Unknown"
	}
}

// projectScopedID builds a cache key for a resource that is only unique within
// a single project. GitLab identifies many project children by values that
// repeat across projects (branch names, file paths, release tags, variable
// keys), so the owning project id has to be part of the key. Without it, a
// query that walks several projects at once (`gitlab.group.projects { ... }`)
// resolves every project after the first to the first one's resource, because
// the runtime caches on resourceName + "\x00" + __id.
func projectScopedID(resource string, projectID int64, parts ...string) string {
	return scopedID(resource, projectID, parts...)
}

// groupScopedID is the group-level counterpart of projectScopedID, for children
// that repeat across groups (SAML links, CI/CD variables).
func groupScopedID(resource string, groupID int64, parts ...string) string {
	return scopedID(resource, groupID, parts...)
}

// userScopedID is the user-level counterpart, for children that repeat across
// users (external identities).
func userScopedID(resource string, userID int64, parts ...string) string {
	return scopedID(resource, userID, parts...)
}

func scopedID(resource string, ownerID int64, parts ...string) string {
	segments := make([]string, 0, len(parts)+2)
	segments = append(segments, resource, strconv.FormatInt(ownerID, 10))
	segments = append(segments, parts...)
	return strings.Join(segments, "/")
}

// labelPriority flattens the SDK's Nullable priority back to the plain int64
// the shipped `priority` field has always carried. client-go v2 can tell "no
// priority set" apart from priority 0; v1 could not and reported 0 for both,
// so collapsing to 0 keeps existing policies returning the same answers.
func labelPriority(priority gitlab.Nullable[int64]) int64 {
	value, err := priority.Get()
	if err != nil {
		return 0
	}
	return value
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"

	"github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection/confluence"
	"go.mondoo.com/mql/types"
)

// confluenceAbsoluteLink joins a relative Confluence link (webui/download) with
// the response base so the field is an absolute URL. Returns "" when either
// piece is missing so a field never surfaces a bare relative path.
func confluenceAbsoluteLink(links *models.LinkScheme, rel string) string {
	if links == nil || links.Base == "" || rel == "" {
		return ""
	}
	return links.Base + rel
}

// ---------- Blog posts ----------

func (a *mqlAtlassianConfluenceSpace) blogposts() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*confluence.ConfluenceConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow confluence access")
	}
	client := conn.Client()

	spaceKey := a.Key.Data
	if spaceKey == "" {
		return []any{}, nil
	}

	// version/history/metadata.labels are populated inline so blog posts are
	// fully mapped from the list response without a per-post re-fetch.
	expand := []string{"version", "history", "metadata.labels"}

	res := []any{}
	startAt := 0
	for {
		page, _, err := client.Space.ContentByType(context.Background(), spaceKey, "blogpost", "current", expand, startAt, CONFLUENCE_PAGE_LIMIT)
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

			var version int64
			var versionMessage string
			var minorEdit bool
			updatedAt := llx.NilData
			updatedBy := llx.NilData
			if content.Version != nil {
				version = int64(content.Version.Number)
				versionMessage = content.Version.Message
				minorEdit = content.Version.MinorEdit
				updatedAt = llx.TimeDataPtr(parseConfluenceTime(content.Version.When))
				updatedBy, err = mqlConfluenceUserFromContent(a.MqlRuntime, content.Version.By)
				if err != nil {
					return nil, err
				}
			}

			createdAt := llx.NilData
			createdBy := llx.NilData
			if content.History != nil {
				createdAt = llx.TimeDataPtr(parseConfluenceTime(content.History.CreatedDate))
				createdBy, err = mqlConfluenceUserFromContent(a.MqlRuntime, content.History.CreatedBy)
				if err != nil {
					return nil, err
				}
			}

			labels := []any{}
			if content.Metadata != nil && content.Metadata.Labels != nil {
				for _, l := range content.Metadata.Labels.Results {
					if l == nil || l.Name == "" {
						continue
					}
					labels = append(labels, l.Name)
				}
			}

			mqlBlogpost, err := CreateResource(a.MqlRuntime, "atlassian.confluence.blogpost",
				map[string]*llx.RawData{
					"id":             llx.StringData(content.ID),
					"title":          llx.StringData(content.Title),
					"status":         llx.StringData(content.Status),
					"type":           llx.StringData(content.Type),
					"spaceKey":       llx.StringData(spaceKey),
					"version":        llx.IntData(version),
					"createdAt":      createdAt,
					"updatedAt":      updatedAt,
					"createdBy":      createdBy,
					"updatedBy":      updatedBy,
					"versionMessage": llx.StringData(versionMessage),
					"minorEdit":      llx.BoolData(minorEdit),
					"webUrl":         llx.StringData(confluenceAbsoluteLink(content.Links, contentWebui(content))),
					"labels":         llx.ArrayData(labels, types.String),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlBlogpost)
		}
		startAt += len(page.Results)
		if len(page.Results) < CONFLUENCE_PAGE_LIMIT {
			break
		}
	}
	return res, nil
}

// contentWebui returns the relative web UI link of a content object, or "".
func contentWebui(content *models.ContentScheme) string {
	if content == nil || content.Links == nil {
		return ""
	}
	return content.Links.Webui
}

func (a *mqlAtlassianConfluenceBlogpost) id() (string, error) {
	return "atlassian.confluence.blogpost/" + a.Id.Data, nil
}

// mqlAtlassianConfluenceBlogpostInternal guards the shared restriction fetch so
// concurrent hasRestrictions()/restrictions() callers do not double up the call.
type mqlAtlassianConfluenceBlogpostInternal struct {
	lock sync.Mutex
}

func (a *mqlAtlassianConfluenceBlogpost) hasRestrictions() (bool, error) {
	restrictions, err := a.fetchRestrictions()
	if err != nil {
		return false, err
	}
	return contentHasRestrictions(restrictions), nil
}

func (a *mqlAtlassianConfluenceBlogpost) restrictions() ([]any, error) {
	return a.fetchRestrictions()
}

func (a *mqlAtlassianConfluenceBlogpost) fetchRestrictions() ([]any, error) {
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

func (a *mqlAtlassianConfluenceBlogpost) attachments() ([]any, error) {
	return confluenceContentAttachments(a.MqlRuntime, a.Id.Data)
}

// ---------- Attachments ----------

func (a *mqlAtlassianConfluenceAttachment) id() (string, error) {
	return "atlassian.confluence.attachment/" + a.Id.Data, nil
}

func (a *mqlAtlassianConfluencePage) attachments() ([]any, error) {
	return confluenceContentAttachments(a.MqlRuntime, a.Id.Data)
}

// contentHasRestrictions reports whether any restriction entry carries at least
// one explicit user or group holder.
func contentHasRestrictions(restrictions []any) bool {
	for _, r := range restrictions {
		entry, ok := r.(*mqlAtlassianConfluencePageRestriction)
		if !ok {
			continue
		}
		if len(entry.UserIds.Data) > 0 || len(entry.GroupNames.Data) > 0 {
			return true
		}
	}
	return false
}

// confluenceContentRestrictions loads the per-operation restrictions of a page
// or blog post and maps them to atlassian.confluence.page.restriction resources
// (the restriction shape is content-generic, keyed by content id + operation).
func confluenceContentRestrictions(runtime *plugin.Runtime, contentID string) ([]any, error) {
	conn, ok := runtime.Connection.(*confluence.ConfluenceConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow confluence access")
	}
	if contentID == "" {
		return []any{}, nil
	}
	client := conn.Client()

	res := []any{}
	startAt := 0
	for {
		page, _, err := client.Content.Restriction.Gets(context.Background(),
			contentID,
			[]string{"restrictions.user", "restrictions.group"},
			startAt,
			CONFLUENCE_PAGE_LIMIT,
		)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Results) == 0 {
			break
		}
		for _, restriction := range page.Results {
			if restriction == nil {
				continue
			}
			users := []any{}
			groups := []any{}
			if restriction.Restrictions != nil {
				if restriction.Restrictions.User != nil {
					for _, u := range restriction.Restrictions.User.Results {
						if u == nil || u.AccountID == "" {
							continue
						}
						users = append(users, u.AccountID)
					}
				}
				if restriction.Restrictions.Group != nil {
					for _, g := range restriction.Restrictions.Group.Results {
						if g == nil || g.Name == "" {
							continue
						}
						groups = append(groups, g.Name)
					}
				}
			}
			compositeID := contentID + "/" + restriction.Operation
			mqlRestriction, err := CreateResource(runtime, "atlassian.confluence.page.restriction",
				map[string]*llx.RawData{
					"id":         llx.StringData(compositeID),
					"operation":  llx.StringData(restriction.Operation),
					"userIds":    llx.ArrayData(users, types.String),
					"groupNames": llx.ArrayData(groups, types.String),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRestriction)
		}
		if len(page.Results) < CONFLUENCE_PAGE_LIMIT {
			break
		}
		startAt += len(page.Results)
	}
	return res, nil
}

// confluenceContentAttachments lists the attachments of a page or blog post and
// maps them to atlassian.confluence.attachment resources. version is expanded so
// the uploader and upload timestamp are available.
func confluenceContentAttachments(runtime *plugin.Runtime, contentID string) ([]any, error) {
	conn, ok := runtime.Connection.(*confluence.ConfluenceConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow confluence access")
	}
	if contentID == "" {
		return []any{}, nil
	}
	client := conn.Client()

	res := []any{}
	startAt := 0
	for {
		page, _, err := client.Content.Attachment.Gets(context.Background(), contentID, startAt, CONFLUENCE_PAGE_LIMIT,
			&models.GetContentAttachmentsOptionsScheme{Expand: []string{"version"}})
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

			mediaType, comment := "", ""
			var fileSize int64
			if content.Extensions != nil {
				mediaType = content.Extensions.MediaType
				comment = content.Extensions.Comment
				fileSize = int64(content.Extensions.FileSize)
			}

			var version int64
			createdAt := llx.NilData
			createdBy := llx.NilData
			if content.Version != nil {
				version = int64(content.Version.Number)
				createdAt = llx.TimeDataPtr(parseConfluenceTime(content.Version.When))
				createdBy, err = mqlConfluenceUserFromContent(runtime, content.Version.By)
				if err != nil {
					return nil, err
				}
			}

			downloadLink := ""
			if content.Links != nil {
				downloadLink = confluenceAbsoluteLink(content.Links, content.Links.Download)
			}

			mqlAttachment, err := CreateResource(runtime, "atlassian.confluence.attachment",
				map[string]*llx.RawData{
					"id":           llx.StringData(content.ID),
					"title":        llx.StringData(content.Title),
					"status":       llx.StringData(content.Status),
					"mediaType":    llx.StringData(mediaType),
					"fileSize":     llx.IntData(fileSize),
					"comment":      llx.StringData(comment),
					"version":      llx.IntData(version),
					"createdAt":    createdAt,
					"createdBy":    createdBy,
					"downloadLink": llx.StringData(downloadLink),
					"webUrl":       llx.StringData(confluenceAbsoluteLink(content.Links, contentWebui(content))),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAttachment)
		}
		startAt += len(page.Results)
		if len(page.Results) < CONFLUENCE_PAGE_LIMIT {
			break
		}
	}
	return res, nil
}

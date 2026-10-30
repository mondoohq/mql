// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/ctreminiom/go-atlassian/v2/admin"
	model "github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEventObjects checks the flattening of an audit event's context and
// container lists, including the fallback to the alt link when the API reports
// no self link, and that a nil entry does not take the whole list down.
func TestEventObjects(t *testing.T) {
	t.Run("nil and empty", func(t *testing.T) {
		assert.Empty(t, eventObjects(nil))
		assert.Empty(t, eventObjects([]*model.OrganizationEventObjectModel{}))
	})

	t.Run("self link preferred, alt as fallback, nil skipped", func(t *testing.T) {
		self := &model.OrganizationEventObjectModel{ID: "obj-1", Type: "user"}
		self.Links.Self = "https://example.invalid/self"
		self.Links.Alt = "https://example.invalid/alt"

		altOnly := &model.OrganizationEventObjectModel{ID: "obj-2", Type: "group"}
		altOnly.Links.Alt = "https://example.invalid/alt-2"

		got := eventObjects([]*model.OrganizationEventObjectModel{self, nil, altOnly})
		require.Len(t, got, 2)
		assert.Equal(t, map[string]any{
			"id": "obj-1", "type": "user", "link": "https://example.invalid/self",
		}, got[0])
		assert.Equal(t, map[string]any{
			"id": "obj-2", "type": "group", "link": "https://example.invalid/alt-2",
		}, got[1])
	})
}

// TestNilIfEmpty pins the choice of null over an invented empty string for a
// value the API did not report.
func TestNilIfEmpty(t *testing.T) {
	assert.Nil(t, nilIfEmpty(""))
	require.NotNil(t, nilIfEmpty("1.2.3.4"))
	assert.Equal(t, "1.2.3.4", *nilIfEmpty("1.2.3.4"))
}

func eventPage(ids []string, next string) *model.OrganizationEventPageScheme {
	page := &model.OrganizationEventPageScheme{}
	for _, id := range ids {
		page.Data = append(page.Data, &model.OrganizationEventModelScheme{
			ID:         id,
			Type:       "event",
			Attributes: &model.OrganizationEventModelAttributesScheme{Action: "user_added_to_group"},
		})
	}
	if next != "" {
		page.Links = &model.LinkPageModelScheme{Next: next}
	}
	return page
}

func TestWalkAdminEvents(t *testing.T) {
	t.Run("follows cursors to the last page", func(t *testing.T) {
		pages := map[string]*model.OrganizationEventPageScheme{
			"":   eventPage([]string{"e1", "e2"}, "https://example.invalid/events?cursor=c2"),
			"c2": eventPage([]string{"e3"}, "https://example.invalid/events?cursor=c3"),
			"c3": eventPage([]string{"e4"}, ""),
		}
		var seen []string
		var cursors []string
		err := walkAdminEvents(
			func(cursor string) (*model.OrganizationEventPageScheme, error) {
				cursors = append(cursors, cursor)
				return pages[cursor], nil
			},
			func(e *model.OrganizationEventModelScheme) error {
				seen = append(seen, e.ID)
				return nil
			})
		require.NoError(t, err)
		assert.Equal(t, []string{"e1", "e2", "e3", "e4"}, seen)
		assert.Equal(t, []string{"", "c2", "c3"}, cursors)
	})

	// A server that keeps echoing the cursor it was handed would otherwise be
	// re-read until the page bound, reporting the same events maxAdminEventPages
	// times over.
	t.Run("stops on a repeated cursor", func(t *testing.T) {
		calls := 0
		var seen []string
		err := walkAdminEvents(
			func(cursor string) (*model.OrganizationEventPageScheme, error) {
				calls++
				return eventPage([]string{"e1"}, "https://example.invalid/events?cursor=stuck"), nil
			},
			func(e *model.OrganizationEventModelScheme) error {
				seen = append(seen, e.ID)
				return nil
			})
		require.NoError(t, err)
		// One page with a fresh cursor, one page that repeats it, then stop.
		assert.Equal(t, 2, calls)
		assert.Equal(t, []string{"e1", "e1"}, seen)
	})

	t.Run("stops on a page with no links", func(t *testing.T) {
		calls := 0
		err := walkAdminEvents(
			func(cursor string) (*model.OrganizationEventPageScheme, error) {
				calls++
				return eventPage([]string{"e1"}, ""), nil
			},
			func(e *model.OrganizationEventModelScheme) error { return nil })
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})

	t.Run("bounded when the server always advances", func(t *testing.T) {
		calls := 0
		err := walkAdminEvents(
			func(cursor string) (*model.OrganizationEventPageScheme, error) {
				calls++
				return eventPage([]string{"e"}, "https://example.invalid/events?cursor=c"+strconv.Itoa(calls)), nil
			},
			func(e *model.OrganizationEventModelScheme) error { return nil })
		require.NoError(t, err)
		assert.Equal(t, maxAdminEventPages, calls)
	})

	t.Run("a nil page ends the walk", func(t *testing.T) {
		err := walkAdminEvents(
			func(cursor string) (*model.OrganizationEventPageScheme, error) { return nil, nil },
			func(e *model.OrganizationEventModelScheme) error {
				t.Fatal("visit must not be called for a nil page")
				return nil
			})
		require.NoError(t, err)
	})
}

// rewriteTransport sends every request to the test server regardless of the
// host the SDK built, so the real admin client can be driven against canned
// responses without reaching the network.
type rewriteTransport struct{ base *url.URL }

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.base.Scheme
	req.URL.Host = t.base.Host
	return http.DefaultTransport.RoundTrip(req)
}

// TestOrganizationEventsDecoding drives the real SDK client against a canned
// response so the JSON field names of an audit event are pinned. A mistyped tag
// here would report a null action or a missing source address on every event,
// which is the half of the record a reviewer relies on.
func TestOrganizationEventsDecoding(t *testing.T) {
	body := `{
	  "data": [{
	    "id": "event-1",
	    "type": "event",
	    "attributes": {
	      "time": "2026-02-03T04:05:06Z",
	      "action": "admin_permission_granted",
	      "actor": {"id": "account-1", "name": "Example Admin"},
	      "context": [{"id": "account-2", "type": "user", "links": {"self": "https://example.invalid/u/2"}}],
	      "container": [{"id": "site-1", "type": "site", "links": {"alt": "https://example.invalid/s/1"}}],
	      "location": {"ip": "198.51.100.7", "geo": "AQ"}
	    }
	  }],
	  "links": {"next": "https://example.invalid/admin/v1/orgs/org-1/events?cursor=next-1"}
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/admin/v1/orgs/org-1/events")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	require.NoError(t, err)
	client, err := admin.New(&http.Client{Transport: rewriteTransport{base: base}})
	require.NoError(t, err)

	page, _, err := client.Organization.Events(context.Background(), "org-1", nil, "")
	require.NoError(t, err)
	require.Len(t, page.Data, 1)

	event := page.Data[0]
	assert.Equal(t, "event-1", event.ID)
	require.NotNil(t, event.Attributes)
	attrs := event.Attributes
	assert.Equal(t, "admin_permission_granted", attrs.Action)
	require.NotNil(t, attrs.Actor)
	assert.Equal(t, "account-1", attrs.Actor.ID)
	assert.Equal(t, "Example Admin", attrs.Actor.Name)
	require.NotNil(t, attrs.Location)
	assert.Equal(t, "198.51.100.7", attrs.Location.IP)
	assert.Equal(t, "AQ", attrs.Location.Geo)

	// The timestamp arrives as a string and must parse to a real time, not the
	// zero value.
	ts := parseAtlassianTime(attrs.Time)
	require.NotNil(t, ts)
	assert.Equal(t, 2026, ts.Year())

	assert.Equal(t, []any{map[string]any{
		"id": "account-2", "type": "user", "link": "https://example.invalid/u/2",
	}}, eventObjects(attrs.Context))
	assert.Equal(t, []any{map[string]any{
		"id": "site-1", "type": "site", "link": "https://example.invalid/s/1",
	}}, eventObjects(attrs.Container))

	// The cursor must come back as the bare value, not the whole next URL.
	require.NotNil(t, page.Links)
	assert.Equal(t, "next-1", extractAtlassianCursor(page.Links.Next))
}

// TestOrganizationEventsAbsentOptionalValues proves that an event carrying no
// actor, no location and no timestamp reports nulls rather than invented empty
// strings or a zero time.
func TestOrganizationEventsAbsentOptionalValues(t *testing.T) {
	var page model.OrganizationEventPageScheme
	require.NoError(t, json.Unmarshal([]byte(`{"data":[{"id":"e","type":"event","attributes":{"action":"a"}}]}`), &page))
	require.Len(t, page.Data, 1)
	attrs := page.Data[0].Attributes
	require.NotNil(t, attrs)

	assert.Nil(t, attrs.Actor)
	assert.Nil(t, attrs.Location)
	assert.Nil(t, parseAtlassianTime(attrs.Time))
	assert.Nil(t, nilIfEmpty(""))
}

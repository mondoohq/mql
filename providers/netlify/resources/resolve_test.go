// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The reference accessors resolve through a list the root resource already
// fetched, falling back to a direct lookup on a miss. The fallback is what
// keeps a record that names something outside the connection's account or site
// scope resolving as it did before: those lists are narrowed by that scope, so
// a scoped-out entry is a miss rather than an absence. These tests pin the miss
// cases, because a miss reported as a hit would resolve the reference to null.

func siteWithID(id string) *mqlNetlifySite {
	return &mqlNetlifySite{Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet}}
}

func siteList(ids ...string) *plugin.TValue[[]any] {
	data := make([]any, 0, len(ids))
	for _, id := range ids {
		data = append(data, siteWithID(id))
	}
	return &plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet}
}

func TestFindCachedResourceHit(t *testing.T) {
	site, ok := findCachedResource(siteList("a", "b", "c"), netlifySiteID, "b")
	if !ok {
		t.Fatal("expected the site to resolve out of the cached list")
	}
	if site.Id.Data != "b" {
		t.Errorf("resolved the wrong site: %q", site.Id.Data)
	}
}

func TestFindCachedResourceFallsBackOnMiss(t *testing.T) {
	tests := []struct {
		name string
		list *plugin.TValue[[]any]
		want string
	}{
		{
			// A site in an account the connection is not scoped to. The direct
			// lookup still reaches it, so this must not resolve to null.
			name: "outside the connection scope",
			list: siteList("a", "b"),
			want: "scoped-out",
		},
		{
			// An empty scope, which is what a token that can reach no site at
			// all sees. The reference is still worth attempting directly.
			name: "empty list",
			list: siteList(),
			want: "a",
		},
		{
			name: "unreadable list",
			list: &plugin.TValue[[]any]{Error: errors.New("boom"), State: plugin.StateIsSet | plugin.StateIsNull},
			want: "a",
		},
		{
			name: "null list",
			list: &plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull},
			want: "a",
		},
		{
			name: "no identifier to match on",
			list: siteList("a"),
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			site, ok := findCachedResource(tc.list, netlifySiteID, tc.want)
			if ok {
				t.Fatalf("expected a miss so the caller falls back, got %q", site.Id.Data)
			}
			if site != nil {
				t.Error("a miss must not report a resource")
			}
		})
	}
}

// A list can hold an entry of another type once a caller passes the wrong
// field. Skipping it keeps the scan from panicking on the type assertion.
func TestFindCachedResourceSkipsForeignEntries(t *testing.T) {
	list := &plugin.TValue[[]any]{
		Data:  []any{&mqlNetlifyAccount{Id: plugin.TValue[string]{Data: "a", State: plugin.StateIsSet}}, siteWithID("a")},
		State: plugin.StateIsSet,
	}

	site, ok := findCachedResource(list, netlifySiteID, "a")
	if !ok {
		t.Fatal("expected the site to resolve past the foreign entry")
	}
	if site.Id.Data != "a" {
		t.Errorf("resolved the wrong site: %q", site.Id.Data)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/memoize"
	"go.mondoo.com/mql/providers/github/connection"
)

// We use a global MQL resource for the connection to store the memoizer.
// In this way we can cache requests for things that aren't directly attached to an MQL resource.
// For example, we don't want to fetch the same users multiple times, for that we can use the memoizer.
type mqlGithubInternal struct {
	memoize memoize.Memoizer
}

var (
	cacheExpirationTime = 24 * time.Hour
	cacheCleanupTime    = 48 * time.Hour
)

func getUser(ctx context.Context, runtime *plugin.Runtime, conn *connection.GithubConnection, user string) (*github.User, error) {
	obj, err := CreateResource(runtime, "github", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	g := obj.(*mqlGithub)
	if g.memoize == nil {
		g.memoize = memoize.New(cacheExpirationTime, cacheCleanupTime)
	}

	res, _, err := g.memoize.Memoize("user-"+user, func() (any, error) {
		log.Debug().Msgf("fetching user %s", user)
		user, _, err := conn.Client().Users.Get(ctx, user)
		return user, err
	})
	if err != nil {
		return nil, err
	}
	return res.(*github.User), nil
}

func getOrg(ctx context.Context, runtime *plugin.Runtime, conn *connection.GithubConnection, name string) (*github.Organization, error) {
	obj, err := CreateResource(runtime, "github", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	g := obj.(*mqlGithub)
	if g.memoize == nil {
		g.memoize = memoize.New(cacheExpirationTime, cacheCleanupTime)
	}
	res, _, err := g.memoize.Memoize("org-"+name, func() (any, error) {
		log.Debug().Msgf("fetching organization %s", name)
		org, _, err := conn.Client().Organizations.Get(ctx, name)
		return org, err
	})
	if err != nil {
		return nil, err
	}
	return res.(*github.Organization), nil
}

func githubTimestamp(ts *github.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	return &ts.Time
}

// githubTime returns the timestamp as a time pointer, or nil when it is absent
// or zero. GitHub omits a timestamp it holds no value for, which decodes to the
// zero time; reporting that verbatim puts 1 January year 1 into an audit as
// though it were a real date.
func githubTime(ts *github.Timestamp) *time.Time {
	if ts == nil || ts.IsZero() {
		return nil
	}
	return &ts.Time
}

// githubTimeValue is githubTime for the timestamps go-github models by value
// rather than by pointer, where an omitted timestamp is indistinguishable from
// a zero one.
func githubTimeValue(ts github.Timestamp) *time.Time {
	return githubTime(&ts)
}

// githubNotAvailable reports whether the error is GitHub saying the endpoint
// does not apply here: 404 for a feature the repository or organization does
// not have, 409 for a setting that only exists in another mode. It excludes
// 403, which means the read was refused rather than that the feature is off,
// and it never matches a transport error, which has to stay a failure instead
// of degrading into a posture verdict.
func githubNotAvailable(err error) bool {
	switch githubResponseStatus(err) {
	case http.StatusNotFound, http.StatusConflict:
		return true
	}
	return false
}

// githubForbidden reports whether GitHub refused the read for lack of
// permission. What such a read would have returned is unknown, never a
// negative posture.
func githubForbidden(err error) bool {
	return githubResponseStatus(err) == http.StatusForbidden
}

const (
	paginationPerPage = 100
)

// nextPage returns the page to request after the one just read, or 0 when the
// walk is done. A next page that is not ahead of the page just read ends the
// walk: GitHub numbers pages upward, so a link pointing at the current page or
// behind it is a broken cursor, and following it re-reads the same page until
// the process runs out of memory.
func nextPage(current int, resp *github.Response) int {
	if resp == nil || resp.NextPage == 0 || resp.NextPage <= current {
		return 0
	}
	return resp.NextPage
}

// collectPages walks a page-numbered GitHub listing to completion. Reading only
// the first page is the quiet version of this bug: the caller gets a short list
// and no indication that anything was left behind.
func collectPages[T any](fetch func(opts *github.ListOptions) ([]T, *github.Response, error)) ([]T, error) {
	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []T
	for {
		items, resp, err := fetch(opts)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		next := nextPage(opts.Page, resp)
		if next == 0 {
			return all, nil
		}
		opts.Page = next
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/circleci/connection"
)

func (r *mqlCircleci) id() (string, error) {
	return "circleci", nil
}

// conn returns the CircleCI connection backing this runtime.
func (r *mqlCircleci) conn() *connection.CircleciConnection {
	return r.MqlRuntime.Connection.(*connection.CircleciConnection)
}

// me returns the currently authenticated user.
func (r *mqlCircleci) me() (*mqlCircleciUser, error) {
	conn := r.conn()
	u, err := conn.Client().GetMe(context.Background())
	if err != nil {
		return nil, err
	}
	res, err := newMqlCircleciUser(r.MqlRuntime, u)
	if err != nil {
		return nil, err
	}
	return res.(*mqlCircleciUser), nil
}

// organizations lists every organization the current token can see.
func (r *mqlCircleci) organizations() ([]any, error) {
	conn := r.conn()
	orgs, err := conn.Client().GetCollaborations(context.Background())
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(orgs))
	for _, o := range orgs {
		res, err := newMqlCircleciOrganization(r.MqlRuntime, o)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// projects lists every project across every organization visible to the
// current token.
func (r *mqlCircleci) projects() ([]any, error) {
	orgs, err := r.organizations()
	if err != nil {
		return nil, err
	}

	var all []any
	for _, o := range orgs {
		org := o.(*mqlCircleciOrganization)
		projects, err := org.projects()
		if err != nil {
			return nil, err
		}
		all = append(all, projects...)
	}
	return all, nil
}

// contexts lists every context across every organization visible to the
// current token.
func (r *mqlCircleci) contexts() ([]any, error) {
	orgs, err := r.organizations()
	if err != nil {
		return nil, err
	}

	var all []any
	for _, o := range orgs {
		org := o.(*mqlCircleciOrganization)
		contexts, err := org.contexts()
		if err != nil {
			return nil, err
		}
		all = append(all, contexts...)
	}
	return all, nil
}

// newMqlCircleciUser maps a single API user to its MQL resource.
func newMqlCircleciUser(runtime *plugin.Runtime, u *connection.User) (plugin.Resource, error) {
	return CreateResource(runtime, "circleci.user", map[string]*llx.RawData{
		"__id":  llx.StringData(u.ID),
		"id":    llx.StringData(u.ID),
		"login": llx.StringData(u.Login),
		"name":  llx.StringData(u.Name),
	})
}

// parseCircleciTime parses a CircleCI RFC3339 timestamp string. An empty
// value means the API reported no timestamp, so the field stays null. A
// value that is present but unparseable is a data-quality problem rather
// than an absent timestamp, so it is logged before falling back to null.
func parseCircleciTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		log.Warn().Err(err).Str("value", s).Msg("circleci> unable to parse timestamp")
		return nil
	}
	return &t
}

// pageWalker guards a CircleCI cursor walk against an endpoint that keeps
// handing back a page token it has already issued. CircleCI paginates with an
// opaque next_page_token, and a proxy or a server-side fault that repeats one
// makes a naive loop append the same page forever: the slice grows until the
// scan runs out of memory rather than finishing with a wrong answer. Tracking
// the tokens already seen turns that into an error.
type pageWalker struct {
	seen map[string]struct{}
}

// next reports the token to request for the following page. done is true once
// the collection is exhausted. An error means the cursor stopped advancing,
// which is a fault rather than the end of the collection.
func (w *pageWalker) next(token string) (next string, done bool, err error) {
	if token == "" {
		return "", true, nil
	}
	if _, dup := w.seen[token]; dup {
		return "", false, fmt.Errorf("circleci> pagination did not advance: page token %q was issued twice", token)
	}
	if w.seen == nil {
		w.seen = map[string]struct{}{}
	}
	w.seen[token] = struct{}{}
	return token, false, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/digitalocean/godo"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// godo does not wrap the Organizations endpoints, so the request goes through
// the client's own NewRequest/Do. That keeps the token, the rate limiter and
// the error decoding the rest of the provider relies on, rather than standing
// up a second HTTP client beside them.
//
// This endpoint is not paginated, so there is deliberately no paginate() call
// here. DigitalOcean's published spec declares no page or per_page parameter on
// it, and its response body is a bare {"teams": [...]} with none of the
// pagination and meta members every paginated endpoint carries. A loop would
// also be dead code rather than a safety net: godo fills Response.Links from
// the body's links key, so a body that never has one always reports the first
// page as the last. That is how the scan-findings loop in #9366 silently
// truncated. If DigitalOcean ever paginates this, it has to be driven off the
// returned slice length instead.
const organizationTeamsPath = "v2/organizations/teams"

type organizationTeam struct {
	ID                   uint64 `json:"id"`
	UUID                 string `json:"uuid"`
	Name                 string `json:"name"`
	Email                string `json:"email"`
	MemberCount          uint64 `json:"member_count"`
	Status               string `json:"status"`
	JoinedOrganizationAt string `json:"joined_organization_at"`
}

type organizationTeamsRoot struct {
	Teams []organizationTeam `json:"teams"`
}

// noOrganizationContext reports the answers that mean this token has no
// organization context, so the teams cannot be enumerated.
//
// The endpoint "must be called in an organization context". A token without
// that context does not establish that the organization has no teams - only
// that this token may not read them, which is a different fact and must not be
// reported as an empty list. A 401 is excluded because a rejected token is a
// plain failure that should surface as an error.
func noOrganizationContext(err error) bool {
	var er *godo.ErrorResponse
	if !errors.As(err, &er) || er.Response == nil {
		return false
	}
	switch er.Response.StatusCode {
	case http.StatusForbidden, http.StatusNotFound, http.StatusPreconditionFailed:
		return true
	}
	return false
}

func (r *mqlDigitaloceanTeam) id() (string, error) {
	return resourceID("digitalocean.team", r.Uuid.Data)
}

func (r *mqlDigitalocean) teams() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	ctx := context.Background()

	req, err := client.NewRequest(ctx, http.MethodGet, organizationTeamsPath, nil)
	if err != nil {
		return nil, err
	}

	root := new(organizationTeamsRoot)
	if _, err := client.Do(ctx, req, root); err != nil {
		if noOrganizationContext(err) {
			// Null, not an empty list. An empty list is an answer - "this
			// organization has no teams" - and `.none()` / `.all()` over it
			// pass vacuously, so a token that may not read the teams would
			// silently satisfy every assertion about them. Null carries no
			// answer and fails those assertions closed.
			//
			// Setting the state proactively is required: returning nil from a
			// list accessor still serializes as [], because the runtime cannot
			// tell a nil slice from an empty one. plugin.GetOrCompute only
			// keeps this value because IsSet() is checked after the accessor
			// runs.
			log.Debug().Err(err).Msg("digitalocean> token is not scoped to an organization; teams are unknown")
			r.Teams.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	all := make([]any, 0, len(root.Teams))
	for i := range root.Teams {
		t := root.Teams[i]
		res, err := CreateResource(r.MqlRuntime, "digitalocean.team", map[string]*llx.RawData{
			"id":                   llx.IntData(int64(t.ID)),
			"uuid":                 llx.StringData(t.UUID),
			"name":                 llx.StringData(t.Name),
			"email":                llx.StringData(t.Email),
			"memberCount":          llx.IntData(int64(t.MemberCount)),
			"status":               llx.StringData(t.Status),
			"joinedOrganizationAt": llx.TimeDataPtr(parseDoTime(t.JoinedOrganizationAt)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

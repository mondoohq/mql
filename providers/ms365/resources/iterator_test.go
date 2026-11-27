// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const registrationDetailsPath = "/reports/authenticationMethods/userRegistrationDetails"

// walkRegistrationDetails reads the first page of the registration report from
// the fake Graph, walks it with iterateEach, and returns the ids handed over
// and what the walk logged.
func walkRegistrationDetails(t *testing.T, routes map[string]fakeRoute, each func(id string) error) ([]string, string, error) {
	t.Helper()
	var logged bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&logged)
	t.Cleanup(func() { log.Logger = prev })

	client := newFakeGraph(t, routes).client()
	ctx := context.Background()
	resp, err := client.Reports().AuthenticationMethods().UserRegistrationDetails().Get(ctx, nil)
	require.NoError(t, err)

	ids := []string{}
	err = iterateEach(ctx, resp, client.GetAdapter(),
		models.CreateUserRegistrationDetailsCollectionResponseFromDiscriminatorValue,
		func(d models.UserRegistrationDetailsable) error {
			ids = append(ids, *d.GetId())
			if each != nil {
				return each(*d.GetId())
			}
			return nil
		})
	return ids, logged.String(), err
}

// iterateEach hands over every item of every page, following
// @odata.nextLink. A null entry in a page is skipped: the rest of its page and
// every later page are still handed over, and one warning names the collection
// and the number of entries skipped.
func TestIterateEachPages(t *testing.T) {
	const skippedWarning = "skipped null entries while paging Graph results"
	const collection = `"collection":"UserRegistrationDetailsCollectionResponse"`

	cases := []struct {
		name    string
		routes  map[string]fakeRoute
		want    []string
		skipped string // the warning's count field; empty when no warning is expected
	}{
		{
			// Synthetic: plain paging, no null entries; no target showed this.
			name: "no null entry",
			routes: map[string]fakeRoute{
				registrationDetailsPath: {status: 200, body: `{
					"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page2",
					"value": [{"id": "u1", "isMfaCapable": true}, {"id": "u2", "isMfaCapable": false}]}`},
				registrationDetailsPath + "/page2": {status: 200, body: `{
					"value": [{"id": "u3"}]}`},
			},
			want: []string{"u1", "u2", "u3"},
		},
		{
			// Synthetic: a null entry on the last page; no target showed this.
			name: "null entry on the last page",
			routes: map[string]fakeRoute{
				registrationDetailsPath: {status: 200, body: `{
					"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page2",
					"value": [{"id": "u1", "isMfaCapable": true}, {"id": "u2", "isMfaCapable": false}]}`},
				registrationDetailsPath + "/page2": {status: 200, body: `{
					"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page3",
					"value": [{"id": "u3", "isMfaCapable": true}]}`},
				registrationDetailsPath + "/page3": {status: 200, body: `{
					"value": [{"id": "u4"}, null, {"id": "u5"}]}`},
			},
			want:    []string{"u1", "u2", "u3", "u4", "u5"},
			skipped: `"skipped":1`,
		},
		{
			// Synthetic: a null entry on a page that has a next page; no
			// target showed this.
			name: "null entry on a page followed by another",
			routes: map[string]fakeRoute{
				registrationDetailsPath: {status: 200, body: `{
					"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page2",
					"value": [{"id": "u1"}]}`},
				registrationDetailsPath + "/page2": {status: 200, body: `{
					"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page3",
					"value": [{"id": "u2"}, null, {"id": "u3"}]}`},
				registrationDetailsPath + "/page3": {status: 200, body: `{
					"value": [{"id": "u4"}, {"id": "u5"}]}`},
			},
			want:    []string{"u1", "u2", "u3", "u4", "u5"},
			skipped: `"skipped":1`,
		},
		{
			// Synthetic: the first entry of the first page is null, and a
			// later page holds two more; no target showed this.
			name: "null entry first on the first page",
			routes: map[string]fakeRoute{
				registrationDetailsPath: {status: 200, body: `{
					"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page2",
					"value": [null, {"id": "u1"}, {"id": "u2"}]}`},
				registrationDetailsPath + "/page2": {status: 200, body: `{
					"value": [null, {"id": "u3"}, null]}`},
			},
			want:    []string{"u1", "u2", "u3"},
			skipped: `"skipped":3`,
		},
		{
			// Synthetic: a page of nothing but a null entry still leads to
			// the next page; no target showed this.
			name: "page holding only a null entry",
			routes: map[string]fakeRoute{
				registrationDetailsPath: {status: 200, body: `{
					"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page2",
					"value": [null]}`},
				registrationDetailsPath + "/page2": {status: 200, body: `{
					"value": [{"id": "u1"}]}`},
			},
			want:    []string{"u1"},
			skipped: `"skipped":1`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids, logged, err := walkRegistrationDetails(t, tc.routes, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.want, ids)
			if tc.skipped == "" {
				assert.NotContains(t, logged, skippedWarning)
				return
			}
			assert.Equal(t, 1, strings.Count(logged, skippedWarning), "one warning per walk")
			assert.Contains(t, logged, collection)
			assert.Contains(t, logged, tc.skipped)
			assert.Contains(t, logged, `"level":"warn"`)
		})
	}
}

// Synthetic: an error from each stops the walk where it was raised and is
// returned as is; the next page is not handed over. No target showed this.
func TestIterateEachStopsOnCallbackError(t *testing.T) {
	stop := errors.New("stop here")
	ids, _, err := walkRegistrationDetails(t, map[string]fakeRoute{
		registrationDetailsPath: {status: 200, body: `{
			"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page2",
			"value": [{"id": "u1"}, {"id": "u2"}, {"id": "u3"}]}`},
		registrationDetailsPath + "/page2": {status: 200, body: `{
			"value": [{"id": "u4"}]}`},
	}, func(id string) error {
		if id == "u2" {
			return stop
		}
		return nil
	})
	assert.Same(t, stop, err)
	assert.Equal(t, []string{"u1", "u2"}, ids)
}

// Synthetic: a panic during the walk ends it with an error for the one list,
// naming the collection, instead of taking the provider down. Callers page
// from worker goroutines, where nothing else would recover it. No target
// showed this.
func TestIterateEachRecoversPanics(t *testing.T) {
	routes := map[string]fakeRoute{
		registrationDetailsPath: {status: 200, body: `{
			"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page2",
			"value": [{"id": "u1"}, {"id": "u2"}]}`},
		registrationDetailsPath + "/page2": {status: 200, body: `{
			"value": [{"id": "u3"}]}`},
	}

	t.Run("in the callback", func(t *testing.T) {
		ids, logged, err := walkRegistrationDetails(t, routes, func(id string) error {
			if id == "u2" {
				panic("callback blew up")
			}
			return nil
		})
		require.EqualError(t, err, "paging UserRegistrationDetailsCollectionResponse: recovered panic: callback blew up")
		assert.Equal(t, []string{"u1", "u2"}, ids)
		assert.Contains(t, logged, `"level":"error"`)
	})

	t.Run("in the SDK fetching the next page", func(t *testing.T) {
		client := newFakeGraph(t, routes).client()
		ctx := context.Background()
		resp, err := client.Reports().AuthenticationMethods().UserRegistrationDetails().Get(ctx, nil)
		require.NoError(t, err)

		ids := []string{}
		err = iterateEach(ctx, resp, &panickingAdapter{RequestAdapter: client.GetAdapter(), panics: 1},
			models.CreateUserRegistrationDetailsCollectionResponseFromDiscriminatorValue,
			func(d models.UserRegistrationDetailsable) error {
				ids = append(ids, *d.GetId())
				return nil
			})
		require.EqualError(t, err, "paging UserRegistrationDetailsCollectionResponse: recovered panic: send blew up")
		assert.Equal(t, []string{"u1", "u2"}, ids)
	})
}

// Synthetic: a refused request for a later page ends the walk with an error,
// after the earlier pages were handed over. No target showed this.
func TestIterateEachNextPageError(t *testing.T) {
	ids, _, err := walkRegistrationDetails(t, map[string]fakeRoute{
		registrationDetailsPath: {status: 200, body: `{
			"@odata.nextLink": "{{base}}` + registrationDetailsPath + `/page2",
			"value": [{"id": "u1"}]}`},
		registrationDetailsPath + "/page2": {status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`},
	}, nil)
	require.Error(t, err)
	assert.Equal(t, []string{"u1"}, ids)
}

// Synthetic: a next link that leads back to a page already fetched would be
// followed forever; the walk ends with an error once it sees the link a second
// time. No target showed this.
func TestIterateEachStuckNextLink(t *testing.T) {
	page := func(next, id string) fakeRoute {
		return fakeRoute{status: 200, body: `{
			"@odata.nextLink": "{{base}}` + registrationDetailsPath + next + `",
			"value": [{"id": "` + id + `"}]}`}
	}
	t.Run("page naming itself", func(t *testing.T) {
		ids, _, err := walkRegistrationDetails(t, map[string]fakeRoute{
			registrationDetailsPath:            page("/page2", "u1"),
			registrationDetailsPath + "/page2": page("/page2", "u2"),
		}, nil)
		require.ErrorContains(t, err, "already fetched page")
		assert.Equal(t, []string{"u1", "u2"}, ids)
	})
	t.Run("two pages naming each other", func(t *testing.T) {
		ids, _, err := walkRegistrationDetails(t, map[string]fakeRoute{
			registrationDetailsPath:            page("/page2", "u1"),
			registrationDetailsPath + "/page2": page("/page3", "u2"),
			registrationDetailsPath + "/page3": page("/page2", "u3"),
		}, nil)
		require.ErrorContains(t, err, "already fetched page")
		assert.Equal(t, []string{"u1", "u2", "u3"}, ids)
	})
}

// Synthetic: a next link that is not a URL ends the walk with an error that
// names the collection and keeps the parse error. No target showed this.
func TestIterateEachMalformedNextLink(t *testing.T) {
	_, _, err := walkRegistrationDetails(t, map[string]fakeRoute{
		registrationDetailsPath: {status: 200, body: `{
			"@odata.nextLink": "http://[bad",
			"value": [{"id": "u1"}]}`},
	}, nil)
	require.ErrorContains(t, err, "paging UserRegistrationDetailsCollectionResponse: parsing nextLink")
	var parseErr *url.Error
	assert.ErrorAs(t, err, &parseErr)
}

// Graph answers a listing with each entry's most specific type. A caller that
// asks for the concrete base type gets a derived entry as the base it is built
// on, with the base properties readable, and the walk goes on past it.
//
// Measured: a Microsoft 365 test tenant, Graph v1.0, 2026-11-23. Its
// /servicePrincipals/delta listing holds entries with the @odata.type below,
// which the SDK's iterator could not hand over as *models.ServicePrincipal, so
// the listing ended at the first page holding one. The ids and names here are
// made up.
func TestIterateDerivedEntries(t *testing.T) {
	client := newFakeGraph(t, map[string]fakeRoute{
		"/servicePrincipals/delta()": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/servicePrincipals/delta()/page2",
			"value": [
				{"id": "sp1", "displayName": "one"},
				{"@odata.type": "#microsoft.graph.agentIdentityBlueprintPrincipal", "id": "sp2", "displayName": "two"}]}`},
		"/servicePrincipals/delta()/page2": {status: 200, body: `{
			"value": [{"id": "sp3", "displayName": "three"}]}`},
	}).client()
	ctx := context.Background()
	resp, err := client.ServicePrincipals().Delta().GetAsDeltaGetResponse(ctx, nil)
	require.NoError(t, err)
	require.IsType(t, &models.AgentIdentityBlueprintPrincipal{}, resp.GetValue()[1], "the fixture must produce a derived entry")

	sps, err := iterate[*models.ServicePrincipal](ctx, resp, client.GetAdapter(), serviceprincipals.CreateDeltaGetResponseFromDiscriminatorValue)
	require.NoError(t, err)
	require.Len(t, sps, 3)
	names := []string{}
	for _, sp := range sps {
		names = append(names, *sp.GetId()+"="+*sp.GetDisplayName())
	}
	assert.Equal(t, []string{"sp1=one", "sp2=two", "sp3=three"}, names)
}

// Synthetic: responses that are not a readable collection page are refused
// with an error, not a panic. No target showed this.
func TestGraphPageRejectsNonPages(t *testing.T) {
	_, _, _, err := graphPage[models.Userable](nil)
	assert.ErrorContains(t, err, "response cannot be nil")

	var absent *models.UserCollectionResponse
	_, _, _, err = graphPage[models.Userable](absent)
	assert.ErrorContains(t, err, "response cannot be nil")

	_, _, _, err = graphPage[models.Userable](models.NewUser())
	assert.ErrorContains(t, err, "value property missing")

	// a response whose accessor panics
	_, _, _, err = graphPage[models.Userable](brokenPage{})
	assert.ErrorContains(t, err, "reading a page of brokenPage: value is gone")

	// a collection read with the wrong element type
	users := models.NewUserCollectionResponse()
	users.SetValue([]models.Userable{models.NewUser()})
	_, _, _, err = graphPage[models.Groupable](users)
	assert.ErrorContains(t, err, "UserCollectionResponse holds entries of type *models.User")
}

// The registration report is held for the whole scan as
// userRegistrationDetail values; every field the resource exposes must
// survive the reduction from the kiota model.
func TestNewMqlUserRegistrationDetailsFromReportRow(t *testing.T) {
	runtime, _ := licenseTestEnv(t, nil, nil, nil)
	row := models.NewUserRegistrationDetails()
	id, upn, yes, no := "u1", "alice@example.com", true, false
	row.SetId(&id)
	row.SetUserPrincipalName(&upn)
	row.SetIsMfaCapable(&yes)
	row.SetIsSsprRegistered(&no)
	row.SetMethodsRegistered([]string{"microsoftAuthenticatorPush", "mobilePhone"})
	userType := models.MEMBER_SIGNINUSERTYPE
	row.SetUserType(&userType)

	res, err := newMqlUserRegistrationDetails(runtime, newUserRegistrationDetail(row))
	require.NoError(t, err)
	assert.Equal(t, id, res.Id.Data)
	assert.Equal(t, upn, res.UserPrincipalName.Data)
	assert.True(t, res.IsMfaCapable.Data)
	assert.False(t, res.IsSsprRegistered.Data)
	assert.Equal(t, []any{"microsoftAuthenticatorPush", "mobilePhone"}, res.MethodsRegistered.Data)
	assert.Equal(t, "member", res.UserType.Data)
}

// brokenPage is a collection response whose GetValue panics.
type brokenPage struct{}

func (brokenPage) GetValue() []models.Userable { panic("value is gone") }
func (brokenPage) GetOdataNextLink() *string   { return nil }

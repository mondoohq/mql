// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestPolicyArgs(t *testing.T) {
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "p-1", "type": "access", "state": "active",
		"subjects": [{"attributes": [{"name": "access_group_id", "value": "AccessGroupId-1"}]}],
		"roles": [{"role_id": "crn:v1:bluemix:public:iam::::role:Administrator", "display_name": "Administrator"}],
		"resources": [{"attributes": [{"name": "accountId", "value": "acc"}, {"name": "serviceName", "value": "is", "operator": "stringEquals"}]}]
	}`), &raw))
	var p *iampolicymanagementv1.PolicyTemplateMetaData
	require.NoError(t, iampolicymanagementv1.UnmarshalPolicyTemplateMetaData(raw, &p))

	args := policyArgs(*p)
	assert.Equal(t, []any{"Administrator"}, args["roles"].Value)
	assert.Equal(t, []any{"crn:v1:bluemix:public:iam::::role:Administrator"}, args["roleIds"].Value)
	assert.Equal(t, map[string]any{"access_group_id": "AccessGroupId-1"}, args["subjectAttributes"].Value)
	assert.Equal(t, map[string]any{"accountId": "acc", "serviceName": "is"}, args["resourceAttributes"].Value)
}

// iamIdentityServer is a real IAM Identity client in front of a fake
// endpoint that answers each path with its JSON body under status, and records
// every request URL.
func iamIdentityServer(t *testing.T, status int, bodies map[string]string, urls *[]string) *iamidentityv1.IamIdentityV1 {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if urls != nil {
			*urls = append(*urls, r.URL.String())
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	svc, err := iamidentityv1.NewIamIdentityV1(&iamidentityv1.IamIdentityV1Options{URL: srv.URL, Authenticator: &core.NoAuthAuthenticator{}})
	require.NoError(t, err)
	return svc
}

// The list calls answer without activity, as IBM Cloud's do; the identities
// are mapped without lastAuthentication and authenticationCount, which are
// computed per identity.
func TestListIdentitiesCarryNoActivity(t *testing.T) {
	var urls []string
	svc := iamIdentityServer(t, http.StatusOK, map[string]string{
		"/v1/apikeys": `{"apikeys": [{"id": "ApiKey-1", "name": "ci", "iam_id": "iam-ServiceId-1", "locked": false, "disabled": true,
			"created_at": "2026-10-07T08:44:00Z", "expires_at": "2027-01-01T00:00:00Z", "action_when_leaked": "disable", "apikey": ""}]}`,
		"/v1/serviceids/": `{"serviceids": [{"id": "ServiceId-1", "iam_id": "iam-ServiceId-1", "name": "ci", "locked": false,
			"created_at": "2026-10-07T08:44:00Z", "modified_at": "2026-10-07T08:44:00Z"}]}`,
		"/v1/profiles": `{"profiles": [{"id": "Profile-1", "iam_id": "iam-Profile-1", "name": "compute", "created_at": "2026-10-07T08:44:00Z"}]}`,
	}, &urls)

	keys, err := listAPIKeys(svc, "acc")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	args := apiKeyArgs(keys[0])
	assert.Equal(t, "ibm.iam.apiKey/ApiKey-1", args["__id"].Value)
	assert.Equal(t, true, args["disabled"].Value)
	assert.NotNil(t, args["expiresAt"].Value)
	assert.NotContains(t, args, "lastAuthentication", "computed from the get call")
	assert.NotContains(t, args, "authenticationCount", "computed from the get call")
	assert.NotContains(t, args, "apikey", "the key value must never be mapped")

	ids, err := listServiceIDs(svc, "acc")
	require.NoError(t, err)
	require.Len(t, ids, 1)
	args = serviceIDArgs(ids[0])
	assert.Equal(t, "iam-ServiceId-1", args["iamId"].Value)
	assert.NotContains(t, args, "lastAuthentication")

	profiles, err := listTrustedProfiles(svc, "acc")
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	args = trustedProfileArgs(profiles[0])
	assert.Equal(t, "compute", args["name"].Value)
	assert.NotContains(t, args, "authenticationCount")

	require.Len(t, urls, 3)
	for _, u := range urls {
		assert.NotContains(t, u, "include_activity", "the list calls do not take include_activity")
	}
}

func TestIdentityActivityFromGet(t *testing.T) {
	activity := `"activity": {"last_authn": "2026-10-15T09:00:00Z", "authn_count": 4}`
	var urls []string
	svc := iamIdentityServer(t, http.StatusOK, map[string]string{
		"/v1/apikeys/ApiKey-1":       `{"id": "ApiKey-1", "name": "ci", "iam_id": "iam-ServiceId-1", "apikey": "", ` + activity + `}`,
		"/v1/serviceids/ServiceId-1": `{"id": "ServiceId-1", "iam_id": "iam-ServiceId-1", "name": "ci", ` + activity + `}`,
		"/v1/profiles/Profile-1":     `{"id": "Profile-1", "iam_id": "iam-Profile-1", "name": "compute", ` + activity + `}`,
	}, &urls)

	want := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	for name, get := range map[string]func() (*iamidentityv1.Activity, error){
		"api key":         func() (*iamidentityv1.Activity, error) { return apiKeyActivity(svc, "ApiKey-1") },
		"service ID":      func() (*iamidentityv1.Activity, error) { return serviceIDActivity(svc, "ServiceId-1") },
		"trusted profile": func() (*iamidentityv1.Activity, error) { return trustedProfileActivity(svc, "Profile-1") },
	} {
		t.Run(name, func(t *testing.T) {
			a, err := get()
			require.NoError(t, err)
			var last plugin.TValue[*time.Time]
			got := lastAuthn(a, &last)
			require.NotNil(t, got)
			assert.True(t, want.Equal(*got))
			assert.Zero(t, last.State, "a known time is not null")
			var count plugin.TValue[int64]
			assert.Equal(t, int64(4), authnCount(a, &count))
		})
	}
	require.Len(t, urls, 3)
	for _, u := range urls {
		assert.Contains(t, u, "include_activity=true", "activity is only returned when asked for")
	}
}

// A key that never authenticated has a count of 0 and no last authentication,
// and IBM Cloud may return no activity at all: neither reads as the zero
// time.
func TestIdentityActivityNeverUsed(t *testing.T) {
	svc := iamIdentityServer(t, http.StatusOK, map[string]string{
		"/v1/apikeys/ApiKey-1": `{"id": "ApiKey-1", "name": "unused", "iam_id": "IBMid-1", "apikey": "", "activity": {"authn_count": 0}}`,
		"/v1/apikeys/ApiKey-2": `{"id": "ApiKey-2", "name": "untracked", "iam_id": "IBMid-1", "apikey": ""}`,
	}, nil)

	a, err := apiKeyActivity(svc, "ApiKey-1")
	require.NoError(t, err)
	var last plugin.TValue[*time.Time]
	assert.Nil(t, lastAuthn(a, &last))
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, last.State)
	var count plugin.TValue[int64]
	assert.Equal(t, int64(0), authnCount(a, &count))
	assert.Zero(t, count.State, "a count of 0 is a value, not null")

	a, err = apiKeyActivity(svc, "ApiKey-2")
	require.NoError(t, err)
	assert.Nil(t, a)
	last, count = plugin.TValue[*time.Time]{}, plugin.TValue[int64]{}
	assert.Nil(t, lastAuthn(a, &last))
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, last.State)
	authnCount(a, &count)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, count.State)

	garbage := "yesterday"
	last = plugin.TValue[*time.Time]{}
	assert.Nil(t, lastAuthn(&iamidentityv1.Activity{LastAuthn: &garbage}, &last))
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, last.State)
}

// A refused get is an error on the field, not a missing authentication.
func TestIdentityActivityRefused(t *testing.T) {
	refused := `{"errorCode": "BXNIM0513E", "errorMessage": "You are not authorized"}`
	svc := iamIdentityServer(t, http.StatusForbidden, map[string]string{
		"/v1/apikeys/ApiKey-1":       refused,
		"/v1/serviceids/ServiceId-1": refused,
		"/v1/profiles/Profile-1":     refused,
	}, nil)

	_, err := apiKeyActivity(svc, "ApiKey-1")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	_, err = serviceIDActivity(svc, "ServiceId-1")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	_, err = trustedProfileActivity(svc, "Profile-1")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
}

func TestParseIAMTime(t *testing.T) {
	want := time.Date(2026, 10, 16, 6, 40, 0, 0, time.UTC)
	for _, in := range []string{
		"2026-10-16T06:40:00Z",
		"2026-10-16T06:40:00.000Z",
		"2026-10-16T06:40+0000",
		"2026-10-16T08:40+0200",
		"2026-10-16T06:40Z",
		"2026-10-16T06:40:00+0000",
		"2026-10-16T06:40:00:000+0000",
	} {
		got, ok := parseIAMTime(in)
		assert.True(t, ok, in)
		assert.True(t, want.Equal(got), in)
	}
	got, ok := parseIAMTime("2026-10-16T08:40:12:345+0200")
	assert.True(t, ok)
	assert.True(t, time.Date(2026, 10, 16, 6, 40, 12, 345e6, time.UTC).Equal(got))
	_, ok = parseIAMTime("yesterday")
	assert.False(t, ok)
}

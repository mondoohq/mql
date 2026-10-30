// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/exoscale/egoscale/v3/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// apiError gets a genuine *v3.APIError by having the SDK decode the answer
// of a fake endpoint, so the classifier is tested against what the SDK
// really produces.
func apiError(t *testing.T, status int, body string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	c, err := v3.NewClient(credentials.NewStaticCredentials("EXOtest", "secret"),
		v3.ClientOptWithEndpoint(v3.Endpoint(srv.URL)),
		v3.ClientOptWithHTTPClient(srv.Client()))
	require.NoError(t, err)
	_, err = c.ListSecurityGroups(ctx())
	require.Error(t, err)
	return err
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		kind   llx.ErrorKind
	}{
		{"401 is unauthenticated", 401, `{"message":"unauthorized"}`, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"bad signature is unauthenticated", 403, `{"message":"Invalid request signature"}`, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"operation not enabled is not applicable", 403, `{"message":"Operation 'list-vpcs' not enabled"}`, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		{"other 403 is forbidden", 403, `{"message":"Forbidden by IAM policy"}`, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"404 is not found", 404, `{"message":"not found"}`, llx.ErrorKind_ERROR_KIND_NOT_FOUND},
		{"429 is too many requests", 429, `{"message":"slow down"}`, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"503 is unavailable", 503, `{"message":"maintenance"}`, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"400 stays unclassified", 400, `{"message":"bad request"}`, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classifyError(apiError(t, tt.status, tt.body), "list-security-groups")
			assert.Equal(t, tt.kind, llx.KindOf(err))
		})
	}
}

func TestClassifyErrorDetails(t *testing.T) {
	forbidden := classifyError(apiError(t, 403, `{"message":"denied"}`), "list-security-groups")
	var e *llx.Error
	require.True(t, errors.As(forbidden, &e))
	assert.Equal(t, []string{"list-security-groups"}, e.Permissions)
	assert.Equal(t, llx.ErrorScope_ERROR_SCOPE_UNSPECIFIED, e.Scope)

	unauth := classifyError(apiError(t, 401, `{"message":"unauthorized"}`), "list-security-groups")
	require.True(t, errors.As(unauth, &e))
	assert.Equal(t, llx.ErrorScope_ERROR_SCOPE_ASSET, e.Scope)
}

func TestClassifyErrorLeavesTransportErrorsAlone(t *testing.T) {
	transport := errors.New("dial tcp: connection refused")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyError(transport, "list-instances")))
	assert.False(t, isRefusal(classifyError(transport, "list-instances")))
	assert.Nil(t, classifyError(nil, "list-instances"))
}

func TestIsRefusal(t *testing.T) {
	assert.True(t, isRefusal(classifyError(apiError(t, 403, `{"message":"denied"}`), "")))
	assert.True(t, isRefusal(classifyError(apiError(t, 403, `{"message":"Operation 'list-vpcs' not enabled"}`), "")))
	// A server failure must fail the list, not shrink it to the other zones.
	assert.False(t, isRefusal(classifyError(apiError(t, 503, `{"message":"down"}`), "")))
	assert.False(t, isRefusal(classifyError(apiError(t, 401, `{"message":"unauthorized"}`), "")))
}

func TestPickByID(t *testing.T) {
	type item struct{ id string }
	a, b, c := &item{"a"}, &item{"b"}, &item{"c"}
	list := []any{a, b, c}
	idOf := func(i *item) string { return i.id }

	// Order follows the ids asked for; unknown ids are skipped.
	assert.Equal(t, []any{c, a}, pickByID(list, []string{"c", "missing", "a"}, idOf))
	assert.Equal(t, []any{}, pickByID(list, nil, idOf))

	got, ok := pickOneByID(list, "b", idOf)
	assert.True(t, ok)
	assert.Same(t, b, got)
	_, ok = pickOneByID(list, "", idOf)
	assert.False(t, ok)
	_, ok = pickOneByID(list, "missing", idOf)
	assert.False(t, ok)
}

func TestTimeDataMapsZeroToNull(t *testing.T) {
	assert.Nil(t, timeData(time.Time{}).Value)
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	assert.NotNil(t, timeData(ts).Value)
}

func TestUUIDStringsSkipsEmpty(t *testing.T) {
	got := uuidStrings([]v3.SecurityGroup{{ID: "a"}, {}, {ID: "b"}}, func(s v3.SecurityGroup) v3.UUID { return s.ID })
	assert.Equal(t, []string{"a", "b"}, got)
}

func TestSetBool(t *testing.T) {
	var f plugin.TValue[bool]
	setBool(&f, nil)
	assert.True(t, f.IsNull())
	yes := true
	setBool(&f, &yes)
	assert.False(t, f.IsNull())
	assert.True(t, f.Data)
}

func TestMergeZoneResults(t *testing.T) {
	denied := classifyError(apiError(t, 403, `{"message":"denied"}`), "list-instances")
	down := classifyError(apiError(t, 503, `{"message":"down"}`), "list-instances")
	zones := []string{"ch-gva-2", "de-fra-1"}

	// One zone refuses: the other zone's items survive.
	got, err := mergeZoneResults(zones, [][]string{nil, {"a", "b"}}, []error{denied, nil}, "list-instances")
	require.NoError(t, err)
	assert.Equal(t, []zoned[string]{{"de-fra-1", "a"}, {"de-fra-1", "b"}}, got)

	// Every zone refuses: the refusal is the answer, not an empty list.
	_, err = mergeZoneResults(zones, [][]string{nil, nil}, []error{denied, denied}, "list-instances")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))

	// A zone that answers with nothing is a genuine empty list.
	got, err = mergeZoneResults(zones, [][]string{nil, {}}, []error{denied, nil}, "list-instances")
	require.NoError(t, err)
	assert.Empty(t, got)

	// Any non-refusal failure fails the whole list.
	_, err = mergeZoneResults(zones, [][]string{{"a"}, nil}, []error{nil, down}, "list-instances")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
}

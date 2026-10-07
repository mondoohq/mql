// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// sdkError gets a genuine IBM SDK error by having a real VPC client call a
// fake endpoint that answers with status, so the classifier is tested against
// the error shape the SDK really produces.
func sdkError(t *testing.T, status int) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"errors":[{"code":"x","message":"refused"}]}`))
	}))
	t.Cleanup(srv.Close)
	client, err := vpcv1.NewVpcV1(&vpcv1.VpcV1Options{Authenticator: &core.NoAuthAuthenticator{}, URL: srv.URL})
	require.NoError(t, err)
	_, _, err = client.ListVpcs(&vpcv1.ListVpcsOptions{})
	require.Error(t, err)
	return err
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		status int
		kind   llx.ErrorKind
	}{
		{http.StatusUnauthorized, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{http.StatusForbidden, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{http.StatusNotFound, llx.ErrorKind_ERROR_KIND_NOT_FOUND},
		{http.StatusGone, llx.ErrorKind_ERROR_KIND_GONE},
		{http.StatusTooManyRequests, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{http.StatusServiceUnavailable, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{http.StatusBadRequest, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.kind, llx.KindOf(classifyError(sdkError(t, tt.status), "is.vpc.vpc.list")))
		})
	}
}

func TestClassifyErrorDetails(t *testing.T) {
	var e *llx.Error
	require.True(t, errors.As(classifyError(sdkError(t, http.StatusForbidden), "is.vpc.vpc.list"), &e))
	assert.Equal(t, []string{"is.vpc.vpc.list"}, e.Permissions)

	require.True(t, errors.As(classifyError(sdkError(t, http.StatusUnauthorized), ""), &e))
	assert.Equal(t, llx.ErrorScope_ERROR_SCOPE_ASSET, e.Scope)

	transport := errors.New("dial tcp: connection refused")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyError(transport, "")))
	assert.Nil(t, classifyError(nil, ""))
}

func TestMergeRegionResults(t *testing.T) {
	denied := classifyError(sdkError(t, http.StatusForbidden), "is.vpc.vpc.list")
	down := classifyError(sdkError(t, http.StatusServiceUnavailable), "is.vpc.vpc.list")
	regions := []string{"us-south", "eu-de"}

	got, err := mergeRegionResults(regions, [][]string{nil, {"a"}}, []error{denied, nil}, "p")
	require.NoError(t, err)
	assert.Equal(t, []regional[string]{{"eu-de", "a"}}, got)

	// Every region refuses: the refusal is the answer, not an empty list.
	_, err = mergeRegionResults(regions, [][]string{nil, nil}, []error{denied, denied}, "p")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))

	got, err = mergeRegionResults(regions, [][]string{{}, {}}, []error{nil, nil}, "p")
	require.NoError(t, err)
	assert.Empty(t, got)

	_, err = mergeRegionResults(regions, [][]string{{"a"}, nil}, []error{nil, down}, "p")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
}

func TestNotSet(t *testing.T) {
	s := func(v string) *string { return &v }
	assert.Nil(t, notSet(nil).Value)
	assert.Nil(t, notSet(s("NOT_SET")).Value)
	assert.Nil(t, notSet(s("")).Value)
	assert.Equal(t, "TOTP", notSet(s("TOTP")).Value)

	assert.Nil(t, notSetInt(s("NOT_SET")).Value)
	assert.Nil(t, notSetInt(s("abc")).Value)
	assert.Equal(t, int64(3600), notSetInt(s("3600")).Value)
}

func TestSplitListAndCrnService(t *testing.T) {
	s := " 10.0.0.0/8, ,192.0.2.1 "
	assert.Equal(t, []string{"10.0.0.0/8", "192.0.2.1"}, splitList(&s))
	assert.Nil(t, splitList(nil))
	assert.Equal(t, "power-iaas", crnService("crn:v1:bluemix:public:power-iaas:wdc06:a/acc:guid::"))
	assert.Equal(t, "", crnService("not-a-crn"))
}

func TestRfc3339Data(t *testing.T) {
	s := func(v string) *string { return &v }
	assert.Nil(t, rfc3339Data(nil).Value)
	assert.Nil(t, rfc3339Data(s("")).Value)
	assert.Nil(t, rfc3339Data(s("garbage")).Value)
	assert.NotNil(t, rfc3339Data(s("2026-10-07T08:44:00Z")).Value)
}

func TestPickByID(t *testing.T) {
	type item struct{ id string }
	a, b := &item{"a"}, &item{"b"}
	list := []any{a, b}
	idOf := func(i *item) string { return i.id }
	assert.Equal(t, []any{b, a}, pickByID(list, []string{"b", "missing", "a"}, idOf))
	assert.Equal(t, []any{}, pickByID(list, nil, idOf))
	got, ok := pickOneByID(list, "a", idOf)
	assert.True(t, ok)
	assert.Same(t, a, got)
	_, ok = pickOneByID(list, "", idOf)
	assert.False(t, ok)
}

func TestStringArg(t *testing.T) {
	// A bare ibm.power.workspace passes no arguments; reading one must not panic.
	assert.Equal(t, "", stringArg(map[string]*llx.RawData{}, "crn"))
	assert.Equal(t, "", stringArg(map[string]*llx.RawData{"crn": nil}, "crn"))
	assert.Equal(t, "", stringArg(map[string]*llx.RawData{"crn": llx.IntData(1)}, "crn"))
	assert.Equal(t, "crn:x", stringArg(map[string]*llx.RawData{"crn": llx.StringData("crn:x")}, "crn"))
}

func TestAdvances(t *testing.T) {
	a, b := "a", "b"
	assert.True(t, advances(nil, &a), "the first page's cursor advances")
	assert.True(t, advances(&a, &b))
	assert.False(t, advances(&a, &a), "an unchanged cursor would loop forever")
	assert.False(t, advances(&a, nil), "no cursor is the last page")
}

func TestCrnSegment(t *testing.T) {
	crn := "crn:v1:bluemix:public:cloud-object-storage:global:a/acc:guid:bucket:logs"
	assert.Equal(t, "cloud-object-storage", crnSegment(crn, 4))
	assert.Equal(t, "guid", crnSegment(crn, 7))
	assert.Equal(t, "bucket", crnSegment(crn, 8))
	assert.Equal(t, "", crnSegment(crn, 12))
}

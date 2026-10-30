// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRoundTripper answers every request with one canned response, or with a
// transport error when transportErr is set.
type stubRoundTripper struct {
	status       int
	body         string
	transportErr error
}

func (rt stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.transportErr != nil {
		return nil, rt.transportErr
	}
	return &http.Response{
		StatusCode: rt.status,
		Status:     http.StatusText(rt.status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(rt.body)),
		Request:    req,
	}, nil
}

// oktaCall runs one real SDK call against a stubbed transport and hands back
// exactly what a resource accessor would see. The error classifiers read the
// SDK's own error type and the body it carries, so building those by hand would
// test a mock rather than the thing the provider actually receives.
func oktaCall(t *testing.T, rt http.RoundTripper) (*okta.APIResponse, error) {
	t.Helper()
	cfg, err := okta.NewConfiguration(
		okta.WithOrgUrl("https://test.okta.com"),
		okta.WithToken("test-token"),
		okta.WithHttpClientPtr(&http.Client{Transport: rt}),
	)
	require.NoError(t, err)

	_, resp, err := okta.NewAPIClient(cfg).UserAPI.ListUsers(context.Background()).Execute()
	return resp, err
}

// Okta reuses 401 for two unrelated conditions and only the body tells them
// apart: E0000015 is a feature the org is not licensed for (realms, group
// owners) and there is genuinely nothing to report, while E0000011 is a dead
// token. Degrading the latter would turn an unusable credential into a clean,
// empty scan.
const (
	oktaFeatureNotEnabledBody = `{"errorCode":"E0000015","errorSummary":"You do not have permission to access the feature you are requesting","errorLink":"E0000015","errorId":"oaeX","errorCauses":[]}`
	oktaInvalidTokenBody      = `{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011","errorId":"oaeY","errorCauses":[]}`
)

func TestOktaErrorCode(t *testing.T) {
	t.Parallel()

	t.Run("reads the code from a feature-gated 401", func(t *testing.T) {
		_, err := oktaCall(t, stubRoundTripper{status: http.StatusUnauthorized, body: oktaFeatureNotEnabledBody})
		require.Error(t, err)
		assert.Equal(t, "E0000015", oktaErrorCode(err))
	})

	t.Run("reads the code from an invalid-token 401", func(t *testing.T) {
		_, err := oktaCall(t, stubRoundTripper{status: http.StatusUnauthorized, body: oktaInvalidTokenBody})
		require.Error(t, err)
		assert.Equal(t, "E0000011", oktaErrorCode(err))
	})

	t.Run("empty for a body that is not an Okta error", func(t *testing.T) {
		_, err := oktaCall(t, stubRoundTripper{status: http.StatusBadGateway, body: `<html>gateway</html>`})
		require.Error(t, err)
		assert.Equal(t, "", oktaErrorCode(err))
	})

	t.Run("empty for a non-API error", func(t *testing.T) {
		assert.Equal(t, "", oktaErrorCode(errors.New("boom")))
		assert.Equal(t, "", oktaErrorCode(nil))
	})
}

// TestIsOktaFeatureUnavailableLicensing pins the 401 split. Without it, `okta.realms`
// and `okta.group.owners` fail the whole collection they belong to on any org
// that is not licensed for those features.
func TestIsOktaFeatureUnavailableLicensing(t *testing.T) {
	t.Parallel()

	t.Run("feature not licensed is an empty result", func(t *testing.T) {
		resp, err := oktaCall(t, stubRoundTripper{status: http.StatusUnauthorized, body: oktaFeatureNotEnabledBody})
		require.Error(t, err)
		assert.True(t, isOktaFeatureUnavailable(resp, err))
	})

	t.Run("invalid token stays an error", func(t *testing.T) {
		resp, err := oktaCall(t, stubRoundTripper{status: http.StatusUnauthorized, body: oktaInvalidTokenBody})
		require.Error(t, err)
		assert.False(t, isOktaFeatureUnavailable(resp, err),
			"a dead token must not be reported as an org with nothing configured")
	})

	t.Run("unlabelled 401 stays an error", func(t *testing.T) {
		resp, err := oktaCall(t, stubRoundTripper{status: http.StatusUnauthorized, body: `{}`})
		require.Error(t, err)
		assert.False(t, isOktaFeatureUnavailable(resp, err))
	})
}

// TestIsOktaFeatureUnavailableSurvivesMissingResponse is the regression for a
// provider panic. When a request never produces a response -- a transport error,
// or a rate-limit retry that ran out of attempts -- the generated SDK still
// returns a non-nil *APIResponse, built around a nil *http.Response. StatusCode
// is a promoted field, so reading it in that state dereferences the nil embed.
// The helper is called from roughly twenty listers, so this panicked whichever
// collection happened to hit the network problem.
func TestIsOktaFeatureUnavailableSurvivesMissingResponse(t *testing.T) {
	t.Parallel()

	t.Run("hand-built response with a nil embed", func(t *testing.T) {
		resp := &okta.APIResponse{}
		require.Nil(t, resp.Response, "guarding the case where the SDK wrapped no response")
		assert.NotPanics(t, func() {
			assert.False(t, isOktaFeatureUnavailable(resp, assert.AnError))
		})
		assert.NotPanics(t, func() {
			assert.False(t, isOktaNotFound(resp))
		})
	})

	t.Run("real transport failure through the SDK", func(t *testing.T) {
		resp, err := oktaCall(t, stubRoundTripper{transportErr: errors.New("connection reset by peer")})
		require.Error(t, err)
		assert.NotPanics(t, func() {
			isOktaFeatureUnavailable(resp, err)
		}, "a network failure must surface as an error, not a panic")
	})
}

// `/apps/{id}/tokens` answers 400 for an application that is not an OAuth 2.0
// client, which is the only meaning a 400 can carry there -- the request sends
// no caller-supplied input beyond the app id. Reading it as "no tokens" is what
// stops one bookmark app from failing every application in the query.
func TestIsOktaStatus(t *testing.T) {
	t.Parallel()

	badRequest := &okta.APIResponse{Response: &http.Response{StatusCode: http.StatusBadRequest}}
	assert.True(t, isOktaStatus(badRequest, http.StatusBadRequest))
	assert.False(t, isOktaStatus(badRequest, http.StatusNotFound))
	assert.False(t, isOktaStatus(&okta.APIResponse{}, http.StatusBadRequest),
		"a response-less APIResponse must not match any status")
	assert.False(t, isOktaStatus(nil, http.StatusBadRequest))
}

func TestIsOktaNotFound(t *testing.T) {
	t.Parallel()

	assert.True(t, isOktaNotFound(&okta.APIResponse{Response: &http.Response{StatusCode: http.StatusNotFound}}))
	assert.False(t, isOktaNotFound(&okta.APIResponse{Response: &http.Response{StatusCode: http.StatusForbidden}}))
	assert.False(t, isOktaNotFound(&okta.APIResponse{Response: &http.Response{StatusCode: http.StatusOK}}))
	assert.False(t, isOktaNotFound(&okta.APIResponse{}))
	assert.False(t, isOktaNotFound(nil))
}

// TestErrOktaResourceNotFoundIsIdentifiable proves the sentinel survives the
// wrapping the inits apply, which is what lets a reference accessor tell "this
// principal does not exist" apart from a real failure and report null.
func TestErrOktaResourceNotFoundIsIdentifiable(t *testing.T) {
	t.Parallel()

	wrapped := errors.New("okta.user \"00u1\" not found: " + errOktaResourceNotFound.Error())
	assert.False(t, errors.Is(wrapped, errOktaResourceNotFound),
		"a string that merely mentions the sentinel must not match")

	assert.True(t, errors.Is(
		fmt.Errorf("%w: okta.user %q", errOktaResourceNotFound, "00u1"),
		errOktaResourceNotFound))
}

// TestNotFoundWrappingIsPairedWithAGuard keeps the two halves of the
// null-on-missing behavior in step. A resolver's errors.Is guard is dead code
// unless the init behind it wraps the sentinel, and an init that wraps without
// a guard downstream just renames the failure -- either half alone reads as
// fixed while the collection still fails. Both directions are checked by
// source, because the behavior only shows up against a live org.
func TestNotFoundWrappingIsPairedWithAGuard(t *testing.T) {
	t.Parallel()

	// resource -> (init that must wrap, file holding the accessor that must guard)
	pairs := []struct{ resource, initFile, guardFile string }{
		{"okta.user", "users.go", "resourceSets.go"},
		{"okta.group", "groups.go", "resourceSets.go"},
		{"okta.application", "applications.go", "resourceSets.go"},
		{"okta.customRole", "customRoles.go", "resourceSets.go"},
		{"okta.resourceSet", "resourceSets.go", "roles.go"},
	}

	for _, p := range pairs {
		t.Run(p.resource, func(t *testing.T) {
			initSrc, err := os.ReadFile(p.initFile)
			require.NoError(t, err)
			assert.Contains(t, string(initSrc), "errOktaResourceNotFound",
				"%s must wrap a 404 from its init in the sentinel, or the guard in %s never fires",
				p.initFile, p.guardFile)

			guardSrc, err := os.ReadFile(p.guardFile)
			require.NoError(t, err)
			assert.Contains(t, string(guardSrc), "errors.Is(err, errOktaResourceNotFound)",
				"%s must report a missing %s as null rather than failing the collection",
				p.guardFile, p.resource)
		})
	}
}

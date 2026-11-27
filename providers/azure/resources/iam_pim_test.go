// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// pimResponseError builds the error azcore returns for an ARM response, so
// the error code is parsed from the body exactly as in a scan.
func pimResponseError(t *testing.T, status int, body string) error {
	req, err := http.NewRequest(http.MethodGet, "https://management.azure.com/subscriptions/s/providers/Microsoft.Authorization/roleEligibilitySchedules", nil)
	require.NoError(t, err)
	return azruntime.NewResponseError(&http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	})
}

// Measured: ARM roleEligibilitySchedules and roleAssignmentSchedules on a
// subscription whose tenant has no Entra ID P2, 2026-11-19.
const pimLicenseRequiredBody = `{"error":{"code":"AadPremiumLicenseRequired","message":"The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license."}}`

func TestClassifyPimFailure(t *testing.T) {
	const perm = "Microsoft.Authorization/roleEligibilitySchedules/read"

	license := pimResponseError(t, http.StatusBadRequest, pimLicenseRequiredBody)
	assert.ErrorIs(t, classifyPimFailure(license, perm), llx.ErrNotApplicable)

	// Synthetic: the 401 and 403 bodies; no target refused these reads.
	unauth := pimResponseError(t, http.StatusUnauthorized, `{"error":{"code":"InvalidAuthenticationToken","message":"expired"}}`)
	assert.ErrorIs(t, classifyPimFailure(unauth, perm), llx.ErrUnauthenticated)

	denied := pimResponseError(t, http.StatusForbidden, `{"error":{"code":"AuthorizationFailed","message":"no access"}}`)
	forbidden := classifyPimFailure(denied, perm)
	assert.ErrorIs(t, forbidden, llx.ErrForbidden)
	var lerr *llx.Error
	require.True(t, errors.As(forbidden, &lerr))
	assert.Equal(t, []string{perm}, lerr.Permissions)

	// Synthetic: a 400 for another reason and a 404 stay unclassified.
	other := pimResponseError(t, http.StatusBadRequest, `{"error":{"code":"InvalidFilter","message":"bad filter"}}`)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyPimFailure(other, perm)))
	missing := pimResponseError(t, http.StatusNotFound, `{"error":{"code":"NotFound","message":"missing"}}`)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyPimFailure(missing, perm)))
}

func TestPimListFailure(t *testing.T) {
	const perm = "Microsoft.Authorization/roleAssignmentSchedules/read"
	partial := []any{"first-page-entry"}
	license := pimResponseError(t, http.StatusBadRequest, pimLicenseRequiredBody)
	// Synthetic: a refused read.
	denied := pimResponseError(t, http.StatusForbidden, `{"error":{"code":"AuthorizationFailed","message":"no access"}}`)
	// Synthetic: throttling is not an absence of PIM data.
	throttled := pimResponseError(t, http.StatusTooManyRequests, `{"error":{"code":"TooManyRequests","message":"slow down"}}`)

	t.Run("v13 behavior keeps what was read", func(t *testing.T) {
		setStructuredErrors(t, false)
		got, err := pimListFailure("s", partial, license, perm)
		require.NoError(t, err)
		assert.Equal(t, partial, got)

		got, err = pimListFailure("s", partial, denied, perm)
		require.NoError(t, err)
		assert.Equal(t, partial, got)

		_, err = pimListFailure("s", partial, throttled, perm)
		assert.Error(t, err)
	})

	t.Run("structured errors report the refusal", func(t *testing.T) {
		setStructuredErrors(t, true)
		got, err := pimListFailure("s", partial, license, perm)
		assert.Nil(t, got)
		assert.ErrorIs(t, err, llx.ErrNotApplicable)

		got, err = pimListFailure("s", partial, denied, perm)
		assert.Nil(t, got)
		assert.ErrorIs(t, err, llx.ErrForbidden)

		_, err = pimListFailure("s", partial, throttled, perm)
		assert.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	})
}

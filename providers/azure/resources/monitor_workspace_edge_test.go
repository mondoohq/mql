// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A diagnostic setting can name a Log Analytics workspace or storage account
// that has since been deleted; live subscriptions do carry these. That must
// read as an unreadable destination (null, with workspaceId or
// storageAccountId still set) rather than take the row down,
// and a genuinely broken read must not be laundered into the same answer.
func TestDiagnosticDestinationUnreadable(t *testing.T) {
	deleted := armError(http.StatusNotFound, `{"error":{"code":"ResourceGroupNotFound","message":"Resource group could not be found."}}`)
	assert.True(t, diagnosticDestinationUnreadable(deleted))

	invisible := armError(http.StatusForbidden, `{"error":{"code":"AuthorizationFailed","message":"does not have authorization"}}`)
	assert.True(t, diagnosticDestinationUnreadable(invisible))

	// A broken read is not a dangling reference.
	serverError := armError(http.StatusInternalServerError, `{"error":{"code":"InternalServerError","message":"boom"}}`)
	assert.False(t, diagnosticDestinationUnreadable(serverError))

	throttled := armError(http.StatusTooManyRequests, `{"error":{"code":"TooManyRequests","message":"slow down"}}`)
	assert.False(t, diagnosticDestinationUnreadable(throttled))

	transport := errors.New("dial tcp: i/o timeout")
	assert.False(t, diagnosticDestinationUnreadable(transport))
}

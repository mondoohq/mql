// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A diagnostic setting can name a Log Analytics workspace that has since been
// deleted; live subscriptions do carry these. That must read as an unreadable
// destination (null, with workspaceId still set) rather than take the row down,
// and a genuinely broken read must not be laundered into the same answer.
func TestDiagnosticWorkspaceUnreadable(t *testing.T) {
	deleted := armError(http.StatusNotFound, `{"error":{"code":"ResourceGroupNotFound","message":"Resource group could not be found."}}`)
	assert.True(t, diagnosticWorkspaceUnreadable(deleted))

	invisible := armError(http.StatusForbidden, `{"error":{"code":"AuthorizationFailed","message":"does not have authorization"}}`)
	assert.True(t, diagnosticWorkspaceUnreadable(invisible))

	// A broken read is not a dangling reference.
	serverError := armError(http.StatusInternalServerError, `{"error":{"code":"InternalServerError","message":"boom"}}`)
	assert.False(t, diagnosticWorkspaceUnreadable(serverError))

	throttled := armError(http.StatusTooManyRequests, `{"error":{"code":"TooManyRequests","message":"slow down"}}`)
	assert.False(t, diagnosticWorkspaceUnreadable(throttled))

	transport := errors.New("dial tcp: i/o timeout")
	assert.False(t, diagnosticWorkspaceUnreadable(transport))
}

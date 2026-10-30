// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

func TestClassifyForbiddenMarksA403(t *testing.T) {
	cause := &connection.APIError{Status: 403, Path: "/x"}
	err := classifyForbidden(cause)
	assert.ErrorIs(t, err, llx.ErrForbidden)
	var apiErr *connection.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, 403, apiErr.Status)
}

func TestClassifyForbiddenKeepsEveryOtherError(t *testing.T) {
	assert.NoError(t, classifyForbidden(nil))
	for name, cause := range map[string]error{
		"a rejected credential": &connection.APIError{Status: 401, Path: "/x"},
		"a missing route":       &connection.APIError{Status: 404, Path: "/x"},
		"a transport error":     errors.New("connection reset"),
	} {
		err := classifyForbidden(cause)
		assert.ErrorIs(t, err, cause, name)
		assert.NotErrorIs(t, err, llx.ErrForbidden, name)
	}
}

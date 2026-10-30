// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Strict mode's errors have to be tellable from ordinary ones: a caller that
// wants to add "did you mean `?`" must be able to ask, rather than matching on
// message text.
func TestErrStrict(t *testing.T) {
	nullBinding := &errNullBinding{field: "params"}
	missingKey := &errMissingKey{key: "PermitRootLogin"}

	assert.ErrorIs(t, nullBinding, ErrStrict)
	assert.ErrorIs(t, missingKey, ErrStrict)

	// still readable on its own
	assert.Contains(t, nullBinding.Error(), "params")
	assert.Contains(t, missingKey.Error(), "PermitRootLogin")

	// and does not swallow unrelated failures
	assert.NotErrorIs(t, errors.New("connection refused"), ErrStrict)
	assert.NotErrorIs(t, nullBinding, errors.New("some other error"))

	// survives wrapping, which is how it reaches a reporter
	assert.ErrorIs(t, fmt.Errorf("failed to run query: %w", missingKey), ErrStrict)
}

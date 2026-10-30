// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package multierr_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/utils/multierr"
)

func TestMultiErr(t *testing.T) {
	t.Run("add nil errors", func(t *testing.T) {
		var e multierr.Errors
		e.Add(nil)
		e.Add(nil, nil, nil)
		assert.Nil(t, e.Deduplicate())
	})

	t.Run("add mixed errors", func(t *testing.T) {
		var e multierr.Errors
		e.Add(errors.New("1"), nil, errors.New("1"))
		var b multierr.Errors
		b.Add(errors.New("1"))
		assert.Equal(t, b.Deduplicate(), e.Deduplicate())
	})

	t.Run("test nil error deduplicate", func(t *testing.T) {
		var e multierr.Errors
		err := e.Deduplicate()
		assert.Nil(t, err)
	})

	// Deduplicate must preserve first-occurrence order: callers render the
	// result into user-visible strings, and a map-ordered rebuild made the
	// same errors produce differently-ordered messages on every run. With
	// three distinct errors an order regression flips the rendered string
	// with probability 5/6 per attempt, so 50 identical runs fail loudly.
	t.Run("deduplicate preserves first-occurrence order", func(t *testing.T) {
		build := func() multierr.Errors {
			var e multierr.Errors
			e.Add(
				errors.New("fdesetup list failed"),
				errors.New("fdesetup hasinstitutionalrecoverykey failed"),
				errors.New("fdesetup list failed"),
				errors.New("fdesetup haspersonalrecoverykey failed"),
			)
			return e
		}

		want := "3 errors occurred:\n" +
			"\t* fdesetup list failed\n" +
			"\t* fdesetup hasinstitutionalrecoverykey failed\n" +
			"\t* fdesetup haspersonalrecoverykey failed\n"

		for range 50 {
			assert.Equal(t, want, build().Deduplicate().Error())
		}
	})
}

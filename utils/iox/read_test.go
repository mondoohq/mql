// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package iox

import (
	"errors"
	"math"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

func TestReadAllLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		limit int64
		want  string
		fail  bool
	}{
		{"empty", "", 0, "", false}, {"at limit", "abcd", 4, "abcd", false},
		{"over limit", "abcde", 4, "", true}, {"invalid limit", "a", -1, "", true},
		{"overflowing limit", "a", math.MaxInt64, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := ReadAllLimit(strings.NewReader(tc.input), tc.limit)
			if tc.fail {
				require.Error(t, err)
				require.Nil(t, b)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, string(b))
			}
		})
	}
	sentinel := errors.New("read failed")
	b, err := ReadAllLimit(iotest.ErrReader(sentinel), 10)
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, b)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/jomei/notionapi"
	"github.com/stretchr/testify/assert"
)

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "notion 401",
			err:  &notionapi.Error{Status: http.StatusUnauthorized, Code: "unauthorized"},
			want: true,
		},
		{
			// The reason this uses errors.As rather than a type assertion: a
			// wrapped 401 must still produce the actionable message.
			name: "wrapped notion 401",
			err:  fmt.Errorf("verifying credentials: %w", &notionapi.Error{Status: http.StatusUnauthorized, Code: "unauthorized"}),
			want: true,
		},
		{
			name: "doubly wrapped notion 401",
			err:  errors.Wrap(fmt.Errorf("transport: %w", &notionapi.Error{Status: http.StatusUnauthorized}), "verifying credentials"),
			want: true,
		},
		{
			name: "notion 403 is a real refusal, not a bad token",
			err:  &notionapi.Error{Status: http.StatusForbidden, Code: "restricted_resource"},
			want: false,
		},
		{
			name: "notion 429 is rate limiting",
			err:  &notionapi.Error{Status: http.StatusTooManyRequests},
			want: false,
		},
		{
			name: "a transport error is not an auth failure",
			err:  errors.New("dial tcp: connection refused"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isUnauthorized(test.err))
		})
	}
}

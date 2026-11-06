// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestIsPublicMember(t *testing.T) {
	cases := map[string]bool{
		"allUsers":               true,
		"allAuthenticatedUsers":  true,
		"user:alice@example.com": false,
		"serviceAccount:sa@p.iam.gserviceaccount.com": false,
		"":         false,
		"AllUsers": false, // case-sensitive
	}
	for in, want := range cases {
		if got := isPublicMember(in); got != want {
			t.Errorf("isPublicMember(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPublicFromIamPolicy(t *testing.T) {
	publicBinding := &mqlGcpResourcemanagerBinding{
		Members: plugin.TValue[[]any]{Data: []any{"user:a@example.com", "allUsers"}, State: plugin.StateIsSet},
	}

	// Synthetic: a refused GetIamPolicy reads as a null policy, so public is
	// null, not false.
	var field plugin.TValue[bool]
	got, err := publicFromIamPolicy(&field, &plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull})
	assert.NoError(t, err)
	assert.False(t, got)
	assert.True(t, field.IsNull())

	// Synthetic: an empty policy is an answer: not public.
	field = plugin.TValue[bool]{}
	got, err = publicFromIamPolicy(&field, &plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet})
	assert.NoError(t, err)
	assert.False(t, got)
	assert.False(t, field.IsNull())

	// Synthetic: a binding to allUsers.
	got, err = publicFromIamPolicy(&field, &plugin.TValue[[]any]{Data: []any{publicBinding}, State: plugin.StateIsSet})
	assert.NoError(t, err)
	assert.True(t, got)

	// Synthetic: the policy read failed with an error, which propagates.
	boom := errors.New("unavailable")
	_, err = publicFromIamPolicy(&field, &plugin.TValue[[]any]{Error: boom, State: plugin.StateIsSet})
	assert.Equal(t, boom, err)
}

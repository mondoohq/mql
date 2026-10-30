// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func httpResponse(status int) *http.Response {
	return &http.Response{StatusCode: status}
}

// A custom role takes its scope from the resource set it is bound to, not from
// a target list, and Okta rejects the target endpoints for one with a 400. Any
// org that has bound a custom role to an admin therefore failed the entire
// `okta.users`/`okta.groups` collection the assignment was read from, because
// one 400 poisons the whole query.
func TestIsCustomRoleAssignment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		roleType plugin.TValue[string]
		want     bool
	}{
		{
			name:     "custom role",
			roleType: plugin.TValue[string]{Data: "CUSTOM", State: plugin.StateIsSet},
			want:     true,
		},
		{
			name:     "standard role keeps its target lookup",
			roleType: plugin.TValue[string]{Data: "USER_ADMIN", State: plugin.StateIsSet},
			want:     false,
		},
		{
			name:     "app admin keeps its target lookup",
			roleType: plugin.TValue[string]{Data: "APP_ADMIN", State: plugin.StateIsSet},
			want:     false,
		},
		{
			name:     "unset type is not assumed custom",
			roleType: plugin.TValue[string]{},
			want:     false,
		},
		{
			name:     "errored type is not assumed custom",
			roleType: plugin.TValue[string]{Data: "CUSTOM", Error: errors.New("boom")},
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			role := &mqlOktaRole{Type: tc.roleType}
			assert.Equal(t, tc.want, role.isCustomRoleAssignment())
		})
	}
}

// TestIsOktaRawFeatureUnavailable covers the raw-HTTP twin of the classifier,
// used by the endpoints the generated SDK cannot serve.
func TestIsOktaRawFeatureUnavailable(t *testing.T) {
	t.Parallel()

	assert.False(t, isOktaRawFeatureUnavailable(nil, nil))
	assert.True(t, isOktaRawFeatureUnavailable(httpResponse(404), nil))
	assert.True(t, isOktaRawFeatureUnavailable(httpResponse(403), nil))
	assert.True(t, isOktaRawFeatureUnavailable(httpResponse(410), nil))
	assert.False(t, isOktaRawFeatureUnavailable(httpResponse(200), nil))
	assert.False(t, isOktaRawFeatureUnavailable(httpResponse(500), nil))
	assert.False(t, isOktaRawFeatureUnavailable(httpResponse(429), nil))
}

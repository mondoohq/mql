// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestSecurityTxt(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/security-center/securitytxt", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, `{"success":true,"result":{
			"enabled":true,
			"contact":["mailto:security@example.com","https://example.com/report"],
			"expires":"2027-01-01T00:00:00Z",
			"encryption":["https://example.com/pgp-key.txt"],
			"acknowledgments":["https://example.com/hall-of-fame"],
			"canonical":["https://example.com/.well-known/security.txt"],
			"policy":["https://example.com/disclosure-policy"],
			"hiring":["https://example.com/jobs"],
			"preferred_languages":"en, es"
		}}`)
	})

	txt, err := zone.securityTxt()
	require.NoError(t, err)
	require.NotNil(t, txt)

	assert.True(t, txt.Enabled.Data)
	assert.Equal(t, []any{"mailto:security@example.com", "https://example.com/report"}, txt.Contact.Data)
	assert.Equal(t, []any{"https://example.com/pgp-key.txt"}, txt.Encryption.Data)
	assert.Equal(t, []any{"https://example.com/hall-of-fame"}, txt.Acknowledgments.Data)
	assert.Equal(t, []any{"https://example.com/.well-known/security.txt"}, txt.Canonical.Data)
	assert.Equal(t, []any{"https://example.com/disclosure-policy"}, txt.Policy.Data)
	assert.Equal(t, []any{"https://example.com/jobs"}, txt.Hiring.Data)
	assert.Equal(t, "en, es", txt.PreferredLanguages.Data)

	require.NotNil(t, txt.Expires.Data)
	assert.Equal(t, 2027, txt.Expires.Data.Year())
}

// A zone that publishes no security.txt still answers, so `enabled` must read
// false with empty lists rather than erroring.
func TestSecurityTxtNotPublished(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/security-center/securitytxt", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":{"enabled":false}}`)
	})

	txt, err := zone.securityTxt()
	require.NoError(t, err)
	require.NotNil(t, txt)
	assert.False(t, txt.Enabled.Data)
	assert.Empty(t, txt.Contact.Data)
	assert.Nil(t, txt.Expires.Data, "an absent expiry must be null, not the zero time")
}

func TestSecurityTxtUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/security-center/securitytxt", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
	})

	txt, err := zone.securityTxt()
	require.NoError(t, err)
	assert.Nil(t, txt)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, zone.SecurityTxt.State)
}

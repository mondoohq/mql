// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContactPointTLSSkipVerify(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{"nil settings", nil, false},
		{"empty settings", map[string]any{}, false},
		{
			"flat tlsConfig skip",
			map[string]any{"tlsConfig": map[string]any{"insecureSkipVerify": true}},
			true,
		},
		{
			"flat tlsConfig no skip",
			map[string]any{"tlsConfig": map[string]any{"insecureSkipVerify": false}},
			false,
		},
		{
			"nested httpConfig.tlsConfig skip",
			map[string]any{"httpConfig": map[string]any{"tlsConfig": map[string]any{"insecureSkipVerify": true}}},
			true,
		},
		{
			// insecureSkipVerify carried as a string must not be read as a bool.
			"non-bool insecureSkipVerify ignored",
			map[string]any{"tlsConfig": map[string]any{"insecureSkipVerify": "true"}},
			false,
		},
		{
			// tlsConfig present but the wrong shape must not panic.
			"tlsConfig wrong type",
			map[string]any{"tlsConfig": "oops"},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, contactPointTLSSkipVerify(tt.settings))
		})
	}
}

func TestContactPointHasHTTPAuth(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{"nil settings", nil, false},
		{"empty settings", map[string]any{}, false},
		{"top-level username", map[string]any{"username": "alice"}, true},
		{"authorizationCredentials", map[string]any{"authorizationCredentials": "xxx"}, true},
		{"nested basicAuth", map[string]any{"httpConfig": map[string]any{"basicAuth": map[string]any{"user": "a"}}}, true},
		{"nested bearerToken", map[string]any{"httpConfig": map[string]any{"bearerToken": "t"}}, true},
		{"nested authorization", map[string]any{"httpConfig": map[string]any{"authorization": map[string]any{}}}, true},
		{"httpConfig wrong type", map[string]any{"httpConfig": "oops"}, false},
		{"no auth keys", map[string]any{"url": "https://x", "httpConfig": map[string]any{"proxyUrl": "p"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, contactPointHasHTTPAuth(tt.settings))
		})
	}
}

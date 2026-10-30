// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDatasourceTLSClientAuth(t *testing.T) {
	tests := []struct {
		name         string
		jsonData     map[string]any
		secureFields []any
		want         bool
	}{
		{"nothing configured", nil, nil, false},
		{"tlsAuth bool", map[string]any{"tlsAuth": true}, nil, true},
		{"tlsAuth string", map[string]any{"tlsAuth": "true"}, nil, true},
		{"tlsAuth false", map[string]any{"tlsAuth": false}, nil, false},
		{"tlsClientCert secret present", nil, []any{"tlsClientCert"}, true},
		{"tlsClientKey secret present", nil, []any{"httpHeaderValue1", "tlsClientKey"}, true},
		{"unrelated secret only", nil, []any{"basicAuthPassword"}, false},
		// A non-string element in secureFields must not panic.
		{"non-string secure field", nil, []any{42, "tlsClientCert"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, datasourceTLSClientAuth(tt.jsonData, tt.secureFields))
		})
	}
}

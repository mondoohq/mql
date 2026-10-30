// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParamIndicatesTLS(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"require_secure_transport", "ON", true},
		{"require_secure_transport", "1", true},
		{"require_secure_transport", "OFF", false},
		{"rds.force_ssl", "1", true},
		{"rds.force_ssl", "0", false},
		// DocumentDB: every allowed value except disabled requires TLS.
		{"tls", "enabled", true},
		{"tls", "tls1.2+", true},
		{"tls", "tls1.3+", true},
		{"tls", "fips-140-3", true},
		{"tls", "disabled", false},
		{"tls", "", false},
		{"audit_logs", "enabled", false},
	} {
		assert.Equal(t, tc.want, paramIndicatesTLS(tc.name, tc.value), "%s=%s", tc.name, tc.value)
	}
}

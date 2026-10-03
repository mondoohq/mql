// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsesLegacySystemID(t *testing.T) {
	// pg_control_system() arrived in 9.6
	assert.True(t, usesLegacySystemID(90224))  // 9.2.24 (RHEL 7)
	assert.True(t, usesLegacySystemID(90526))  // 9.5.26
	assert.False(t, usesLegacySystemID(90600)) // 9.6.0
	assert.False(t, usesLegacySystemID(170004))
}

func TestLegacySystemID(t *testing.T) {
	a := legacySystemID("db.example.internal", "5432")
	assert.True(t, strings.HasPrefix(a, "legacy-"), a)
	assert.Len(t, a, len("legacy-")+32)
	// stable for the same server
	assert.Equal(t, a, legacySystemID("db.example.internal", "5432"))
	// two clusters on one host differ by port
	assert.NotEqual(t, a, legacySystemID("db.example.internal", "5433"))
	// and the same port on another host differs
	assert.NotEqual(t, a, legacySystemID("db2.example.internal", "5432"))
	// the separator keeps host and port from running together
	assert.NotEqual(t, legacySystemID("h1", "5432"), legacySystemID("h15", "432"))
}

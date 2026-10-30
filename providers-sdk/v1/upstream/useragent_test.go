// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserAgent(t *testing.T) {
	assert.True(t, strings.HasPrefix(UserAgent(""), "mql/"))
	assert.NotContains(t, UserAgent(""), "(")
	assert.True(t, strings.HasSuffix(UserAgent("os"), " (provider os)"))
	assert.True(t, strings.HasPrefix(UserAgent("os"), "mql/"))
}

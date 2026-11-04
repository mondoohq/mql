// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePeerIPv6AndCommandSafety(t *testing.T) {
	for _, peer := range []string{"::1", "::ffff:192.0.2.1", "fe80::1%eth0", "swp1", "192.0.2.1"} {
		assert.NoError(t, ValidatePeer(peer), peer)
	}
	for _, peer := range []string{"", "::1;id", "::1$(id)", "::1\nshow version", "::1\"", "::1'", "::1|id"} {
		assert.Error(t, ValidatePeer(peer), peer)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPSJsonTimestamp(t *testing.T) {

	timestamp := PSJsonTimestamp("\\/Date(1599609600000)\\/")
	assert.Equal(t, time.Unix(1599609600, 0).Unix(), timestamp.Unix())

	// the DataContractJsonSerializer form carries the zone the value was local
	// to; ms stays UTC
	timestamp = PSJsonTimestamp("/Date(1767830400000+0100)/")
	if assert.NotNil(t, timestamp) {
		assert.Equal(t, time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC), timestamp.UTC())
	}

	timestamp = PSJsonTimestamp("/Date(-86400000)/")
	if assert.NotNil(t, timestamp) {
		assert.Equal(t, time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC), timestamp.UTC())
	}

	assert.Nil(t, PSJsonTimestamp("20200810000000.000000+000"))
}

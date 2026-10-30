// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestInt64PtrsToInts covers the listen-port slice flattening used to build the
// WAF domain httpPorts/httpsPorts fields (and the derived httpsEnabled signal),
// ensuring nil entries are dropped.
func TestInt64PtrsToInts(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	assert.Equal(t, []any{}, int64PtrsToInts(nil))
	assert.Equal(t, []any{int64(443)}, int64PtrsToInts([]*int64{i64(443), nil}))
	assert.Equal(t, []any{int64(80), int64(8080)}, int64PtrsToInts([]*int64{i64(80), i64(8080)}))
}

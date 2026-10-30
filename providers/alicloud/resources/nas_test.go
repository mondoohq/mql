// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNasEncrypted covers the NAS encrypted-at-rest derivation. EncryptType 0 is
// unencrypted; 1 (service key) and 2 (customer key) are encrypted. A bug here
// would misreport a file system's encryption posture.
func TestNasEncrypted(t *testing.T) {
	i32 := func(v int32) *int32 { return &v }
	assert.False(t, nasEncrypted(nil), "nil EncryptType => not encrypted")
	assert.False(t, nasEncrypted(i32(0)), "0 => not encrypted")
	assert.True(t, nasEncrypted(i32(1)), "1 (service key) => encrypted")
	assert.True(t, nasEncrypted(i32(2)), "2 (KMS customer key) => encrypted")
}

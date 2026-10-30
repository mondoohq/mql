// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCryptoKeyPath(t *testing.T) {
	key := "projects/p/locations/us-central1/keyRings/kr/cryptoKeys/k"
	// The form Compute reports for the key protecting a disk, image or machine image.
	assert.Equal(t, key, cryptoKeyPath(key+"/cryptoKeyVersions/1"))
	assert.Equal(t, key, cryptoKeyPath(key))
	assert.Equal(t, "", cryptoKeyPath(""))
}

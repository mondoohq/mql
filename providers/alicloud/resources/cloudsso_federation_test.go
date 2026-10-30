// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCloudssoStatusEnabled(t *testing.T) {
	assert.True(t, cloudssoStatusEnabled(new("Enabled")))
	assert.True(t, cloudssoStatusEnabled(new("enabled")))
	assert.True(t, cloudssoStatusEnabled(new(" Enabled ")))
	assert.False(t, cloudssoStatusEnabled(new("Disabled")))
	// a status nobody could read must not report a control that may not be in
	// place
	assert.False(t, cloudssoStatusEnabled(nil))
	assert.False(t, cloudssoStatusEnabled(new("")))
}

func TestCloudssoTaskSucceeded(t *testing.T) {
	assert.True(t, cloudssoTaskSucceeded(new("Success")))
	assert.True(t, cloudssoTaskSucceeded(new("success")))
	// a failed revocation leaves the access it was withdrawing still granted
	assert.False(t, cloudssoTaskSucceeded(new("Failed")))
	// a task still running has not withdrawn anything yet either
	assert.False(t, cloudssoTaskSucceeded(new("InProgress")))
	assert.False(t, cloudssoTaskSucceeded(nil))
}

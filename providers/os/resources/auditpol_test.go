// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// A setting that could not be read is null in all three fields, never
// "No Auditing" and false.
func TestAuditpolFlagData(t *testing.T) {
	success, failure, setting := auditpolFlagData(nil)
	assert.Equal(t, llx.NilData, success)
	assert.Equal(t, llx.NilData, failure)
	assert.Equal(t, llx.NilData, setting)

	f := windows.AuditFailure
	success, failure, setting = auditpolFlagData(&f)
	assert.Equal(t, false, success.Value)
	assert.Equal(t, true, failure.Value)
	assert.Equal(t, "Failure", setting.Value)
}

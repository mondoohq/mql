// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"testing"
	"time"
	_ "time/tzdata" // the zones below, also where no Go installation provides them

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The values are Get-ComputerInfo's on a Windows 11 host in Pacific time:
// InstallDate 1769411198 (2026-01-26 07:06:38 UTC, in PST) comes out as
// /Date(1769439998000)/, eight hours later.
func TestInstallDateJSONMatchesGetComputerInfo(t *testing.T) {
	pacific, err := time.LoadLocation("America/Los_Angeles")
	require.NoError(t, err)
	assert.Equal(t, "/Date(1769439998000)/", installDateJSON(1769411198, pacific))

	// a UTC host has no shift
	assert.Equal(t, "/Date(1769411198000)/", installDateJSON(1769411198, time.UTC))

	// the offset is the one at the install date (CEST in summer)
	berlin, err := time.LoadLocation("Europe/Berlin")
	require.NoError(t, err)
	assert.Equal(t, "/Date(1751346000000)/", installDateJSON(1751353200, berlin)) // 2025-07-01 07:00 UTC
}

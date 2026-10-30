// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package uptime_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/uptime"
)

func TestWindowsUptime(t *testing.T) {
	// uptime
	data := `
	{
		"Ticks":  2258270365,
		"Days":  0,
		"Hours":  0,
		"Milliseconds":  827,
		"Minutes":  3,
		"Seconds":  45,
		"TotalDays":  0.0026137388483796296,
		"TotalHours":  0.06272973236111111,
		"TotalMilliseconds":  225827.03650000002,
		"TotalMinutes":  3.763783941666667,
		"TotalSeconds":  225.8270365
	}
	`
	duration, err := uptime.ParseWindowsUptime(data)
	assert.Nil(t, err)
	assert.Equal(t, time.Duration(225827036500), duration)
	assert.Equal(t, "3m45.8270365s", duration.String())
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTimeToDurationString(t *testing.T) {
	const mins = 60
	const hours = 60 * mins
	const days = 24 * hours

	for seconds, want := range map[int64]string{
		0:                           "0 seconds",
		42:                          "42 seconds",
		5*mins + 3:                  "5 minutes 3 seconds",
		4*days + 13*hours + 42*mins: "4 days 13 hours 42 minutes",
		2 * days:                    "2 days",
		-42:                         "-42 seconds",
		-(48*mins + 24):             "-48 minutes -24 seconds",
		// The Baltimore CyberTrust Root expired on 2025-05-12, and its
		// expiresIn read "-48 minutes -24 seconds" 508 days later.
		-(508*days + 48*mins + 24): "-508 days -48 minutes -24 seconds",
		-(3*days + 2*hours):        "-3 days -2 hours",
		-days:                      "-1 days",
	} {
		assert.Equal(t, want, TimeToDurationString(DurationToTime(seconds)), "%d seconds", seconds)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"go.mondoo.com/mql/llx"
)

// graphTimeData converts a Microsoft Graph timestamp into a time value.
// Graph reports a timestamp that was never set as 0001-01-01T00:00:00Z
// instead of omitting it, so a year-1 value is null like an absent one.
func graphTimeData(t *time.Time) *llx.RawData {
	if t == nil || t.Year() <= 1 {
		return llx.NilData
	}
	return llx.TimeDataPtr(t)
}

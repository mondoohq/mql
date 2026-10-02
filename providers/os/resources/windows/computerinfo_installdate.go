// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strconv"
	"time"
)

// installDateJSON renders the registry's InstallDate (seconds since the Unix
// epoch, UTC) as Get-ComputerInfo's JSON has it. Get-ComputerInfo reports a
// DateTime of unspecified kind that holds the UTC clock time, and
// ConvertTo-Json writes an unspecified DateTime as local time, converting it
// to UTC with the host's offset at that date. Its /Date(ms)/ is therefore
// shifted by that offset (0 on a UTC host). The same conversion here keeps the
// native path's value equal to Get-ComputerInfo's on every host; loc is the
// host's time zone.
func installDateJSON(seconds uint64, loc *time.Location) string {
	utc := time.Unix(int64(seconds), 0).UTC()
	asLocal := time.Date(utc.Year(), utc.Month(), utc.Day(), utc.Hour(), utc.Minute(), utc.Second(), 0, loc)
	return "/Date(" + strconv.FormatInt(asLocal.UnixMilli(), 10) + ")/"
}

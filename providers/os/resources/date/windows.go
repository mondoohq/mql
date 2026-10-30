// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type windowsDateResult struct {
	DateTime  string `json:"DateTime"`
	Timezone  string `json:"Timezone"`
	UtcOffset *int64 `json:"UtcOffset"`
}

// PowerShell command that returns the current UTC time, the system time zone
// ID, and the zone's offset from UTC in seconds at this moment (DST included).
// The time is formatted with the invariant culture, since a custom format's
// ':' is otherwise the current culture's time separator.
const windowsDateCmd = `$tz=[System.TimeZoneInfo]::Local;@{DateTime=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ',[System.Globalization.CultureInfo]::InvariantCulture);Timezone=$tz.Id;UtcOffset=[int64]$tz.GetUtcOffset([DateTime]::UtcNow).TotalSeconds} | ConvertTo-Json`

type Windows struct {
	conn shared.Connection
}

func (w *Windows) Name() string {
	return "Windows Date"
}

func (w *Windows) Get() (*Result, error) {
	if !w.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return &Result{Timezone: "UTC"}, nil
	}

	cmd, err := w.conn.RunCommand(powershell.Encode(windowsDateCmd))
	if err != nil {
		return nil, fmt.Errorf("failed to get system date: %w", err)
	}

	return w.parse(cmd.Stdout)
}

func (w *Windows) parse(r io.Reader) (*Result, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read date output: %w", err)
	}

	var res windowsDateResult
	if err := json.Unmarshal(content, &res); err != nil {
		return nil, fmt.Errorf("failed to parse date output: %w", err)
	}

	t, err := time.Parse(time.RFC3339, res.DateTime)
	if err != nil {
		return nil, fmt.Errorf("failed to parse datetime %q: %w", res.DateTime, err)
	}

	// Windows reports its own zone IDs ("W. Europe Standard Time"), not IANA
	// names. CLDR maps them; an ID it does not know is kept as is.
	tz := res.Timezone
	if iana, ok := WindowsZoneToIANA(tz); ok {
		tz = iana
	}
	var windowsTZ *string
	if res.Timezone != "" {
		windowsTZ = &res.Timezone
	}

	lt, offset := localize(&t, tz, res.UtcOffset)
	return &Result{
		Time:            lt,
		Timezone:        tz,
		WindowsTimezone: windowsTZ,
		UTCOffset:       offset,
	}, nil
}

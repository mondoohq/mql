// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// wuaEventLog is the event log the Windows Update client writes its scan
// results to.
const wuaEventLog = "Microsoft-Windows-WindowsUpdateClient/Operational"

// wuaNeverYear is the first year a COM date must reach to count as a real
// date. The agent reports "never" as DateTime.MinValue, 1601 or the 1899-12-30
// OLE zero; WINDOWS_QUERY_WUA_RESULTS drops everything before 1980 the same way.
const wuaNeverYear = 1980

var wuaErrorCodeRegexp = regexp.MustCompile(`^(0[xX])?([0-9a-fA-F]+)$`)

// normalizeWUAErrorCode turns an errorCode value of an event ("0x8024402c",
// "8024402C") into "0x8024402C". Anything else yields "".
func normalizeWUAErrorCode(code string) string {
	m := wuaErrorCodeRegexp.FindStringSubmatch(strings.TrimSpace(code))
	if m == nil {
		return ""
	}
	return "0x" + strings.ToUpper(m[2])
}

// wuaEventXML is the part of a rendered event (EvtRenderEventXml) that is read.
type wuaEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// parseWUAEvent reads the creation time (UTC, truncated to seconds like the
// PowerShell path's output) and the normalised errorCode of a rendered event.
// The code is "" when the event has none or it is not hexadecimal. When the
// event has several errorCode values, the last one wins, as in the script.
func parseWUAEvent(rendered string) (time.Time, string, error) {
	var ev wuaEventXML
	if err := xml.Unmarshal([]byte(rendered), &ev); err != nil {
		return time.Time{}, "", fmt.Errorf("failed to parse event xml: %w", err)
	}
	st := strings.TrimSpace(ev.System.TimeCreated.SystemTime)
	if st == "" {
		return time.Time{}, "", errors.New("event xml has no TimeCreated SystemTime")
	}
	t, err := time.Parse(time.RFC3339Nano, st)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("failed to parse event time %q: %w", st, err)
	}
	code := ""
	for _, d := range ev.Data {
		if d.Name == "errorCode" {
			code = normalizeWUAErrorCode(d.Value)
		}
	}
	return t.UTC().Truncate(time.Second), code, nil
}

// oleDateToTime converts an OLE automation date (days since 1899-12-30, the
// fraction is the time of day) to its wall-clock value, labelled UTC: the COM
// dates are not converted to another time zone. The result is truncated to
// seconds.
func oleDateToTime(f float64) time.Time {
	ms := int64(math.Round(f * 86400000))
	return time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC).
		Add(time.Duration(ms) * time.Millisecond).Truncate(time.Second)
}

// wuaCOMDate maps a COM date value to a result time. nil and a "never"
// sentinel (before 1980) are nil. Supported types are time.Time and float64
// (an OLE automation date).
func wuaCOMDate(v any) (*time.Time, error) {
	var t time.Time
	switch d := v.(type) {
	case nil:
		return nil, nil
	case time.Time:
		t = d
	case float64:
		t = oleDateToTime(d)
	default:
		return nil, fmt.Errorf("unexpected COM date type %T", v)
	}
	if t.Year() < wuaNeverYear {
		return nil, nil
	}
	t = t.Truncate(time.Second)
	return &t, nil
}

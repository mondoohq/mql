// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func wuaTestEvent(id int, systemTime, dataXML string) string {
	return `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>` +
		`<Provider Name='Microsoft-Windows-WindowsUpdateClient' Guid='{945a8954-c147-4acd-923f-40c45405a658}'/>` +
		`<EventID>` + strconv.Itoa(id) + `</EventID><Version>0</Version><Level>4</Level>` +
		`<TimeCreated SystemTime='` + systemTime + `'/>` +
		`<Channel>Microsoft-Windows-WindowsUpdateClient/Operational</Channel><Computer>host</Computer></System>` +
		`<EventData>` + dataXML + `</EventData></Event>`
}

func TestParseWUAEvent(t *testing.T) {
	// Synthetic: event 26 shaped like an EvtRender result, 7 fractional digits; no target showed this.
	ev26 := wuaTestEvent(26, "2026-10-30T08:15:42.1234567Z",
		`<Data Name='updateCount'>3</Data><Data Name='serviceGuid'>{9482f4b4-e343-43b6-b170-9a65bc822c77}</Data>`)
	ts, code, err := parseWUAEvent(ev26)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 10, 30, 8, 15, 42, 0, time.UTC), ts)
	assert.Equal(t, "", code)

	// Synthetic: event 25 with a lower-case code; no target showed this.
	ev25 := wuaTestEvent(25, "2026-10-29T23:59:59.9999999Z",
		`<Data Name='errorCode'>0x8024402c</Data><Data Name='serviceGuid'>{9482f4b4-e343-43b6-b170-9a65bc822c77}</Data>`)
	ts, code, err = parseWUAEvent(ev25)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 10, 29, 23, 59, 59, 0, time.UTC), ts, "truncated, not rounded")
	assert.Equal(t, "0x8024402C", code)

	// Synthetic: a non-UTC offset is converted to UTC.
	ts, _, err = parseWUAEvent(wuaTestEvent(26, "2026-10-30T10:00:00+02:00", ""))
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC), ts)
	assert.Equal(t, time.UTC, ts.Location())

	// Synthetic: no EventData at all.
	_, code, err = parseWUAEvent(`<Event><System><TimeCreated SystemTime='2026-10-30T08:00:00Z'/></System></Event>`)
	require.NoError(t, err)
	assert.Equal(t, "", code)

	// Synthetic: a non-hex errorCode is dropped.
	_, code, err = parseWUAEvent(wuaTestEvent(25, "2026-10-30T08:00:00Z", `<Data Name='errorCode'>not a code</Data>`))
	require.NoError(t, err)
	assert.Equal(t, "", code)
}

func TestParseWUAEventErrors(t *testing.T) {
	// Synthetic: malformed XML.
	_, _, err := parseWUAEvent(`<Event><System>`)
	assert.Error(t, err)
	// Synthetic: no TimeCreated.
	_, _, err = parseWUAEvent(`<Event><System></System></Event>`)
	assert.Error(t, err)
	// Synthetic: unparsable time.
	_, _, err = parseWUAEvent(wuaTestEvent(26, "yesterday", ""))
	assert.Error(t, err)
}

func TestNormalizeWUAErrorCode(t *testing.T) {
	// Synthetic: the script's regex cases; no target showed other shapes.
	tests := map[string]string{
		"0x8024402c":   "0x8024402C",
		"0X8024402C":   "0x8024402C",
		"8024402c":     "0x8024402C",
		" 0x80240438 ": "0x80240438",
		"":             "",
		"0x":           "",
		"0xZZ":         "",
		"error 1":      "",
	}
	for in, want := range tests {
		assert.Equal(t, want, normalizeWUAErrorCode(in), "input %q", in)
	}
}

func TestOleDateToTime(t *testing.T) {
	// Synthetic: 46000.5 days after 1899-12-30 is 2025-12-09 12:00:00, no tz conversion.
	assert.Equal(t, time.Date(2025, 12, 9, 12, 0, 0, 0, time.UTC), oleDateToTime(46000.5))
	// Synthetic: sub-second parts are truncated (0.9999 s before noon).
	assert.Equal(t, time.Date(2025, 12, 9, 11, 59, 59, 0, time.UTC), oleDateToTime(46000.5-0.9999/86400))
	// Synthetic: the OLE zero.
	assert.Equal(t, time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC), oleDateToTime(0))
}

func TestWUACOMDate(t *testing.T) {
	// Synthetic: absent value.
	got, err := wuaCOMDate(nil)
	require.NoError(t, err)
	assert.Nil(t, got)

	// Synthetic: "never" sentinels (OLE zero, 1601, .NET MinValue) are null.
	for _, v := range []any{
		float64(0),
		time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1979, 12, 31, 23, 59, 59, 0, time.UTC),
	} {
		got, err = wuaCOMDate(v)
		require.NoError(t, err)
		assert.Nil(t, got, "%v", v)
	}

	// Synthetic: 1980 is the first real year.
	got, err = wuaCOMDate(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.NotNil(t, got)

	// Synthetic: time.Time keeps its wall clock, truncated to seconds.
	got, err = wuaCOMDate(time.Date(2026, 10, 30, 8, 15, 42, 900_000_000, time.UTC))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2026, 10, 30, 8, 15, 42, 0, time.UTC), *got)

	// Synthetic: float OLE date.
	got, err = wuaCOMDate(46000.5)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2025, 12, 9, 12, 0, 0, 0, time.UTC), *got)

	// Synthetic: another type is an error.
	_, err = wuaCOMDate("2026-01-01")
	assert.Error(t, err)
}

// Measured: Windows Server 2022 Datacenter Azure Edition (20348.5773), 2026-11-02.
// The XML is Get-WinEvent's ToXml() of the newest event 25 (a search against a
// WSUS policy pointing at 127.0.0.1:8530) and event 26, which is the same
// EvtRender output the native path reads. On that host the PowerShell path and
// the native path both reported lastDetectionError 0x80240438 for event 25.
func TestParseWUAEventMeasuredServer2022(t *testing.T) {
	ev25 := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WindowsUpdateClient' Guid='{945a8954-c147-4acd-923f-40c45405a658}'/><EventID>25</EventID><Version>1</Version><Level>2</Level><Task>1</Task><Opcode>11</Opcode><Keywords>0x4000000000000022</Keywords><TimeCreated SystemTime='2026-11-02T14:38:45.7433914Z'/><EventRecordID>19</EventRecordID><Correlation/><Execution ProcessID='4952' ThreadID='1796'/><Channel>Microsoft-Windows-WindowsUpdateClient/Operational</Channel><Computer>pkgwin</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='errorCode'>0x80240438</Data><Data Name='serviceGuid'>{3da21691-e39d-4da6-8a4b-b43877bcb1b7}</Data></EventData></Event>`
	ts, code, err := parseWUAEvent(ev25)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 11, 2, 14, 38, 45, 0, time.UTC), ts)
	assert.Equal(t, "0x80240438", code)

	ev26 := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WindowsUpdateClient' Guid='{945a8954-c147-4acd-923f-40c45405a658}'/><EventID>26</EventID><Version>1</Version><Level>4</Level><Task>1</Task><Opcode>11</Opcode><Keywords>0x4000000000000012</Keywords><TimeCreated SystemTime='2026-11-02T14:29:09.2090419Z'/><EventRecordID>18</EventRecordID><Correlation/><Execution ProcessID='3952' ThreadID='5720'/><Channel>Microsoft-Windows-WindowsUpdateClient/Operational</Channel><Computer>pkgwin</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='updateCount'>1</Data><Data Name='serviceGuid'>{8b24b027-1dee-babb-9a95-3517dfb9c552}</Data></EventData></Event>`
	ts, code, err = parseWUAEvent(ev26)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 11, 2, 14, 29, 9, 0, time.UTC), ts)
	assert.Empty(t, code, "event 26 carries no errorCode")
}

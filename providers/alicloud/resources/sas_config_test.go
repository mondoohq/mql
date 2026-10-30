// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

// TestSasNoticeChannels covers the notification route decode. The API packs the
// delivery channels into one integer, and every bit has to be read: dropping
// one would report an event type as unnotified when it does raise a message,
// and inventing one would report a channel nobody configured.
func TestSasNoticeChannels(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route *int32
		want  []any
	}{
		{"nil raises nothing", nil, []any{}},
		{"zero raises nothing", tea.Int32(0), []any{}},
		{"1 is text message", tea.Int32(1), []any{"sms"}},
		{"2 is email", tea.Int32(2), []any{"email"}},
		{"3 is text message and email", tea.Int32(3), []any{"sms", "email"}},
		{"4 is internal message", tea.Int32(4), []any{"internal"}},
		{"5 is text message and internal", tea.Int32(5), []any{"sms", "internal"}},
		{"6 is email and internal", tea.Int32(6), []any{"email", "internal"}},
		{"7 is all three", tea.Int32(7), []any{"sms", "email", "internal"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sasNoticeChannels(tc.route))
		})
	}

	t.Run("an unknown high bit does not invent a channel", func(t *testing.T) {
		// bit 4 is not a documented channel; the three known ones still decode
		assert.Equal(t, []any{"sms", "email", "internal"}, sasNoticeChannels(tea.Int32(15)))
	})
}

// TestSasSwitchEnabled covers the vulnerability scan on/off switch. Only "on"
// counts, so a type nobody could read fails a "scanning is enabled" check
// rather than passing it.
func TestSasSwitchEnabled(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value *string
		want  bool
	}{
		{"nil is off", nil, false},
		{"empty is off", new(""), false},
		{"on", new("on"), true},
		{"case insensitive", new("ON"), true},
		{"surrounding space", new(" on "), true},
		{"off", new("off"), false},
		{"unknown value is off", new("partial"), false},
		{"substring must not match", new("gone"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sasSwitchEnabled(tc.value))
		})
	}
}

// TestSasScheduleHours covers the fingerprint collection interval conversion.
// An unreadable value has to land on 0, which reads as "not scheduled" rather
// than as a collection frequency nobody configured.
func TestSasScheduleHours(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value *string
		want  int64
	}{
		{"nil is zero", nil, 0},
		{"empty is zero", new(""), 0},
		{"garbage is zero", new("daily"), 0},
		{"negative is zero", new("-12"), 0},
		{"twice a day", new("12"), 12},
		{"daily", new("24"), 24},
		{"weekly", new("168"), 168},
		{"surrounding space", new(" 24 "), 24},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sasScheduleHours(tc.value))
		})
	}
}

// TestSasStrings covers the path-list flattening. A nil or empty entry must be
// dropped rather than surfacing as a blank, which would read as a configured
// scan path covering nothing.
func TestSasStrings(t *testing.T) {
	assert.Equal(t, []any{}, sasStrings(nil))
	assert.Equal(t, []any{}, sasStrings([]*string{nil, new("")}))
	assert.Equal(t, []any{"/var/www"}, sasStrings([]*string{new("/var/www"), nil}))
	assert.Equal(t, []any{"/var/www", "/srv/http"},
		sasStrings([]*string{new("/var/www"), new(""), new("/srv/http")}))
}

// TestSasPropertyScheduleTypes pins the fingerprint kinds walked by
// propertySchedules. GetPropertyScheduleConfig answers for one kind per
// request, so a kind missing from this list is never asked about and silently
// reports no schedule at all rather than an error.
func TestSasPropertyScheduleTypes(t *testing.T) {
	assert.Equal(t, []string{
		"scheduler_software_period",
		"scheduler_cron_period",
		"scheduler_sca_period",
		"scheduler_autorun_period",
		"scheduler_lkm_period",
		"scheduler_sca_proxy_period",
	}, sasPropertyScheduleTypes)
}

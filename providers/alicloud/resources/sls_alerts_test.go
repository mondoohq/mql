// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	slsclient "github.com/alibabacloud-go/sls-20201230/v6/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSlsAlertEnabled covers the alert rule on/off classifier. A rule that
// silently read as enabled would report monitoring in place for events nothing
// is watching, which is the failure direction that matters here.
func TestSlsAlertEnabled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status *string
		want   bool
	}{
		{"nil is off", nil, false},
		{"empty is off", new(""), false},
		{"ENABLED", new("ENABLED"), true},
		{"lowercase", new("enabled"), true},
		{"surrounding space", new(" ENABLED "), true},
		{"DISABLED", new("DISABLED"), false},
		{"unknown state is off", new("PENDING"), false},
		{"substring must not match", new("NOT_ENABLED"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, slsAlertEnabled(tc.status))
		})
	}
}

// TestSlsEpochSeconds covers the timestamp conversion. An absent timestamp has
// to stay null: becoming 1 January 1970 would report a real creation or
// modification date for a rule that never gave one, and a zero muteUntil would
// read as "muted until the epoch" rather than "not muted".
func TestSlsEpochSeconds(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		assert.Nil(t, slsEpochSeconds(nil))
	})
	t.Run("zero stays nil, not the epoch", func(t *testing.T) {
		assert.Nil(t, slsEpochSeconds(tea.Int64(0)))
	})
	t.Run("negative stays nil", func(t *testing.T) {
		assert.Nil(t, slsEpochSeconds(tea.Int64(-1)))
	})
	t.Run("seconds convert", func(t *testing.T) {
		got := slsEpochSeconds(tea.Int64(1755000000))
		require.NotNil(t, got)
		assert.Equal(t, time.Unix(1755000000, 0).UTC(), got.UTC())
	})
	t.Run("seconds are not treated as milliseconds", func(t *testing.T) {
		// SLS reports seconds. Reading them as milliseconds would place every
		// rule in 1970 and make a recency assertion meaningless.
		got := slsEpochSeconds(tea.Int64(1755000000))
		require.NotNil(t, got)
		assert.Equal(t, 2025, got.UTC().Year())
	})
}

// TestSlsAlertTags covers the label and annotation flattening. An entry with no
// key must be dropped rather than collapsing onto a shared empty key, where the
// last one silently overwrites the rest.
func TestSlsAlertTags(t *testing.T) {
	tag := func(k, v string) *slsclient.AlertTag {
		return &slsclient.AlertTag{Key: new(k), Value: new(v)}
	}

	t.Run("nil is an empty map, not nil", func(t *testing.T) {
		assert.Equal(t, map[string]any{}, slsAlertTags(nil))
	})
	t.Run("keys and values", func(t *testing.T) {
		assert.Equal(t, map[string]any{"severity": "high", "team": "secops"},
			slsAlertTags([]*slsclient.AlertTag{tag("severity", "high"), tag("team", "secops")}))
	})
	t.Run("nil and keyless entries are dropped", func(t *testing.T) {
		got := slsAlertTags([]*slsclient.AlertTag{
			nil,
			{Key: new("")},
			{Key: nil, Value: new("orphan")},
			tag("severity", "high"),
		})
		assert.Equal(t, map[string]any{"severity": "high"}, got)
	})
	t.Run("a key with no value reports empty, not missing", func(t *testing.T) {
		assert.Equal(t, map[string]any{"severity": ""},
			slsAlertTags([]*slsclient.AlertTag{{Key: new("severity")}}))
	})
}

// TestLogAlertID covers the alert cache key. A rule name is unique only within
// its project, and a project name only within its region, so two rules sharing
// a name in different projects must not collide: the second would otherwise be
// reported carrying the first one's queries.
func TestLogAlertID(t *testing.T) {
	base := logAlertID("cn-hangzhou", "audit-project", "root-usage")

	t.Run("differs by region", func(t *testing.T) {
		assert.NotEqual(t, base, logAlertID("ap-southeast-1", "audit-project", "root-usage"))
	})
	t.Run("differs by project", func(t *testing.T) {
		assert.NotEqual(t, base, logAlertID("cn-hangzhou", "other-project", "root-usage"))
	})
	t.Run("differs by rule name", func(t *testing.T) {
		assert.NotEqual(t, base, logAlertID("cn-hangzhou", "audit-project", "mfa-signin"))
	})
	t.Run("same rule is stable", func(t *testing.T) {
		assert.Equal(t, base, logAlertID("cn-hangzhou", "audit-project", "root-usage"))
	})
}

// TestScheduleString covers the optional-schedule reader. The API documents the
// schedule as required but it is optional on the wire, so an absent one must
// read as empty rather than panicking on the nil dereference.
func TestScheduleString(t *testing.T) {
	getInterval := func(s *slsclient.Schedule) *string { return s.Interval }

	t.Run("absent schedule is empty", func(t *testing.T) {
		assert.Equal(t, "", scheduleString(nil, getInterval))
	})
	t.Run("absent field is empty", func(t *testing.T) {
		assert.Equal(t, "", scheduleString(&slsclient.Schedule{}, getInterval))
	})
	t.Run("interval is read", func(t *testing.T) {
		assert.Equal(t, "5m", scheduleString(&slsclient.Schedule{Interval: new("5m")}, getInterval))
	})
	t.Run("a cron rule reports no interval", func(t *testing.T) {
		s := &slsclient.Schedule{
			Type:           new("Cron"),
			CronExpression: new("0 * * * *"),
		}
		assert.Equal(t, "", scheduleString(s, getInterval))
		assert.Equal(t, "0 * * * *", scheduleString(s, func(s *slsclient.Schedule) *string { return s.CronExpression }))
	})
}

// TestFirstNonEmpty covers the placement fallback used when an alert query
// leaves its project or region implicit. Returning empty in that case would
// make the logstore reference unresolvable for every same-project query, which
// is the common case rather than the edge case.
func TestFirstNonEmpty(t *testing.T) {
	assert.Equal(t, "", firstNonEmpty())
	assert.Equal(t, "", firstNonEmpty("", ""))
	assert.Equal(t, "cn-hangzhou", firstNonEmpty("cn-hangzhou", "ap-southeast-1"))
	assert.Equal(t, "ap-southeast-1", firstNonEmpty("", "ap-southeast-1"))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/require"
	reports "google.golang.org/api/admin/reports/v1"
)

func TestParseUserReports(t *testing.T) {
	params := []*reports.UsageReportParameters{
		{Name: "accounts:is_disabled", BoolValue: true},
		{Name: "accounts:is_super_admin", BoolValue: true},
		{Name: "accounts:is_2sv_enrolled", BoolValue: true},
		{Name: "accounts:is_2sv_enforced", BoolValue: false},
		{Name: "accounts:password_length_compliance", StringValue: "COMPLIANT"},
		{Name: "accounts:password_strength", StringValue: "STRONG"},
		{Name: "accounts:is_less_secure_apps_access_allowed", BoolValue: false},
		{Name: "accounts:admin_set_name", StringValue: "admin"},
		{Name: "accounts:num_authorized_apps", IntValue: 5},
		{Name: "accounts:num_security_keys", IntValue: 2},
		{Name: "accounts:gmail_used_quota_in_mb", IntValue: 100},
		{Name: "accounts:drive_used_quota_in_mb", IntValue: 200},
		{Name: "accounts:used_quota_in_mb", IntValue: 350},
		{Name: "gplus_photos_used_quota_in_mb", IntValue: 50},
		{Name: "gmail:num_emails_exchanged", IntValue: 1000},
		{Name: "gmail:num_emails_sent", IntValue: 400},
		{Name: "gmail:num_emails_received", IntValue: 600},
		{Name: "gmail:last_imap_time", DatetimeValue: "2024-07-29T15:04:05Z"},
		{Name: "gmail:last_webmail_time", DatetimeValue: "2024-07-30T09:00:00Z"},
		{Name: "docs:num_owned_items_edited", IntValue: 10},
		{Name: "docs:num_owned_items_viewed", IntValue: 25},
		{Name: "drive:last_active_usage_time", DatetimeValue: "2024-07-28T12:00:00Z"},
	}

	r := parseUserReports(params)
	require.NotNil(t, r)

	// account fields shared with security
	require.True(t, r.Account.IsDisabled)
	require.True(t, r.Security.IsDisabled)
	require.True(t, r.Account.IsSuperAdmin)
	require.True(t, r.Security.IsSuperAdmin)
	require.True(t, r.Account.IsS2svEnrolled)
	require.True(t, r.Security.IsS2svEnrolled)
	require.Equal(t, "COMPLIANT", r.Account.PasswordLengthCompliance)
	require.Equal(t, "COMPLIANT", r.Security.PasswordLengthCompliance)
	require.Equal(t, "admin", r.Account.AdminSetName)

	// security-only fields
	require.Equal(t, int64(5), r.Security.NumAuthorizedApps)
	require.Equal(t, int64(2), r.Security.NumSecurityKeys)

	// usage shared between account + appUsage
	require.Equal(t, int64(100), r.Account.GmailUsedQuotaInMb)
	require.Equal(t, int64(100), r.AppUsage.GmailUsedQuotaInMb)
	require.Equal(t, int64(200), r.Account.DriveUsedQuotaInMb)
	require.Equal(t, int64(350), r.Account.UsedQuotaInMb)
	require.Equal(t, int64(350), r.AppUsage.UsedQuotaInMb)
	require.Equal(t, int64(50), r.AppUsage.GPlusPhotosUsedQuotaInMb)

	// gmail / docs counters land on appUsage only
	require.Equal(t, int64(1000), r.AppUsage.NumEmailsExchanged)
	require.Equal(t, int64(400), r.AppUsage.NumEmailSent)
	require.Equal(t, int64(600), r.AppUsage.NumEmailsReceived)
	require.Equal(t, int64(10), r.AppUsage.NumOwnedItemsEdited)
	require.Equal(t, int64(25), r.AppUsage.NumOwnedItemsViewed)

	// timestamps parse to non-nil pointers
	require.NotNil(t, r.AppUsage.LastImapTime)
	require.NotNil(t, r.AppUsage.LastWebmailTime)
	require.NotNil(t, r.AppUsage.DriveLastActiveUsageTime)
}

func TestIndexUsageReportsByEmail(t *testing.T) {
	// nil and empty inputs return an empty map, not nil.
	require.Empty(t, indexUsageReportsByEmail(nil))
	require.Empty(t, indexUsageReportsByEmail([]*reports.UsageReport{}))

	in := []*reports.UsageReport{
		{Entity: &reports.UsageReportEntity{UserEmail: "alice@example.com"}, Date: "2026-05-20"},
		{Entity: &reports.UsageReportEntity{UserEmail: "bob@example.com"}, Date: "2026-05-20"},
		// nil Entity (should be skipped, not panic)
		{Date: "2026-05-20"},
		// empty UserEmail (customer-level aggregate, skipped)
		{Entity: &reports.UsageReportEntity{UserEmail: ""}, Date: "2026-05-20"},
		// nil report (skipped)
		nil,
	}
	got := indexUsageReportsByEmail(in)
	require.Len(t, got, 2)
	require.Contains(t, got, "alice@example.com")
	require.Contains(t, got, "bob@example.com")
	require.Equal(t, "2026-05-20", got["alice@example.com"].Date)

	// Duplicates keep the last write — Google's API returns one report per
	// (user, date) so collisions are not expected, but the index should be
	// deterministic if the SDK ever changes that.
	dup := []*reports.UsageReport{
		{Entity: &reports.UsageReportEntity{UserEmail: "alice@example.com"}, Date: "2026-05-19"},
		{Entity: &reports.UsageReportEntity{UserEmail: "alice@example.com"}, Date: "2026-05-20"},
	}
	got = indexUsageReportsByEmail(dup)
	require.Len(t, got, 1)
	require.Equal(t, "2026-05-20", got["alice@example.com"].Date)
}

func TestParseUserReports_EmptyAndUnknownParams(t *testing.T) {
	// no params at all
	r := parseUserReports(nil)
	require.NotNil(t, r)
	require.False(t, r.Account.IsDisabled)
	require.Equal(t, "", r.Account.AdminSetName)

	// unknown param names are ignored
	r = parseUserReports([]*reports.UsageReportParameters{
		{Name: "unknown:param", IntValue: 99},
	})
	require.NotNil(t, r)
	require.Equal(t, int64(0), r.AppUsage.NumEmailSent)

	// malformed datetime leaves the pointer nil
	r = parseUserReports([]*reports.UsageReportParameters{
		{Name: "gmail:last_imap_time", DatetimeValue: "not a date"},
	})
	require.Nil(t, r.AppUsage.LastImapTime)
}

func TestReportActivityID(t *testing.T) {
	// Distinct activities that share a unique qualifier (0 is the common
	// "absent" value) must still get distinct cache keys via app + time.
	a := reportActivityID("drive", "2026-01-01T00:00:00Z", 0)
	b := reportActivityID("admin", "2026-01-01T00:00:00Z", 0)
	c := reportActivityID("drive", "2026-01-02T00:00:00Z", 0)
	require.NotEqual(t, a, b, "same qualifier across apps must not collide")
	require.NotEqual(t, a, c, "same qualifier across times must not collide")

	// Stable for identical inputs, and carries the composed parts.
	require.Equal(t, a, reportActivityID("drive", "2026-01-01T00:00:00Z", 0))
	require.Equal(t,
		"googleworkspace.report.activity/login/2026-01-01T00:00:00Z/42",
		reportActivityID("login", "2026-01-01T00:00:00Z", 42),
	)
}

func TestHashActivity(t *testing.T) {
	a := &reports.Activity{IpAddress: "1.2.3.4", OwnerDomain: "example.com"}
	b := &reports.Activity{IpAddress: "5.6.7.8", OwnerDomain: "example.com"}

	// Distinct nil-id activities get distinct discriminators.
	require.NotEqual(t, hashActivity(a), hashActivity(b))
	// Stable for identical content across calls.
	require.Equal(t, hashActivity(a), hashActivity(&reports.Activity{IpAddress: "1.2.3.4", OwnerDomain: "example.com"}))
	require.NotEmpty(t, hashActivity(a))
}

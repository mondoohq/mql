// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"hash/fnv"
	"strconv"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	"go.mondoo.com/mql/types"
	reports "google.golang.org/api/admin/reports/v1"
)

// https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list#ApplicationName
const (
	appAccessTransparency = "access_transparency"
	appAdmin              = "admin"
	appCalendar           = "calendar"
	appChat               = "chat"
	appDrive              = "drive"
	appGcp                = "gcp"
	appGplus              = "gplus"
	appGroups             = "groups"
	appGroupsEnterprise   = "groups_enterprise"
	appJamboard           = "jamboard"
	appLogin              = "login"
	appMeet               = "meet"
	appMobile             = "mobile"
	appRules              = "rules"
	appSaml               = "saml"
	appToken              = "token"
	appUserAccounts       = "user_accounts"
	appContextAwareAccess = "context_aware_access"
	appChrome             = "chrome"
	appDataStudio         = "data_studio"
	appKeep               = "keep"
)

func (g *mqlGoogleworkspaceReportApps) id() (string, error) {
	return "googleworkspace.report.apps", nil
}

func (g *mqlGoogleworkspaceReportApps) drive() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	reportsService, err := reportsService(conn)
	if err != nil {
		return nil, err
	}

	res := []any{}

	activities, err := reportsService.Activities.List("all", "drive").CustomerId(conn.CustomerID()).Do()
	if err != nil {
		return nil, err
	}

	for {
		for i := range activities.Items {
			r, err := newMqlGoogleWorkspaceReportActivity(g.MqlRuntime, activities.Items[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}

		if activities.NextPageToken == "" {
			break
		}

		activities, err = reportsService.Activities.List("all", "drive").CustomerId(conn.CustomerID()).
			PageToken(activities.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func (g *mqlGoogleworkspaceReportApps) admin() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	reportsService, err := reportsService(conn)
	if err != nil {
		return nil, err
	}

	res := []any{}

	activities, err := reportsService.Activities.List("all", "admin").CustomerId(conn.CustomerID()).Do()
	if err != nil {
		return nil, err
	}

	for {
		for i := range activities.Items {
			r, err := newMqlGoogleWorkspaceReportActivity(g.MqlRuntime, activities.Items[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}

		if activities.NextPageToken == "" {
			break
		}

		activities, err = reportsService.Activities.List("all", "admin").CustomerId(conn.CustomerID()).
			PageToken(activities.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func (g *mqlGoogleworkspaceReportActivity) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "googleworkspace.report.activity/" + strconv.FormatInt(id, 10), nil
}

func newMqlGoogleWorkspaceReportActivity(runtime *plugin.Runtime, entry *reports.Activity) (any, error) {
	actor, err := convert.JsonToDict(entry.Actor)
	if err != nil {
		return nil, err
	}
	events, err := convert.JsonToDictSlice(entry.Events)
	if err != nil {
		return nil, err
	}

	var uniqueQualifier int64
	var activityID string
	if entry.Id != nil {
		uniqueQualifier = entry.Id.UniqueQualifier
		// The cache key must include the application name and event time:
		// uniqueQualifier is only a tiebreaker for events sharing a time (and is
		// absent for most events), so keying on it alone aliases distinct
		// activities. The public `id` field keeps the bare uniqueQualifier.
		activityID = reportActivityID(entry.Id.ApplicationName, entry.Id.Time, uniqueQualifier)
	} else {
		// No id from the API (malformed/partial event): fall back to a content
		// hash so nil-id activities get distinct, stable keys instead of all
		// aliasing to a single cache entry.
		activityID = "googleworkspace.report.activity/nil/" + hashActivity(entry)
	}

	var deviceId, deviceType, deviceOsVersion string
	if entry.UserDeviceInfo != nil {
		deviceId = entry.UserDeviceInfo.DeviceId
		deviceType = entry.UserDeviceInfo.DeviceType
		deviceOsVersion = entry.UserDeviceInfo.DeviceOsVersion
	}

	return CreateResource(runtime, "googleworkspace.report.activity", map[string]*llx.RawData{
		"__id":            llx.StringData(activityID),
		"id":              llx.IntData(uniqueQualifier),
		"ipAddress":       llx.StringData(entry.IpAddress),
		"ownerDomain":     llx.StringData(entry.OwnerDomain),
		"actor":           llx.MapData(actor, types.Any),
		"events":          llx.ArrayData(events, types.Any),
		"isAgenticAction": llx.BoolData(entry.IsAgenticAction),
		"deviceId":        llx.StringData(deviceId),
		"deviceType":      llx.StringData(deviceType),
		"deviceOsVersion": llx.StringData(deviceOsVersion),
	})
}

// reportActivityID builds a stable, unique cache key for a report activity from
// the application name, event time, and unique qualifier that together identify
// it in the Reports API.
func reportActivityID(appName, eventTime string, uniqueQualifier int64) string {
	return "googleworkspace.report.activity/" + appName + "/" + eventTime + "/" + strconv.FormatInt(uniqueQualifier, 10)
}

// hashActivity produces a stable 64-bit content hash of an activity, used as a
// cache-key discriminator for the rare event that arrives without an id. It is
// deterministic (same content -> same key across scans) so two distinct
// nil-id activities don't alias each other.
func hashActivity(entry *reports.Activity) string {
	h := fnv.New64a()
	if data, err := json.Marshal(entry); err == nil {
		h.Write(data)
	} else {
		// json.Marshal of this plain struct effectively never fails, but if it
		// ever did we still hash the stable scalar fields so distinct events get
		// distinct keys instead of all collapsing onto one empty discriminator.
		h.Write([]byte(entry.Etag + "\x00" + entry.IpAddress + "\x00" + entry.OwnerDomain))
	}
	return strconv.FormatUint(h.Sum64(), 16)
}

func (g *mqlGoogleworkspaceReportUsers) id() (string, error) {
	return "googleworkspace.report.users", nil
}

func (g *mqlGoogleworkspaceReportUsers) list() ([]any, error) {
	parent, err := workspaceResource(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	reportsByEmail, _, err := parent.loadUsageReports()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(reportsByEmail))
	for _, u := range reportsByEmail {
		r, err := newMqlGoogleWorkspaceUsageReport(g.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// fetchAllUsageReports issues a single `UserUsageReport.Get("all", date)`
// for the most recent date with published data (Google's reports lag 1–3
// days; we walk back up to 8 days finding the latest available). The result
// is keyed by primary email so per-user lookups become map reads instead of
// individual Get(email, date) calls. Without this shared fetch, querying
// `users { usageReport }` on a tenant with N users would issue up to 10×N
// API calls (the per-user retry loop x N users).
func fetchAllUsageReports(service *reports.Service, customerId string) (map[string]*reports.UsageReport, string, error) {
	date := time.Now()
	// 8 attempts cover the documented 1–3 day lag plus a safety margin for
	// weekends and holidays when Google may not publish a new daily report.
	for attempts := 8; attempts > 0; attempts-- {
		dateStr := date.Format(time.DateOnly)
		rpts, err := fetchAllUsageReportsForDate(service, customerId, dateStr)
		if err != nil && shouldCheckEarlierDateForReport(err) {
			date = date.Add(-24 * time.Hour)
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if len(rpts) == 0 {
			date = date.Add(-24 * time.Hour)
			continue
		}
		return indexUsageReportsByEmail(rpts), dateStr, nil
	}
	return map[string]*reports.UsageReport{}, "", nil
}

// indexUsageReportsByEmail keys a flat slice of usage reports by the
// per-entity primary email. Reports without an Entity or with an empty
// UserEmail (e.g. customer-level aggregates) are skipped so the index
// stays usable for the user.usageReport lookup path.
func indexUsageReportsByEmail(rpts []*reports.UsageReport) map[string]*reports.UsageReport {
	m := make(map[string]*reports.UsageReport, len(rpts))
	for _, r := range rpts {
		if r == nil || r.Entity == nil || r.Entity.UserEmail == "" {
			continue
		}
		m[r.Entity.UserEmail] = r
	}
	return m
}

func fetchAllUsageReportsForDate(service *reports.Service, customerId, date string) ([]*reports.UsageReport, error) {
	var out []*reports.UsageReport
	usageReports, err := service.UserUsageReport.Get("all", date).CustomerId(customerId).Do()
	if err != nil {
		return nil, err
	}
	for {
		out = append(out, usageReports.UsageReports...)
		if usageReports.NextPageToken == "" {
			break
		}
		usageReports, err = service.UserUsageReport.Get("all", date).CustomerId(customerId).PageToken(usageReports.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func newMqlGoogleWorkspaceUsageReport(runtime *plugin.Runtime, entry *reports.UsageReport) (*mqlGoogleworkspaceReportUsage, error) {
	var date *time.Time
	parsedDate, err := time.Parse(time.DateOnly, entry.Date)
	if err == nil {
		date = &parsedDate
	}

	parameters, err := convert.JsonToDictSlice(entry.Parameters)
	if err != nil {
		return nil, err
	}

	r := parseUserReports(entry.Parameters)

	appUsage, err := convert.JsonToDict(r.AppUsage)
	if err != nil {
		return nil, err
	}

	var customerId, entityId, profileId, entityType, userEmail string
	if entry.Entity != nil {
		customerId = entry.Entity.CustomerId
		entityId = entry.Entity.EntityId
		profileId = entry.Entity.ProfileId
		entityType = entry.Entity.Type
		userEmail = entry.Entity.UserEmail
	}

	report, err := CreateResource(runtime, "googleworkspace.report.usage", map[string]*llx.RawData{
		"customerId": llx.StringData(customerId),
		"entityId":   llx.StringData(entityId),
		"profileId":  llx.StringData(profileId),
		"type":       llx.StringData(entityType),
		"userEmail":  llx.StringData(userEmail),
		"date":       llx.TimeDataPtr(date),
		"parameters": llx.ArrayData(parameters, types.Any),
		"appUsage":   llx.MapData(appUsage, types.Any),
		// Typed promotions of the account/security dicts (already parsed into
		// r above) so audits can assert on them directly.
		"isDisabled":                    llx.BoolData(r.Account.IsDisabled),
		"isSuperAdmin":                  llx.BoolData(r.Account.IsSuperAdmin),
		"is2svEnrolled":                 llx.BoolData(r.Account.IsS2svEnrolled),
		"is2svEnforced":                 llx.BoolData(r.Account.Is2svEnforced),
		"passwordStrength":              llx.StringData(r.Account.PasswordStrength),
		"passwordLengthCompliance":      llx.StringData(r.Account.PasswordLengthCompliance),
		"isLessSecureAppsAccessAllowed": llx.BoolData(r.Account.IsLessSecureAppsAccessAllowed),
		"numAuthorizedApps":             llx.IntData(r.Security.NumAuthorizedApps),
		"numSecurityKeys":               llx.IntData(r.Security.NumSecurityKeys),
		"gmailUsedQuotaInMb":            llx.IntData(r.Account.GmailUsedQuotaInMb),
		"driveUsedQuotaInMb":            llx.IntData(r.Account.DriveUsedQuotaInMb),
		"usedQuotaInMb":                 llx.IntData(r.Account.UsedQuotaInMb),
	})
	return report.(*mqlGoogleworkspaceReportUsage), err
}

func (g *mqlGoogleworkspaceReportUsage) id() (string, error) {
	if g.CustomerId.Error != nil {
		return "", g.CustomerId.Error
	}
	customerId := g.CustomerId.Data
	if g.ProfileId.Error != nil {
		return "", g.ProfileId.Error
	}
	profileId := g.ProfileId.Data
	if g.Date.Error != nil {
		return "", g.Date.Error
	}
	date := g.Date.Data

	return "googleworkspace.report.usage/" + customerId + "/" + profileId + "/" + date.Format(time.DateOnly), nil
}

type userReport struct {
	Account  userReportAccount
	Security userReportSecurity
	AppUsage userReportAppUsage
}

type userReportAccount struct {
	IsDisabled                    bool   `json:"isDisabled"`
	IsSuperAdmin                  bool   `json:"isSuperAdmin"`
	IsS2svEnrolled                bool   `json:"isS2SvEnrolled"`
	Is2svEnforced                 bool   `json:"is2SvEnforced"`
	PasswordLengthCompliance      string `json:"passwordLengthCompliance"`
	PasswordStrength              string `json:"passwordStrength"`
	IsLessSecureAppsAccessAllowed bool   `json:"isLessSecureAppsAccessAllowed"`
	GmailUsedQuotaInMb            int64  `json:"gmailUsedQuotaInMb"`
	DriveUsedQuotaInMb            int64  `json:"driveUsedQuotaInMb"`
	UsedQuotaInMb                 int64  `json:"usedQuotaInMb"`
	AdminSetName                  string `json:"adminSetName"`
}

type userReportSecurity struct {
	NumAuthorizedApps             int64  `json:"numAuthorizedApps"`
	IsS2svEnrolled                bool   `json:"isS2SvEnrolled"`
	Is2svEnforced                 bool   `json:"is2SvEnforced"`
	PasswordLengthCompliance      string `json:"passwordLengthCompliance"`
	PasswordStrength              string `json:"passwordStrength"`
	IsDisabled                    bool   `json:"isDisabled"`
	IsSuperAdmin                  bool   `json:"isSuperAdmin"`
	NumSecurityKeys               int64  `json:"numSecurityKeys"`
	IsLessSecureAppsAccessAllowed bool   `json:"isLessSecureAppsAccessAllowed"`
}

type userReportAppUsage struct {
	GmailUsedQuotaInMb       int64      `json:"gmailUsedQuotaInMb"`
	DriveUsedQuotaInMb       int64      `json:"driveUsedQuotaInMb"`
	GPlusPhotosUsedQuotaInMb int64      `json:"gPlusPhotosUsedQuotaInMb"`
	UsedQuotaInMb            int64      `json:"usedQuotaInMb"`
	NumEmailsExchanged       int64      `json:"numEmailsExchanged"`
	NumEmailSent             int64      `json:"numEmailSent"`
	NumEmailsReceived        int64      `json:"numEmailsReceived"`
	LastImapTime             *time.Time `json:"lastImapTime"`
	LastWebmailTime          *time.Time `json:"lastWebmailTime"`
	NumOwnedItemsEdited      int64      `json:"numOwnedItemsEdited"`
	NumOwnedItemsViewed      int64      `json:"numOwnedItemsViewed"`
	DriveLastActiveUsageTime *time.Time `json:"driveLastActiveUsageTime"`
}

func parseUserReports(params []*reports.UsageReportParameters) *userReport {
	r := &userReport{}

	for i := range params {
		param := params[i]
		switch param.Name {
		// account
		case "accounts:is_disabled":
			r.Account.IsDisabled = param.BoolValue
			r.Security.IsDisabled = param.BoolValue
		case "accounts:is_super_admin":
			r.Account.IsSuperAdmin = param.BoolValue
			r.Security.IsSuperAdmin = param.BoolValue
		case "accounts:is_2sv_enrolled":
			r.Account.IsS2svEnrolled = param.BoolValue
			r.Security.IsS2svEnrolled = param.BoolValue
		case "accounts:is_2sv_enforced":
			r.Account.Is2svEnforced = param.BoolValue
			r.Security.Is2svEnforced = param.BoolValue
		case "accounts:password_length_compliance":
			r.Account.PasswordLengthCompliance = param.StringValue
			r.Security.PasswordLengthCompliance = param.StringValue
		case "accounts:password_strength":
			r.Account.PasswordStrength = param.StringValue
			r.Security.PasswordStrength = param.StringValue
		case "accounts:is_less_secure_apps_access_allowed":
			r.Account.IsLessSecureAppsAccessAllowed = param.BoolValue
			r.Security.IsLessSecureAppsAccessAllowed = param.BoolValue
		case "accounts:admin_set_name":
			r.Account.AdminSetName = param.StringValue
			// security
		case "accounts:num_authorized_apps":
			r.Security.NumAuthorizedApps = param.IntValue
		case "accounts:num_security_keys":
			r.Security.NumSecurityKeys = param.IntValue
			// usage
		case "accounts:gmail_used_quota_in_mb":
			r.Account.GmailUsedQuotaInMb = param.IntValue
			r.AppUsage.GmailUsedQuotaInMb = param.IntValue
		case "accounts:drive_used_quota_in_mb":
			r.Account.DriveUsedQuotaInMb = param.IntValue
			r.AppUsage.DriveUsedQuotaInMb = param.IntValue
		case "gplus_photos_used_quota_in_mb":
			r.AppUsage.GPlusPhotosUsedQuotaInMb = param.IntValue
		case "accounts:used_quota_in_mb":
			r.Account.UsedQuotaInMb = param.IntValue
			r.AppUsage.UsedQuotaInMb = param.IntValue
		case "gmail:num_emails_exchanged":
			r.AppUsage.NumEmailsExchanged = param.IntValue
		case "gmail:num_emails_sent":
			r.AppUsage.NumEmailSent = param.IntValue
		case "gmail:num_emails_received":
			r.AppUsage.NumEmailsReceived = param.IntValue
		case "gmail:last_imap_time":
			var datetime *time.Time
			parseDateTime, err := time.Parse(time.RFC3339, param.DatetimeValue)
			if err == nil {
				datetime = &parseDateTime
			}
			r.AppUsage.LastImapTime = datetime
		case "gmail:last_webmail_time":
			var datetime *time.Time
			parseDateTime, err := time.Parse(time.RFC3339, param.DatetimeValue)
			if err == nil {
				datetime = &parseDateTime
			}
			r.AppUsage.LastWebmailTime = datetime
		case "docs:num_owned_items_edited":
			r.AppUsage.NumOwnedItemsEdited = param.IntValue
		case "docs:num_owned_items_viewed":
			r.AppUsage.NumOwnedItemsViewed = param.IntValue
		case "drive:last_active_usage_time":
			var datetime *time.Time
			parseDateTime, err := time.Parse(time.RFC3339, param.DatetimeValue)
			if err == nil {
				datetime = &parseDateTime
			}
			r.AppUsage.DriveLastActiveUsageTime = datetime
		}
	}

	return r
}

func (g *mqlGoogleworkspaceReportUsage) appUsage() (any, error) {
	// is auto-computed during creation time
	return nil, errors.New("not implemented")
}

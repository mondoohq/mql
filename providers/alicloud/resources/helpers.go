// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	tea "github.com/alibabacloud-go/tea/tea"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// epochSeconds converts an epoch-seconds timestamp into a *time.Time, returning
// nil when the value is nil or zero. A zero must stay null rather than becoming
// 1 January 1970, which a report would render as a real date.
func epochSeconds(v *int64) *time.Time {
	if v == nil || *v == 0 {
		return nil
	}
	t := time.Unix(*v, 0).UTC()
	return &t
}

// strPtrsToStrings converts a []*string SDK slice into a []string, dropping nil
// and empty entries so downstream resolvers are never handed a blank id.
func strPtrsToStrings(in []*string) []string {
	res := []string{}
	for _, s := range in {
		if v := tea.StringValue(s); v != "" {
			res = append(res, v)
		}
	}
	return res
}

// strPtrsToAny converts a []*string SDK slice into a []any of the non-empty
// strings, for populating MQL list fields.
func strPtrsToAny(in []*string) []any {
	res := []any{}
	for _, s := range in {
		if v := tea.StringValue(s); v != "" {
			res = append(res, v)
		}
	}
	return res
}

// int64PtrsToInts converts a []*int64 SDK slice into a []any of the non-nil
// values, for populating MQL int list fields.
func int64PtrsToInts(in []*int64) []any {
	res := []any{}
	for _, v := range in {
		if v != nil {
			res = append(res, *v)
		}
	}
	return res
}

// alicloudCenterRegions are the two center endpoints that WAF, Cloud Firewall,
// and Anti-DDoS answer at: cn-hangzhou for the China partition and
// ap-southeast-1 for the international partition. An account belongs to one of
// them, so a call against the other partition returns no data (or an error).
var alicloudCenterRegions = []string{"cn-hangzhou", "ap-southeast-1"}

// filteredOutByTags reports whether a resource carrying these tags should be
// dropped for the connection's --filters tag settings.
//
// Filters are applied in the listers rather than in discovery, so a scan and a
// plain MQL query see the same set. Callers whose tags cost a separate API call
// gate the lookup on conn.Filters.General.HasTags() first, so an unfiltered
// scan does not pay for tags nobody asked for.
func filteredOutByTags(conn *connection.AlicloudConnection, tags map[string]any) bool {
	if !conn.Filters.General.HasTags() {
		return false
	}
	return conn.Filters.General.IsFilteredOutByTags(tagsToStringMap(tags))
}

// tagsToStringMap narrows an MQL tag map to the string-valued entries the tag
// filters compare against.
func tagsToStringMap(tags map[string]any) map[string]string {
	res := make(map[string]string, len(tags))
	for k, v := range tags {
		if s, ok := v.(string); ok {
			res[k] = s
		}
	}
	return res
}

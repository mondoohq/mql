// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
)

// alicloudErrorStatus returns the HTTP status and error code of an Alibaba Cloud
// SDK error. The Darabonba clients convert every service response error into a
// *tea.SDKError before returning it, so that is the only shape inspected. ok is
// false for anything else, such as a transport failure.
func alicloudErrorStatus(err error) (status int, code string, ok bool) {
	var sdkErr *tea.SDKError
	if !errors.As(err, &sdkErr) || sdkErr.StatusCode == nil {
		return 0, "", false
	}
	return *sdkErr.StatusCode, tea.StringValue(sdkErr.Code), true
}

// alicloudServiceNotOpen reports whether an error code says the service is not
// activated for the account. Alibaba Cloud spells this per service
// (NotOpen, Forbidden.NotOpen, ServiceNotOpen, NotActivated), so the check
// matches the shared fragments.
func alicloudServiceNotOpen(code string) bool {
	lower := strings.ToLower(code)
	return strings.Contains(lower, "notopen") || strings.Contains(lower, "notactivat")
}

// classifyAlicloudError maps a refused Alibaba Cloud API call to its ADR 046
// kind, naming the permission the call needs. An error the target did not
// refuse, such as a transport failure, is returned unchanged.
func classifyAlicloudError(err error, permission string) error {
	if err == nil {
		return nil
	}
	status, code, ok := alicloudErrorStatus(err)
	if !ok {
		return err
	}
	if alicloudServiceNotOpen(code) {
		return llx.NotApplicable(err)
	}
	if strings.Contains(code, "Throttling") || status == http.StatusTooManyRequests {
		return llx.TooManyRequests(err)
	}
	switch {
	case status == http.StatusUnauthorized:
		return llx.Unauthenticated(err)
	case status == http.StatusForbidden:
		return llx.Forbidden(err, llx.WithPermissions(permission))
	case status >= 500:
		return llx.Unavailable(err)
	}
	return err
}

// alicloudRegionSkippable reports whether a first-page error in a per-region
// listing means the region does not offer the service to this account or the
// credential cannot read it there. Both are ordinary on an account with many
// enabled regions and are logged at debug level; anything else is warned about,
// so a region skipped because the API failed is distinguishable from one that
// legitimately has nothing.
func alicloudRegionSkippable(err error) bool {
	status, code, ok := alicloudErrorStatus(err)
	if !ok {
		return false
	}
	if alicloudServiceNotOpen(code) {
		return true
	}
	switch status {
	case http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}

// logSkippedRegion records a per-region listing that was skipped after a
// first-page error. The other regions' results are kept.
func logSkippedRegion(err error, service, region string) {
	if alicloudRegionSkippable(err) {
		log.Debug().Err(err).Str("region", region).
			Msgf("alicloud> skipping region with no %s access", service)
		return
	}
	log.Warn().Err(err).Str("region", region).
		Msgf("alicloud> skipping %s region after an unexpected error", service)
}

// alicloudTimeLayouts are the timestamp formats the newer Alibaba Cloud APIs
// return, from full RFC 3339 down to a bare date.
var alicloudTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04Z",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// parseAlicloudTime parses an Alibaba Cloud timestamp string. A nil, empty, or
// unparseable value yields nil rather than a fabricated date.
func parseAlicloudTime(s *string) *time.Time {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	if v == "" {
		return nil
	}
	for _, layout := range alicloudTimeLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// epochAuto converts an epoch timestamp that may be in seconds or in
// milliseconds into a time. APIs are not consistent about the unit, and a
// value in milliseconds read as seconds lands tens of thousands of years in
// the future, so anything above 1e12 (September 2001 in milliseconds) is taken
// as milliseconds. A nil or non-positive value yields nil.
func epochAuto(v *int64) *time.Time {
	if v == nil || *v <= 0 {
		return nil
	}
	var t time.Time
	if *v > 1e12 {
		t = time.UnixMilli(*v).UTC()
	} else {
		t = time.Unix(*v, 0).UTC()
	}
	return &t
}

// parseJSONStringList decodes an API value that carries a JSON array encoded
// as a string, such as `["0","1","23"]` or `[1,2]`, into its members as
// strings. An empty or undecodable value yields an empty list.
func parseJSONStringList(s *string) []string {
	res := []string{}
	if s == nil || strings.TrimSpace(*s) == "" {
		return res
	}
	var raw []any
	if err := json.Unmarshal([]byte(*s), &raw); err != nil {
		return res
	}
	for _, item := range raw {
		switch v := item.(type) {
		case string:
			if t := strings.TrimSpace(v); t != "" {
				res = append(res, t)
			}
		case float64:
			res = append(res, strconv.FormatFloat(v, 'f', -1, 64))
		}
	}
	return res
}

// parseJSONIntList decodes a JSON array encoded as a string into its integer
// members, dropping any member that is not a whole number.
func parseJSONIntList(s *string) []any {
	res := []any{}
	for _, item := range parseJSONStringList(s) {
		if n, err := strconv.ParseInt(item, 10, 64); err == nil {
			res = append(res, n)
		}
	}
	return res
}

// stringsToAny converts a []string into a []any for an MQL list field.
func stringsToAny(in []string) []any {
	res := make([]any, 0, len(in))
	for _, s := range in {
		res = append(res, s)
	}
	return res
}

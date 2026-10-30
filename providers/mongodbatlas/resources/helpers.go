// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxPages bounds every paginated walk. An Atlas listing terminates by
// returning a short page; an endpoint that ignores the page number instead
// returns the first page forever, which would multiply every record up to
// whatever the caller runs out of memory at. The bound turns that into a
// reported error.
const maxPages = 1000

// forEachPage walks a page-numbered Atlas listing. fetch reports how many
// results the page carried, and the walk stops on the first short page.
func forEachPage(fetch func(page int) (int, error)) error {
	for page := 1; page <= maxPages; page++ {
		n, err := fetch(page)
		if err != nil {
			return err
		}
		if n < pageSize {
			return nil
		}
	}
	return fmt.Errorf("MongoDB Atlas listing did not terminate within %d pages of %d results", maxPages, pageSize)
}

// hostOf reduces a destination address to its host and port. A notification or
// telemetry endpoint frequently carries a token in its path or query, and any
// userinfo in the URL is a credential outright, so only the host is ever
// exposed. Returns an empty string when there is no address or no host in it.
func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		// A bare host, which may still carry a port and a path.
		if i := strings.IndexAny(raw, "/?#"); i >= 0 {
			raw = raw[:i]
		}
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// hostPtrOf renders hostOf as a pointer so an address the API did not report
// stays null rather than becoming an empty string.
func hostPtrOf(raw *string) *string {
	if raw == nil {
		return nil
	}
	host := hostOf(*raw)
	if host == "" {
		return nil
	}
	return &host
}

// atlasTimeLayouts are the timestamp forms the Atlas API returns for fields the
// SDK models as a string rather than a time.
var atlasTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.000Z0700",
	"2006-01-02T15:04:05Z0700",
}

// parseAtlasTime converts an ISO 8601 timestamp the SDK carries as a string.
// An absent or unparseable value stays null rather than becoming the zero time,
// which would otherwise report the year 1 as a real date.
func parseAtlasTime(s *string) *time.Time {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil
	}
	for _, layout := range atlasTimeLayouts {
		if t, err := time.Parse(layout, *s); err == nil {
			return &t
		}
	}
	return nil
}

// isSet reports whether the API returned a non-empty value for a field that is
// only ever read for its presence, such as a webhook secret or a certificate
// authority bundle. The value itself is never exposed.
func isSet(v *string) bool {
	return v != nil && *v != ""
}

// firstBool returns the first flag the API actually reported. Several Atlas
// records carry the same setting under two names depending on the integration
// kind, and only one of the two is ever populated.
func firstBool(vals ...*bool) *bool {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

// int64ToString renders a numeric identifier for use inside a cache key.
func int64ToString(v int64) string {
	return strconv.FormatInt(v, 10)
}

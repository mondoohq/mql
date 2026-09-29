// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// redactedValue replaces a setting value that is likely to be a credential.
const redactedValue = "<redacted>"

// stripURLCredentials removes the parts of a URL that carry credentials: the
// user information and the query string (where a shared access signature
// lives), plus the fragment. It reports whether a query string was present.
//
// A value that does not parse as a URL is cut at the first '?' so that a SAS
// token in a malformed URL still does not leak.
func stripURLCredentials(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		before, _, found := strings.Cut(raw, "?")
		before, _, _ = strings.Cut(before, "#")
		return before, found
	}
	hadQuery := u.RawQuery != "" || u.ForceQuery
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), hadQuery
}

// urlHasSASToken reports whether a URL carries an Azure shared access
// signature, which is always passed in the `sig` query parameter.
func urlHasSASToken(raw string) bool {
	if raw == "" {
		return false
	}
	_, query, found := strings.Cut(raw, "?")
	if !found {
		return false
	}
	query, _, _ = strings.Cut(query, "#")
	values, err := url.ParseQuery(query)
	if err != nil {
		// A query that does not parse still counts when it names a signature.
		return strings.Contains(strings.ToLower(query), "sig=")
	}
	for k := range values {
		if strings.EqualFold(k, "sig") {
			return true
		}
	}
	return false
}

// secretSettingKeyFragments are lower-cased fragments of a setting name that
// mark its value as a credential.
var secretSettingKeyFragments = []string{
	"password",
	"secret",
	"token",
	"sas",
	"accountkey",
	"storagekey",
	"workspacekey",
	"privatekey",
	"apikey",
	"connectionstring",
	"credential",
}

// isSecretSettingKey reports whether a setting name marks its value as a
// credential.
func isSecretSettingKey(key string) bool {
	k := strings.ToLower(key)
	if k == "key" {
		return true
	}
	for _, frag := range secretSettingKeyFragments {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return false
}

// redactSettings returns a copy of an extension's public settings with
// credential-looking values removed. Values under a key that names a
// credential are replaced with redactedValue, and URL values lose their user
// information and query string. The input is not modified.
func redactSettings(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSecretSettingKey(k) && val != nil {
				out[k] = redactedValue
				continue
			}
			out[k] = redactSettings(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = redactSettings(t[i])
		}
		return out
	case string:
		if strings.Contains(t, "://") {
			clean, _ := stripURLCredentials(t)
			return clean
		}
		return t
	default:
		return v
	}
}

// redactSettingsDict applies redactSettings to a settings dict.
func redactSettingsDict(settings map[string]any) map[string]any {
	if settings == nil {
		return nil
	}
	out, _ := redactSettings(settings).(map[string]any)
	return out
}

// classifyAzureRefusal wraps an ARM refusal (403) as a Forbidden error when
// structured errors are enabled, naming the permission the call needed. Any
// other error is returned unchanged.
func classifyAzureRefusal(err error, permissions ...string) error {
	if err == nil {
		return nil
	}
	if plugin.StructuredErrors() && isAzureAccessDenied(err) {
		return llx.Forbidden(err, llx.WithPermissions(permissions...))
	}
	return err
}

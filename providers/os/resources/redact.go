// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"regexp"
	"strings"
)

// redactedValue replaces a secret read from an AI tool's configuration. The
// key or flag it belonged to is kept, so a policy can still see that a secret
// is configured there.
const redactedValue = "<redacted>"

// urlRedactionPlaceholder stands in for redactedValue while a URL is
// re-encoded, since url.URL would percent-encode the angle brackets.
const urlRedactionPlaceholder = "MQLREDACTEDVALUE"

// secretKeySuffixes are the endings of a key, flag, header or env var name
// that holds a secret, compared after lowercasing and dropping separators. So
// GITHUB_PERSONAL_ACCESS_TOKEN, x-api-key and clientSecret all match, while
// apiKeyHelper (a script path) and max_tokens do not.
var secretKeySuffixes = []string{
	"token",
	"apikey",
	"secret",
	"password",
	"passwd",
	"passphrase",
	"authorization",
	"cookie",
	"privatekey",
	"accesskey",
	"credential",
	"credentials",
}

// secretQueryKeys are URL query parameters that carry a credential even though
// the name alone is too generic to treat as secret elsewhere, such as Google's
// `?key=`.
var secretQueryKeys = map[string]bool{
	"key":       true,
	"auth":      true,
	"sig":       true,
	"signature": true,
	"code":      true,
}

// secretHeaderMapKeys are settings keys whose value maps HTTP header names to
// header values. Every value in them is treated as a secret.
var secretHeaderMapKeys = map[string]bool{
	"headers":          true,
	"http_headers":     true,
	"httpheaders":      true,
	"env_http_headers": true,
}

// mcpServerMapKeys are settings keys under which AI tools declare MCP servers.
// An env block inside one of them is treated like the MCP server env handled
// by mcpServerSpec: every value is a secret.
var mcpServerMapKeys = map[string]bool{
	"mcpservers":      true,
	"mcp_servers":     true,
	"context_servers": true,
}

// knownTokenPattern matches credentials whose vendor prefix identifies them
// regardless of where they appear: OpenAI and Anthropic keys, GitHub, GitLab,
// Slack and Hugging Face tokens, AWS access key IDs and Google API keys.
var knownTokenPattern = regexp.MustCompile(
	`sk-[A-Za-z0-9_-]{20,}` +
		`|gh[pousr]_[A-Za-z0-9]{30,}` +
		`|github_pat_[A-Za-z0-9_]{30,}` +
		`|glpat-[A-Za-z0-9_-]{20,}` +
		`|xox[abposr]-[A-Za-z0-9-]{10,}` +
		`|hf_[A-Za-z0-9]{30,}` +
		`|AKIA[0-9A-Z]{16}` +
		`|AIza[0-9A-Za-z_-]{35}`)

// varRefPattern matches a value that only references a variable, such as
// ${GITHUB_TOKEN}, ${env:GITHUB_TOKEN}, {env:GITHUB_TOKEN} or $GITHUB_TOKEN.
// Such a value is not a secret, and keeping it tells a policy the secret is
// not written into the file.
var varRefPattern = regexp.MustCompile(`^(\$?\{(env:)?[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)$`)

func isSecretKey(name string) bool {
	compact := strings.NewReplacer("-", "", "_", "", ".", "", " ", "").Replace(strings.ToLower(name))
	if compact == "" {
		return false
	}
	for _, s := range secretKeySuffixes {
		if strings.HasSuffix(compact, s) {
			return true
		}
	}
	// A trailing "key" segment (STRIPE_KEY, x-key) names a key. A camelCase
	// "...Key" too often names a shortcut or an identifier, so only the
	// separated form counts.
	segments := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	return len(segments) > 1 && segments[len(segments)-1] == "key"
}

// isVarRef reports whether a value only references a variable, optionally
// after an HTTP auth scheme such as "Bearer ${TOKEN}".
func isVarRef(v string) bool {
	v = strings.TrimSpace(v)
	if scheme, rest, ok := strings.Cut(v, " "); ok {
		switch strings.ToLower(scheme) {
		case "bearer", "basic", "token":
			v = strings.TrimSpace(rest)
		}
	}
	return varRefPattern.MatchString(v)
}

// redactSecretValue returns redactedValue unless the value only references a
// variable.
func redactSecretValue(v string) string {
	if v == "" || isVarRef(v) {
		return v
	}
	return redactedValue
}

// redactURL removes the password from a URL's userinfo and the values of query
// parameters that carry a credential. A string that is not an absolute URL is
// returned with only known token shapes redacted.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return knownTokenPattern.ReplaceAllString(raw, redactedValue)
	}

	changed := false
	if u.User != nil {
		if pw, ok := u.User.Password(); ok && !isVarRef(pw) {
			u.User = url.UserPassword(u.User.Username(), urlRedactionPlaceholder)
			changed = true
		} else if !ok && knownTokenPattern.MatchString(u.User.Username()) {
			// A token used as the username, as in https://ghp_x@github.com.
			u.User = url.User(urlRedactionPlaceholder)
			changed = true
		}
	}

	if u.RawQuery != "" {
		q := u.Query()
		queryChanged := false
		for k, vals := range q {
			secretKey := isSecretKey(k) || secretQueryKeys[strings.ToLower(k)]
			for i, v := range vals {
				if isVarRef(v) {
					continue
				}
				if secretKey || knownTokenPattern.MatchString(v) {
					vals[i] = urlRedactionPlaceholder
					queryChanged = true
				}
			}
		}
		if queryChanged {
			u.RawQuery = q.Encode()
			changed = true
		}
	}

	out := raw
	if changed {
		out = strings.ReplaceAll(u.String(), urlRedactionPlaceholder, redactedValue)
	}
	return knownTokenPattern.ReplaceAllString(out, redactedValue)
}

// redactString redacts the secrets a free-form configuration string can hold:
// an "Authorization: Bearer ..." header line, a KEY=VALUE assignment whose key
// names a secret, credentials in a URL, and tokens with a known vendor prefix.
func redactString(s string) string {
	if name, value, ok := strings.Cut(s, ":"); ok && !strings.Contains(name, "/") && isSecretKey(strings.TrimSpace(name)) {
		if isVarRef(value) {
			return s
		}
		return name + ": " + redactedValue
	}
	if name, value, ok := strings.Cut(s, "="); ok && !strings.ContainsAny(name, " /") && isSecretKey(name) {
		return name + "=" + redactSecretValue(value)
	}
	return redactURL(s)
}

// redactArgs redacts the secrets in a command line: the value of a flag whose
// name names a secret, given as --flag=value or as the next argument, plus
// whatever redactString finds in each argument.
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	redactNext := false
	for i, a := range args {
		if redactNext && !strings.HasPrefix(a, "-") {
			out[i] = redactSecretValue(a)
			redactNext = false
			continue
		}
		redactNext = false

		if strings.HasPrefix(a, "-") {
			name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
			switch {
			case isSecretKey(name) && hasValue:
				out[i] = a[:len(a)-len(value)] + redactSecretValue(value)
			case isSecretKey(name):
				out[i] = a
				redactNext = true
			case hasValue:
				out[i] = a[:len(a)-len(value)] + redactString(value)
			default:
				out[i] = a
			}
			continue
		}
		out[i] = redactString(a)
	}
	return out
}

// redactSettings returns a copy of a parsed settings file with secret values
// replaced by redactedValue:
//   - values under a key that names a secret (an API key, a token, a password)
//   - every header value, and every env value inside an MCP server definition
//   - credentials in URLs and tokens with a known vendor prefix anywhere
//   - secrets in MCP server args
//
// Values that only reference a variable (${GITHUB_TOKEN}) are kept. Env values
// outside an MCP server definition are kept unless they look like a secret,
// because tools such as Claude Code configure non-secret behavior there
// (CLAUDE_CODE_USE_BEDROCK, DISABLE_TELEMETRY).
func redactSettings(settings map[string]any) map[string]any {
	if settings == nil {
		return nil
	}
	return redactSettingsMap(settings, false, false)
}

func redactSettingsMap(m map[string]any, inMcp, allSecret bool) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		lower := strings.ToLower(k)
		childInMcp := inMcp || mcpServerMapKeys[lower]
		childAllSecret := allSecret || secretHeaderMapKeys[lower] ||
			(inMcp && (lower == "env" || lower == "environment"))
		out[k] = redactSettingsValue(k, v, childInMcp, childAllSecret)
	}
	return out
}

func redactSettingsValue(key string, v any, inMcp, allSecret bool) any {
	switch t := v.(type) {
	case map[string]any:
		return redactSettingsMap(t, inMcp, allSecret)
	case []any:
		if strings.EqualFold(key, "args") && allStrings(t) {
			args := make([]string, len(t))
			for i, a := range t {
				args[i] = a.(string)
			}
			redacted := redactArgs(args)
			out := make([]any, len(redacted))
			for i, a := range redacted {
				out[i] = a
			}
			return out
		}
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactSettingsValue(key, e, inMcp, allSecret)
		}
		return out
	case string:
		if allSecret || isSecretKey(key) {
			return redactSecretValue(t)
		}
		return redactString(t)
	case nil, bool:
		return v
	default:
		// A number under a secret key (a PIN, a numeric token) is a secret too.
		if allSecret || isSecretKey(key) {
			return redactedValue
		}
		return v
	}
}

func allStrings(in []any) bool {
	for _, e := range in {
		if _, ok := e.(string); !ok {
			return false
		}
	}
	return true
}

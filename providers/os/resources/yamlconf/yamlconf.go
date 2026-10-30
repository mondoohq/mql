// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package yamlconf holds the reader shared by the YAML-shaped server
// configuration files, currently MongoDB's mongod.conf and Cassandra's
// cassandra.yaml. Both are a single nested YAML document with no include
// mechanism, so a parse reads exactly one file and the result is a tree
// rather than the flat key/value map the MySQL and PostgreSQL option files
// produce. A value is addressed by its key path ("net", "tls", "mode").
//
// The package operates on already-read file content so it doesn't depend on
// a particular filesystem implementation, which lets it be unit-tested
// against inlined fixtures and re-used over different transports (local,
// SSH, container snapshot, ...).
package yamlconf

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Parse reads the content of a YAML configuration file into a normalized
// tree. The name identifies the file in the error a malformed document
// produces.
//
// An empty file is not an error: both servers accept one and run entirely on
// their built-in defaults, so it parses to an empty tree and every accessor
// reports the default it would have used.
func Parse(content string, name string) (map[string]any, error) {
	var root any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return nil, err
	}

	if root == nil {
		return map[string]any{}, nil
	}

	params, ok := Normalize(root).(map[string]any)
	if !ok {
		// A YAML document whose root is a scalar or a sequence is not a
		// configuration file. Reporting it as an empty config would present
		// a malformed file as a server running on defaults.
		return nil, fmt.Errorf("%s must be a YAML mapping at the top level", name)
	}
	return params, nil
}

// Normalize rewrites a decoded YAML value into the JSON-native subset llx
// accepts for a dict. Numbers are the reason this exists: yaml.v3 decodes
// integers as `int`, which llx has no encoding for.
func Normalize(v any) any {
	switch x := v.(type) {
	case nil, bool, string, int64, float64:
		return x
	case int:
		return int64(x)
	case int8:
		return int64(x)
	case int16:
		return int64(x)
	case int32:
		return int64(x)
	case uint:
		return int64(x)
	case uint8:
		return int64(x)
	case uint16:
		return int64(x)
	case uint32:
		return int64(x)
	case uint64:
		// Values above the int64 ceiling are not representable. No server
		// setting is anywhere near it, so a string keeps the value visible
		// rather than silently wrapping it negative.
		if x > 1<<63-1 {
			return strconv.FormatUint(x, 10)
		}
		return int64(x)
	case float32:
		return float64(x)
	case time.Time:
		// YAML auto-detects unquoted ISO-8601 scalars as timestamps. No
		// server setting is a timestamp, so this only fires on a value that
		// happens to look like one, and the original text is what matters.
		return x.Format(time.RFC3339)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = Normalize(x[i])
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = Normalize(val)
		}
		return out
	case map[any]any:
		// yaml.v3 produces map[string]any for string keys, but a document
		// using non-string keys still decodes to this shape.
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprintf("%v", k)] = Normalize(val)
		}
		return out
	default:
		return fmt.Sprintf("%v", x)
	}
}

// ---------------------------------------------------------------------------
// lookups
// ---------------------------------------------------------------------------

// Lookup walks the key path and reports the value at it. The second return
// distinguishes an unset key from a key explicitly set to null, which matters
// because the accessors fall back to the server's own default only for the
// former.
func Lookup(params map[string]any, path ...string) (any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	cur := params
	for i, key := range path {
		v, ok := cur[key]
		if !ok {
			return nil, false
		}
		if i == len(path)-1 {
			return v, true
		}
		next, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return nil, false
}

// String reports the value at path as a string, empty when unset. Scalars
// that YAML typed as something other than a string are formatted back, so a
// numeric-looking setting still reads as written.
func String(params map[string]any, path ...string) string {
	v, ok := Lookup(params, path...)
	if !ok || v == nil {
		return ""
	}
	return ScalarString(v)
}

// Bool reports the value at path, falling back to def when the key is unset.
//
// The caller supplies the default rather than the function assuming false,
// because both servers default security-relevant settings to true. A
// hardcoded false fallback would report an unhardened host as hardened.
func Bool(params map[string]any, def bool, path ...string) bool {
	v, ok := Lookup(params, path...)
	if !ok || v == nil {
		return def
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		// Values are frequently written as quoted strings.
		b, err := strconv.ParseBool(strings.TrimSpace(x))
		if err != nil {
			return def
		}
		return b
	case int64:
		return x != 0
	default:
		return def
	}
}

// Int reports the value at path, falling back to def when the key is unset or
// holds something that is not a whole number.
func Int(params map[string]any, def int64, path ...string) int64 {
	v, ok := Lookup(params, path...)
	if !ok || v == nil {
		return def
	}
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return def
		}
		return n
	default:
		return def
	}
}

// List reports the value at path as a list of strings.
//
// It accepts both spellings the servers do. Several settings are documented
// as a single comma-delimited string but are commonly written as a YAML
// sequence, and the servers read either, so treating only the documented form
// would drop every entry on those hosts.
func List(params map[string]any, path ...string) []string {
	v, ok := Lookup(params, path...)
	if !ok || v == nil {
		return nil
	}
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s := strings.TrimSpace(ScalarString(item))
			if s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case string:
		return SplitList(x)
	default:
		s := strings.TrimSpace(ScalarString(v))
		if s == "" {
			return nil
		}
		return []string{s}
	}
}

// Mappings reports the value at path as a list of mappings, which is the
// shape Cassandra uses for the plugin blocks (seed_provider, key_provider,
// and the audit logger). A single mapping written without the leading dash is
// accepted too, since the server reads it.
func Mappings(params map[string]any, path ...string) []map[string]any {
	v, ok := Lookup(params, path...)
	if !ok || v == nil {
		return nil
	}
	switch x := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case map[string]any:
		return []map[string]any{x}
	default:
		return nil
	}
}

// SplitList splits a comma-delimited scalar into its entries, dropping blanks.
func SplitList(raw string) []string {
	out := []string{}
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ScalarString formats a normalized scalar back to the text it was written
// as, and reports empty for anything that is not a scalar.
func ScalarString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return ""
	}
}

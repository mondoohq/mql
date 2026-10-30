// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package firefox

import (
	"encoding/json"
	"maps"
	"strconv"
	"strings"
)

// RegistryValue is one named value inside a registry key.
type RegistryValue struct {
	// Name is the value's name, which is also the policy name at the top level.
	Name string
	// Kind is the registry type, spelled the way the registrykey resource
	// spells it: "string", "expandstring", "dword", "qword", "multistring",
	// "binary".
	Kind string
	// Data is the value read from the registry: a string for the string kinds,
	// an int64 for the numeric kinds, a []any of strings for multistring.
	Data any
}

// RegistryKey is a registry key with the values and child keys below it. It is
// the input to NormalizeRegistry, kept free of any MQL or Windows types so the
// normalization can be exercised without a Windows host.
type RegistryKey struct {
	// Name is the key's own name, not its full path. Empty for the root.
	Name string
	// Values are the value entries directly under this key.
	Values []RegistryValue
	// Children are the immediate sub-keys.
	Children []RegistryKey
}

// mergeableRegistryPolicies may be supplied either as a single value holding
// JSON or as a sub-key tree, and Firefox merges the two rather than letting one
// drop the other, with the value winning collisions. The list mirrors
// MERGEABLE_POLICIES in WindowsGPOParser.sys.mjs.
var mergeableRegistryPolicies = map[string]bool{
	"ExtensionSettings": true,
}

// numericPolicyPaths are the policy paths whose value is genuinely a number,
// dotted from the top-level policy name.
//
// This exists because a REG_DWORD is the only way the registry can carry a
// boolean, so nearly every DWORD backing a Firefox policy means true or false
// and has to be normalized to a bool — otherwise the same check needs `== true`
// on Linux and `== 1` on Windows, and the resource has bought nothing. Firefox
// makes that conversion from its policy schema (JsonSchemaValidator, type
// "boolean": a number that is 0 or 1 becomes !!param), and reproducing the
// conversion needs to know which policies are the exception.
//
// Embedding Mozilla's whole schema would be the tracking obligation this
// resource is designed to avoid, so only the exceptions are listed. They are
// few: of the 126 top-level policies in the current schema exactly two are
// number-typed, and both have enums that include 0 and 1, so getting them wrong
// would be visible. The paths were derived from
// browser/components/enterprisepolicies/schemas/policies-schema.json.
//
// The failure mode if Mozilla adds a number-typed policy and this list is not
// updated: a DWORD of 0 or 1 on that new policy reports as false/true instead
// of 0/1. That is a narrow, visible miss, and far cheaper than tracking all 126.
var numericPolicyPaths = map[string]bool{
	"ContentAnalysis.AgentTimeout":             true,
	"ContentAnalysis.DefaultResult":            true,
	"ContentAnalysis.MaxConnectionsCount":      true,
	"ContentAnalysis.TimeoutResult":            true,
	"DefaultSerialGuardSetting":                true,
	"PrivateBrowsingModeAvailability":          true,
	"Proxy.SOCKSVersion":                       true,
	"RelaunchRequired.NotificationPeriodHours": true,
	"RelaunchRequired.RestartTimeOfDay.Hour":   true,
	"RelaunchRequired.RestartTimeOfDay.Minute": true,
}

// numericPolicyPrefixes are policy subtrees whose leaves are numbers wherever
// they appear. Preferences is keyed by preference name and its values are typed
// ["number","boolean","string"] — number first, so Firefox's validator accepts a
// DWORD as a number and leaves it alone.
var numericPolicyPrefixes = []string{"Preferences"}

// NormalizeRegistry projects a registry key tree onto the same dict shape a
// policies.json file produces.
//
// The rules follow WindowsGPOParser.registryToObject: a value becomes a leaf, a
// sub-key becomes a nested object, and a key whose entries are named "1", "2",
// … is an array rather than an object. On top of that sits the type coercion
// Firefox performs afterwards from its policy schema, which is what turns a
// REG_DWORD into a bool and a JSON-bearing REG_SZ into an object.
//
// It returns nil when the key contributes nothing, so an empty or absent key is
// a resolved "no configuration" rather than an empty object.
func NormalizeRegistry(key RegistryKey) map[string]any {
	normalized, _ := normalizeKey(key, "")
	res, ok := normalized.(map[string]any)
	if !ok || len(res) == 0 {
		return nil
	}
	return res
}

// normalizeKey converts one key and everything below it. path is the dotted
// policy path of the key itself, empty at the root.
func normalizeKey(key RegistryKey, path string) (any, bool) {
	// A key whose entries are numbered from 1 is an array. Firefox decides this
	// by looking at whether the first enumerated entry is named "1"; we require
	// the whole set to be 1..n instead, because the order entries come back in
	// is not something we control off-host, and a partial match would silently
	// produce a differently shaped result.
	if values, ok := numberedValues(key, path); ok {
		return values, true
	}
	if children, ok := numberedChildren(key, path); ok {
		return children, true
	}

	res := map[string]any{}
	for _, value := range key.Values {
		normalized, ok := normalizeValue(value, joinPolicyPath(path, value.Name))
		if !ok {
			// Firefox drops a value it cannot make sense of rather than
			// recording it as null, and so do we: a key absent from params
			// reads as "not configured", which is the honest answer.
			continue
		}
		res[value.Name] = normalized
	}

	for _, child := range key.Children {
		normalized, ok := normalizeKey(child, joinPolicyPath(path, child.Name))
		if !ok {
			continue
		}
		// A policy that can arrive both as a JSON-bearing value and as a
		// sub-key of the same name is merged, with the value winning, so
		// neither form can silently drop the other.
		if mergeableRegistryPolicies[child.Name] {
			if merged, ok := mergeMergeable(res[child.Name], normalized); ok {
				res[child.Name] = merged
				continue
			}
		}
		res[child.Name] = normalized
	}

	if len(res) == 0 {
		return nil, false
	}
	return res, true
}

// mergeMergeable combines the value form and the sub-key form of a mergeable
// policy. The value's entries win, mirroring `{ ...value, ...existing }`.
func mergeMergeable(existing, fromSubkey any) (any, bool) {
	subkeyObj, ok := fromSubkey.(map[string]any)
	if !ok {
		return nil, false
	}

	// The value form may still be an unparsed JSON string when it did not open
	// as an object or array.
	if raw, isString := existing.(string); isString {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			return nil, false
		}
		existing = parsed
	}

	existingObj, ok := existing.(map[string]any)
	if !ok {
		return nil, false
	}

	res := make(map[string]any, len(subkeyObj)+len(existingObj))
	maps.Copy(res, subkeyObj)
	maps.Copy(res, existingObj)
	return res, true
}

// numberedValues recognizes a key whose values are named 1..n and returns them
// as an array.
func numberedValues(key RegistryKey, path string) ([]any, bool) {
	if len(key.Values) == 0 || len(key.Children) > 0 {
		return nil, false
	}
	names := make([]string, 0, len(key.Values))
	for _, v := range key.Values {
		names = append(names, v.Name)
	}
	if !isNumberedSet(names) {
		return nil, false
	}

	byName := make(map[string]RegistryValue, len(key.Values))
	for _, v := range key.Values {
		byName[v.Name] = v
	}

	res := make([]any, 0, len(names))
	for i := 1; i <= len(names); i++ {
		// Array entries share the schema of the list they are in, so the index
		// contributes nothing to the policy path.
		normalized, ok := normalizeValue(byName[strconv.Itoa(i)], path)
		if !ok {
			continue
		}
		res = append(res, normalized)
	}
	return res, true
}

// numberedChildren recognizes a key whose sub-keys are named 1..n and returns
// them as an array of objects.
func numberedChildren(key RegistryKey, path string) ([]any, bool) {
	if len(key.Children) == 0 || len(key.Values) > 0 {
		return nil, false
	}
	names := make([]string, 0, len(key.Children))
	for _, c := range key.Children {
		names = append(names, c.Name)
	}
	if !isNumberedSet(names) {
		return nil, false
	}

	byName := make(map[string]RegistryKey, len(key.Children))
	for _, c := range key.Children {
		byName[c.Name] = c
	}

	res := make([]any, 0, len(names))
	for i := 1; i <= len(names); i++ {
		normalized, ok := normalizeKey(byName[strconv.Itoa(i)], path)
		if !ok {
			continue
		}
		res = append(res, normalized)
	}
	return res, true
}

// isNumberedSet reports whether names is exactly the set "1".."n".
func isNumberedSet(names []string) bool {
	seen := make(map[int]bool, len(names))
	for _, name := range names {
		n, err := strconv.Atoi(name)
		if err != nil || n < 1 || n > len(names) || seen[n] {
			return false
		}
		seen[n] = true
	}
	return len(seen) == len(names)
}

// normalizeValue converts one registry value into the shape the equivalent
// entry has in a policies.json file.
func normalizeValue(value RegistryValue, path string) (any, bool) {
	switch value.Kind {
	case "multistring":
		// A REG_MULTI_SZ backing a policy is always JSON — Firefox parses it
		// unconditionally and discards the value when it does not parse.
		raw, ok := value.Data.(string)
		if !ok {
			raw = strings.Join(multiStringParts(value.Data), "\n")
		}
		var parsed any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			return nil, false
		}
		return parsed, true

	case "string", "expandstring":
		raw, ok := value.Data.(string)
		if !ok {
			return value.Data, true
		}
		// An object- or array-typed policy delivered through the registry
		// arrives as a string holding JSON, and Firefox's schema validator
		// parses it. This is what makes a Preferences entry such as
		//   security.default_personal_cert = {"Value":"…","Status":"locked"}
		// come out byte-identical to the same entry in a policies.json file,
		// instead of a string a policy author has to match with a regex.
		//
		// Only a value that opens as a JSON object or array is parsed. A
		// string-typed policy is left alone, so SSLVersionMin stays "tls1.2"
		// and a value of "true" stays the string "true" rather than turning
		// into a bool that was never in the registry.
		if parsed, ok := parseJSONObjectOrArray(raw); ok {
			return parsed, true
		}
		return raw, true

	case "dword", "qword":
		number, ok := toInt64(value.Data)
		if !ok {
			return value.Data, true
		}
		if isNumericPolicy(path) {
			return number, true
		}
		// 0 and 1 are how the registry spells false and true. Any other number
		// cannot be a boolean, so it stays a number.
		if number == 0 || number == 1 {
			return number == 1, true
		}
		return number, true

	default:
		if value.Data == nil {
			return nil, false
		}
		return value.Data, true
	}
}

// parseJSONObjectOrArray parses raw when, and only when, it is a JSON object or
// array.
func parseJSONObjectOrArray(raw string) (any, bool) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return nil, false
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

func multiStringParts(data any) []string {
	parts, ok := data.([]any)
	if !ok {
		return nil
	}
	res := make([]string, 0, len(parts))
	for _, part := range parts {
		if s, ok := part.(string); ok {
			res = append(res, s)
		}
	}
	return res
}

func toInt64(data any) (int64, bool) {
	switch v := data.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case float64:
		return int64(v), true
	default:
		return 0, false
	}
}

func isNumericPolicy(path string) bool {
	if numericPolicyPaths[path] {
		return true
	}
	for _, prefix := range numericPolicyPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+".") {
			return true
		}
	}
	return false
}

func joinPolicyPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

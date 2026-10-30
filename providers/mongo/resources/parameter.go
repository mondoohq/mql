// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// parameterValue renders a getParameter value as a string. Scalars keep their
// plain form ("10000", "true", "SCRAM-SHA-256"). Arrays and documents render as
// relaxed extended JSON (["SCRAM-SHA-1","SCRAM-SHA-256"]), since Go's own
// formatting of them ([SCRAM-SHA-1 SCRAM-SHA-256], map[...]) is ambiguous and
// cannot be parsed back.
func parameterValue(v any) string {
	switch v.(type) {
	case bson.A, []any, bson.D, bson.M, map[string]any:
	default:
		return toStr(v)
	}
	out, err := bson.MarshalExtJSON(bson.D{{Key: "v", Value: canonicalBSON(v)}}, false, false)
	if err != nil {
		return toStr(v)
	}
	s := string(out)
	s = strings.TrimPrefix(s, `{"v":`)
	s = strings.TrimSuffix(s, "}")
	return s
}

// canonicalBSON turns maps into documents with sorted keys, recursively, so
// the rendered value is stable from run to run.
func canonicalBSON(v any) any {
	switch t := v.(type) {
	case bson.M:
		return sortedDoc(t)
	case map[string]any:
		return sortedDoc(t)
	case bson.D:
		out := make(bson.D, 0, len(t))
		for _, e := range t {
			out = append(out, bson.E{Key: e.Key, Value: canonicalBSON(e.Value)})
		}
		return out
	case bson.A:
		out := make(bson.A, 0, len(t))
		for _, x := range t {
			out = append(out, canonicalBSON(x))
		}
		return out
	case []any:
		out := make(bson.A, 0, len(t))
		for _, x := range t {
			out = append(out, canonicalBSON(x))
		}
		return out
	default:
		return v
	}
}

func sortedDoc(m map[string]any) bson.D {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(bson.D, 0, len(keys))
	for _, k := range keys {
		out = append(out, bson.E{Key: k, Value: canonicalBSON(m[k])})
	}
	return out
}

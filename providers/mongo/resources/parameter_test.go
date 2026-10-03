// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Values as getParameter '*' returns them on MongoDB 8.0.32, decoded by the
// driver the way parameters() decodes them.
func TestParameterValue(t *testing.T) {
	raw := []byte(`{
		"authenticationMechanisms": ["MONGODB-X509", "SCRAM-SHA-1", "SCRAM-SHA-256"],
		"diagnosticDataCollectionStatsNamespaces": [],
		"featureCompatibilityVersion": {"version": "8.0"},
		"mirrorReads": {"samplingRate": 0.01, "maxTimeMS": {"$numberInt": "1000"}},
		"scramIterationCount": {"$numberInt": "10000"},
		"authenticationMechanismsCaseSensitive": true,
		"clusterAuthMode": "undefined"
	}`)
	var res bson.M
	if err := bson.UnmarshalExtJSON(raw, false, &res); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"authenticationMechanisms":                `["MONGODB-X509","SCRAM-SHA-1","SCRAM-SHA-256"]`,
		"diagnosticDataCollectionStatsNamespaces": `[]`,
		"featureCompatibilityVersion":             `{"version":"8.0"}`,
		"mirrorReads":                             `{"samplingRate":0.01,"maxTimeMS":1000}`,
		"scramIterationCount":                     `10000`,
		"authenticationMechanismsCaseSensitive":   `true`,
		"clusterAuthMode":                         `undefined`,
	}
	for name, w := range want {
		if got := parameterValue(res[name]); got != w {
			t.Errorf("%s = %s, want %s", name, got, w)
		}
	}
}

func TestParameterValueSortsMapKeys(t *testing.T) {
	m := bson.M{"b": int32(2), "a": bson.M{"d": true, "c": "x"}}
	for i := 0; i < 20; i++ {
		if got := parameterValue(m); got != `{"a":{"c":"x","d":true},"b":2}` {
			t.Fatalf("run %d: %s", i, got)
		}
	}
}

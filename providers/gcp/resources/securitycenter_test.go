// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	sccpb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
)

// assertDictSerializable mirrors llx's dict2primitive allow-list: a value stored
// in an mql dict/[]dict field must be one of bool/int64/float64/string/[]any/
// map[string]any/nil. Anything else (int32, []string, map[string]string, *T)
// errors at query time with "unsupported child type". This guards the class of
// bug where a hand-built dict embeds a non-JSON-native value.
func assertDictSerializable(t *testing.T, path string, v any) {
	t.Helper()
	switch x := v.(type) {
	case nil, bool, int64, float64, string:
		// native scalar, ok
	case []any:
		for _, e := range x {
			assertDictSerializable(t, path+"[]", e)
		}
	case map[string]any:
		for k, e := range x {
			assertDictSerializable(t, path+"."+k, e)
		}
	default:
		t.Errorf("dict value at %q has non-serializable type %T (would error at query time)", path, v)
	}
}

func TestSecuritycenterDictBuildersAreSerializable(t *testing.T) {
	// Populate the []string/float64 fields that previously shipped as-is.
	chokepoint := chokepointToDict(&sccpb.Chokepoint{
		RelatedFindings: []string{"organizations/1/sources/2/findings/3", "f4"},
	})
	assertDictSerializable(t, "chokepoint", chokepoint)

	toxic := toxicCombinationToDict(&sccpb.ToxicCombination{
		AttackExposureScore: 8.5,
		RelatedFindings:     []string{"f1", "f2"},
	})
	assertDictSerializable(t, "toxicCombination", toxic)

	exposure := externalExposureToDict(&sccpb.ExternalExposure{
		PrivateIpAddress: "10.0.0.1",
		PrivatePort:      "8080",
		PublicIpAddress:  "203.0.113.1",
		PublicPort:       "443",
	})
	assertDictSerializable(t, "externalExposure", exposure)
}

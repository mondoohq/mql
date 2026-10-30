// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestStringValue(t *testing.T) {
	t.Run("nil returns empty string", func(t *testing.T) {
		assert.Equal(t, "", stringValue(nil))
	})

	t.Run("non-nil returns value", func(t *testing.T) {
		s := "hello"
		assert.Equal(t, "hello", stringValue(&s))
	})

	t.Run("empty string pointer returns empty string", func(t *testing.T) {
		s := ""
		assert.Equal(t, "", stringValue(&s))
	})
}

func TestBoolValue(t *testing.T) {
	t.Run("nil returns false", func(t *testing.T) {
		assert.False(t, boolValue(nil))
	})

	t.Run("true pointer returns true", func(t *testing.T) {
		b := true
		assert.True(t, boolValue(&b))
	})

	t.Run("false pointer returns false", func(t *testing.T) {
		b := false
		assert.False(t, boolValue(&b))
	})
}

func TestInt64Value(t *testing.T) {
	t.Run("nil returns 0", func(t *testing.T) {
		assert.Equal(t, int64(0), int64Value(nil))
	})

	t.Run("non-nil returns value", func(t *testing.T) {
		i := int64(42)
		assert.Equal(t, int64(42), int64Value(&i))
	})

	t.Run("zero pointer returns 0", func(t *testing.T) {
		i := int64(0)
		assert.Equal(t, int64(0), int64Value(&i))
	})
}

func TestIntValue(t *testing.T) {
	t.Run("nil returns 0", func(t *testing.T) {
		assert.Equal(t, int64(0), intValue(nil))
	})

	t.Run("non-nil returns value as int64", func(t *testing.T) {
		i := 42
		assert.Equal(t, int64(42), intValue(&i))
	})
}

func TestOciResourceTypeFromOCID(t *testing.T) {
	tests := []struct {
		name string
		ocid string
		want string
	}{
		{"internet gateway", "ocid1.internetgateway.oc1.iad.aaaaaaaaexample", "internetgateway"},
		{"drg", "ocid1.drg.oc1.phx.aaaaaaaaexample", "drg"},
		{"private ip", "ocid1.privateip.oc1.iad.aaaaaaaaexample", "privateip"},
		{"empty string", "", ""},
		{"no dots", "ocid1", ""},
		{"only ocid1 prefix", "ocid1.", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociResourceTypeFromOCID(tt.ocid))
		})
	}
}

func TestOciRouteTargetType(t *testing.T) {
	tests := []struct {
		name string
		ocid string
		want string
	}{
		{"internet gateway", "ocid1.internetgateway.oc1.iad.aaaa", "INTERNET_GATEWAY"},
		{"nat gateway", "ocid1.natgateway.oc1.iad.aaaa", "NAT_GATEWAY"},
		{"service gateway", "ocid1.servicegateway.oc1.iad.aaaa", "SERVICE_GATEWAY"},
		{"drg", "ocid1.drg.oc1.iad.aaaa", "DRG"},
		{"local peering gateway", "ocid1.localpeeringgateway.oc1.iad.aaaa", "LOCAL_PEERING_GATEWAY"},
		{"private ip", "ocid1.privateip.oc1.iad.aaaa", "PRIVATE_IP"},
		{"unknown type falls back to uppercased raw type", "ocid1.dynamicroutingentity.oc1.iad.aaaa", "DYNAMICROUTINGENTITY"},
		{"malformed OCID", "not-an-ocid", ""},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociRouteTargetType(tt.ocid))
		})
	}
}

func TestOciRegionFromOCID(t *testing.T) {
	tests := []struct {
		name string
		ocid string
		want string
	}{
		{"short region key", "ocid1.instance.oc1.iad.aaaaaaaa", "iad"},
		{"full region name", "ocid1.vcn.oc1.us-sanjose-1.aaaaaaaa", "us-sanjose-1"},
		// Global resources carry an empty region segment; callers must fall
		// back to a known region rather than build a client for "".
		{"global ocid", "ocid1.user.oc1..aaaaaaaa", ""},
		{"too few segments", "ocid1.drg.oc1", ""},
		{"not an ocid", "ORACLE_MANAGED_KEY", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociRegionFromOCID(tt.ocid))
		})
	}
}

func TestIsOcid(t *testing.T) {
	// The guard that keeps OCI's placeholder values out of NewResource
	// lookups, where they surface as a hard "not found" instead of a null.
	assert.True(t, isOcid("ocid1.vault.oc1.iad.aaaaaaaa"))
	assert.False(t, isOcid("ORACLE_MANAGED_KEY"))
	assert.False(t, isOcid(""))
	assert.False(t, isOcid("ocid2.vault.oc1.iad.aaaa"))
	assert.False(t, isOcid("my-vault"))
}

func TestSdkTimeData(t *testing.T) {
	assert.Equal(t, llx.NilData, sdkTimeData(nil))

	ts := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	got := sdkTimeData(&common.SDKTime{Time: ts})
	require.NotNil(t, got)
	assert.Equal(t, ts, *(got.Value.(*time.Time)))
}

func TestDefinedTagsToAny(t *testing.T) {
	assert.Empty(t, definedTagsToAny(nil))

	out := definedTagsToAny(map[string]map[string]any{
		"Operations": {"CostCenter": "42", "Reviewed": true},
	})
	ns, ok := out["Operations"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "42", ns["CostCenter"])
	// Non-string values pass through unchanged rather than being dropped.
	assert.Equal(t, true, ns["Reviewed"])
}

func TestStringsToAnyAndStrMapToAny(t *testing.T) {
	assert.Equal(t, []any{}, stringsToAny(nil))
	assert.Equal(t, []any{"a", "b"}, stringsToAny([]string{"a", "b"}))

	assert.Empty(t, strMapToAny(nil))
	assert.Equal(t, map[string]any{"k": "v"}, strMapToAny(map[string]string{"k": "v"}))
}

// The tag helpers replaced a copy loop that had been written out by hand at 64
// listers. These pin the property that made that replacement safe: the helper
// returns what the loop returned. Written as the loop, not as a literal, so the
// comparison keeps meaning if either side is ever changed.

func TestStrMapToAnyMatchesInlineCopy(t *testing.T) {
	for _, in := range []map[string]string{
		nil,
		{},
		{"env": "prod"},
		{"env": "prod", "owner": "platform", "": "empty-key"},
	} {
		want := make(map[string]any, len(in))
		for k, v := range in {
			want[k] = v
		}
		assert.Equal(t, want, strMapToAny(in))
	}
}

func TestDefinedTagsToAnyMatchesInlineCopy(t *testing.T) {
	for _, in := range []map[string]map[string]any{
		nil,
		{},
		{"Operations": {"CostCenter": "42"}},
		{
			"Operations": {"CostCenter": "42", "Reviewed": true, "Count": 7},
			"Empty":      {},
		},
	} {
		want := make(map[string]any, len(in))
		for k, v := range in {
			want[k] = v
		}

		got := definedTagsToAny(in)

		// Equal, not Same: the helper rebuilds each namespace map instead of
		// aliasing the SDK's, so it does not hand MQL a map the SDK still owns.
		// The contents are what has to match.
		assert.Equal(t, len(want), len(got))
		for ns, kv := range want {
			assert.EqualValues(t, kv, got[ns])
		}
	}
}

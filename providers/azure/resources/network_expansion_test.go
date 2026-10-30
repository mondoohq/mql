// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	trafficmanager "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrafficManagerProfileRecordType(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    any
	}{
		{"record type set", `{"properties":{"recordType":"CNAME"}}`, "CNAME"},
		{"AAAA record type", `{"properties":{"recordType":"AAAA"}}`, "AAAA"},
		{"record type null", `{"properties":{"recordType":null}}`, nil},
		{"record type absent", `{"properties":{"profileStatus":"Enabled"}}`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p trafficmanager.Profile
			require.NoError(t, json.Unmarshal([]byte(tc.payload), &p))
			got := trafficManagerProfileRecordType(p.Properties)
			assert.Equal(t, tc.want, got.Value)
		})
	}

	t.Run("nil properties", func(t *testing.T) {
		assert.Nil(t, trafficManagerProfileRecordType(nil).Value)
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertLogConfiguration(t *testing.T) {
	t.Run("nil config returns nil", func(t *testing.T) {
		result, err := convertLogConfiguration(nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("archiving is carried through", func(t *testing.T) {
		// Archiving is the third field on the SDK's Configuration and was
		// dropped entirely, so log-archiving state read as "not configured"
		// on every log in the tenancy.
		enabled := true
		result, err := convertLogConfiguration(&logging.Configuration{
			Archiving: &logging.Archiving{IsEnabled: &enabled},
		})
		require.NoError(t, err)
		archiving, ok := result["archiving"].(map[string]any)
		require.True(t, ok, "archiving key must be present")
		assert.Equal(t, true, archiving["isEnabled"])
	})

	t.Run("absent archiving omits the key", func(t *testing.T) {
		result, err := convertLogConfiguration(&logging.Configuration{})
		require.NoError(t, err)
		assert.NotContains(t, result, "archiving")
	})

	t.Run("empty config returns empty map", func(t *testing.T) {
		cfg := &logging.Configuration{}
		result, err := convertLogConfiguration(cfg)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("config with compartment ID", func(t *testing.T) {
		cfg := &logging.Configuration{
			CompartmentId: new("ocid1.compartment.oc1..example"),
		}
		result, err := convertLogConfiguration(cfg)
		require.NoError(t, err)
		assert.Equal(t, "ocid1.compartment.oc1..example", result["compartmentId"])
	})

	t.Run("config with source", func(t *testing.T) {
		cfg := &logging.Configuration{
			Source: &logging.OciService{
				Service:  new("flowlogs"),
				Resource: new("ocid1.subnet.oc1..example"),
				Category: new("all"),
			},
		}
		result, err := convertLogConfiguration(cfg)
		require.NoError(t, err)
		source, ok := result["source"].(map[string]any)
		require.True(t, ok, "source should be a map")
		assert.Equal(t, "flowlogs", source["service"])
		assert.Equal(t, "ocid1.subnet.oc1..example", source["resource"])
		assert.Equal(t, "all", source["category"])
	})

	t.Run("config with all fields", func(t *testing.T) {
		cfg := &logging.Configuration{
			CompartmentId: new("ocid1.compartment.oc1..example"),
			Source: &logging.OciService{
				Service:  new("objectstorage"),
				Resource: new("ocid1.bucket.oc1..example"),
				Category: new("write"),
			},
		}
		result, err := convertLogConfiguration(cfg)
		require.NoError(t, err)
		assert.Equal(t, "ocid1.compartment.oc1..example", result["compartmentId"])
		assert.NotNil(t, result["source"])
	})
}

// nonOciSource stands in for a hypothetical non-OciService source type.
// OciService is the only modeled logging source today, so the extractor must
// return empty values when the source is something else.
type nonOciSource struct{}

func TestExtractLogSource(t *testing.T) {
	tests := []struct {
		name         string
		cfg          *logging.Configuration
		wantCategory string
		wantService  string
		wantResource string
	}{
		{
			name: "nil configuration",
			cfg:  nil,
		},
		{
			name: "nil source",
			cfg:  &logging.Configuration{},
		},
		{
			name: "OciService flow log",
			cfg: &logging.Configuration{
				Source: logging.OciService{
					Service:  new("flowlogs"),
					Resource: new("ocid1.subnet.oc1..example"),
					Category: new("all"),
				},
			},
			wantCategory: "all",
			wantService:  "flowlogs",
			wantResource: "ocid1.subnet.oc1..example",
		},
		{
			name: "OciService with only service set",
			cfg: &logging.Configuration{
				Source: logging.OciService{
					Service: new("objectstorage"),
				},
			},
			wantService: "objectstorage",
		},
		{
			name: "non-OciService source returns empty strings",
			cfg: &logging.Configuration{
				Source: nonOciSource{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			category, service, resource := extractLogSource(tc.cfg)
			assert.Equal(t, tc.wantCategory, category)
			assert.Equal(t, tc.wantService, service)
			assert.Equal(t, tc.wantResource, resource)
		})
	}
}

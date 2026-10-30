// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	cosmos "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v4"
	"github.com/stretchr/testify/assert"
)

// newAzureResponseError builds an *azcore.ResponseError populated as the
// azcore runtime would after parsing a real ARM JSON error body. The
// RawResponse is fully populated (request, URL, body) so rerr.Error()
// renders the same multi-line message that real callers see, including
// the JSON body — that is what the substring match in
// isCosmosServerlessThroughputError reads.
func newAzureResponseError(statusCode int, errorCode, message string) *azcore.ResponseError {
	body := fmt.Sprintf(`{"code":%q,"message":%q}`, errorCode, message)
	reqURL, _ := url.Parse("https://example.documents.azure.com/dbs/x/throughputSettings/default")
	resp := &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request: &http.Request{
			Method: http.MethodGet,
			URL:    reqURL,
		},
	}
	return &azcore.ResponseError{
		ErrorCode:   errorCode,
		StatusCode:  statusCode,
		RawResponse: resp,
	}
}

func TestCosmosAccountResourceGroup(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		wantSub     string
		wantRG      string
		wantAccount string
		wantErr     bool
	}{
		{
			name:        "well-formed account id",
			id:          "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.DocumentDB/databaseAccounts/myacct",
			wantSub:     "00000000-0000-0000-0000-000000000000",
			wantRG:      "my-rg",
			wantAccount: "myacct",
		},
		{
			name:    "missing databaseAccounts segment",
			id:      "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.DocumentDB",
			wantErr: true,
		},
		{
			name:    "malformed id",
			id:      "not-an-arm-id",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sub, rg, acct, err := cosmosAccountResourceGroup(tc.id)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantSub, sub)
			assert.Equal(t, tc.wantRG, rg)
			assert.Equal(t, tc.wantAccount, acct)
		})
	}
}

func TestThroughputFromResource(t *testing.T) {
	t.Run("nil props returns zero", func(t *testing.T) {
		manual, auto, autoEnabled, shared := throughputFromResource(nil)
		assert.Equal(t, int32(0), manual)
		assert.Equal(t, int32(0), auto)
		assert.False(t, autoEnabled)
		assert.False(t, shared)
	})

	t.Run("manual throughput only", func(t *testing.T) {
		tp := int32(400)
		props := &cosmos.ThroughputSettingsGetProperties{
			Resource: &cosmos.ThroughputSettingsGetPropertiesResource{
				Throughput: &tp,
			},
		}
		manual, auto, autoEnabled, shared := throughputFromResource(props)
		assert.Equal(t, int32(400), manual)
		assert.Equal(t, int32(0), auto)
		assert.False(t, autoEnabled)
		assert.False(t, shared)
	})

	t.Run("autoscale only", func(t *testing.T) {
		max := int32(4000)
		props := &cosmos.ThroughputSettingsGetProperties{
			Resource: &cosmos.ThroughputSettingsGetPropertiesResource{
				AutoscaleSettings: &cosmos.AutoscaleSettingsResource{
					MaxThroughput: &max,
				},
			},
		}
		manual, auto, autoEnabled, shared := throughputFromResource(props)
		assert.Equal(t, int32(0), manual)
		assert.Equal(t, int32(4000), auto)
		assert.True(t, autoEnabled)
		assert.False(t, shared)
	})
}

func TestIsCosmosNotFoundError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.False(t, isCosmosNotFoundError(nil))
	})
	t.Run("non-azcore error", func(t *testing.T) {
		assert.False(t, isCosmosNotFoundError(errors.New("boom")))
	})
	t.Run("404 azcore.ResponseError", func(t *testing.T) {
		assert.True(t, isCosmosNotFoundError(&azcore.ResponseError{StatusCode: http.StatusNotFound}))
	})
	t.Run("403 not treated as not-found", func(t *testing.T) {
		assert.False(t, isCosmosNotFoundError(&azcore.ResponseError{StatusCode: http.StatusForbidden}))
	})
}

func TestIsCosmosServerlessThroughputError(t *testing.T) {
	const serverlessMsg = "Reading or replacing offers is not supported for serverless accounts."

	t.Run("nil error", func(t *testing.T) {
		assert.False(t, isCosmosServerlessThroughputError(nil))
	})
	t.Run("non-azcore error", func(t *testing.T) {
		assert.False(t, isCosmosServerlessThroughputError(errors.New("boom")))
	})
	t.Run("404 not treated as serverless", func(t *testing.T) {
		err := newAzureResponseError(http.StatusNotFound, "NotFound", serverlessMsg)
		assert.False(t, isCosmosServerlessThroughputError(err))
	})
	t.Run("400 with serverless message", func(t *testing.T) {
		err := newAzureResponseError(http.StatusBadRequest, "BadRequest", serverlessMsg)
		assert.True(t, isCosmosServerlessThroughputError(err))
	})
	t.Run("400 with empty ErrorCode still matches via body", func(t *testing.T) {
		// Older SDK responses may not surface ErrorCode.
		err := newAzureResponseError(http.StatusBadRequest, "", serverlessMsg)
		assert.True(t, isCosmosServerlessThroughputError(err))
	})
	t.Run("400 with unrelated BadRequest message is not treated as serverless", func(t *testing.T) {
		err := newAzureResponseError(http.StatusBadRequest, "BadRequest", "Invalid throughput value")
		assert.False(t, isCosmosServerlessThroughputError(err))
	})
	t.Run("400 with specific ErrorCode unrelated to BadRequest is rejected", func(t *testing.T) {
		err := newAzureResponseError(http.StatusBadRequest, "InvalidInput", serverlessMsg)
		assert.False(t, isCosmosServerlessThroughputError(err))
	})
	t.Run("error wrapping does not pick up outer wrapper text", func(t *testing.T) {
		// An outer wrapper that *does not* mention "serverless" must still
		// match because we look at the unwrapped rerr.Error(), not err.Error().
		rerr := newAzureResponseError(http.StatusBadRequest, "BadRequest", serverlessMsg)
		wrapped := fmt.Errorf("failed to fetch Cosmos DB SQL database throughput: %w", rerr)
		assert.True(t, isCosmosServerlessThroughputError(wrapped))
	})
	t.Run("wrapper substring alone is not enough", func(t *testing.T) {
		// If the inner ResponseError body does not contain "serverless" but
		// the outer wrapper happens to, we must reject — otherwise the check
		// silently passes through any 400 simply because a caller mentioned
		// the word in a wrapping message.
		rerr := newAzureResponseError(http.StatusBadRequest, "BadRequest", "Invalid throughput value")
		wrapped := fmt.Errorf("serverless probe failed: %w", rerr)
		assert.False(t, isCosmosServerlessThroughputError(wrapped))
	})
}

func TestCosmosNetworkConsistency(t *testing.T) {
	t.Run("nil props returns nils and empty slices", func(t *testing.T) {
		dcl, bypass, cors, locs := cosmosNetworkConsistency(nil)
		assert.Nil(t, dcl)
		assert.Nil(t, bypass)
		assert.Equal(t, []any{}, cors)
		assert.Equal(t, []any{}, locs)
	})

	t.Run("populated props map to typed values", func(t *testing.T) {
		strong := cosmos.DefaultConsistencyLevelStrong
		bypassNone := cosmos.NetworkACLBypassNone
		origin1, origin2 := "https://example.com", "*"
		east, west := "East US", "West US"
		props := &cosmos.DatabaseAccountGetProperties{
			ConsistencyPolicy: &cosmos.ConsistencyPolicy{DefaultConsistencyLevel: &strong},
			NetworkACLBypass:  &bypassNone,
			Cors: []*cosmos.CorsPolicy{
				{AllowedOrigins: &origin1},
				{AllowedOrigins: &origin2},
				{AllowedOrigins: nil},
			},
			Locations: []*cosmos.Location{
				{LocationName: &east},
				{LocationName: &west},
				nil,
			},
		}
		dcl, bypass, cors, locs := cosmosNetworkConsistency(props)
		assert.Equal(t, "Strong", *dcl)
		assert.Equal(t, "None", *bypass)
		assert.Equal(t, []any{"https://example.com", "*"}, cors)
		assert.Equal(t, []any{"East US", "West US"}, locs)
	})

	t.Run("nil consistency policy leaves level nil", func(t *testing.T) {
		dcl, _, _, _ := cosmosNetworkConsistency(&cosmos.DatabaseAccountGetProperties{})
		assert.Nil(t, dcl)
	})
}

func TestIsCosmosForbiddenError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.False(t, isCosmosForbiddenError(nil))
	})
	t.Run("403 azcore.ResponseError", func(t *testing.T) {
		assert.True(t, isCosmosForbiddenError(&azcore.ResponseError{StatusCode: http.StatusForbidden}))
	})
	t.Run("404 not treated as forbidden", func(t *testing.T) {
		assert.False(t, isCosmosForbiddenError(&azcore.ResponseError{StatusCode: http.StatusNotFound}))
	})
}

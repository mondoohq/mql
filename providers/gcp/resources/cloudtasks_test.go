// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestConvertCloudTasksHttpTarget_Nil(t *testing.T) {
	assert.Nil(t, convertCloudTasksHttpTarget(nil))
}

func TestConvertCloudTasksHttpTarget_Full(t *testing.T) {
	scheme := cloudtaskspb.UriOverride_HTTPS
	ht := &cloudtaskspb.HttpTarget{
		HttpMethod: cloudtaskspb.HttpMethod_PUT,
		UriOverride: &cloudtaskspb.UriOverride{
			Scheme:                 &scheme,
			Host:                   proto.String("worker.example.com"),
			Port:                   proto.Int64(8443),
			PathOverride:           &cloudtaskspb.PathOverride{Path: "/run"},
			QueryOverride:          &cloudtaskspb.QueryOverride{QueryParams: "a=1"},
			UriOverrideEnforceMode: cloudtaskspb.UriOverride_ALWAYS,
		},
		HeaderOverrides: []*cloudtaskspb.HttpTarget_HeaderOverride{
			{Header: &cloudtaskspb.HttpTarget_Header{Key: "X-Env", Value: "prod"}},
			{Header: nil},
		},
		AuthorizationHeader: &cloudtaskspb.HttpTarget_OidcToken{
			OidcToken: &cloudtaskspb.OidcToken{
				ServiceAccountEmail: "runner@p.iam.gserviceaccount.com",
				Audience:            "https://worker.example.com",
			},
		},
	}

	got := convertCloudTasksHttpTarget(ht)
	require.NotNil(t, got)
	assert.Equal(t, "PUT", got.httpMethod)
	assert.Equal(t, map[string]any{"X-Env": "prod"}, got.headerOverrides)
	require.NotNil(t, got.uriScheme)
	assert.Equal(t, "HTTPS", *got.uriScheme)
	require.NotNil(t, got.uriHost)
	assert.Equal(t, "worker.example.com", *got.uriHost)
	require.NotNil(t, got.uriPort)
	assert.Equal(t, int64(8443), *got.uriPort)
	require.NotNil(t, got.uriPath)
	assert.Equal(t, "/run", *got.uriPath)
	require.NotNil(t, got.uriQuery)
	assert.Equal(t, "a=1", *got.uriQuery)
	require.NotNil(t, got.uriOverrideEnforceMode)
	assert.Equal(t, "ALWAYS", *got.uriOverrideEnforceMode)

	assert.Equal(t, "runner@p.iam.gserviceaccount.com", got.oidcServiceAccount)
	require.NotNil(t, got.oidcAudience)
	assert.Equal(t, "https://worker.example.com", *got.oidcAudience)
	assert.Empty(t, got.oauthServiceAccount)
	assert.Nil(t, got.oauthScope)
}

func TestConvertCloudTasksHttpTarget_OAuth(t *testing.T) {
	ht := &cloudtaskspb.HttpTarget{
		AuthorizationHeader: &cloudtaskspb.HttpTarget_OauthToken{
			OauthToken: &cloudtaskspb.OAuthToken{
				ServiceAccountEmail: "caller@p.iam.gserviceaccount.com",
			},
		},
	}
	got := convertCloudTasksHttpTarget(ht)
	require.NotNil(t, got)
	assert.Equal(t, "caller@p.iam.gserviceaccount.com", got.oauthServiceAccount)
	// Scope is present but empty: the token type is in use with the default scope.
	require.NotNil(t, got.oauthScope)
	assert.Equal(t, "", *got.oauthScope)
	assert.Empty(t, got.oidcServiceAccount)
	assert.Nil(t, got.oidcAudience)
}

// A queue that only overrides the method sets no URI override and no token:
// every URI field and both token fields must read as absent, not as zero values.
func TestConvertCloudTasksHttpTarget_NoOverridesNoToken(t *testing.T) {
	got := convertCloudTasksHttpTarget(&cloudtaskspb.HttpTarget{HttpMethod: cloudtaskspb.HttpMethod_POST})
	require.NotNil(t, got)
	assert.Equal(t, "POST", got.httpMethod)
	assert.Empty(t, got.headerOverrides)
	assert.Nil(t, got.uriScheme)
	assert.Nil(t, got.uriHost)
	assert.Nil(t, got.uriPort)
	assert.Nil(t, got.uriPath)
	assert.Nil(t, got.uriQuery)
	assert.Nil(t, got.uriOverrideEnforceMode)
	assert.Empty(t, got.oidcServiceAccount)
	assert.Nil(t, got.oidcAudience)
	assert.Empty(t, got.oauthServiceAccount)
	assert.Nil(t, got.oauthScope)
}

// A URI override that sets only the host leaves scheme, port, path and query absent.
func TestConvertCloudTasksHttpTarget_PartialUriOverride(t *testing.T) {
	got := convertCloudTasksHttpTarget(&cloudtaskspb.HttpTarget{
		UriOverride: &cloudtaskspb.UriOverride{
			Host:                   proto.String("other.example.com"),
			UriOverrideEnforceMode: cloudtaskspb.UriOverride_IF_NOT_EXISTS,
		},
	})
	require.NotNil(t, got)
	require.NotNil(t, got.uriHost)
	assert.Equal(t, "other.example.com", *got.uriHost)
	assert.Nil(t, got.uriScheme)
	assert.Nil(t, got.uriPort)
	assert.Nil(t, got.uriPath)
	assert.Nil(t, got.uriQuery)
	require.NotNil(t, got.uriOverrideEnforceMode)
	assert.Equal(t, "IF_NOT_EXISTS", *got.uriOverrideEnforceMode)
}

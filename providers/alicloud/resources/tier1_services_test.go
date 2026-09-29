// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	cloudapiclient "github.com/alibabacloud-go/cloudapi-20160714/v5/client"
	imsclient "github.com/alibabacloud-go/ims-20190815/v4/client"
	privatelinkclient "github.com/alibabacloud-go/privatelink-20200415/v5/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootAccessKeyCountFrom(t *testing.T) {
	var body imsclient.GetAccountSecurityPracticeReportResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{
		"AccountSecurityPracticeInfo": {
			"Score": 63,
			"AccountSecurityPracticeUserInfo": {"BindMfa": false, "RootWithAccessKey": 2, "UnusedAkNum": 0}
		}
	}`), &body))
	got := rootAccessKeyCountFrom(&imsclient.GetAccountSecurityPracticeReportResponse{Body: &body})
	require.NotNil(t, got)
	assert.Equal(t, int64(2), *got)

	t.Run("a report without the count is null, not zero", func(t *testing.T) {
		var empty imsclient.GetAccountSecurityPracticeReportResponseBody
		require.NoError(t, json.Unmarshal([]byte(`{"AccountSecurityPracticeInfo": {"Score": 80, "AccountSecurityPracticeUserInfo": {"BindMfa": true}}}`), &empty))
		assert.Nil(t, rootAccessKeyCountFrom(&imsclient.GetAccountSecurityPracticeReportResponse{Body: &empty}))
		assert.Nil(t, rootAccessKeyCountFrom(&imsclient.GetAccountSecurityPracticeReportResponse{}))
		assert.Nil(t, rootAccessKeyCountFrom(nil))
	})
}

func TestRamMarkerDone(t *testing.T) {
	assert.True(t, ramMarkerDone(tea.Bool(false), tea.String("next")))
	assert.True(t, ramMarkerDone(nil, nil))
	assert.False(t, ramMarkerDone(tea.Bool(true), tea.String("next")))
	assert.True(t, ramMarkerDone(tea.Bool(true), tea.String("")), "a truncated page without a marker must not loop")
}

func TestApiGatewayDeployedStages(t *testing.T) {
	var body cloudapiclient.DescribeApisResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{
		"ApiSummarys": {"ApiSummary": [{
			"ApiId": "a1",
			"DeployedInfos": {"DeployedInfo": [
				{"StageName": "RELEASE", "DeployedStatus": "DEPLOYED", "EffectiveVersion": "1"},
				{"StageName": "TEST", "DeployedStatus": "NONDEPLOYED"},
				{"StageName": "PRE", "DeployedStatus": "deployed"},
				{"StageName": "", "DeployedStatus": "DEPLOYED"}
			]}
		}]}
	}`), &body))
	infos := body.ApiSummarys.ApiSummary[0].DeployedInfos.DeployedInfo
	assert.Equal(t, []any{"RELEASE", "PRE"}, apiGatewayDeployedStages(infos))
	assert.Empty(t, apiGatewayDeployedStages(nil))
}

func TestApiGatewayFlag(t *testing.T) {
	require.NotNil(t, apiGatewayFlag(tea.String("TRUE")))
	assert.True(t, *apiGatewayFlag(tea.String("TRUE")))
	assert.True(t, *apiGatewayFlag(tea.String("true")))
	assert.False(t, *apiGatewayFlag(tea.String("FALSE")))
	assert.Nil(t, apiGatewayFlag(tea.String("")), "an empty value is unknown, not false")
	assert.Nil(t, apiGatewayFlag(nil))
}

func TestPrivateLinkTokenDone(t *testing.T) {
	assert.True(t, privateLinkTokenDone(nil, nil))
	assert.True(t, privateLinkTokenDone(tea.String(""), tea.String("t1")))
	assert.False(t, privateLinkTokenDone(tea.String("t2"), tea.String("t1")))
	assert.True(t, privateLinkTokenDone(tea.String("t1"), tea.String("t1")), "a repeated token must not loop")
}

func TestPrivateLinkAllowlistEntries(t *testing.T) {
	var users privatelinkclient.ListVpcEndpointServiceUsersResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{"Users": [{"UserId": 1234567890123456}, {}], "TotalCount": "1"}`), &users))
	assert.Equal(t, []any{"1234567890123456"}, privateLinkAllowlistEntries(&users))

	var arns privatelinkclient.ListVpcEndpointServiceUsersResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{"UserARNs": [{"UserARN": "acs:ram::1234567890123456:root"}, {"UserARN": ""}]}`), &arns))
	assert.Equal(t, []any{"acs:ram::1234567890123456:root"}, privateLinkAllowlistEntries(&arns))
}

func TestCasCertificateTime(t *testing.T) {
	want := time.Date(2022, 11, 17, 0, 0, 0, 0, time.UTC)
	epoch := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()

	got := casCertificateTime(tea.String("2022-11-17"), &epoch)
	require.NotNil(t, got)
	assert.True(t, want.Equal(*got), "the date wins over the epoch, got %s", got)

	got = casCertificateTime(nil, &epoch)
	require.NotNil(t, got)
	assert.Equal(t, 2023, got.Year(), "the epoch is the fallback")

	assert.Nil(t, casCertificateTime(tea.String(""), nil))
}

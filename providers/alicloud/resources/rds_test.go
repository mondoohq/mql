// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	rdsclient "github.com/alibabacloud-go/rds-20140815/v17/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRdsStatusEnabled covers the on/off classifier shared by the TDE and SQL
// Explorer readers. The two APIs spell the same state differently (Enabled vs
// Enable), and every unrecognised value has to read as off: a status that
// silently became true would report encryption or auditing on an instance that
// has neither.
func TestRdsStatusEnabled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status *string
		want   bool
	}{
		{"nil is off", nil, false},
		{"empty is off", new(""), false},
		{"TDE spelling", new("Enabled"), true},
		{"SQL Explorer spelling", new("Enable"), true},
		{"lowercase", new("enabled"), true},
		{"surrounding space", new("  Enable  "), true},
		{"disabled", new("Disabled"), false},
		{"disable", new("Disable"), false},
		{"unrecognised value is off", new("Pending"), false},
		{"substring must not match", new("NotEnabled"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rdsStatusEnabled(tc.status))
		})
	}
}

// TestRdsRetentionDays covers the string-to-days conversion for the SQL
// Explorer retention window. Anything unreadable must land on 0, which fails a
// minimum-retention assertion rather than satisfying it with a made-up number.
func TestRdsRetentionDays(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value *string
		want  int64
	}{
		{"nil is zero", nil, 0},
		{"empty is zero", new(""), 0},
		{"garbage is zero", new("forever"), 0},
		{"negative is zero", new("-1"), 0},
		{"thirty days", new("30"), 30},
		{"surrounding space", new(" 365 "), 365},
		{"six months", new("180"), 180},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rdsRetentionDays(tc.value))
		})
	}
}

// TestRdsRunningParameters covers the parameter map build. It must read the
// running parameters and not the configured ones: a parameter changed but not
// yet applied is not in effect, and reporting it would say a PostgreSQL
// instance is logging connections before the restart that makes it true.
func TestRdsRunningParameters(t *testing.T) {
	param := func(name, value string) *rdsclient.DescribeParametersResponseBodyRunningParametersDBInstanceParameter {
		return &rdsclient.DescribeParametersResponseBodyRunningParametersDBInstanceParameter{
			ParameterName:  new(name),
			ParameterValue: new(value),
		}
	}

	t.Run("nil body is an empty map, not nil", func(t *testing.T) {
		assert.Equal(t, map[string]any{}, rdsRunningParameters(nil))
	})

	t.Run("no running parameters is an empty map", func(t *testing.T) {
		assert.Equal(t, map[string]any{}, rdsRunningParameters(&rdsclient.DescribeParametersResponseBody{}))
	})

	t.Run("running parameters are keyed by name", func(t *testing.T) {
		got := rdsRunningParameters(&rdsclient.DescribeParametersResponseBody{
			RunningParameters: &rdsclient.DescribeParametersResponseBodyRunningParameters{
				DBInstanceParameter: []*rdsclient.DescribeParametersResponseBodyRunningParametersDBInstanceParameter{
					param("log_connections", "on"),
					param("log_disconnections", "off"),
					param("log_duration", "on"),
				},
			},
		})
		assert.Equal(t, map[string]any{
			"log_connections":    "on",
			"log_disconnections": "off",
			"log_duration":       "on",
		}, got)
	})

	t.Run("nil and unnamed entries are dropped", func(t *testing.T) {
		got := rdsRunningParameters(&rdsclient.DescribeParametersResponseBody{
			RunningParameters: &rdsclient.DescribeParametersResponseBodyRunningParameters{
				DBInstanceParameter: []*rdsclient.DescribeParametersResponseBodyRunningParametersDBInstanceParameter{
					nil,
					{ParameterName: new("")},
					{ParameterName: nil, ParameterValue: new("on")},
					param("log_duration", "on"),
				},
			},
		})
		assert.Equal(t, map[string]any{"log_duration": "on"}, got)
	})

	t.Run("a parameter with no value reports empty, not missing", func(t *testing.T) {
		got := rdsRunningParameters(&rdsclient.DescribeParametersResponseBody{
			RunningParameters: &rdsclient.DescribeParametersResponseBodyRunningParameters{
				DBInstanceParameter: []*rdsclient.DescribeParametersResponseBodyRunningParametersDBInstanceParameter{
					{ParameterName: new("log_statement")},
				},
			},
		})
		assert.Equal(t, map[string]any{"log_statement": ""}, got)
	})

	t.Run("configured-but-unapplied parameters are not reported", func(t *testing.T) {
		got := rdsRunningParameters(&rdsclient.DescribeParametersResponseBody{
			ConfigParameters: &rdsclient.DescribeParametersResponseBodyConfigParameters{
				DBInstanceParameter: []*rdsclient.DescribeParametersResponseBodyConfigParametersDBInstanceParameter{
					{ParameterName: new("log_connections"), ParameterValue: new("on")},
				},
			},
		})
		assert.Equal(t, map[string]any{}, got)
	})
}

// TestRdsOperatorPermissionFrom covers the decode of the access granted to
// Alibaba Cloud technical support, from the JSON the API returns, so a
// mistyped struct tag or a split on the wrong separator cannot report "no
// grant" on an instance that has one.
func TestRdsOperatorPermissionFrom(t *testing.T) {
	decode := func(t *testing.T, body string) *rdsOperatorPermission {
		var resp rdsclient.DescribeOperatorPermissionResponseBody
		require.NoError(t, json.Unmarshal([]byte(body), &resp))
		return rdsOperatorPermissionFrom(&resp)
	}

	t.Run("grant with both privileges", func(t *testing.T) {
		// Synthetic: response shape and values from the SDK's documented
		// example; no live instance with a grant was available.
		got := decode(t, `{"CreatedTime":"2026-10-12T02:27:04Z","ExpiredTime":"2030-01-01T11:58:17Z","Privileges":"Control,Data","RequestId":"r1"}`)
		assert.Equal(t, []string{"Control", "Data"}, got.privileges)
		require.NotNil(t, got.created)
		require.NotNil(t, got.expires)
		assert.Equal(t, time.Date(2026, 10, 12, 2, 27, 4, 0, time.UTC), *got.created)
		assert.Equal(t, time.Date(2030, 1, 1, 11, 58, 17, 0, time.UTC), *got.expires)
	})

	t.Run("spaces and empty members are dropped", func(t *testing.T) {
		// Synthetic: separator variants no target showed.
		got := decode(t, `{"Privileges":" Control , ,Data,"}`)
		assert.Equal(t, []string{"Control", "Data"}, got.privileges)
	})

	t.Run("no grant is an empty list and null times", func(t *testing.T) {
		// Synthetic: an instance with no grant; no target showed this.
		for _, body := range []string{`{"RequestId":"r1"}`, `{"Privileges":"","CreatedTime":"","ExpiredTime":"","RequestId":"r1"}`} {
			got := decode(t, body)
			assert.Equal(t, []string{}, got.privileges)
			assert.Nil(t, got.created)
			assert.Nil(t, got.expires)
		}
	})

	t.Run("nil body is no grant", func(t *testing.T) {
		got := rdsOperatorPermissionFrom(nil)
		assert.Equal(t, []string{}, got.privileges)
		assert.Nil(t, got.expires)
	})
}

// TestRdsOperatorPermissionActive covers the derived "support currently holds
// access" predicate. A grant without an expiry has to count as active, so a
// check for no standing access fails on it.
func TestRdsOperatorPermissionActive(t *testing.T) {
	// Synthetic: grants built around a fixed instant; no target showed these.
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	for _, tc := range []struct {
		name string
		p    *rdsOperatorPermission
		want bool
	}{
		{"nil", nil, false},
		{"no privileges", &rdsOperatorPermission{privileges: []string{}, expires: &future}, false},
		{"unexpired grant", &rdsOperatorPermission{privileges: []string{"Control"}, expires: &future}, true},
		{"expired grant", &rdsOperatorPermission{privileges: []string{"Data"}, expires: &past}, false},
		{"expires exactly now", &rdsOperatorPermission{privileges: []string{"Data"}, expires: &now}, false},
		{"grant without expiry is standing", &rdsOperatorPermission{privileges: []string{"Control"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.p.active(now))
		})
	}
}

// TestRdsPeerInstance covers how a disaster recovery replica or warm standby is
// read from the instance detail. No id means no peer, so the accessor reports
// null; a peer that names no region is looked up in the instance's own region.
func TestRdsPeerInstance(t *testing.T) {
	// Synthetic: the API documents DrReplicaInfo and WarmStandbyInfo only by
	// field name; no instance with a replica was available to measure.
	for _, tc := range []struct {
		name       string
		insName    *string
		region     *string
		wantID     string
		wantRegion string
	}{
		{"absent", nil, nil, "", ""},
		{"empty id ignores region", new(""), new("cn-shanghai"), "", ""},
		{"blank id", new("  "), nil, "", ""},
		{"cross-region peer", new("rm-dr1"), new("cn-shanghai"), "rm-dr1", "cn-shanghai"},
		{"peer without region uses own region", new("rm-dr1"), new(""), "rm-dr1", "cn-hangzhou"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, region := rdsPeerInstance(tc.insName, tc.region, "cn-hangzhou")
			assert.Equal(t, tc.wantID, id)
			assert.Equal(t, tc.wantRegion, region)
		})
	}
}

// TestRdsInstanceAttributePeersDecode checks that the SDK struct tags for the
// disaster recovery replica and warm standby match the documented response
// field names, so a renamed tag cannot silently turn both accessors null.
func TestRdsInstanceAttributePeersDecode(t *testing.T) {
	// Synthetic: response shape from the DescribeDBInstanceAttribute API
	// reference, with invented ids.
	body := `{"Items":{"DBInstanceAttribute":[{"DBInstanceId":"rm-primary","DrReplicaInfo":{"InsName":"rm-dr1","Region":"cn-shanghai","UnitCode":"u1"},"WarmStandbyInfo":{"InsName":"rm-ws1","Region":"","UnitCode":""}}]}}`
	var resp rdsclient.DescribeDBInstanceAttributeResponseBody
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.Len(t, resp.Items.DBInstanceAttribute, 1)
	attr := resp.Items.DBInstanceAttribute[0]
	require.NotNil(t, attr.DrReplicaInfo)
	require.NotNil(t, attr.WarmStandbyInfo)

	id, region := rdsPeerInstance(attr.DrReplicaInfo.InsName, attr.DrReplicaInfo.Region, "cn-hangzhou")
	assert.Equal(t, "rm-dr1", id)
	assert.Equal(t, "cn-shanghai", region)

	id, region = rdsPeerInstance(attr.WarmStandbyInfo.InsName, attr.WarmStandbyInfo.Region, "cn-hangzhou")
	assert.Equal(t, "rm-ws1", id)
	assert.Equal(t, "cn-hangzhou", region)
}

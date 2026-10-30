// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestDerefFloat(t *testing.T) {
	if got := derefFloat[*float64](nil); got != 0 {
		t.Fatalf("nil pointer: got %v, want 0", got)
	}
	f := 3.5
	if got := derefFloat(&f); got != 3.5 {
		t.Fatalf("got %v, want 3.5", got)
	}
}

const (
	fakeDailyPolicy  = "0d1c2b3a-4958-4776-8695-a4b3c2d1e0f9"
	fakeWeeklyPolicy = "1e2d3c4b-5a69-4887-97a6-b5c4d3e2f1a0"
	fakeNightly      = "2f3e4d5c-6b7a-4998-88b7-c6d5e4f3a2b1"
	fakePoolDaily    = "3a4f5e6d-7c8b-4aa9-99c8-d7e6f5a4b3c2"
	fakePoolNone     = "4b5a6f7e-8d9c-4bba-aad9-e8f7a6b5c4d3"

	snapshotPoliciesPath = "GET /v1/projects/" + fakeProjectID + "/snapshotPolicies"
	resourcePoolsPath    = "GET /v1/projects/" + fakeProjectID + "/regions/" + fakeRegion + "/resourcePools"
)

// Synthetic: two policies sharing the nightly schedule with different
// retention, the weekly one disabled and without a retention count, shaped
// after the SDK's sfs SnapshotPolicy model; no target showed this.
var snapshotPoliciesBody = `{"snapshotPolicies":[
	{"id":"` + fakeDailyPolicy + `","name":"daily","enabled":true,"comment":"keep a week",
	 "createdAt":"2026-03-01T10:00:00Z",
	 "snapshotSchedules":[{"id":"` + fakeNightly + `","name":"nightly","interval":"0 2 * * *","prefix":"auto",
	   "retentionCount":7,"retentionPeriod":"P7D","createdAt":"2026-03-01T10:00:00Z"}]},
	{"id":"` + fakeWeeklyPolicy + `","name":"weekly","enabled":false,
	 "snapshotSchedules":[{"id":"` + fakeNightly + `","name":"nightly","interval":"0 2 * * *",
	   "retentionPeriod":"infinite"}]}
]}`

// Synthetic: one pool on the daily policy, one with no policy.
var resourcePoolsBody = `{"resourcePools":[
	{"id":"` + fakePoolDaily + `","name":"data","snapshotPolicy":{"id":"` + fakeDailyPolicy + `","name":"daily"}},
	{"id":"` + fakePoolNone + `","name":"scratch"}
]}`

func newSfs(t *testing.T, runtime *plugin.Runtime) *mqlStackitSfs {
	t.Helper()
	res, err := makeNamespace(runtime, "stackit.sfs")
	require.NoError(t, err)
	return res.(*mqlStackitSfs)
}

func policyByName(t *testing.T, items []any, name string) *mqlStackitSfsSnapshotPolicy {
	t.Helper()
	for _, it := range items {
		if p := it.(*mqlStackitSfsSnapshotPolicy); p.Name.Data == name {
			return p
		}
	}
	t.Fatalf("no policy named %q", name)
	return nil
}

func TestSfsSnapshotPolicies(t *testing.T) {
	runtime, _ := fakeRuntime(t, map[string]fakeAnswer{
		snapshotPoliciesPath: json200(snapshotPoliciesBody),
		resourcePoolsPath:    json200(resourcePoolsBody),
	})
	policies := newSfs(t, runtime).GetSnapshotPolicies()
	require.NoError(t, policies.Error)
	require.Len(t, policies.Data, 2)

	daily := policyByName(t, policies.Data, "daily")
	assert.Equal(t, fakeDailyPolicy, daily.Id.Data)
	assert.True(t, daily.Enabled.Data)
	assert.Equal(t, "keep a week", daily.Comment.Data)
	require.NotNil(t, daily.CreatedAt.Data)
	assert.Equal(t, 2026, daily.CreatedAt.Data.Year())
	weekly := policyByName(t, policies.Data, "weekly")
	assert.False(t, weekly.Enabled.Data)

	t.Run("schedules carry interval and retention", func(t *testing.T) {
		s := daily.GetSchedules()
		require.NoError(t, s.Error)
		require.Len(t, s.Data, 1)
		sched := s.Data[0].(*mqlStackitSfsSnapshotPolicySchedule)
		assert.Equal(t, fakeNightly, sched.Id.Data)
		assert.Equal(t, "0 2 * * *", sched.Interval.Data)
		assert.Equal(t, "auto", sched.Prefix.Data)
		assert.Equal(t, int64(7), sched.RetentionCount.Data)
		assert.Equal(t, "P7D", sched.RetentionPeriod.Data)
	})

	t.Run("a shared schedule keeps each policy's retention", func(t *testing.T) {
		s := weekly.GetSchedules()
		require.NoError(t, s.Error)
		require.Len(t, s.Data, 1)
		sched := s.Data[0].(*mqlStackitSfsSnapshotPolicySchedule)
		assert.Equal(t, "infinite", sched.RetentionPeriod.Data,
			"the weekly policy's schedule must not come back as the daily policy's cached one")
		assert.True(t, sched.RetentionCount.IsNull(), "an omitted retention count is null, not 0")
	})

	t.Run("resourcePools lists the pools on the policy", func(t *testing.T) {
		pools := daily.GetResourcePools()
		require.NoError(t, pools.Error)
		require.Len(t, pools.Data, 1)
		assert.Equal(t, fakePoolDaily, pools.Data[0].(*mqlStackitSfsResourcePool).Id.Data)

		none := weekly.GetResourcePools()
		require.NoError(t, none.Error)
		assert.Empty(t, none.Data)
	})

	t.Run("resource pool resolves its policy", func(t *testing.T) {
		pools := newSfs(t, runtime).GetResourcePools()
		require.NoError(t, pools.Error)
		require.Len(t, pools.Data, 2)
		for _, p := range pools.Data {
			pool := p.(*mqlStackitSfsResourcePool)
			got := pool.GetSnapshotPolicy()
			require.NoError(t, got.Error)
			switch pool.Id.Data {
			case fakePoolDaily:
				require.NotNil(t, got.Data)
				assert.Same(t, daily, got.Data)
			case fakePoolNone:
				assert.True(t, got.IsNull())
			}
		}
	})
}

func TestSfsSnapshotPoliciesRefused(t *testing.T) {
	runtime, _ := fakeRuntime(t, map[string]fakeAnswer{snapshotPoliciesPath: jsonStatus(http.StatusForbidden)})
	got := newSfs(t, runtime).GetSnapshotPolicies()
	require.Error(t, got.Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(got.Error))
}

func TestPoolsWithSnapshotPolicy(t *testing.T) {
	// Synthetic: pools built without a runtime; the filter reads only the
	// policy id.
	pool := func(id, policy string) *mqlStackitSfsResourcePool {
		return &mqlStackitSfsResourcePool{
			Id:               plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
			SnapshotPolicyId: plugin.TValue[string]{Data: policy, State: plugin.StateIsSet},
		}
	}
	pools := []any{pool("a", fakeDailyPolicy), pool("b", ""), pool("c", fakeDailyPolicy)}
	assert.Len(t, poolsWithSnapshotPolicy(pools, fakeDailyPolicy), 2)
	assert.Empty(t, poolsWithSnapshotPolicy(pools, fakeWeeklyPolicy))
	assert.Empty(t, poolsWithSnapshotPolicy(pools, ""), "an empty policy id must not match pools without a policy")
}

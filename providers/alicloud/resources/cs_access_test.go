// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCsGrantCoversCluster covers the scope matcher behind
// alicloud.cs.cluster.grants. Getting it wrong is silent in both directions: too
// narrow drops an account-wide administrator from a cluster's grant list, and
// too broad attributes another cluster's grants to this one.
func TestCsGrantCoversCluster(t *testing.T) {
	const cluster = "c1a2b3c4d5"

	for _, tc := range []struct {
		name       string
		resourceID string
		clusterID  string
		want       bool
	}{
		{"cluster scope matches", cluster, cluster, true},
		{"namespace scope matches", cluster + "/kube-system", cluster, true},
		{"namespace with a slash in it still matches", cluster + "/team/app", cluster, true},
		{"all-clusters reaches every cluster", csAllClusters, cluster, true},
		{"a different cluster does not match", "c9z8y7x6w5", cluster, false},
		{"empty resource id does not match", "", cluster, false},
		{"empty cluster id does not match", cluster, "", false},

		// The prefix check must be anchored on a separator. Container Service
		// ids share a shape, so a plain HasPrefix would let a longer id whose
		// first characters happen to match steal another cluster's grants.
		{"an id that merely starts with the cluster id does not match", cluster + "extra", cluster, false},
		{"a longer id sharing a prefix does not match", cluster + "99", cluster, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, csGrantCoversCluster(tc.resourceID, tc.clusterID))
		})
	}
}

// TestCsGrantID covers the grant cache key. A principal holds many grants, so
// every dimension the grant varies along has to be in the key: two grants
// sharing one would collide in the resource cache and the second would be
// reported carrying the first one's values.
func TestCsGrantID(t *testing.T) {
	base := csGrantID("281", "cluster", "c1a2b3", "admin", "")

	t.Run("differs by principal", func(t *testing.T) {
		assert.NotEqual(t, base, csGrantID("999", "cluster", "c1a2b3", "admin", ""))
	})
	t.Run("differs by scope", func(t *testing.T) {
		assert.NotEqual(t, base, csGrantID("281", "namespace", "c1a2b3", "admin", ""))
	})
	t.Run("differs by resource", func(t *testing.T) {
		assert.NotEqual(t, base, csGrantID("281", "cluster", "c9z8y7", "admin", ""))
	})
	t.Run("differs by role type", func(t *testing.T) {
		assert.NotEqual(t, base, csGrantID("281", "cluster", "c1a2b3", "dev", ""))
	})
	t.Run("differs by custom role name", func(t *testing.T) {
		a := csGrantID("281", "namespace", "c1a2b3/app", "custom", "pod-reader")
		b := csGrantID("281", "namespace", "c1a2b3/app", "custom", "pod-writer")
		assert.NotEqual(t, a, b)
	})
	t.Run("same grant is stable", func(t *testing.T) {
		assert.Equal(t, base, csGrantID("281", "cluster", "c1a2b3", "admin", ""))
	})
	t.Run("contains no NUL byte", func(t *testing.T) {
		assert.NotContains(t, base, "\x00")
	})

	t.Run("two namespaces of one cluster do not collide", func(t *testing.T) {
		a := csGrantID("281", "namespace", "c1a2b3/kube-system", "admin", "")
		b := csGrantID("281", "namespace", "c1a2b3/default", "admin", "")
		assert.NotEqual(t, a, b)
	})

	// resourceID legitimately contains slashes, so a slash-joined key could in
	// principle be read two ways. The components that would have to absorb the
	// slash are closed enums today, so the collision is not reachable in
	// practice, but the key is joined on a separator no component can contain,
	// which makes it structurally impossible rather than accidentally safe.
	// Pin that: a slash moving between adjacent components must not collide.
	t.Run("a slash inside a component cannot be read as a separator", func(t *testing.T) {
		a := csGrantID("281", "cluster", "c1a2b3/kube-system", "admin", "reader")
		b := csGrantID("281", "cluster", "c1a2b3", "kube-system/admin", "reader")
		assert.NotEqual(t, a, b)
	})

	t.Run("an empty component does not let its neighbours merge", func(t *testing.T) {
		a := csGrantID("281", "cluster", "c1a2b3", "", "admin")
		b := csGrantID("281", "cluster", "c1a2b3", "admin", "")
		assert.NotEqual(t, a, b)
	})
}

// TestCsClusterCheckID covers the inspection-run cache key. The API gives no
// guarantee that run ids are unique across clusters, so the key is qualified
// with the cluster: an id that repeated would otherwise collide in the resource
// cache and report the first cluster's run as the second cluster's.
func TestCsClusterCheckID(t *testing.T) {
	const check = "1697100584236600453-ce0da5a1-clustercheck-lboto"

	t.Run("differs by cluster", func(t *testing.T) {
		assert.NotEqual(t,
			csClusterCheckID("c1a2b3", check),
			csClusterCheckID("c9z8y7", check))
	})
	t.Run("differs by run", func(t *testing.T) {
		assert.NotEqual(t,
			csClusterCheckID("c1a2b3", check),
			csClusterCheckID("c1a2b3", "1697100584236600453-ce0da5a1-clustercheck-other"))
	})
	t.Run("same run on the same cluster is stable", func(t *testing.T) {
		assert.Equal(t,
			csClusterCheckID("c1a2b3", check),
			csClusterCheckID("c1a2b3", check))
	})
	t.Run("the run id stays readable in the key", func(t *testing.T) {
		assert.Equal(t, "c1a2b3/"+check, csClusterCheckID("c1a2b3", check))
	})
}

// TestCsParseTime covers the cluster-check timestamp parser. An unparseable
// value has to stay null: becoming the zero time would report 1 January year 1
// as a real inspection run, which reads as "checked, long ago" rather than
// "never checked".
func TestCsParseTime(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		assert.Nil(t, csParseTime(nil))
	})
	t.Run("empty stays nil", func(t *testing.T) {
		assert.Nil(t, csParseTime(tea.String("")))
	})
	t.Run("garbage stays nil", func(t *testing.T) {
		assert.Nil(t, csParseTime(tea.String("not a date")))
	})
	t.Run("an in-progress run has no finish time", func(t *testing.T) {
		// a run that has not completed reports an empty finished_at
		assert.Nil(t, csParseTime(tea.String("")))
	})
	t.Run("nanosecond rfc3339, as the API returns it", func(t *testing.T) {
		got := csParseTime(tea.String("2025-04-11T02:56:18.881054031Z"))
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2025, 4, 11, 2, 56, 18, 881054031, time.UTC), got.UTC())
	})
	t.Run("plain rfc3339", func(t *testing.T) {
		got := csParseTime(tea.String("2025-04-11T02:56:02Z"))
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2025, 4, 11, 2, 56, 2, 0, time.UTC), got.UTC())
	})
}

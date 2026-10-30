// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// TestAccessReviewRequiresLiveConnection verifies that on a manifest scan (which
// cannot run a SubjectAccessReview) the result fields resolve to a clear error
// rather than a misleading allowed=false.
func TestAccessReviewRequiresLiveConnection(t *testing.T) {
	k8s := workloadSecurityK8s(t) // manifest-backed runtime

	r, err := CreateResource(k8s.MqlRuntime, "k8s.accessReview", map[string]*llx.RawData{
		"subject":  llx.StringData("system:serviceaccount:prod:web"),
		"verb":     llx.StringData("get"),
		"resource": llx.StringData("secrets"),
	})
	require.NoError(t, err)
	ar := r.(*mqlK8sAccessReview)

	allowed := ar.GetAllowed()
	require.Error(t, allowed.Error, "manifest connection must not silently allow/deny")
	assert.Contains(t, allowed.Error.Error(), "live Kubernetes")

	reason := ar.GetReason()
	require.Error(t, reason.Error)
}

func TestAccessReviewInitDefaultsAndID(t *testing.T) {
	args := map[string]*llx.RawData{
		"subject":  llx.StringData("alice"),
		"verb":     llx.StringData("list"),
		"resource": llx.StringData("pods"),
	}
	out, _, err := initK8sAccessReview(nil, args)
	require.NoError(t, err)

	// missing fields are defaulted to empty strings
	for _, f := range []string{"group", "namespace", "name"} {
		v, ok := out[f]
		require.True(t, ok, "field %s defaulted", f)
		assert.Equal(t, "", v.Value)
	}
	// a stable id is derived from the query
	id, ok := out["__id"]
	require.True(t, ok)
	assert.Contains(t, id.Value.(string), "alice")
	assert.Contains(t, id.Value.(string), "pods")
}

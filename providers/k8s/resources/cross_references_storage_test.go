// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// These tests cover the storage and networking/Gateway-API cross-references,
// which had no fixture coverage. They lean on the shared cross_references.yaml
// fixture and the loadCrossRefRuntime harness.

func TestPVClaimAndStorageClassRefs(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.persistentvolume", map[string]*llx.RawData{
		"name": llx.StringData("pv-data"),
	})
	require.NoError(t, err)
	pv := obj.(*mqlK8sPersistentvolume)

	claim := pv.GetClaim()
	require.NoError(t, claim.Error)
	require.NotNil(t, claim.Data, "pv-data is bound to data-claim")
	assert.Equal(t, "data-claim", claim.Data.Name.Data)
	assert.Equal(t, "prod", claim.Data.Namespace.Data,
		"claim() must carry the namespace from claimRef, not drop it")

	sc := pv.GetStorageClass()
	require.NoError(t, sc.Error)
	require.NotNil(t, sc.Data)
	assert.Equal(t, "fast", sc.Data.Name.Data)
}

func TestPVUnboundRefsAreNull(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.persistentvolume", map[string]*llx.RawData{
		"name": llx.StringData("pv-unbound"),
	})
	require.NoError(t, err)
	pv := obj.(*mqlK8sPersistentvolume)

	claim := pv.GetClaim()
	require.NoError(t, claim.Error)
	assert.Nil(t, claim.Data, "an unbound PV has no claim")
	assert.NotZero(t, claim.State&plugin.StateIsNull, "claim must be marked null, not left unresolved")

	sc := pv.GetStorageClass()
	require.NoError(t, sc.Error)
	assert.Nil(t, sc.Data, "a PV without a storageClassName has no storage class")
	assert.NotZero(t, sc.State&plugin.StateIsNull)
}

func TestPVCVolumeAndStorageClassRefs(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.persistentvolumeclaim", map[string]*llx.RawData{
		"name":      llx.StringData("data-claim"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	pvc := obj.(*mqlK8sPersistentvolumeclaim)

	vol := pvc.GetVolume()
	require.NoError(t, vol.Error)
	require.NotNil(t, vol.Data, "data-claim is bound to pv-data")
	assert.Equal(t, "pv-data", vol.Data.Name.Data)

	sc := pvc.GetStorageClass()
	require.NoError(t, sc.Error)
	require.NotNil(t, sc.Data)
	assert.Equal(t, "fast", sc.Data.Name.Data)
}

// TestPVCStorageClassNotFoundIsNull exercises the ErrResourceNotFound swallow:
// a PVC that references a StorageClass with no matching object must resolve to
// null (not error), so a deleted/cluster-scoped class doesn't fail the query.
func TestPVCStorageClassNotFoundIsNull(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.persistentvolumeclaim", map[string]*llx.RawData{
		"name":      llx.StringData("missing-sc-claim"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	pvc := obj.(*mqlK8sPersistentvolumeclaim)

	sc := pvc.GetStorageClass()
	require.NoError(t, sc.Error, "a missing StorageClass must resolve to null, not error")
	assert.Nil(t, sc.Data)
	assert.NotZero(t, sc.State&plugin.StateIsNull)
}

func TestIngressClassRef(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.ingress", map[string]*llx.RawData{
		"name":      llx.StringData("web"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	ing := obj.(*mqlK8sIngress)

	ic := ing.GetIngressClass()
	require.NoError(t, ic.Error)
	require.NotNil(t, ic.Data, "ingress 'web' references ingressClassName 'nginx'")
	assert.Equal(t, "nginx", ic.Data.Name.Data)
}

func TestGatewayClassRef(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.gateway", map[string]*llx.RawData{
		"name":      llx.StringData("public-gw"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	gw := obj.(*mqlK8sGateway)

	gc := gw.GetGatewayClass()
	require.NoError(t, gc.Error)
	require.NotNil(t, gc.Data, "gateway 'public-gw' references gatewayClassName 'istio'")
	assert.Equal(t, "istio", gc.Data.Name.Data)
}

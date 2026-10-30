// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func provenanceTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

//go:fix inline
func boolPtr(b bool) *bool { return new(b) }

// objectWithProvenance returns a Pod carrying two owner references (one with
// the controller/blockOwnerDeletion bools set, one with both nil) and two
// managed-field entries (one without a timestamp or field set, one with both).
func objectWithProvenance() *corev1.Pod {
	managedTime := metav1.NewTime(time.Date(2026, 6, 12, 8, 0, 0, 0, time.UTC))
	return &corev1.Pod{
		Kind: "Pod", APIVersion: "v1",
		Name:      "app-pod",
		Namespace: "prod",
		UID:       "pod-uid-1",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion:         "apps/v1",
				Kind:               "ReplicaSet",
				Name:               "app-rs",
				UID:                "rs-uid-1",
				Controller:         new(true),
				BlockOwnerDeletion: new(true),
			},
			{
				// no Controller / BlockOwnerDeletion: must surface as MQL null
				APIVersion: "v1",
				Kind:       "Node",
				Name:       "node-1",
				UID:        "node-uid-1",
			},
		},
		ManagedFields: []metav1.ManagedFieldsEntry{
			{
				Manager:    "kubectl",
				Operation:  metav1.ManagedFieldsOperationApply,
				APIVersion: "v1",
				FieldsType: "FieldsV1",
				// no Time, no FieldsV1: both must surface as null
			},
			{
				Manager:     "kube-controller-manager",
				Operation:   metav1.ManagedFieldsOperationUpdate,
				APIVersion:  "v1",
				Subresource: "status",
				FieldsType:  "FieldsV1",
				Time:        &managedTime,
				FieldsV1:    &metav1.FieldsV1{Raw: []byte(`{"f:status":{"f:phase":{}}}`)},
			},
		},
	}
}

func TestK8sOwnerReferences(t *testing.T) {
	pod := objectWithProvenance()
	items, err := k8sOwnerReferences(provenanceTestRuntime(), pod)
	require.NoError(t, err)
	require.Len(t, items, 2)

	rs := items[0].(*mqlK8sOwnerReference)
	assert.Equal(t, "apps/v1", rs.ApiVersion.Data)
	assert.Equal(t, "ReplicaSet", rs.Kind.Data)
	assert.Equal(t, "app-rs", rs.Name.Data)
	assert.Equal(t, "rs-uid-1", rs.Uid.Data)
	assert.Equal(t, "pod-uid-1/ownerref/rs-uid-1", rs.__id, "id should be parent-scoped to avoid cache collisions")
	assert.True(t, rs.Controller.Data)
	assert.True(t, rs.BlockOwnerDeletion.Data)
	assert.Zero(t, rs.Controller.State&plugin.StateIsNull, "set controller must not be null")

	// The second ref omits both bools: they must be MQL null, not false.
	node := items[1].(*mqlK8sOwnerReference)
	assert.Equal(t, "Node", node.Kind.Data)
	assert.NotZero(t, node.Controller.State&plugin.StateIsNull, "absent controller must be null")
	assert.NotZero(t, node.BlockOwnerDeletion.State&plugin.StateIsNull, "absent blockOwnerDeletion must be null")
}

func TestK8sManagedFields(t *testing.T) {
	pod := objectWithProvenance()
	items, err := k8sManagedFields(provenanceTestRuntime(), pod)
	require.NoError(t, err)
	require.Len(t, items, 2)

	// First entry: no time, no field set.
	apply := items[0].(*mqlK8sManagedField)
	assert.Equal(t, "kubectl", apply.Manager.Data)
	assert.Equal(t, "Apply", apply.Operation.Data)
	assert.Equal(t, "", apply.Subresource.Data)
	assert.Nil(t, apply.Time.Data, "missing managed-field time must be null")
	assert.Nil(t, apply.FieldsV1.Data, "missing field set must be null")
	assert.Equal(t, "pod-uid-1/managedfield/kubectl/Apply/v1/", apply.__id)

	// Second entry: timestamp + parsed FieldsV1 dict.
	update := items[1].(*mqlK8sManagedField)
	assert.Equal(t, "kube-controller-manager", update.Manager.Data)
	assert.Equal(t, "Update", update.Operation.Data)
	assert.Equal(t, "status", update.Subresource.Data)
	require.NotNil(t, update.Time.Data)
	assert.Equal(t, 2026, update.Time.Data.Year())
	fields, ok := update.FieldsV1.Data.(map[string]any)
	require.True(t, ok, "fieldsV1 must decode into a dict")
	assert.Contains(t, fields, "f:status")
	assert.Equal(t, "pod-uid-1/managedfield/kube-controller-manager/Update/v1/status", update.__id)
}

// TestK8sManagedFieldsApiVersionNotDeduped guards against a cache collision:
// two managed-field entries that differ only by apiVersion must both survive
// rather than the second silently returning the first's cached resource.
func TestK8sManagedFieldsApiVersionNotDeduped(t *testing.T) {
	pod := &corev1.Pod{
		Kind: "Pod", APIVersion: "v1",
		Name: "app-pod",
		UID:  "pod-uid-1",
		ManagedFields: []metav1.ManagedFieldsEntry{
			{Manager: "ctrl", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: "v1", FieldsType: "FieldsV1"},
			{Manager: "ctrl", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: "v1beta1", FieldsType: "FieldsV1"},
		},
	}

	items, err := k8sManagedFields(provenanceTestRuntime(), pod)
	require.NoError(t, err)
	require.Len(t, items, 2, "entries differing only by apiVersion must not be deduplicated")
	assert.Equal(t, "v1", items[0].(*mqlK8sManagedField).ApiVersion.Data)
	assert.Equal(t, "v1beta1", items[1].(*mqlK8sManagedField).ApiVersion.Data)
}

// TestPodOwnerReferencesTyped guards the pod accessor specifically, since its
// ownerReferences field changed from []dict to []k8s.ownerReference.
func TestPodOwnerReferencesTyped(t *testing.T) {
	p := &mqlK8sPod{MqlRuntime: provenanceTestRuntime()}
	p.obj = objectWithProvenance()

	items, err := p.ownerReferences()
	require.NoError(t, err)
	require.Len(t, items, 2)
	ref := items[0].(*mqlK8sOwnerReference)
	assert.Equal(t, "ReplicaSet", ref.Kind.Data)
	assert.True(t, ref.Controller.Data)
}

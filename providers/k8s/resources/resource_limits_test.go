// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// TestResourceLimitRollups_Fixtures checks the rollups against the shared
// workload fixtures: the hardened deployment sets full CPU/memory
// limits+requests, while the risky one sets none.
func TestResourceLimitRollups_Fixtures(t *testing.T) {
	k8s := workloadSecurityK8s(t)

	t.Run("fully constrained workload", func(t *testing.T) {
		d := deploymentByName(t, k8s, "hardened")
		assert.True(t, d.GetHasCpuLimit().Data, "hasCpuLimit")
		assert.True(t, d.GetHasMemoryLimit().Data, "hasMemoryLimit")
		assert.True(t, d.GetHasResourceLimits().Data, "hasResourceLimits")
		assert.True(t, d.GetHasResourceRequests().Data, "hasResourceRequests")
	})

	t.Run("unconstrained workload", func(t *testing.T) {
		d := deploymentByName(t, k8s, "risky")
		assert.False(t, d.GetHasCpuLimit().Data, "hasCpuLimit")
		assert.False(t, d.GetHasMemoryLimit().Data, "hasMemoryLimit")
		assert.False(t, d.GetHasResourceLimits().Data, "hasResourceLimits")
		assert.False(t, d.GetHasResourceRequests().Data, "hasResourceRequests")
	})
}

func qty(s string) resource.Quantity { return resource.MustParse(s) }

// TestResourceLimitRollups_Helpers exercises the spec helpers directly, covering
// partial coverage, init containers, and the nil/empty cases.
func TestResourceLimitRollups_Helpers(t *testing.T) {
	bothLimits := corev1.ResourceList{corev1.ResourceCPU: qty("500m"), corev1.ResourceMemory: qty("256Mi")}
	bothRequests := corev1.ResourceList{corev1.ResourceCPU: qty("100m"), corev1.ResourceMemory: qty("128Mi")}

	t.Run("nil spec is false", func(t *testing.T) {
		assert.False(t, specHasCPULimit(nil))
		assert.False(t, specHasMemoryLimit(nil))
		assert.False(t, specHasResourceLimits(nil))
		assert.False(t, specHasResourceRequests(nil))
	})

	t.Run("all set", func(t *testing.T) {
		spec := &corev1.PodSpec{Containers: []corev1.Container{
			{Name: "a", Resources: corev1.ResourceRequirements{Limits: bothLimits, Requests: bothRequests}},
		}}
		assert.True(t, specHasResourceLimits(spec))
		assert.True(t, specHasResourceRequests(spec))
	})

	t.Run("memory limit missing on one container", func(t *testing.T) {
		spec := &corev1.PodSpec{Containers: []corev1.Container{
			{Name: "a", Resources: corev1.ResourceRequirements{Limits: bothLimits}},
			{Name: "b", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceCPU: qty("250m")}}},
		}}
		assert.True(t, specHasCPULimit(spec), "both set cpu")
		assert.False(t, specHasMemoryLimit(spec), "container b lacks memory limit")
		assert.False(t, specHasResourceLimits(spec))
	})

	t.Run("init container without limits fails", func(t *testing.T) {
		spec := &corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init"}},
			Containers:     []corev1.Container{{Name: "a", Resources: corev1.ResourceRequirements{Limits: bothLimits}}},
		}
		assert.False(t, specHasResourceLimits(spec), "init container is unbounded")
	})

	t.Run("ephemeral containers are ignored", func(t *testing.T) {
		spec := &corev1.PodSpec{
			Containers: []corev1.Container{{Name: "a", Resources: corev1.ResourceRequirements{Limits: bothLimits, Requests: bothRequests}}},
			EphemeralContainers: []corev1.EphemeralContainer{
				{Name: "debug"},
			},
		}
		assert.True(t, specHasResourceLimits(spec), "ephemeral debug container must not flip the result")
	})

	t.Run("zero quantity does not count as set", func(t *testing.T) {
		spec := &corev1.PodSpec{Containers: []corev1.Container{
			{Name: "a", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
				corev1.ResourceCPU: qty("0"), corev1.ResourceMemory: qty("0"),
			}}},
		}}
		assert.False(t, specHasCPULimit(spec))
		assert.False(t, specHasMemoryLimit(spec))
	})
}

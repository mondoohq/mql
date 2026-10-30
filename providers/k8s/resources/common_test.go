// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
)

func TestResourceId(t *testing.T) {
	t.Run("namespaced resource", func(t *testing.T) {
		pod := corev1.Pod{
			Name:       "nginx",
			Namespace:  "test123",
			Kind:       "Pod",
			APIVersion: "v1",
		}

		id := objIdFromFields(pod.Kind, pod.Namespace, pod.Name)

		assert.NotEmpty(t, id)
		assert.Equal(t, "pod:test123:nginx", id)
	})

	t.Run("non-namespaced resource", func(t *testing.T) {
		ns := corev1.Namespace{
			Name:       "nginx",
			Kind:       "Namespace",
			APIVersion: "v1",
		}

		id := objIdFromFields(ns.Kind, ns.Namespace, ns.Name)

		assert.NotEmpty(t, id)
		assert.Equal(t, "namespace:nginx", id)
	})
}

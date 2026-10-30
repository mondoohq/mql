// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestPodImageRefs(t *testing.T) {
	t.Run("status wins over spec and refs are sorted and unique", func(t *testing.T) {
		pod := newTestPod("ns", "p", "u", nil, "nginx:1.25", "redis:7")
		pod.Status.ContainerStatuses[0].ImageID = "docker.io/library/nginx@sha256:aaa"
		pod.Status.ContainerStatuses[1].ImageID = "docker.io/library/redis@sha256:bbb"
		assert.Equal(t, []string{"docker.io/library/nginx@sha256:aaa", "docker.io/library/redis@sha256:bbb"}, podImageRefs(&pod))
	})
	t.Run("falls back to spec without status", func(t *testing.T) {
		pod := newTestPod("ns", "p", "u", nil, "nginx:1.25")
		pod.Status.ContainerStatuses = nil
		assert.Equal(t, []string{"nginx:1.25"}, podImageRefs(&pod))
	})
	t.Run("init containers count", func(t *testing.T) {
		pod := newTestPod("ns", "p", "u", nil)
		pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "busybox:1.36"}}
		assert.Equal(t, []string{"busybox:1.36"}, podImageRefs(&pod))
	})
}

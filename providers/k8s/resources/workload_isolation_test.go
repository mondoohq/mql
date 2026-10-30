// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// hostUsers is the field that decides whether root in a container is root on
// the node, and Kubernetes treats an unset field as true. Getting the
// direction wrong would report isolation the workload never asked for.
func TestSpecHostUsers(t *testing.T) {
	tests := []struct {
		name     string
		spec     *corev1.PodSpec
		expected bool
	}{
		{
			name:     "unset means the host user namespace is shared",
			spec:     &corev1.PodSpec{},
			expected: true,
		},
		{
			name:     "explicit true shares the host user namespace",
			spec:     &corev1.PodSpec{HostUsers: new(true)},
			expected: true,
		},
		{
			name:     "explicit false requests an isolated user namespace",
			spec:     &corev1.PodSpec{HostUsers: new(false)},
			expected: false,
		},
		{
			name:     "a spec we could not read reports the unsafe direction",
			spec:     nil,
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, specHostUsers(test.spec))
		})
	}
}

func TestNodeRuntimeHandlerFeatures(t *testing.T) {
	userNS := func(f *corev1.NodeRuntimeHandlerFeatures) *bool { return f.UserNamespaces }

	tests := []struct {
		name              string
		handlers          []corev1.NodeRuntimeHandler
		expectedSupported bool
		expectedReported  bool
	}{
		{
			name:             "a kubelet that advertises no handlers reports nothing",
			handlers:         nil,
			expectedReported: false,
		},
		{
			name:             "handlers without a features block report nothing",
			handlers:         []corev1.NodeRuntimeHandler{{Name: "runc"}},
			expectedReported: false,
		},
		{
			name: "a features block that omits the field reports nothing",
			handlers: []corev1.NodeRuntimeHandler{
				{Name: "runc", Features: &corev1.NodeRuntimeHandlerFeatures{
					RecursiveReadOnlyMounts: new(true),
				}},
			},
			expectedReported: false,
		},
		{
			name: "every handler reporting false is a real negative answer",
			handlers: []corev1.NodeRuntimeHandler{
				{Name: "", Features: &corev1.NodeRuntimeHandlerFeatures{UserNamespaces: new(false)}},
				{Name: "runc", Features: &corev1.NodeRuntimeHandlerFeatures{UserNamespaces: new(false)}},
			},
			expectedSupported: false,
			expectedReported:  true,
		},
		{
			name: "one supporting handler is enough",
			handlers: []corev1.NodeRuntimeHandler{
				{Name: "runc", Features: &corev1.NodeRuntimeHandlerFeatures{UserNamespaces: new(false)}},
				{Name: "runsc", Features: &corev1.NodeRuntimeHandlerFeatures{UserNamespaces: new(true)}},
			},
			expectedSupported: true,
			expectedReported:  true,
		},
		{
			name: "a handler with no features does not mask one that has them",
			handlers: []corev1.NodeRuntimeHandler{
				{Name: "runc"},
				{Name: "runsc", Features: &corev1.NodeRuntimeHandlerFeatures{UserNamespaces: new(true)}},
			},
			expectedSupported: true,
			expectedReported:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			supported, reported := nodeRuntimeHandlerFeatures(test.handlers, userNS)
			assert.Equal(t, test.expectedReported, reported, "reported")
			if reported {
				assert.Equal(t, test.expectedSupported, supported, "supported")
			}
		})
	}
}

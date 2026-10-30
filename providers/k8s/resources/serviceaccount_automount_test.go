// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// TestAutomountFromSpecAndAccount pins the Kubernetes precedence rule. The
// account level used to be ignored entirely, so a workload whose ServiceAccount
// disables automounting was reported as mounting a token.
func TestAutomountFromSpecAndAccount(t *testing.T) {
	tests := []struct {
		name    string
		pod     *bool
		account *bool
		want    bool
	}{
		{name: "neither set defaults to true", want: true},
		{name: "pod true", pod: new(true), want: true},
		{name: "pod false", pod: new(false), want: false},
		{name: "account false applies when pod is unset", account: new(false), want: false},
		{name: "account true applies when pod is unset", account: new(true), want: true},
		{name: "pod true overrides account false", pod: new(true), account: new(false), want: true},
		{name: "pod false overrides account true", pod: new(false), account: new(true), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, automountFromSpecAndAccount(tt.pod, tt.account))
		})
	}
}

// TestPodServiceAccountName pins which account a pod spec runs as, since that
// is the account whose automount setting applies.
func TestPodServiceAccountName(t *testing.T) {
	tests := []struct {
		name string
		spec *corev1.PodSpec
		want string
	}{
		{name: "nil spec", spec: nil, want: "default"},
		{name: "empty spec falls back to default", spec: &corev1.PodSpec{}, want: "default"},
		{name: "serviceAccountName wins", spec: &corev1.PodSpec{ServiceAccountName: "app"}, want: "app"},
		{
			name: "deprecated field is honored when the current one is empty",
			spec: &corev1.PodSpec{DeprecatedServiceAccount: "legacy"},
			want: "legacy",
		},
		{
			name: "current field wins over deprecated",
			spec: &corev1.PodSpec{ServiceAccountName: "app", DeprecatedServiceAccount: "legacy"},
			want: "app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, podServiceAccountName(tt.spec))
		})
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSolarisHypervisor(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
		ok   bool
	}{
		// verbatim from a Solaris 11.4.86 guest on OCI
		{"kvm guest", "kvm\n", "KVM", true},
		{"ldom", "logical-domain\n", "Oracle VM Server for SPARC", true},
		{"zone inside a kernel zone", "non-global-zone\nkernel-zone\n", "Oracle Solaris Kernel Zones", true},
		{"zone on bare metal", "non-global-zone\n", "", false},
		{"bare metal", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseSolarisHypervisor(tt.out)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

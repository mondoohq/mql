// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/stretchr/testify/require"
)

func TestIsAzureDevOpsHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// Azure DevOps Services
		{"dev.azure.com", true},
		{"DEV.AZURE.COM", true},
		{"dev.azure.com.", true},
		{"mondoo-ado-scan-test.visualstudio.com", true},
		{"Mondoo-ADO-Scan-Test.VisualStudio.com", true},
		{"mondoo-ado-scan-test.visualstudio.com.", true},
		{"vs-ssh.visualstudio.com", true},

		// everything else, including near misses and Azure DevOps Server
		{"", false},
		{"github.com", false},
		{"gitlab.com", false},
		{"gitlab.example.com", false},
		{"bitbucket.org", false},
		{"ssh.dev.azure.com", false},
		{"azure.com", false},
		{"visualstudio.com", false},
		{".visualstudio.com", false},
		{"notvisualstudio.com", false},
		{"evildev.azure.com", false},
		{"dev.azure.com.evil.example", false},
		{"mondoo-ado-scan-test.visualstudio.com.evil.example", false},
		{"tfs.corp.example", false},
		{"127.0.0.1", false},
		{"localhost", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			require.Equal(t, tc.want, isAzureDevOpsHost(tc.host))
		})
	}
}

func newCaps(t *testing.T, caps ...capability.Capability) *capability.List {
	t.Helper()
	list := capability.NewList()
	for _, c := range caps {
		require.NoError(t, list.Set(c))
	}
	return list
}

func TestAdjustAzureDevOpsCapabilities(t *testing.T) {
	tests := []struct {
		name string
		in   []capability.Capability
		want []string
	}{
		{
			name: "what go-git sends by default",
			in:   []capability.Capability{capability.Sideband64k, capability.OFSDelta},
			want: []string{"multi_ack_detailed", "ofs-delta", "side-band-64k"},
		},
		{
			name: "multi_ack becomes multi_ack_detailed",
			in:   []capability.Capability{capability.MultiACK, capability.Sideband64k},
			want: []string{"multi_ack_detailed", "side-band-64k"},
		},
		{
			name: "thin-pack is dropped",
			in:   []capability.Capability{capability.MultiACKDetailed, capability.ThinPack, capability.Sideband64k},
			want: []string{"multi_ack_detailed", "side-band-64k"},
		},
		{
			name: "multi_ack, multi_ack_detailed and thin-pack together",
			in:   []capability.Capability{capability.MultiACK, capability.MultiACKDetailed, capability.ThinPack},
			want: []string{"multi_ack_detailed"},
		},
		{
			name: "an empty request still gets multi_ack_detailed",
			in:   nil,
			want: []string{"multi_ack_detailed"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps := newCaps(t, tc.in...)
			require.NoError(t, adjustAzureDevOpsCapabilities(caps))
			require.Equal(t, tc.want, capSet(caps))

			// Applying it again changes nothing.
			require.NoError(t, adjustAzureDevOpsCapabilities(caps))
			require.Equal(t, tc.want, capSet(caps))
		})
	}
}

func TestAdjustAzureDevOpsCapabilities_KeepsValuesAndStaysValid(t *testing.T) {
	req := packp.NewUploadPackRequest()
	req.Wants = []plumbing.Hash{plumbing.NewHash("1519ae7d83e8fc731716a103ee805027f122058c")}
	require.NoError(t, req.Capabilities.Set(capability.Agent, "go-git/test"))
	require.NoError(t, req.Capabilities.Set(capability.MultiACK))
	require.NoError(t, req.Capabilities.Set(capability.ThinPack))

	require.NoError(t, adjustAzureDevOpsCapabilities(req.Capabilities))

	require.Equal(t, []string{"go-git/test"}, req.Capabilities.Get(capability.Agent))
	// multi_ack together with multi_ack_detailed is what Validate rejects.
	require.NoError(t, req.Validate())
}

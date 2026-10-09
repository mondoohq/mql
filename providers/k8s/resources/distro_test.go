// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/k8s/connection/shared/distro"
)

type distroConnection struct {
	stubConnection
	runtime string
	distro  *distro.Result
}

func (c *distroConnection) Runtime() string        { return c.runtime }
func (c *distroConnection) Distro() *distro.Result { return c.distro }

func TestAddDistroMetadata(t *testing.T) {
	conn := &distroConnection{runtime: "k8s-cluster", distro: &distro.Result{Name: distro.AKS, Source: distro.ProbeCertificate}}
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{
		{Name: "cluster", Platform: &inventory.Platform{Name: "k8s-cluster"}},
		{Name: "pod", Platform: &inventory.Platform{Name: "k8s-pod", Metadata: map[string]string{"other": "kept"}}},
		{Name: "no platform"},
	}}}
	addDistroMetadata(conn, in)
	for _, a := range in.Spec.Assets[:2] {
		assert.Equal(t, "aks", a.Platform.Metadata[distro.MetadataDistribution], a.Name)
		assert.Equal(t, "certificate", a.Platform.Metadata[distro.MetadataDistributionSource], a.Name)
	}
	assert.Equal(t, "kept", in.Spec.Assets[1].Platform.Metadata["other"])
	assert.Nil(t, in.Spec.Assets[2].Platform)

	// manifests have no API server: no metadata, so policies keep their
	// behavior for them
	manifest := &distroConnection{runtime: "k8s-manifest", distro: &distro.Result{Name: distro.Unknown}}
	in = &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{
		{Name: "pod", Platform: &inventory.Platform{Name: "k8s-pod"}},
	}}}
	addDistroMetadata(manifest, in)
	assert.Nil(t, in.Spec.Assets[0].Platform.Metadata)
}

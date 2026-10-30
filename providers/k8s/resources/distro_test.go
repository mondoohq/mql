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

func TestAddDistroMetadataAnnotatesAwsAccount(t *testing.T) {
	newInventory := func() *inventory.Inventory {
		return &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{
			{Name: "cluster", Platform: &inventory.Platform{Name: "k8s-cluster"}},
			{Name: "ns/deploy", Platform: &inventory.Platform{Name: "k8s-deployment"}, Annotations: map[string]string{"team": "a"}},
			{Name: "no platform yet"},
			nil,
		}}}
	}

	t.Run("EKS: distribution on the platform, account on the asset", func(t *testing.T) {
		conn := &distroConnection{runtime: "k8s-cluster", distro: &distro.Result{
			Name: distro.EKS, Source: distro.ProbeVersion,
			Identity: distro.Identity{Account: "111111111111", Region: "eu-central-1"},
		}}
		in := newInventory()
		addDistroMetadata(conn, in)

		cluster, deploy, bare := in.Spec.Assets[0], in.Spec.Assets[1], in.Spec.Assets[2]
		assert.Equal(t, "eks", cluster.Platform.Metadata[distro.MetadataDistribution])
		assert.Equal(t, "111111111111", cluster.Annotations[inventory.AnnotationAwsAccountId])
		// the account joins the asset's own annotations instead of replacing them
		assert.Equal(t, map[string]string{"team": "a", inventory.AnnotationAwsAccountId: "111111111111"}, deploy.Annotations)
		// an asset without a platform still belongs to the account
		assert.Equal(t, "111111111111", bare.Annotations[inventory.AnnotationAwsAccountId])
		assert.Nil(t, bare.Platform)
	})

	t.Run("GKE: a project is not an AWS account", func(t *testing.T) {
		conn := &distroConnection{runtime: "k8s-cluster", distro: &distro.Result{
			Name: distro.GKE, Source: distro.ProbeVersion, Identity: distro.Identity{Account: "my-project"},
		}}
		in := newInventory()
		addDistroMetadata(conn, in)
		assert.Equal(t, "gke", in.Spec.Assets[0].Platform.Metadata[distro.MetadataDistribution])
		assert.Nil(t, in.Spec.Assets[0].Annotations)
		assert.Equal(t, map[string]string{"team": "a"}, in.Spec.Assets[1].Annotations)
	})

	t.Run("EKS without a known account leaves annotations alone", func(t *testing.T) {
		conn := &distroConnection{runtime: "k8s-cluster", distro: &distro.Result{Name: distro.EKS, Source: distro.ProbeVersion}}
		in := newInventory()
		addDistroMetadata(conn, in)
		assert.Nil(t, in.Spec.Assets[0].Annotations)
		assert.Equal(t, map[string]string{"team": "a"}, in.Spec.Assets[1].Annotations)
	})
}

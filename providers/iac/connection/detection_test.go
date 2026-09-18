// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func testRoot() *inventory.Asset {
	return &inventory.Asset{
		Id:          "project",
		Mrn:         "//assets.api.mondoo.app/project",
		PlatformIds: []string{"//platform/project"},
		Name:        "IaC project repo",
	}
}

func testChild() *inventory.Asset {
	return &inventory.Asset{
		Name:        "Terraform HCL directory prod",
		PlatformIds: []string{"//platform/terraform/prod"},
		Connections: []*inventory.Config{{Type: "terraform-hcl", Path: "/repo/envs/prod"}},
	}
}

func TestNewDetectionWritesOneEdgeToTheAssetItReturns(t *testing.T) {
	child := testChild()
	root := testRoot()

	d := NewDetection("terraform", "envs/prod", []string{"envs/prod/main.tf"}, child, RootRef(root), nil)

	// The asset the edge is written onto and the asset the detection answers
	// with have to be the same object, or a `detection.asset` read resolves to
	// something the inventory never carried (ADR 030's one invariant).
	require.Same(t, child, d.Asset())

	require.Len(t, child.Relationships, 1)
	rel := child.Relationships[0]
	assert.Equal(t, DetectionResourceType, rel.ResourceType)
	assert.Equal(t, d.AnchorID(), rel.ResourceId)
	assert.Equal(t, AnchorID("terraform", "envs/prod"), rel.ResourceId)

	// The edge points back by identity alone: no connection, no name, no
	// credentials.
	assert.Equal(t, "project", rel.Asset.Id)
	assert.Equal(t, "//assets.api.mondoo.app/project", rel.Asset.Mrn)
	assert.Equal(t, []string{"//platform/project"}, rel.Asset.PlatformIds)
	assert.Empty(t, rel.Asset.Name)
	assert.Empty(t, rel.Asset.Connections)
}

func TestAnchorIDIsUniquePerToolAndPath(t *testing.T) {
	// Same path, different tools: a folder holding both dialects gets two
	// detections, and they must not collide on one id.
	assert.NotEqual(t, AnchorID("terraform", "mixed"), AnchorID("opentofu", "mixed"))
	// Same tool, different paths.
	assert.NotEqual(t, AnchorID("helm", "charts/api"), AnchorID("helm", "charts/web"))
	// The separator cannot be forged out of path characters, so two different
	// (tool, path) pairs cannot produce one id.
	assert.NotEqual(t, AnchorID("a", "b/c"), AnchorID("a/b", "c"))
}

func TestAdoptAssetSharesOneAssetBetweenTwoDetections(t *testing.T) {
	child := testChild()
	root := testRoot()

	first := NewDetection("terraform", "mixed", []string{"mixed/main.tf"}, child, RootRef(root), nil)
	second := NewDetection("opentofu", "mixed", []string{"mixed/main.tofu"}, nil, RootRef(root), nil)
	second.AdoptAsset(child, RootRef(root))

	// Terraform's platform ID is deliberately dialect-agnostic, so both probes
	// return one identity. One asset carrying both anchors is the honest
	// outcome, and either detection resolves into it.
	assert.Same(t, child, first.Asset())
	assert.Same(t, child, second.Asset())

	require.Len(t, child.Relationships, 2)
	assert.Equal(t, AnchorID("terraform", "mixed"), child.Relationships[0].ResourceId)
	assert.Equal(t, AnchorID("opentofu", "mixed"), child.Relationships[1].ResourceId)
}

func TestFailedDetectionCarriesNoAssetAndNoEdge(t *testing.T) {
	child := testChild()

	d := NewDetection("helm", "broken", []string{"broken/Chart.yaml"}, child,
		RootRef(testRoot()), errors.New("cannot load Chart.yaml"))

	assert.Equal(t, "cannot load Chart.yaml", d.Err)
	// Null, not an empty asset: the tool reported a failure, so there is
	// nothing to connect to and nothing to correlate on.
	assert.Nil(t, d.Asset())
	assert.Empty(t, child.Relationships)
}

func TestAttachOnAFailedDetectionIsANoOp(t *testing.T) {
	d := &Detection{Tool: "helm", Path: "broken", Err: "boom"}
	d.Attach(RootRef(testRoot()))
	assert.Nil(t, d.Asset())
}

func TestRootRefReducesToIdentity(t *testing.T) {
	ref := RootRef(testRoot())
	require.NotNil(t, ref)
	assert.Equal(t, "project", ref.Id)
	assert.Equal(t, []string{"//platform/project"}, ref.PlatformIds)
	assert.Empty(t, ref.Name)
	assert.Empty(t, ref.Platform)

	assert.Nil(t, RootRef(nil))
}

func TestDetectionByAnchor(t *testing.T) {
	root := testRoot()
	conn := NewIacConnection(1, root, Source{Kind: KindFile, Origin: "/repo"})
	d := NewDetection("terraform", "envs/prod", nil, testChild(), RootRef(root), nil)
	conn.SetDetections([]*Detection{d})

	// This is the lookup a resolve goes through, so it has to agree with the
	// id written onto the edge.
	assert.Same(t, d, conn.DetectionByAnchor(AnchorID("terraform", "envs/prod")))
	assert.Same(t, d, conn.DetectionByAnchor(d.AnchorID()))
	assert.Nil(t, conn.DetectionByAnchor(AnchorID("helm", "envs/prod")))
}

func TestPlatformIDIsStableAndPathSpecific(t *testing.T) {
	assert.Equal(t, PlatformID("/repo"), PlatformID("/repo"))
	assert.NotEqual(t, PlatformID("/repo"), PlatformID("/other"))
	assert.Contains(t, PlatformID("/repo"), "//platformid.api.mondoo.app/runtime/iac/hash/")
}

func TestAssetName(t *testing.T) {
	assert.Equal(t, "IaC project repo", AssetName("/home/dev/repo"))
	// A root path has no meaningful base name to report.
	assert.Equal(t, "IaC project", AssetName("/"))
}

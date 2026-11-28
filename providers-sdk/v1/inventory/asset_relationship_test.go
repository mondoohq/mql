// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

const testRepoPlatformID = "//platformid.api.mondoo.app/runtime/github/owner/acme/repository/app"

// declaresBucket is a declares edge as a dataset producer writes it.
func declaresBucket(t *testing.T) *AssetRelationship {
	t.Helper()
	attrs, err := structpb.NewStruct(map[string]any{
		"resource_address": "module.data.aws_s3_bucket.logs",
		"resolution":       "literal",
		"line":             3,
	})
	require.NoError(t, err)
	return &AssetRelationship{
		Kind:             RelationshipKindDeclares,
		Asset:            &Asset{Claims: []*AssetClaim{NewCloudResourceClaim("aws_s3_bucket", "acme-logs")}},
		FromResourceType: "file",
		FromResourceId:   "infra/modules/data/main.tf",
		Evidence:         RelationshipEvidence_RELATIONSHIP_EVIDENCE_DECLARED,
		Attributes:       attrs,
	}
}

func TestAssetRelationshipValidate(t *testing.T) {
	require.NoError(t, declaresBucket(t).Validate())

	// The shapes the ADR 030 producers on main write: a host stub as
	// hostRefOf builds it (MCP discovery), anchored on the host's resource.
	anchored := &AssetRelationship{
		Asset:        &Asset{Id: "host", Mrn: "", PlatformIds: []string{"//platformid.api.mondoo.app/hostname/h"}},
		ResourceType: "claude.code.mcpServer",
		ResourceId:   "claude.code.mcpServer/github",
	}
	require.NoError(t, anchored.Validate())

	// A store end the producer could name canonically joins by platform id.
	byPlatformID := declaresBucket(t)
	byPlatformID.Asset = &Asset{PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/s3/v1/accounts/1/regions/us-east-1/bucket/acme-logs"}}
	require.NoError(t, byPlatformID.Validate())

	// Synthetic: each case breaks one rule.
	cases := []struct {
		name   string
		mutate func(r *AssetRelationship)
		want   string
	}{
		{"unknown kind", func(r *AssetRelationship) { r.Kind = "can-read" }, `unknown kind "can-read"`},
		{"no asset", func(r *AssetRelationship) { r.Asset = nil }, "asset is not set"},
		{"asset with nothing to identify it", func(r *AssetRelationship) {
			r.Asset = &Asset{Name: "acme-logs", PlatformIds: []string{""}}
		}, "no mrn, platform id or claim"},
		{"asset with a credential", func(r *AssetRelationship) {
			r.Asset.Connections = []*Config{{Credentials: []*vault.Credential{vault.NewPasswordCredential("u", "hunter2")}}}
		}, "may only carry id, mrn, platform_ids, name and claims"},
		{"asset with labels", func(r *AssetRelationship) {
			r.Asset.Labels = map[string]string{"db_url": "postgres://u:p@h/db"}
		}, "may only carry"},
		{"asset with a nested asset", func(r *AssetRelationship) {
			r.Asset.RelatedAssets = []*Asset{{Name: "x"}}
		}, "may only carry"},
		{"claim of a kind the edge does not allow", func(r *AssetRelationship) {
			r.Asset.Claims = []*AssetClaim{NewDatabaseEndpointClaim("postgresql", "db", "", "")}
		}, "a database-endpoint claim cannot identify"},
		{"invalid claim", func(r *AssetRelationship) {
			r.Asset.Claims = []*AssetClaim{{Kind: AssetClaimKindCloudResource, Claims: map[string]string{AssetClaimType: "aws_s3_bucket"}}}
		}, `has no "name"`},
		{"from anchor missing where the kind requires it", func(r *AssetRelationship) {
			r.FromResourceType, r.FromResourceId = "", ""
		}, "from anchor is required"},
		{"half an anchor", func(r *AssetRelationship) { r.ResourceType = "aws.s3.bucket" }, "anchor needs both"},
		{"unknown evidence", func(r *AssetRelationship) { r.Evidence = RelationshipEvidence(99) }, "unknown evidence 99"},
		{"attribute the kind does not have", func(r *AssetRelationship) {
			r.Attributes.Fields["connection_url"] = structpb.NewStringValue("postgres://u:p@db/app")
		}, `has no attribute "connection_url"`},
		{"string where a line belongs", func(r *AssetRelationship) {
			r.Attributes.Fields["line"] = structpb.NewStringValue("3")
		}, `attribute "line" has the wrong type`},
		{"fractional line", func(r *AssetRelationship) {
			r.Attributes.Fields["line"] = structpb.NewNumberValue(1.5)
		}, `attribute "line" has the wrong type`},
		{"line zero", func(r *AssetRelationship) {
			r.Attributes.Fields["line"] = structpb.NewNumberValue(0)
		}, `attribute "line" has the wrong type`},
		{"attributes over 4 KiB", func(r *AssetRelationship) {
			r.Attributes.Fields["resource_address"] = structpb.NewStringValue(strings.Repeat("a", MaxRelationshipAttributesBytes))
		}, "attributes are"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := declaresBucket(t)
			tc.mutate(r)
			err := r.Validate()
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidRelationship), "%v", err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	// Synthetic: an ADR 030 edge must carry the anchor on the other asset.
	unanchored := &AssetRelationship{Asset: &Asset{PlatformIds: []string{testRepoPlatformID}}}
	assert.ErrorContains(t, unanchored.Validate(), "anchor is required")

	var nilRel *AssetRelationship
	assert.True(t, errors.Is(nilRel.Validate(), ErrInvalidRelationship))
}

func TestAssetRelationshipTraversable(t *testing.T) {
	assert.True(t, (&AssetRelationship{}).Traversable(), "the ADR 030 edge")
	assert.False(t, (&AssetRelationship{Kind: RelationshipKindDeclares}).Traversable())
	assert.False(t, (&AssetRelationship{Kind: RelationshipKindConnectsTo}).Traversable())
	assert.False(t, (&AssetRelationship{Kind: "unregistered"}).Traversable())
	// Synthetic: GetKind on nil reads "", the traversable kind; nil must
	// still not be followed.
	assert.False(t, (*AssetRelationship)(nil).Traversable(), "nil is not traversable")
}

func TestAssetRelationshipFieldNumbers(t *testing.T) {
	fields := (&AssetRelationship{}).ProtoReflect().Descriptor().Fields()
	for name, n := range map[protoreflect.Name]int{
		"asset": 1, "resource_type": 2, "resource_id": 3, "kind": 4,
		"from_resource_type": 5, "from_resource_id": 6, "evidence": 7, "attributes": 8,
	} {
		f := fields.ByName(name)
		require.NotNil(t, f, "AssetRelationship.%s", name)
		assert.EqualValues(t, n, f.Number(), "AssetRelationship.%s", name)
	}
	assert.Equal(t, 8, fields.Len(), "a field was added without a pin")

	assert.EqualValues(t, 1, RelationshipEvidence_RELATIONSHIP_EVIDENCE_ATTESTED)
	assert.EqualValues(t, 2, RelationshipEvidence_RELATIONSHIP_EVIDENCE_DIGEST_EXACT)
	assert.EqualValues(t, 3, RelationshipEvidence_RELATIONSHIP_EVIDENCE_RECORDED)
	assert.EqualValues(t, 4, RelationshipEvidence_RELATIONSHIP_EVIDENCE_DECLARED)
}

// Synthetic: every registered kind's claim kinds and attribute types are
// ones the validators know, so a typo in the registry fails here rather
// than refusing every record of that kind.
func TestRelationshipKindsAreConsistent(t *testing.T) {
	for name, k := range RelationshipKinds {
		for _, ck := range k.ClaimKinds {
			_, ok := assetClaimKeys[ck]
			assert.True(t, ok, "kind %q names unknown claim kind %q", name, ck)
		}
		for attr, typ := range k.Attributes {
			assert.Contains(t, []RelationshipAttributeType{RelationshipAttributeString, RelationshipAttributeBool, RelationshipAttributePositiveInt}, typ, "kind %q attribute %q", name, attr)
		}
	}
}

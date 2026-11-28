// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

// MaxRelationshipAttributesBytes is the largest serialized size of a
// relationship's attributes.
const MaxRelationshipAttributesBytes = 4 << 10

// Relationship kinds (ADR 060). The empty kind is the ADR 030 edge.
const (
	// RelationshipKindAnchored is the ADR 030 edge: the carrying asset hangs
	// off the anchor resource on the other asset, e.g. a discovered MCP server
	// off the host's mcpServer resource.
	RelationshipKindAnchored = ""
	// RelationshipKindDeclares: infrastructure as code in the carrying asset
	// (a repository) declares the other end, a cloud resource.
	RelationshipKindDeclares = "declares"
	// RelationshipKindConnectsTo: configuration in the carrying asset holds a
	// connection URL to the other end, a database endpoint.
	RelationshipKindConnectsTo = "connects-to"
)

// RelationshipAttributeType is the type of a relationship attribute.
type RelationshipAttributeType int

const (
	RelationshipAttributeString RelationshipAttributeType = iota + 1
	RelationshipAttributeBool
	// RelationshipAttributePositiveInt is a number that is a whole number of
	// at least 1, such as a 1-based line.
	RelationshipAttributePositiveInt
)

// RelationshipKind is what a kind allows on a relationship.
type RelationshipKind struct {
	// Traversable kinds are followed by cross-asset traversal (ADR 031).
	Traversable bool
	// AnchorRequired: the other end's anchor resource must be set.
	AnchorRequired bool
	// FromAnchorRequired: the carrying asset's anchor resource must be set.
	FromAnchorRequired bool
	// ClaimKinds are the claim kinds that may identify the other end when it
	// has no MRN or platform id. Empty: it must have one of those.
	ClaimKinds []string
	// Attributes are the attribute keys the kind allows, with their types.
	Attributes map[string]RelationshipAttributeType
}

// RelationshipKinds registers every relationship kind. Validate refuses any
// other kind.
var RelationshipKinds = map[string]RelationshipKind{
	RelationshipKindAnchored: {
		Traversable:    true,
		AnchorRequired: true,
	},
	RelationshipKindDeclares: {
		FromAnchorRequired: true,
		ClaimKinds:         []string{AssetClaimKindCloudResource},
		Attributes: map[string]RelationshipAttributeType{
			// the declaring resource's address, module-qualified
			// (module.data.aws_s3_bucket.exports), or a CloudFormation
			// logical id
			"resource_address": RelationshipAttributeString,
			// the directory of the root module the resource is applied
			// from, relative to the repository root
			"root_module_dir": RelationshipAttributeString,
			// how the name was read: "literal", "tfvars", ...
			"resolution": RelationshipAttributeString,
			// 1-based line of the declaration in the from anchor's file
			"line": RelationshipAttributePositiveInt,
		},
	},
	RelationshipKindConnectsTo: {
		FromAnchorRequired: true,
		ClaimKinds:         []string{AssetClaimKindDatabaseEndpoint},
		Attributes: map[string]RelationshipAttributeType{
			// how the endpoint was read: "literal", "fields",
			// "placeholder-default", ...
			"resolution": RelationshipAttributeString,
			// 1-based line of the URL in the from anchor's file
			"line": RelationshipAttributePositiveInt,
		},
	},
}

// ErrInvalidRelationship is returned, wrapped, by AssetRelationship.Validate.
var ErrInvalidRelationship = errors.New("invalid asset relationship")

// Traversable reports whether cross-asset traversal (ADR 031) follows r.
func (r *AssetRelationship) Traversable() bool {
	k, ok := RelationshipKinds[r.GetKind()]
	return ok && k.Traversable
}

// Validate checks r against the rules every relationship meets and the rules
// of its kind:
//
//   - the kind is registered in RelationshipKinds;
//   - the other end is an asset stub, carrying only id, mrn, platform_ids,
//     name and claims, so it has no room for credentials, labels or a
//     nested asset tree;
//   - the stub is identified by an MRN, a non-empty platform id, or claims
//     of a kind the relationship kind allows, each valid (ValidateClaim);
//   - each anchor is set in full (type and id) or not at all, and is set
//     where the kind requires it;
//   - evidence is a value its enum declares;
//   - the attributes are keys the kind allows, each with its type, and at
//     most MaxRelationshipAttributesBytes serialized.
func (r *AssetRelationship) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: nil", ErrInvalidRelationship)
	}
	kind, ok := RelationshipKinds[r.GetKind()]
	if !ok {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidRelationship, r.GetKind())
	}
	if err := validateRelationshipEnd(r.GetAsset(), kind); err != nil {
		return err
	}
	if err := validateAnchor("anchor", r.GetResourceType(), r.GetResourceId(), kind.AnchorRequired); err != nil {
		return err
	}
	if err := validateAnchor("from anchor", r.GetFromResourceType(), r.GetFromResourceId(), kind.FromAnchorRequired); err != nil {
		return err
	}
	if !knownEnum(r.GetEvidence()) {
		return fmt.Errorf("%w: unknown evidence %d", ErrInvalidRelationship, r.GetEvidence())
	}
	return validateRelationshipAttributes(r.GetKind(), r.GetAttributes(), kind)
}

func validateRelationshipEnd(a *Asset, kind RelationshipKind) error {
	if a == nil {
		return fmt.Errorf("%w: asset is not set", ErrInvalidRelationship)
	}
	if !isAssetStub(a) {
		return fmt.Errorf("%w: asset may only carry id, mrn, platform_ids, name and claims", ErrInvalidRelationship)
	}
	for _, c := range a.GetClaims() {
		if err := ValidateClaim(c); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidRelationship, err)
		}
		if !slices.Contains(kind.ClaimKinds, c.GetKind()) {
			return fmt.Errorf("%w: a %s claim cannot identify this kind's asset", ErrInvalidRelationship, c.GetKind())
		}
	}
	if a.GetMrn() == "" && !hasPlatformID(a) && len(a.GetClaims()) == 0 {
		return fmt.Errorf("%w: asset has no mrn, platform id or claim", ErrInvalidRelationship)
	}
	return nil
}

func validateAnchor(name, resourceType, resourceID string, required bool) error {
	switch {
	case resourceType == "" && resourceID == "":
		if required {
			return fmt.Errorf("%w: %s is required for this kind", ErrInvalidRelationship, name)
		}
	case resourceType == "" || resourceID == "":
		return fmt.Errorf("%w: %s needs both a resource type and an id", ErrInvalidRelationship, name)
	}
	return nil
}

func validateRelationshipAttributes(kindName string, attrs *structpb.Struct, kind RelationshipKind) error {
	if attrs == nil {
		return nil
	}
	if n := proto.Size(attrs); n > MaxRelationshipAttributesBytes {
		return fmt.Errorf("%w: attributes are %d bytes, more than %d", ErrInvalidRelationship, n, MaxRelationshipAttributesBytes)
	}
	for name, v := range attrs.GetFields() {
		want, ok := kind.Attributes[name]
		if !ok {
			return fmt.Errorf("%w: kind %q has no attribute %q", ErrInvalidRelationship, kindName, name)
		}
		var valid bool
		switch want {
		case RelationshipAttributeString:
			_, valid = v.GetKind().(*structpb.Value_StringValue)
		case RelationshipAttributeBool:
			_, valid = v.GetKind().(*structpb.Value_BoolValue)
		case RelationshipAttributePositiveInt:
			n, isNumber := v.GetKind().(*structpb.Value_NumberValue)
			valid = isNumber && n.NumberValue >= 1 && n.NumberValue == math.Trunc(n.NumberValue)
		}
		if !valid {
			return fmt.Errorf("%w: attribute %q has the wrong type or value", ErrInvalidRelationship, name)
		}
	}
	return nil
}

// isAssetStub reports whether a carries nothing but its identity.
func isAssetStub(a *Asset) bool {
	rest := proto.Clone(a).(*Asset)
	rest.Id, rest.Mrn, rest.PlatformIds, rest.Name, rest.Claims = "", "", nil, "", nil
	return proto.Size(rest) == 0
}

// hasPlatformID reports whether a has at least one non-empty platform id.
func hasPlatformID(a *Asset) bool {
	return slices.ContainsFunc(a.GetPlatformIds(), func(id string) bool { return id != "" })
}

// knownEnum reports whether v is a value its enum declares; proto3 enums
// accept any number on the wire.
func knownEnum(v protoreflect.Enum) bool {
	return v.Descriptor().Values().ByNumber(v.Number()) != nil
}

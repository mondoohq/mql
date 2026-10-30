// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

func schemaWith(resourceList ...*resources.ResourceInfo) *resources.Schema {
	s := &resources.Schema{Resources: map[string]*resources.ResourceInfo{}}
	for _, r := range resourceList {
		s.Resources[r.Id] = r
	}
	return s
}

func bucket(fields map[string]*resources.Field) *resources.ResourceInfo {
	return &resources.ResourceInfo{Id: "aws.s3.bucket", Name: "aws.s3.bucket", Fields: fields}
}

func detailsFor(t *testing.T, changes []Change, path string) []Change {
	t.Helper()
	var res []Change
	for _, c := range changes {
		if c.Path == path {
			res = append(res, c)
		}
	}
	return res
}

// The change this whole gate exists for: a type is baked into the bytecode and
// folded into the content checksum, so changing one re-identifies every query
// that touches the field.
func TestDiffFlagsTypeChangeAsBreaking(t *testing.T) {
	old := schemaWith(bucket(map[string]*resources.Field{
		"vpcId": {Name: "vpcId", Type: string(types.String)},
	}))
	nu := schemaWith(bucket(map[string]*resources.Field{
		"vpcId": {Name: "vpcId", Type: string(types.Resource("aws.vpc"))},
	}))

	changes := DiffSchemas(old, nu)
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeBreaking, changes[0].Kind)
	assert.Equal(t, "aws.s3.bucket.vpcId", changes[0].Path)
	assert.Contains(t, changes[0].Detail, `from "string" to "aws.vpc"`,
		"the message has to name the types in the form the author wrote them")
}

func TestDiffClassifiesAdditions(t *testing.T) {
	old := schemaWith(bucket(map[string]*resources.Field{
		"arn": {Name: "arn", Type: string(types.String)},
	}))
	nu := schemaWith(
		bucket(map[string]*resources.Field{
			"arn":       {Name: "arn", Type: string(types.String)},
			"isPublic":  {Name: "isPublic", Type: string(types.Bool)},
			"vpcRefNew": {Name: "vpcRefNew", Type: string(types.Resource("aws.vpc"))},
		}),
		&resources.ResourceInfo{Id: "aws.vpc", Name: "aws.vpc"},
	)

	changes := DiffSchemas(old, nu)
	assert.Empty(t, Breaking(changes))
	assert.Len(t, changes, 3)
	for _, c := range changes {
		assert.Equal(t, ChangeAdditive, c.Kind, c.String())
	}
}

func TestDiffFlagsRemovals(t *testing.T) {
	old := schemaWith(
		bucket(map[string]*resources.Field{
			"arn":    {Name: "arn", Type: string(types.String)},
			"legacy": {Name: "legacy", Type: string(types.Dict)},
		}),
		&resources.ResourceInfo{Id: "aws.gone", Name: "aws.gone"},
	)
	nu := schemaWith(bucket(map[string]*resources.Field{
		"arn": {Name: "arn", Type: string(types.String)},
	}))

	breaking := Breaking(DiffSchemas(old, nu))
	require.Len(t, breaking, 2)
	assert.Equal(t, "aws.gone", breaking[0].Path)
	assert.Equal(t, "resource removed", breaking[0].Detail)
	assert.Equal(t, "aws.s3.bucket.legacy", breaking[1].Path)
	assert.Equal(t, "field removed", breaking[1].Detail)
}

// An alias is a name a user can write, so dropping one breaks content just as
// dropping the resource does.
func TestDiffTreatsAliasRemovalAsBreaking(t *testing.T) {
	base := &resources.ResourceInfo{Id: "aws.iam.accessAnalyzer", Name: "aws.iam.accessAnalyzer"}
	old := &resources.Schema{Resources: map[string]*resources.ResourceInfo{
		"aws.iam.accessAnalyzer": base,
		"aws.accessanalyzer":     base,
	}}
	nu := &resources.Schema{Resources: map[string]*resources.ResourceInfo{
		"aws.iam.accessAnalyzer": base,
	}}

	breaking := Breaking(DiffSchemas(old, nu))
	require.Len(t, breaking, 1)
	assert.Equal(t, "aws.accessanalyzer", breaking[0].Path)
	assert.Contains(t, breaking[0].Detail, "alias")
}

func TestDiffClassifiesVisibilityAndMandatoryFlips(t *testing.T) {
	old := schemaWith(bucket(map[string]*resources.Field{
		"a": {Name: "a", Type: string(types.String)},
		"b": {Name: "b", Type: string(types.String), IsPrivate: true},
		"c": {Name: "c", Type: string(types.String)},
	}))
	nu := schemaWith(bucket(map[string]*resources.Field{
		"a": {Name: "a", Type: string(types.String), IsPrivate: true},
		"b": {Name: "b", Type: string(types.String)},
		"c": {Name: "c", Type: string(types.String), IsMandatory: true},
	}))

	changes := DiffSchemas(old, nu)
	assert.Equal(t, ChangeBreaking, detailsFor(t, changes, "aws.s3.bucket.a")[0].Kind)
	assert.Equal(t, ChangeAdditive, detailsFor(t, changes, "aws.s3.bucket.b")[0].Kind)
	assert.Equal(t, ChangeBreaking, detailsFor(t, changes, "aws.s3.bucket.c")[0].Kind)
}

// A list field that stops being a list is the structural change ADR 040 calls
// out by name.
func TestDiffFlagsListTypeChange(t *testing.T) {
	old := schemaWith(&resources.ResourceInfo{
		Id: "aws.s3.buckets", Name: "aws.s3.buckets",
		ListType: string(types.Resource("aws.s3.bucket")),
	})
	nu := schemaWith(&resources.ResourceInfo{
		Id: "aws.s3.buckets", Name: "aws.s3.buckets",
		ListType: string(types.Resource("aws.s3.bucketV2")),
	})

	breaking := Breaking(DiffSchemas(old, nu))
	require.Len(t, breaking, 1)
	assert.Contains(t, breaking[0].Detail, "list type changed")
}

func TestDiffInitSignatures(t *testing.T) {
	withInit := func(args ...*resources.TypedArg) *resources.Schema {
		return schemaWith(&resources.ResourceInfo{
			Id: "aws.vpc", Name: "aws.vpc",
			Init: &resources.Init{Args: args},
		})
	}
	arn := &resources.TypedArg{Name: "arn", Type: string(types.String)}
	id := &resources.TypedArg{Name: "id", Type: string(types.String), Optional: true}

	t.Run("a trailing optional arg is additive", func(t *testing.T) {
		assert.Empty(t, Breaking(DiffSchemas(withInit(arn), withInit(arn, id))))
	})

	t.Run("a mandatory arg cannot be added", func(t *testing.T) {
		mandatory := &resources.TypedArg{Name: "id", Type: string(types.String)}
		breaking := Breaking(DiffSchemas(withInit(arn), withInit(arn, mandatory)))
		require.Len(t, breaking, 1)
		assert.Contains(t, breaking[0].Detail, "mandatory init argument added")
	})

	t.Run("removing an arg is breaking", func(t *testing.T) {
		breaking := Breaking(DiffSchemas(withInit(arn, id), withInit(arn)))
		require.Len(t, breaking, 1)
		assert.Contains(t, breaking[0].Detail, "init argument removed")
	})

	t.Run("an optional arg cannot become mandatory", func(t *testing.T) {
		nowRequired := &resources.TypedArg{Name: "id", Type: string(types.String)}
		breaking := Breaking(DiffSchemas(withInit(arn, id), withInit(arn, nowRequired)))
		require.Len(t, breaking, 1)
		assert.Contains(t, breaking[0].Detail, "became mandatory")
	})
}

// Docs, provenance and presentation churn on every commit and cannot break
// content, so they must not show up as changes at all.
func TestDiffIgnoresDocumentationAndProvenance(t *testing.T) {
	old := schemaWith(&resources.ResourceInfo{
		Id: "aws.s3.bucket", Name: "aws.s3.bucket",
		Title: "Old title", Desc: "Old desc", Defaults: "arn",
		Provider: "go.mondoo.com/mql/providers/aws", MinProviderVersion: "13.1.0",
		Fields: map[string]*resources.Field{
			"arn": {Name: "arn", Type: string(types.String), Title: "Old", Desc: "Old"},
		},
	})
	nu := schemaWith(&resources.ResourceInfo{
		Id: "aws.s3.bucket", Name: "aws.s3.bucket",
		Title: "New title", Desc: "New desc", Defaults: "arn name",
		Provider: "go.mondoo.com/mql/providers/aws", MinProviderVersion: "13.9.0",
		Fields: map[string]*resources.Field{
			"arn": {
				Name: "arn", Type: string(types.String), Title: "New", Desc: "New",
				MinProviderVersion: "13.9.0",
			},
		},
	})

	assert.Empty(t, DiffSchemas(old, nu))
}

// Deprecating something is how an author retires it without breaking content,
// so the gate must not treat the marker itself as breakage.
func TestDiffTreatsDeprecationAsAdditive(t *testing.T) {
	old := schemaWith(bucket(map[string]*resources.Field{
		"endpoint": {Name: "endpoint", Type: string(types.Dict)},
	}))
	nu := schemaWith(bucket(map[string]*resources.Field{
		"endpoint": {Name: "endpoint", Type: string(types.Dict), Maturity: "deprecated"},
	}))

	changes := DiffSchemas(old, nu)
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeAdditive, changes[0].Kind)
}

func TestDiffIsStableAndNilSafe(t *testing.T) {
	assert.Nil(t, DiffSchemas(nil, schemaWith(bucket(nil))))
	assert.Nil(t, DiffSchemas(schemaWith(bucket(nil)), nil))

	old := schemaWith(bucket(map[string]*resources.Field{
		"z": {Name: "z", Type: string(types.String)},
		"a": {Name: "a", Type: string(types.String)},
	}))
	nu := schemaWith(bucket(map[string]*resources.Field{}))

	first := DiffSchemas(old, nu)
	for range 5 {
		assert.Equal(t, first, DiffSchemas(old, nu), "output must not depend on map order")
	}
	require.Len(t, first, 2)
	assert.Equal(t, "aws.s3.bucket.a", first[0].Path)
	assert.Equal(t, "aws.s3.bucket.z", first[1].Path)
}

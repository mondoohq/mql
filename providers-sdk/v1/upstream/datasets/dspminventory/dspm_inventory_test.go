// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dspminventory

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// valueBearing matches field names that suggest the field holds a data
// value, a sample, a credential or a hash of one. The records carry names
// and classes only.
var valueBearing = regexp.MustCompile(`(?i)value|sample|secret|password|passwd|token|credential|hash|key`)

// allowValueBearing lists reviewed exceptions, by full field name, each with
// the reason it carries no value. It starts empty.
var allowValueBearing = map[protoreflect.FullName]string{}

// TestDatasetRecordsCarryNoValues fails when a field whose name suggests a
// value is added to any record message without a reviewed allow entry, or
// when a store relationship attribute's name suggests one.
//
// The walk covers this file's messages. A store relationship is an
// inventory.AssetRelationship, defined in the inventory SDK, whose Validate
// keeps everything but identity off the store's asset; the attribute keys
// of the store kinds and the claim keys that name a store are checked below.
func TestDatasetRecordsCarryNoValues(t *testing.T) {
	checked := 0
	var walk func(protoreflect.MessageDescriptors)
	walk = func(msgs protoreflect.MessageDescriptors) {
		for i := range msgs.Len() {
			m := msgs.Get(i)
			for j := range m.Fields().Len() {
				f := m.Fields().Get(j)
				checked++
				if !valueBearing.MatchString(string(f.Name())) {
					continue
				}
				if _, ok := allowValueBearing[f.FullName()]; ok {
					continue
				}
				t.Errorf("%s looks like it carries a value; the dataset carries names and classes only. "+
					"Rename it, or add a reviewed entry to allowValueBearing that says why it holds no value.",
					f.FullName())
			}
			walk(m.Messages())
		}
	}
	walk(File_dspm_inventory_proto.Messages())
	require.Greater(t, checked, 25, "walked almost no fields; the descriptor walk is broken")

	// A store relationship's attributes and claims are part of the schema
	// too: a key whose name suggests a value fails the same way.
	attrs := 0
	for _, kind := range []string{inventory.RelationshipKindDeclares, inventory.RelationshipKindConnectsTo} {
		for name := range inventory.RelationshipKinds[kind].Attributes {
			attrs++
			if valueBearing.MatchString(name) {
				t.Errorf("%s attribute %q looks like it carries a value; the dataset carries names and classes only", kind, name)
			}
		}
	}
	require.Equal(t, 6, attrs, "a store attribute was added or removed; review it against the no-values rule")
	for _, key := range []string{
		inventory.AssetClaimType, inventory.AssetClaimName, inventory.AssetClaimScheme,
		inventory.AssetClaimHost, inventory.AssetClaimPort, inventory.AssetClaimDatabase,
	} {
		if valueBearing.MatchString(key) {
			t.Errorf("store claim key %q looks like it carries a value", key)
		}
	}
}

// TestDatasetRecordFieldNumbers pins the wire numbers of the record oneof and
// of the fields a consumer joins on. The dataset is versioned by package: a
// renumber is a new package (v2), never an edit.
func TestDatasetRecordFieldNumbers(t *testing.T) {
	num := func(m protoreflect.ProtoMessage, name protoreflect.Name) protoreflect.FieldNumber {
		f := m.ProtoReflect().Descriptor().Fields().ByName(name)
		require.NotNil(t, f, "field %s", name)
		return f.Number()
	}
	assert.Equal(t, protoreflect.FullName("mondoo.datasets.dspm_inventory.v1"), File_dspm_inventory_proto.Package())
	assert.EqualValues(t, 1, num(&Record{}, "entity"))
	assert.EqualValues(t, 2, num(&Record{}, "field"))
	assert.EqualValues(t, 4, num(&Record{}, "flow"))
	assert.EqualValues(t, 5, num(&Record{}, "relationship"))
	assert.EqualValues(t, 6, num(&Record{}, "unresolved_store"))
	assert.Equal(t, protoreflect.FullName("cnquery.providers.v1.AssetRelationship"),
		(&Record{}).ProtoReflect().Descriptor().Fields().ByName("relationship").Message().FullName())

	// Field 3 was store_ref; it stays reserved so no later field reuses it.
	rd := (&Record{}).ProtoReflect().Descriptor()
	assert.True(t, rd.ReservedRanges().Has(3), "field 3 is reserved")
	assert.True(t, rd.ReservedNames().Has("store_ref"), "store_ref is reserved")
	assert.Nil(t, rd.Fields().ByNumber(3))
	assert.EqualValues(t, 4, num(&Entity{}, "table"))
	assert.EqualValues(t, 4, num(&Field{}, "column"))
	assert.EqualValues(t, 2, num(&Flow{}, "finding_fingerprint"))
	assert.EqualValues(t, 4, num(&UnresolvedStore{}, "reason"))
}

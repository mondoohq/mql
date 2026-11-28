// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dspminventory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func entity(file, name string) *Record {
	return &Record{Record: &Record_Entity{Entity: &Entity{File: file, Name: name, Language: "go"}}}
}

func field(entityFile, ent, name string) *Record {
	return &Record{Record: &Record_Field{Field: &Field{EntityFile: entityFile, Entity: ent, Name: name, Category: "PII", Confidence: "HIGH"}}}
}

// storeRel builds a store relationship as a producer writes it: from the
// repository's file to the store, named by claim.
func storeRel(t testing.TB, kind, file string, claim *inventory.AssetClaim, attrs map[string]any) *Record {
	t.Helper()
	s, err := structpb.NewStruct(attrs)
	require.NoError(t, err)
	return &Record{Record: &Record_Relationship{Relationship: &inventory.AssetRelationship{
		Kind:             kind,
		Asset:            &inventory.Asset{Claims: []*inventory.AssetClaim{claim}},
		FromResourceType: FileAnchorType,
		FromResourceId:   file,
		Evidence:         inventory.RelationshipEvidence_RELATIONSHIP_EVIDENCE_DECLARED,
		Attributes:       s,
	}}}
}

// storeRecord is a store relationship to a store named name: a bucket for
// declares, a database host for connects-to.
func storeRecord(t testing.TB, file string, line int, kind, name string) *Record {
	claim := inventory.NewCloudResourceClaim("aws_s3_bucket", name)
	if kind == inventory.RelationshipKindConnectsTo {
		claim = inventory.NewDatabaseEndpointClaim("postgresql", name, "", "")
	}
	return storeRel(t, kind, file, claim, map[string]any{"line": line})
}

// storeName is the name or host a store relationship's claim gives.
func storeName(r *inventory.AssetRelationship) string {
	c := r.GetAsset().GetClaims()[0].GetClaims()
	if n := c[inventory.AssetClaimName]; n != "" {
		return n
	}
	return c[inventory.AssetClaimHost]
}

func unresolved(kind, file string, line uint32, reason string) *Record {
	return &Record{Record: &Record_UnresolvedStore{UnresolvedStore: &UnresolvedStore{Kind: kind, File: file, Line: line, Reason: reason}}}
}

func flow(file string, line uint32, rule string) *Record {
	return &Record{Record: &Record_Flow{Flow: &Flow{File: file, Line: line, RuleId: rule, Field: "email", Sink: "logs"}}}
}

// sample is a small inventory: an entity mapped to a table, a field mapped
// to a column, a declared bucket, a connection URL already reduced by the
// producer, a bucket the producer could name by platform id, an unresolved
// reference and a flow.
// Synthetic: shapes of the records a code scanner writes; no producer sends
// these yet.
func sample(t testing.TB) []*Record {
	return []*Record{
		{Record: &Record_Flow{Flow: &Flow{RuleId: "go-pii-to-log", FindingFingerprint: "fp-1", Field: "Email", Entity: "User", Category: "PII", Sink: "logs", File: "api/user.go", Line: 40}}},
		storeRel(t, inventory.RelationshipKindDeclares, "infra/modules/data/main.tf", inventory.NewCloudResourceClaim("aws_s3_bucket", "acme-logs"), map[string]any{"resource_address": "module.data.aws_s3_bucket.logs", "root_module_dir": "infra", "resolution": "literal", "line": 3}),
		storeRel(t, inventory.RelationshipKindConnectsTo, ".env", inventory.NewDatabaseEndpointClaim("postgres", "db.example.com", "5432", "app"), map[string]any{"resolution": "literal", "line": 1}),
		{Record: &Record_Relationship{Relationship: &inventory.AssetRelationship{
			Kind:             inventory.RelationshipKindDeclares,
			Asset:            &inventory.Asset{PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/s3/v1/accounts/111122223333/regions/us-east-1/bucket/acme-exports"}},
			FromResourceType: FileAnchorType,
			FromResourceId:   "infra/exports.tf",
			Evidence:         inventory.RelationshipEvidence_RELATIONSHIP_EVIDENCE_DECLARED,
		}}},
		{Record: &Record_UnresolvedStore{UnresolvedStore: &UnresolvedStore{Kind: inventory.RelationshipKindConnectsTo, File: "config/database.yml", Line: 12, Reason: "erb", Scheme: "postgresql"}}},
		{Record: &Record_Field{Field: &Field{Entity: "User", EntityFile: "models/user.go", Name: "Email", Column: "email_addr", Category: "PII", Confidence: "HIGH", File: "models/user.go", Line: 4}}},
		{Record: &Record_Entity{Entity: &Entity{Name: "User", Language: "go", File: "models/user.go", Table: "app_users", TableSource: TableSource_TABLE_SOURCE_MAPPING, Subject: "customer", Line: 2}}},
	}
}

func TestSort(t *testing.T) {
	recs := []*Record{
		flow("b.go", 2, "r1"),
		storeRecord(t, "b.tf", 1, inventory.RelationshipKindDeclares, "z"),
		storeRecord(t, "a.tf", 10, inventory.RelationshipKindDeclares, "c"),
		field("m.go", "User", "phone"),
		field("m.go", "Admin", "zip"),
		entity("m.go", "User"),
		flow("a.go", 9, "r2"),
		storeRecord(t, "a.tf", 7, inventory.RelationshipKindDeclares, "b"),
		storeRecord(t, "a.tf", 7, inventory.RelationshipKindConnectsTo, "a"),
		storeRecord(t, "a.tf", 7, inventory.RelationshipKindConnectsTo, "0"),
		field("m.go", "User", "email"),
		entity("a.go", "Zed"),
		flow("a.go", 9, "r1"),
		field("a.go", "Zed", "ssn"),
		unresolved(inventory.RelationshipKindDeclares, "b.tf", 4, "expression"),
		unresolved(inventory.RelationshipKindConnectsTo, "a.yml", 9, "erb"),
	}
	Sort(recs)

	var got []string
	for _, r := range recs {
		switch x := r.GetRecord().(type) {
		case *Record_Entity:
			got = append(got, "entity "+x.Entity.GetFile()+" "+x.Entity.GetName())
		case *Record_Field:
			got = append(got, "field "+x.Field.GetEntityFile()+" "+x.Field.GetEntity()+" "+x.Field.GetName())
		case *Record_Relationship:
			rel := x.Relationship
			got = append(got, fmt.Sprintf("store %s:%v %s %s", rel.GetFromResourceId(), attrNumber(rel, "line"), rel.GetKind(), storeName(rel)))
		case *Record_UnresolvedStore:
			got = append(got, fmt.Sprintf("unresolved %s:%d %s", x.UnresolvedStore.GetFile(), x.UnresolvedStore.GetLine(), x.UnresolvedStore.GetKind()))
		case *Record_Flow:
			got = append(got, fmt.Sprintf("flow %s:%d %s", x.Flow.GetFile(), x.Flow.GetLine(), x.Flow.GetRuleId()))
		}
	}
	assert.Equal(t, []string{
		"entity a.go Zed",
		"entity m.go User",
		"field a.go Zed ssn",
		"field m.go Admin zip",
		"field m.go User email",
		"field m.go User phone",
		"store a.tf:7 connects-to 0",
		"store a.tf:7 connects-to a",
		"store a.tf:7 declares b",
		"store a.tf:10 declares c",
		"store b.tf:1 declares z",
		"unresolved a.yml:9 connects-to",
		"unresolved b.tf:4 declares",
		"flow a.go:9 r1",
		"flow a.go:9 r2",
		"flow b.go:2 r1",
	}, got)
}

func TestWriteReadRoundTrip(t *testing.T) {
	recs := sample(t)
	Sort(recs)

	var buf bytes.Buffer
	digest, err := Write(&buf, recs)
	require.NoError(t, err)

	sum := sha256.Sum256(buf.Bytes())
	assert.Equal(t, hex.EncodeToString(sum[:]), digest, "the digest is the SHA-256 of the bytes written")

	got, err := Read(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.Len(t, got, len(recs))
	for i := range recs {
		assert.True(t, proto.Equal(recs[i], got[i]), "record %d", i)
	}

	// Same records, same bytes.
	var again bytes.Buffer
	digest2, err := Write(&again, recs)
	require.NoError(t, err)
	assert.Equal(t, digest, digest2)
}

// TestWriteIsProtobufDelimited reads Write's output with the protobuf
// library's own delimited reader, so the framing is the standard one any
// consumer can read without this package.
func TestWriteIsProtobufDelimited(t *testing.T) {
	recs := sample(t)
	var buf bytes.Buffer
	_, err := Write(&buf, recs)
	require.NoError(t, err)

	br := bufio.NewReader(&buf)
	for i := range recs {
		r := &Record{}
		require.NoError(t, protodelim.UnmarshalFrom(br, r), "record %d", i)
		assert.True(t, proto.Equal(recs[i], r), "record %d", i)
	}
	_, err = br.ReadByte()
	assert.Equal(t, io.EOF, err)
}

// delimited writes records with the protobuf library's delimited writer,
// bypassing Write's limits, to build inputs Read must refuse.
func delimited(t *testing.T, recs []*Record) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range recs {
		_, err := protodelim.MarshalTo(&buf, r)
		require.NoError(t, err)
	}
	return buf.Bytes()
}

func TestStoreRelationshipLimit(t *testing.T) {
	recs := make([]*Record, 0, MaxStoreRelationships+1)
	for i := range MaxStoreRelationships + 1 {
		recs = append(recs, storeRecord(t, "main.tf", i+1, inventory.RelationshipKindDeclares, fmt.Sprintf("b%d", i)))
	}

	_, err := Write(io.Discard, recs)
	assert.True(t, errors.Is(err, ErrLimit), "Write: %v", err)

	_, err = Read(bytes.NewReader(delimited(t, recs)))
	assert.True(t, errors.Is(err, ErrLimit), "Read: %v", err)

	// At the limit is fine.
	_, err = Read(bytes.NewReader(delimited(t, recs[:MaxStoreRelationships])))
	assert.NoError(t, err)
}

// TestStoreRelationshipRules: Write and Read refuse every store relationship
// the schema does not allow.
// Synthetic: producer bugs; no producer sends these.
func TestStoreRelationshipRules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *inventory.AssetRelationship)
		want   string
	}{
		{"attribute the kind does not have", func(r *inventory.AssetRelationship) {
			r.Attributes.Fields["connection_url"] = structpb.NewStringValue("postgres://u:p@db/app")
		}, `has no attribute "connection_url"`},
		{"fractional line", func(r *inventory.AssetRelationship) {
			r.Attributes.Fields["line"] = structpb.NewNumberValue(1.5)
		}, `attribute "line" has the wrong type`},
		{"other kind", func(r *inventory.AssetRelationship) { r.Kind = "can-read" }, `unknown kind "can-read"`},
		{"the ADR 030 kind", func(r *inventory.AssetRelationship) {
			r.Kind = inventory.RelationshipKindAnchored
			r.Attributes = nil
			r.Asset = &inventory.Asset{PlatformIds: []string{"//platformid/host"}}
			r.ResourceType, r.ResourceId = "os.base", "x"
		}, `store relationship kind "" is not`},
		{"from anchor not a file", func(r *inventory.AssetRelationship) { r.FromResourceType = "storeRef" }, `from anchor is "storeRef"`},
		{"no from anchor", func(r *inventory.AssetRelationship) { r.FromResourceType, r.FromResourceId = "", "" }, "from anchor is required"},
		{"evidence not declared", func(r *inventory.AssetRelationship) {
			r.Evidence = inventory.RelationshipEvidence_RELATIONSHIP_EVIDENCE_RECORDED
		}, "not declared"},
		{"store named by the wrong claim kind", func(r *inventory.AssetRelationship) {
			r.Asset.Claims = []*inventory.AssetClaim{inventory.NewDatabaseEndpointClaim("postgresql", "db", "", "")}
		}, "cannot identify"},
		// Synthetic: what a full inventory.Asset could smuggle into a record.
		{"store asset with a credential", func(r *inventory.AssetRelationship) {
			r.Asset.Connections = []*inventory.Config{{Credentials: []*vault.Credential{vault.NewPasswordCredential("u", "hunter2")}}}
		}, "may only carry"},
		{"store asset with labels", func(r *inventory.AssetRelationship) {
			r.Asset.Labels = map[string]string{"db_url": "postgres://u:p@h/db"}
		}, "may only carry"},
		{"store asset with related assets", func(r *inventory.AssetRelationship) {
			r.Asset.RelatedAssets = []*inventory.Asset{{Name: "x"}}
		}, "may only carry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := storeRecord(t, "main.tf", 1, inventory.RelationshipKindDeclares, "bucket")
			tc.mutate(rec.GetRelationship())

			_, err := Write(io.Discard, []*Record{rec})
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidRecord), "Write: %v", err)
			assert.Contains(t, err.Error(), tc.want)

			_, err = Read(bytes.NewReader(delimited(t, []*Record{rec})))
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidRecord), "Read: %v", err)
		})
	}

	// Every attribute each store kind registers, with its type, is accepted.
	for _, kind := range []string{inventory.RelationshipKindDeclares, inventory.RelationshipKindConnectsTo} {
		all := map[string]any{}
		for name, typ := range inventory.RelationshipKinds[kind].Attributes {
			switch typ {
			case inventory.RelationshipAttributeString:
				all[name] = "x"
			case inventory.RelationshipAttributeBool:
				all[name] = true
			case inventory.RelationshipAttributePositiveInt:
				all[name] = 1
			}
		}
		rec := storeRecord(t, "main.tf", 1, kind, "store")
		s, err := structpb.NewStruct(all)
		require.NoError(t, err)
		rec.GetRelationship().Attributes = s
		_, err = Write(io.Discard, []*Record{rec})
		assert.NoError(t, err, kind)
	}
}

// Synthetic: unresolved store records the schema does not allow.
func TestUnresolvedStoreRules(t *testing.T) {
	cases := map[string]*UnresolvedStore{
		"other kind": {Kind: "can-read", File: "a.tf", Reason: "expression"},
		"no file":    {Kind: inventory.RelationshipKindDeclares, Reason: "expression"},
		"no reason":  {Kind: inventory.RelationshipKindDeclares, File: "a.tf"},
	}
	for name, u := range cases {
		rec := &Record{Record: &Record_UnresolvedStore{UnresolvedStore: u}}
		_, err := Write(io.Discard, []*Record{rec})
		assert.True(t, errors.Is(err, ErrInvalidRecord), "%s, Write: %v", name, err)
		_, err = Read(bytes.NewReader(delimited(t, []*Record{rec})))
		assert.True(t, errors.Is(err, ErrInvalidRecord), "%s, Read: %v", name, err)
	}

	recs := make([]*Record, 0, MaxUnresolvedStores+1)
	for i := range MaxUnresolvedStores + 1 {
		recs = append(recs, unresolved(inventory.RelationshipKindDeclares, "main.tf", uint32(i+1), "expression"))
	}
	_, err := Write(io.Discard, recs)
	assert.True(t, errors.Is(err, ErrLimit), "Write: %v", err)
	_, err = Read(bytes.NewReader(delimited(t, recs[:MaxUnresolvedStores])))
	assert.NoError(t, err, "at the limit")
}

func TestEntityLimit(t *testing.T) {
	recs := make([]*Record, 0, MaxEntities+1)
	for i := range MaxEntities + 1 {
		recs = append(recs, entity("m.go", fmt.Sprintf("E%d", i)))
	}
	_, err := Read(bytes.NewReader(delimited(t, recs)))
	assert.True(t, errors.Is(err, ErrLimit), "Read: %v", err)
}

func TestReadRefusesOversizedRecordBeforeReadingIt(t *testing.T) {
	// A length prefix just over the limit and no body: Read must refuse on
	// the prefix, not try to read (or allocate) the body.
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], MaxRecordBytes+1)
	_, err := Read(bytes.NewReader(prefix[:n]))
	assert.True(t, errors.Is(err, ErrLimit), "Read: %v", err)
}

func TestReadTruncated(t *testing.T) {
	data := delimited(t, sample(t))

	_, err := Read(bytes.NewReader(data[:len(data)-3]))
	assert.Error(t, err, "a dataset that ends inside a record")

	// A lone continuation byte: a length prefix that never ends.
	_, err = Read(bytes.NewReader([]byte{0x80}))
	assert.Error(t, err)
}

func TestReadEmpty(t *testing.T) {
	got, err := Read(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Empty(t, got)
}

// BenchmarkWrite writes a 100,000-record inventory: 1,000 entities, 98,000
// fields, 500 store relationships and 500 flows.
func BenchmarkWrite(b *testing.B) {
	recs := make([]*Record, 0, 100_000)
	for i := range 1_000 {
		recs = append(recs, entity(fmt.Sprintf("models/m%d.go", i), fmt.Sprintf("Entity%d", i)))
	}
	for i := range 98_000 {
		recs = append(recs, field(fmt.Sprintf("models/m%d.go", i%1_000), fmt.Sprintf("Entity%d", i%1_000), fmt.Sprintf("field_%d", i)))
	}
	for i := range 500 {
		recs = append(recs, storeRecord(b, "infra/main.tf", i+1, inventory.RelationshipKindDeclares, fmt.Sprintf("bucket-%d", i)))
		recs = append(recs, flow(fmt.Sprintf("api/h%d.go", i), uint32(i+1), "go-pii-to-log"))
	}
	b.ReportAllocs()
	for b.Loop() {
		Sort(recs)
		if _, err := Write(io.Discard, recs); err != nil {
			b.Fatal(err)
		}
	}
}

// TestSortTiesAreCanonical gives records that are equal on the sort keys in
// both orders. Sort must put them in one order, so a producer that builds
// them from map iteration still writes one digest.
// Synthetic: two fields logged in one statement, and two resources on one
// line naming the same bucket; no producer sends these yet.
func TestSortTiesAreCanonical(t *testing.T) {
	build := func() []*Record {
		return []*Record{
			{Record: &Record_Flow{Flow: &Flow{File: "api/user.go", Line: 40, RuleId: "go-pii-to-log", FindingFingerprint: "fp-1", Field: "Email", Sink: "logs"}}},
			{Record: &Record_Flow{Flow: &Flow{File: "api/user.go", Line: 40, RuleId: "go-pii-to-log", FindingFingerprint: "fp-2", Field: "Phone", Sink: "logs"}}},
			storeRel(t, inventory.RelationshipKindDeclares, "main.tf", inventory.NewCloudResourceClaim("aws_s3_bucket", "logs"), map[string]any{"line": 3, "resource_address": "aws_s3_bucket.a"}),
			storeRel(t, inventory.RelationshipKindDeclares, "main.tf", inventory.NewCloudResourceClaim("aws_s3_bucket", "logs"), map[string]any{"line": 3, "resource_address": "aws_s3_bucket.b"}),
		}
	}
	fwd, rev := build(), build()
	slices.Reverse(rev)
	Sort(fwd)
	Sort(rev)

	var a, b bytes.Buffer
	da, err := Write(&a, fwd)
	require.NoError(t, err)
	db, err := Write(&b, rev)
	require.NoError(t, err)
	assert.Equal(t, da, db)
	assert.Equal(t, a.Bytes(), b.Bytes())
}

// TestRecordLimit feeds records that no per-kind limit counts: an empty
// record encodes to zero bytes, so each is one 0x00 length prefix.
// Synthetic; no producer writes empty records.
func TestRecordLimit(t *testing.T) {
	got, err := Read(bytes.NewReader(make([]byte, MaxRecords)))
	require.NoError(t, err)
	assert.Len(t, got, MaxRecords)

	_, err = Read(bytes.NewReader(make([]byte, MaxRecords+1)))
	assert.True(t, errors.Is(err, ErrLimit), "Read: %v", err)

	recs := make([]*Record, MaxRecords+1)
	for i := range recs {
		recs[i] = &Record{}
	}
	_, err = Write(io.Discard, recs)
	assert.True(t, errors.Is(err, ErrLimit), "Write: %v", err)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package dspminventory is the record schema of the data-inventory dataset
// (proto package mondoo.datasets.dspm_inventory.v1) and the helpers that
// write and read its protobuf-delimited form.
package dspminventory

//go:generate protoc --plugin=protoc-gen-go=../../../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-go-vtproto=../../../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=../../../../../:. --go_out=. --go_opt=paths=source_relative --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size dspm_inventory.proto

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"google.golang.org/protobuf/proto"
)

// Limits of one dataset upload. Write refuses to produce, and Read refuses
// to accept, a dataset over any of them.
const (
	// MaxRecordBytes is the largest encoded size of one record.
	MaxRecordBytes = 1 << 20
	MaxEntities    = 10_000
	MaxFields      = 100_000
	// MaxStoreRelationships is the most store relationship records.
	MaxStoreRelationships = 1_000
	// MaxUnresolvedStores is the most unresolved store records.
	MaxUnresolvedStores = 1_000
	MaxFlows            = 100_000
	// MaxRecords is the most records of any kind. It also bounds the records
	// no per-kind limit counts: one with no kind set, or a kind from a newer
	// producer, which can be as small as zero bytes.
	MaxRecords = MaxEntities + MaxFields + MaxStoreRelationships + MaxUnresolvedStores + MaxFlows
)

// ErrLimit is returned, wrapped, when a dataset is over one of the limits.
var ErrLimit = errors.New("dspm inventory over limit")

// ErrInvalidRecord is returned, wrapped, when a record breaks the schema's
// rules (a store relationship with an unknown kind or attribute).
var ErrInvalidRecord = errors.New("invalid dspm inventory record")

// FileAnchorType is the from anchor's resource type on a store
// relationship: the file that names the store.
const FileAnchorType = "file"

// isStoreKind reports whether kind is one a store record may have.
func isStoreKind(kind string) bool {
	return kind == inventory.RelationshipKindDeclares || kind == inventory.RelationshipKindConnectsTo
}

// ValidateStoreRelationship checks a store relationship record: the rules of
// its kind (inventory.AssetRelationship.Validate), a kind of declares or
// connects-to, a from anchor on a file, and declared evidence.
func ValidateStoreRelationship(r *inventory.AssetRelationship) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRecord, err)
	}
	if !isStoreKind(r.GetKind()) {
		return fmt.Errorf("%w: store relationship kind %q is not %q or %q", ErrInvalidRecord,
			r.GetKind(), inventory.RelationshipKindDeclares, inventory.RelationshipKindConnectsTo)
	}
	if r.GetFromResourceType() != FileAnchorType {
		return fmt.Errorf("%w: store relationship from anchor is %q, not %q", ErrInvalidRecord, r.GetFromResourceType(), FileAnchorType)
	}
	if r.GetEvidence() != inventory.RelationshipEvidence_RELATIONSHIP_EVIDENCE_DECLARED {
		return fmt.Errorf("%w: store relationship evidence is %s, not declared", ErrInvalidRecord, r.GetEvidence())
	}
	return nil
}

// ValidateUnresolvedStore checks an unresolved store record: a store kind, a
// file and a reason.
func ValidateUnresolvedStore(u *UnresolvedStore) error {
	if !isStoreKind(u.GetKind()) {
		return fmt.Errorf("%w: unresolved store kind %q is not %q or %q", ErrInvalidRecord,
			u.GetKind(), inventory.RelationshipKindDeclares, inventory.RelationshipKindConnectsTo)
	}
	if u.GetFile() == "" {
		return fmt.Errorf("%w: unresolved store has no file", ErrInvalidRecord)
	}
	if u.GetReason() == "" {
		return fmt.Errorf("%w: unresolved store has no reason", ErrInvalidRecord)
	}
	return nil
}

func attrNumber(r *inventory.AssetRelationship, name string) float64 {
	return r.GetAttributes().GetFields()[name].GetNumberValue()
}

// targetKey is the store's identity as a sort key: its MRN, else its first
// platform id, else its claims in key order.
func targetKey(a *inventory.Asset) string {
	if a.GetMrn() != "" {
		return a.GetMrn()
	}
	for _, id := range a.GetPlatformIds() {
		if id != "" {
			return id
		}
	}
	var b strings.Builder
	for _, c := range a.GetClaims() {
		b.WriteString(c.GetKind())
		for _, k := range slices.Sorted(maps.Keys(c.GetClaims())) {
			b.WriteString("\x00" + k + "=" + c.GetClaims()[k])
		}
		b.WriteString("\x01")
	}
	return b.String()
}

// Sort orders records into the canonical order of a dataset: entities, then
// fields, then store relationships, then unresolved stores, then flows.
// Entities are ordered by (file, name), fields by (entity file, entity, name),
// store relationships by (file, line, kind, store), with the file from the
// from anchor, the line from the attributes and the store from its identity,
// unresolved stores by (file, line, kind), and flows by (file, line, rule id). Records equal on those keys are ordered by their
// deterministic encoding, so the order depends only on the records, not on
// the order they were given in: two producers that build the same records
// write the same bytes and the same digest.
func Sort(records []*Record) {
	// Ties are rare, so a record is encoded only when it ties, and once.
	enc := map[*Record][]byte{}
	encoded := func(r *Record) []byte {
		b, ok := enc[r]
		if !ok {
			// An encoding error leaves b nil; Write reports it.
			b, _ = deterministic.Marshal(r)
			enc[r] = b
		}
		return b
	}
	slices.SortStableFunc(records, func(a, b *Record) int {
		if c := compareRecords(a, b); c != 0 {
			return c
		}
		return bytes.Compare(encoded(a), encoded(b))
	})
}

func kindRank(r *Record) int {
	switch r.GetRecord().(type) {
	case *Record_Entity:
		return 0
	case *Record_Field:
		return 1
	case *Record_Relationship:
		return 2
	case *Record_UnresolvedStore:
		return 3
	case *Record_Flow:
		return 4
	default:
		return 5
	}
}

func compareRecords(a, b *Record) int {
	if c := cmp.Compare(kindRank(a), kindRank(b)); c != 0 {
		return c
	}
	switch {
	case a.GetEntity() != nil:
		x, y := a.GetEntity(), b.GetEntity()
		return cmp.Or(
			cmp.Compare(x.GetFile(), y.GetFile()),
			cmp.Compare(x.GetName(), y.GetName()),
		)
	case a.GetField() != nil:
		x, y := a.GetField(), b.GetField()
		return cmp.Or(
			cmp.Compare(x.GetEntityFile(), y.GetEntityFile()),
			cmp.Compare(x.GetEntity(), y.GetEntity()),
			cmp.Compare(x.GetName(), y.GetName()),
		)
	case a.GetRelationship() != nil:
		x, y := a.GetRelationship(), b.GetRelationship()
		return cmp.Or(
			cmp.Compare(x.GetFromResourceId(), y.GetFromResourceId()),
			cmp.Compare(attrNumber(x, "line"), attrNumber(y, "line")),
			cmp.Compare(x.GetKind(), y.GetKind()),
			cmp.Compare(targetKey(x.GetAsset()), targetKey(y.GetAsset())),
		)
	case a.GetUnresolvedStore() != nil:
		x, y := a.GetUnresolvedStore(), b.GetUnresolvedStore()
		return cmp.Or(
			cmp.Compare(x.GetFile(), y.GetFile()),
			cmp.Compare(x.GetLine(), y.GetLine()),
			cmp.Compare(x.GetKind(), y.GetKind()),
		)
	case a.GetFlow() != nil:
		x, y := a.GetFlow(), b.GetFlow()
		return cmp.Or(
			cmp.Compare(x.GetFile(), y.GetFile()),
			cmp.Compare(x.GetLine(), y.GetLine()),
			cmp.Compare(x.GetRuleId(), y.GetRuleId()),
		)
	}
	return 0
}

// counter enforces the per-kind limits, and checks each store record,
// while a dataset is written or read.
type counter struct {
	records, entities, fields, storeRelationships, unresolvedStores, flows int
}

func (c *counter) add(r *Record) error {
	c.records++
	if c.records > MaxRecords {
		return fmt.Errorf("%w: more than %d records", ErrLimit, MaxRecords)
	}
	var n, limit int
	var kind string
	switch r.GetRecord().(type) {
	case *Record_Entity:
		c.entities++
		n, limit, kind = c.entities, MaxEntities, "entities"
	case *Record_Field:
		c.fields++
		n, limit, kind = c.fields, MaxFields, "fields"
	case *Record_Relationship:
		if err := ValidateStoreRelationship(r.GetRelationship()); err != nil {
			return err
		}
		c.storeRelationships++
		n, limit, kind = c.storeRelationships, MaxStoreRelationships, "store relationships"
	case *Record_UnresolvedStore:
		if err := ValidateUnresolvedStore(r.GetUnresolvedStore()); err != nil {
			return err
		}
		c.unresolvedStores++
		n, limit, kind = c.unresolvedStores, MaxUnresolvedStores, "unresolved stores"
	case *Record_Flow:
		c.flows++
		n, limit, kind = c.flows, MaxFlows, "flows"
	default:
		// A record kind this version does not know, from a newer producer.
		// Only MaxRecords counts it; its size is still bounded.
		return nil
	}
	if n > limit {
		return fmt.Errorf("%w: more than %d %s", ErrLimit, limit, kind)
	}
	return nil
}

// deterministic encodes map entries (a relationship's attributes, an asset's
// labels) in key order. MarshalVT does not: it hands the Struct to the
// reflection codec, whose map order is random, so two writes of the same
// records would give two digests.
var deterministic = proto.MarshalOptions{Deterministic: true}

// Write writes records to w, each as its encoded bytes prefixed with their
// length as a uvarint, in the order given (call Sort first for the canonical
// order). It returns the lowercase hex SHA-256 of the bytes written, the
// dataset's content digest. It refuses a dataset over a limit before writing
// the record that crosses it, and a store record that
// ValidateStoreRelationship or ValidateUnresolvedStore refuses.
func Write(w io.Writer, records []*Record) (string, error) {
	h := sha256.New()
	out := io.MultiWriter(w, h)
	var c counter
	var prefix [binary.MaxVarintLen64]byte
	for i, r := range records {
		if err := c.add(r); err != nil {
			return "", err
		}
		data, err := deterministic.Marshal(r)
		if err != nil {
			return "", fmt.Errorf("dspm inventory: encode record %d: %w", i, err)
		}
		if len(data) > MaxRecordBytes {
			return "", fmt.Errorf("%w: record %d is %d bytes, more than %d", ErrLimit, i, len(data), MaxRecordBytes)
		}
		n := binary.PutUvarint(prefix[:], uint64(len(data)))
		if _, err := out.Write(prefix[:n]); err != nil {
			return "", err
		}
		if _, err := out.Write(data); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Read reads a dataset written by Write. It refuses a record whose length
// prefix is over MaxRecordBytes before reading it, and a dataset over any
// per-kind limit or with a store record that ValidateStoreRelationship or
// ValidateUnresolvedStore refuses. A dataset that ends inside a record is an error.
func Read(r io.Reader) ([]*Record, error) {
	br := bufio.NewReader(r)
	var c counter
	var out []*Record
	for i := 0; ; i++ {
		size, err := binary.ReadUvarint(br)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("dspm inventory: record %d: truncated length prefix", i)
			}
			return nil, fmt.Errorf("dspm inventory: record %d: %w", i, err)
		}
		if size > MaxRecordBytes {
			return nil, fmt.Errorf("%w: record %d is %d bytes, more than %d", ErrLimit, i, size, MaxRecordBytes)
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(br, data); err != nil {
			return nil, fmt.Errorf("dspm inventory: record %d: truncated: %w", i, err)
		}
		rec := &Record{}
		if err := rec.UnmarshalVT(data); err != nil {
			return nil, fmt.Errorf("dspm inventory: record %d: %w", i, err)
		}
		if err := c.add(rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
}

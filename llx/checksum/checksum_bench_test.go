// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package checksum

import (
	"fmt"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// The checksum pass runs over every row of every scan, on the client (C0
// emission) and the server (backfill + verification recompute), so per-row
// cost is fleet-wide cost. Together with BenchmarkHashDataRow_Array500
// (checksum_test.go — the flat array shapes), these pin the remaining
// shapes that matter: the scalar row (the floor — most data rows), the
// dict-ENCODED package list (the proto-decode path a real scandb payload
// takes, distinctly more expensive than the same entries as plain maps),
// and the resource row (thousands per scan when resource recording is on).

// benchPackage mimics one package entry: a dict of ten scalar fields.
func benchPackage(i int) *llx.Primitive {
	return &llx.Primitive{
		Type: string(types.Dict),
		Map: map[string]*llx.Primitive{
			"name":        llx.StringPrimitive(fmt.Sprintf("pkg-%d", i)),
			"version":     llx.StringPrimitive("1.2.3-r4"),
			"arch":        llx.StringPrimitive("aarch64"),
			"origin":      llx.StringPrimitive("upstream-distro"),
			"format":      llx.StringPrimitive("deb"),
			"purl":        llx.StringPrimitive(fmt.Sprintf("pkg:deb/distro/pkg-%d@1.2.3-r4", i)),
			"status":      llx.StringPrimitive("installed"),
			"vendor":      llx.StringPrimitive("The Vendor"),
			"description": llx.StringPrimitive("a package that does package things, at some length"),
			"license":     llx.StringPrimitive("Apache-2.0"),
		},
	}
}

func BenchmarkHashDataRow_Scalar(b *testing.B) {
	r := strResult("code-1", "a short scalar value")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := HashDataRow("code-1", r); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHashDataRow_DictEncoded500 is the heavy row as a scandb actually
// carries it: a dict-encoded array of 500 package dicts, so every element
// rides through the proto decode before the multiset fold and per-entry map
// key-sort. Compare against BenchmarkHashDataRow_Array500/maps to see the
// decode's share.
func BenchmarkHashDataRow_DictEncoded500(b *testing.B) {
	arr := make([]*llx.Primitive, 500)
	for i := range arr {
		arr[i] = benchPackage(i)
	}
	inner := &llx.Primitive{Type: string(types.Array(types.Dict)), Array: arr}
	raw, err := inner.MarshalVT()
	if err != nil {
		b.Fatal(err)
	}
	r := &llx.Result{Data: &llx.Primitive{Type: string(types.Dict), Value: raw}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := HashDataRow("code-1", r); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashResourceRow(b *testing.B) {
	fields := make(map[string]*llx.Result, 10)
	for i := range 10 {
		k := fmt.Sprintf("field-%d", i)
		fields[k] = strResult(k, "a plausible field value")
	}
	rec := &llx.ResourceRecording{Resource: "user", Id: "root", Fields: fields}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := HashResourceRow(rec); err != nil {
			b.Fatal(err)
		}
	}
}

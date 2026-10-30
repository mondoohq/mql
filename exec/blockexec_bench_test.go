// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package exec_test

import (
	"strconv"
	"strings"
	"testing"

	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// arrayLiteralQuery builds `[0,1,...,n-1]` followed by tail.
func arrayLiteralQuery(n int, tail string) string {
	var sb strings.Builder
	sb.WriteString("[")
	for i := range n {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.Itoa(i))
	}
	sb.WriteString("]")
	sb.WriteString(tail)
	return sb.String()
}

func benchmarkArrayQuery(b *testing.B, n int, tail string) {
	runtime := testutils.LinuxMock()
	query := arrayLiteralQuery(n, tail)

	bundle, err := mqlc.Compile(query, nil, mqlc.NewConfig(runtime.Schema(), testutils.Features))
	if err != nil {
		b.Fatal(err)
	}
	var props map[string]*llx.Primitive

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := exec.ExecuteCode(runtime, bundle, props, testutils.Features)
		if err != nil {
			b.Fatal(err)
		}
		if len(res) == 0 {
			b.Fatal("no results")
		}
	}
}

// BenchmarkWhereBlock runs one block executor per array element. It measures
// the cost the executor pays per element of a filtered array.
func BenchmarkWhereBlock(b *testing.B) {
	benchmarkArrayQuery(b, 5000, ".where(_ >= 0)")
}

// BenchmarkNoBlock is the same array without a block, as a reference point.
func BenchmarkNoBlock(b *testing.B) {
	benchmarkArrayQuery(b, 5000, ".length")
}
